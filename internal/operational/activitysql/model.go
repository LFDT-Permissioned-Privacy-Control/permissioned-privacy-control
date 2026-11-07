// Package activitysql is the named operational SQL boundary for the bounded
// SEALED activity population. It reads no users, groups or policy projections.
package activitysql

import (
	"context"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	a "privacy-proxy/internal/activitylog"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/networkidentity"
)

type Scope struct {
	NetworkKey                   [32]byte
	SourceID, ExpectedGeneration string
}

func (s Scope) Valid() bool {
	return a.CanonicalUUID(s.SourceID) && a.CanonicalUUID(s.ExpectedGeneration)
}

type StorageLimits struct{ Rows, Bytes, Runs int64 }

func DefaultStorageLimits() StorageLimits { return StorageLimits{100000000, 64 << 30, 65536} }
func (l StorageLimits) Valid() bool {
	return l.Rows >= 1 && l.Rows <= 1000000000 && l.Bytes >= 1 && l.Bytes <= 1<<40 && l.Runs >= 1 && l.Runs <= 1000000
}

type RoleNames struct{ Writer, Reader, Retention string }

var rolePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

func (r RoleNames) Valid() bool {
	return rolePattern.MatchString(r.Writer) && rolePattern.MatchString(r.Reader) && rolePattern.MatchString(r.Retention) && r.Writer != r.Reader && r.Writer != r.Retention && r.Reader != r.Retention
}

type Registration struct {
	Network       networkidentity.Binding
	SourceID      string
	Configuration [32]byte
	Limits        StorageLimits
	Roles         RoleNames
}
type sourceState struct {
	metadata      a.StoreMetadata
	chain         string
	lock          int64
	ready         bool
	floor, headID int64
	headHash      string
	rows, bytes   int64
	limits        StorageLimits
	roles         RoleNames
	pruneThrough  *int64
}

const sourceColumns = `network_key,source_id::text,chain_name,chain_lock_key,generation::text,configuration,ready,retained_from_us,head_id,head_hash,row_count,byte_count,max_rows,max_bytes,max_runs,writer_role::text,reader_role::text,retention_role::text,prune_through_id`

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func scanSource(row pgx.Row) (sourceState, error) {
	var s sourceState
	var network, config []byte
	err := row.Scan(&network, &s.metadata.SourceID, &s.chain, &s.lock, &s.metadata.Generation, &config, &s.ready, &s.floor, &s.headID, &s.headHash, &s.rows, &s.bytes, &s.limits.Rows, &s.limits.Bytes, &s.limits.Runs, &s.roles.Writer, &s.roles.Reader, &s.roles.Retention, &s.pruneThrough)
	if err != nil || len(network) != 32 || len(config) != 32 {
		return s, a.ErrUnavailable
	}
	copy(s.metadata.NetworkKey[:], network)
	copy(s.metadata.Configuration[:], config)
	s.metadata.Format = a.Format()
	if !a.CanonicalUUID(s.metadata.SourceID) || !a.CanonicalUUID(s.metadata.Generation) || s.chain != chainName([32]byte(s.metadata.NetworkKey)) || s.lock != audit.AccessLogChainLockKey(s.chain) || !s.limits.Valid() || !s.roles.Valid() || s.floor < 0 || s.floor > a.MaxObservedMicros || s.rows < 0 || s.bytes < 0 || s.rows > s.limits.Rows || s.bytes > s.limits.Bytes || s.headID < 0 || (s.headID == 0) != (s.headHash == "") || (s.headID == 0 && (s.rows != 0 || s.bytes != 0)) || (s.rows == 0) != (s.bytes == 0) {
		return s, a.ErrUnavailable
	}
	if s.headID > 0 {
		if _, err := a.ParseDigestHex(s.headHash); err != nil {
			return s, a.ErrUnavailable
		}
	}
	return s, nil
}
func chainName(key [32]byte) string { return "ops-activity-v1/" + hex.EncodeToString(key[:]) }
func selected(ctx context.Context, q queryer, scope Scope, locked bool, requireReady bool) (sourceState, error) {
	sql := `SELECT ` + sourceColumns + ` FROM ops_activity_v1.sources WHERE network_key=$1`
	if locked {
		sql += ` FOR UPDATE`
	}
	s, err := scanSource(q.QueryRow(ctx, sql, scope.NetworkKey[:]))
	if err != nil || s.metadata.SourceID != scope.SourceID || s.metadata.Generation != scope.ExpectedGeneration || s.metadata.NetworkKey != a.Digest(scope.NetworkKey) || s.pruneThrough != nil || requireReady && !s.ready {
		return sourceState{}, a.ErrUnavailable
	}
	return s, nil
}

type store struct {
	pool  *pgxpool.Pool
	scope Scope
	mode  string
	state sourceState // immutable selected assembly values; moving fields re-read
}
type Writer struct{ *store }
type Reader struct{ *store }
type Retention struct{ *store }

func (s *store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}
func (s *store) Metadata() a.StoreMetadata {
	if s == nil {
		return a.StoreMetadata{}
	}
	return s.state.metadata
}

func open(ctx context.Context, dsn string, scope Scope, mode string) (*store, error) {
	if strings.TrimSpace(dsn) == "" || !scope.Valid() {
		return nil, a.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	c.MaxConns = 4
	c.ConnConfig.ConnectTimeout = 3 * time.Second
	if c.ConnConfig.RuntimeParams == nil {
		c.ConnConfig.RuntimeParams = map[string]string{}
	}
	c.ConnConfig.RuntimeParams["timezone"] = "UTC"
	c.ConnConfig.RuntimeParams["search_path"] = "pg_catalog,public,pg_temp"
	p, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	s := &store{pool: p, scope: scope, mode: mode}
	tx, err := begin(ctx, p, true)
	if err != nil {
		p.Close()
		return nil, err
	}
	success := false
	defer func() {
		rollback(tx)
		if !success {
			p.Close()
		}
	}()
	state, err := selected(ctx, tx, scope, false, true)
	if err != nil {
		return nil, err
	}
	s.state = state
	if err := checkSchema(ctx, tx); err != nil {
		return nil, err
	}
	if err := checkRole(ctx, tx, state.roles, mode); err != nil {
		return nil, err
	}
	if err := checkHead(ctx, tx, state, mode); err != nil {
		return nil, err
	}
	if tx.Commit(ctx) != nil {
		return nil, a.ErrUnavailable
	}
	success = true
	return s, nil
}
func OpenWriter(ctx context.Context, dsn string, scope Scope) (*Writer, error) {
	s, err := open(ctx, dsn, scope, "writer")
	if err != nil {
		return nil, err
	}
	return &Writer{s}, nil
}
func OpenReader(ctx context.Context, dsn string, scope Scope) (*Reader, error) {
	s, err := open(ctx, dsn, scope, "reader")
	if err != nil {
		return nil, err
	}
	return &Reader{s}, nil
}
func OpenRetention(ctx context.Context, dsn string, scope Scope) (*Retention, error) {
	s, err := open(ctx, dsn, scope, "retention")
	if err != nil {
		return nil, err
	}
	return &Retention{s}, nil
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func begin(ctx context.Context, p *pgxpool.Pool, read bool) (pgx.Tx, error) {
	opts := pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	statement := "3s"
	if read {
		opts.IsoLevel = pgx.RepeatableRead
		opts.AccessMode = pgx.ReadOnly
		statement = "2s"
	}
	tx, err := p.BeginTx(ctx, opts)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout',$1,true),set_config('work_mem','4MB',true),set_config('max_parallel_workers_per_gather','0',true)`, statement); err != nil {
		rollback(tx)
		return nil, a.ErrUnavailable
	}
	return tx, nil
}
