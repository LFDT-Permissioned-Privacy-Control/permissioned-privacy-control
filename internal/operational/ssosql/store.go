package ssosql

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	m "privacy-proxy/internal/ssotransaction"
	"strings"
	"time"
)

type beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func begin(ctx context.Context, p beginner) (pgx.Tx, error) {
	tx, e := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return nil, ErrUnavailable
	}
	if _, e = tx.Exec(ctx, `SELECT pg_catalog.set_config('search_path','pg_catalog,pg_temp',true),pg_catalog.set_config('lock_timeout','500ms',true),pg_catalog.set_config('statement_timeout','2s',true),pg_catalog.set_config('synchronous_commit','on',true)`); e != nil {
		rollback(tx)
		return nil, ErrUnavailable
	}
	return tx, nil
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

const stateColumns = `singleton,schema_version,CASE WHEN octet_length(schema_checksum)=71 THEN schema_checksum ELSE NULL END,namespace,epoch::text,broker_namespace,broker_epoch::text,ready,app_role::text,retention_role::text,max_active_rows,max_ready_rows,max_active_bytes,max_all_rows,max_metadata_bytes,audit_retention_seconds,active_rows,ready_rows,active_bytes,all_rows,metadata_bytes,last_gc_us`

type state struct {
	StatusResult
	lastGC m.Micros
}

func readState(ctx context.Context, q querier, lock string) (state, error) {
	var z state
	var singleton bool
	var ns, bns []byte
	var ver int16
	e := q.QueryRow(ctx, `SELECT `+stateColumns+` FROM ops_sso_v1.state WHERE singleton `+lock).Scan(&singleton, &ver, &z.Metadata.SchemaChecksum, &ns, &z.Metadata.Scope.Epoch, &bns, &z.Metadata.Scope.BrokerRecoveryEpoch, &z.Ready, &z.Metadata.Roles.App, &z.Metadata.Roles.Retention, &z.Metadata.Limits.ActiveRows, &z.Metadata.Limits.ReadyRows, &z.Metadata.Limits.ActiveCipherBytes, &z.Metadata.Limits.AllRows, &z.Metadata.Limits.MetadataBytes, &z.Metadata.Limits.AuditRetentionSeconds, &z.Usage.ActiveRows, &z.Usage.ReadyRows, &z.Usage.ActiveCipherBytes, &z.Usage.AllRows, &z.Usage.MetadataBytes, &z.lastGC)
	if e != nil || !singleton || ver != 1 || z.Metadata.SchemaChecksum != SchemaChecksum() || len(ns) != 32 || len(bns) != 32 {
		return state{}, ErrUnavailable
	}
	copy(z.Metadata.Scope.Namespace[:], ns)
	copy(z.Metadata.Scope.BrokerNamespace[:], bns)
	z.Metadata.SchemaVersion = 1
	if !z.Metadata.Scope.Valid() || !validRoles(z.Metadata.Roles) || !usageValid(z.Usage, z.Metadata.Limits) || !z.lastGC.Valid() {
		return state{}, ErrUnavailable
	}
	return z, nil
}
func OpenApp(ctx context.Context, c Config) (*Store, error)       { return open(ctx, c, "app") }
func OpenRetention(ctx context.Context, c Config) (*Store, error) { return open(ctx, c, "retention") }
func open(ctx context.Context, c Config, mode string) (*Store, error) {
	if strings.TrimSpace(c.DSN) == "" || !c.Expected.Valid() || c.Clock == nil {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, e := pgxpool.ParseConfig(c.DSN)
	if e != nil {
		return nil, ErrUnavailable
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, ErrUnavailable
	}
	s := &Store{pool: pool, clock: c.Clock, mode: mode}
	fail := func(e error) (*Store, error) { s.Close(); return nil, e }
	tx, e := begin(ctx, pool)
	if e != nil {
		return fail(e)
	}
	defer rollback(tx)
	failTx := func(e error) (*Store, error) { rollback(tx); return fail(e) }
	if checkCatalog(ctx, tx) != nil {
		return failTx(ErrUnavailable)
	}
	z, e := readState(ctx, tx, "FOR SHARE")
	if e != nil {
		return failTx(e)
	}
	s.metadata = z.Metadata
	if !z.Ready || z.Metadata.Scope != c.Expected {
		return failTx(ErrConflict)
	}
	if e = s.check(ctx, tx, false); e != nil {
		return failTx(e)
	}
	if _, e = s.now(); e != nil {
		return failTx(e)
	}
	if e = tx.Commit(ctx); e != nil {
		return failTx(ErrUnavailable)
	}
	if ctx.Err() != nil {
		return failTx(ErrUnavailable)
	}
	return s, nil
}
func (s *Store) check(ctx context.Context, q querier, write bool) error {
	if checkCatalog(ctx, q) != nil {
		return ErrUnavailable
	}
	lock := "FOR SHARE"
	if write {
		lock = "FOR UPDATE"
	}
	z, e := readState(ctx, q, lock)
	if e != nil {
		return e
	}
	if !z.Ready || z.Metadata != s.metadata {
		return ErrConflict
	}
	var current string
	if q.QueryRow(ctx, `SELECT current_user`).Scan(&current) != nil {
		return ErrUnavailable
	}
	expected := z.Metadata.Roles.App
	if s.mode == "retention" {
		expected = z.Metadata.Roles.Retention
	}
	if current != expected {
		return ErrRole
	}
	for _, mode := range []string{"app", "retention"} {
		if e = checkPrivileges(ctx, q, z.Metadata.Roles, mode); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) start(ctx context.Context, mode string, write bool) (context.Context, context.CancelFunc, pgx.Tx, error) {
	if !s.valid(mode) {
		return nil, nil, nil, ErrRole
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	tx, e := begin(ctx, s.pool)
	if e != nil {
		cancel()
		return nil, nil, nil, e
	}
	if e = s.check(ctx, tx, write); e != nil {
		rollback(tx)
		cancel()
		return nil, nil, nil, e
	}
	return ctx, cancel, tx, nil
}
func (s *Store) commit(ctx context.Context, tx pgx.Tx, g CommitGate, write bool) error {
	if e := s.check(ctx, tx, write); e != nil {
		return e
	}
	if e := gateNow(ctx, g); e != nil {
		return e
	}
	if e := tx.Commit(ctx); e != nil {
		return ErrUnavailable
	}
	if e := gateNow(ctx, g); e != nil {
		return e
	}
	if _, e := s.now(); e != nil {
		return e
	}
	return nil
}
func (s *Store) usage(ctx context.Context, tx pgx.Tx, active, ready, bytes, all int64) error {
	z, e := readState(ctx, tx, "FOR UPDATE")
	if e != nil {
		return e
	}
	u := z.Usage
	u.ActiveRows += active
	u.ReadyRows += ready
	u.ActiveCipherBytes += bytes
	u.AllRows += all
	u.MetadataBytes = u.AllRows * m.MetadataChargeBytes
	if !usageValid(u, z.Metadata.Limits) {
		return ErrCapacity
	}
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.state SET active_rows=active_rows+$1,ready_rows=ready_rows+$2,active_bytes=active_bytes+$3,all_rows=all_rows+$4 WHERE singleton`, active, ready, bytes, all)
	if e != nil || tag.RowsAffected() != 1 {
		return ErrUnavailable
	}
	return nil
}
