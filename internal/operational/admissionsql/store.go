// Package admissionsql owns the narrow operational admission PostgreSQL schema.
// It reads no SQL configuration, users, groups or membership projections.
package admissionsql

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	a "privacy-proxy/internal/admission"
)

type Store struct {
	pool           *pgxpool.Pool
	mode           string
	schemaVersion  int
	creationLimits a.CreationLimits
}

var _ a.Store = (*Store)(nil)

func Open(ctx context.Context, dsn string) (*Store, error)       { return open(ctx, dsn, "app") }
func OpenReader(ctx context.Context, dsn string) (*Store, error) { return open(ctx, dsn, "reader") }
func OpenRetention(ctx context.Context, dsn string) (*Store, error) {
	return open(ctx, dsn, "retention")
}
func open(ctx context.Context, dsn, mode string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	config.MaxConns = 8
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	version, versionErr := schemaVersion(ctx, pool)
	s := &Store{pool: pool, mode: mode, schemaVersion: version, creationLimits: a.DefaultCreationLimits()}
	if versionErr != nil || s.CheckSchema(ctx) != nil || s.checkPrivileges(ctx) != nil {
		pool.Close()
		return nil, a.ErrUnavailable
	}
	return s, nil
}
func (s *Store) Close() { s.pool.Close() }
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func closeConnection(c *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = c.Close(ctx)
}
func dbError(err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505", "23503":
			return a.ErrConflict
		case "23514", "22P02", "22003":
			return a.ErrInvalid
		}
	}
	return a.ErrUnavailable
}
func begin(ctx context.Context, pool *pgxpool.Pool, read bool) (pgx.Tx, error) {
	opts := pgx.TxOptions{IsoLevel: pgx.ReadCommitted}
	if read {
		opts.AccessMode = pgx.ReadOnly
		opts.IsoLevel = pgx.RepeatableRead
	}
	tx, err := pool.BeginTx(ctx, opts)
	if err != nil {
		return nil, a.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','3s',true)`); err != nil {
		rollback(tx)
		return nil, a.ErrUnavailable
	}
	return tx, nil
}
func state(ctx context.Context, q querier, network a.Digest, expected a.ExpectedState) error {
	if !expected.Valid() {
		return a.ErrInvalid
	}
	var ready bool
	err := q.QueryRow(ctx, `SELECT ready AND generation=$2::uuid AND coverage_digest=$3 FROM ops_admission_v2.network_state WHERE network_key=$1`, network[:], expected.Generation, expected.Coverage[:]).Scan(&ready)
	if err != nil || !ready {
		return a.ErrUnavailable
	}
	return nil
}
func (s *Store) WithRawTransaction(ctx context.Context, scope a.Scope, callback func(a.RawTx) (a.CommitKind, error)) (a.CommitReceipt, error) {
	if s.mode != "app" || !scope.Valid() || callback == nil {
		return a.CommitReceipt{}, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, false)
	if err != nil {
		return a.CommitReceipt{}, err
	}
	defer rollback(tx)
	first, second := a.HashLock(scope.Network, scope.Hash)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, first, second); err != nil {
		return a.CommitReceipt{}, a.ErrUnavailable
	}
	if err := state(ctx, tx, scope.Network, scope.State); err != nil {
		return a.CommitReceipt{}, err
	}
	rows := &rawTx{recordReader: recordReader{ctx, tx, scope}, tx: tx, creationLimits: s.creationLimits}
	kind, err := callback(rows)
	if err != nil {
		return a.CommitReceipt{}, err
	}
	if kind != a.CommitAllow && kind != a.CommitDeny {
		return a.CommitReceipt{}, a.ErrInvalid
	}
	if kind == a.CommitDeny && rows.effects {
		return a.CommitReceipt{}, a.ErrInvalid
	}
	if err := state(ctx, tx, scope.Network, scope.State); err != nil {
		return a.CommitReceipt{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return a.CommitReceipt{}, a.ErrUnavailable
	}
	return a.CommitReceipt{Committed: true, Kind: kind}, nil
}
func (s *Store) WithReadOnly(ctx context.Context, scope a.Scope, callback func(a.ReadTx) error) error {
	if s.mode == "retention" || !scope.Valid() || callback == nil {
		return a.ErrInvalid
	}
	return s.readReady(ctx, scope.Network, scope.State, func(ctx context.Context, tx pgx.Tx) error { return callback(recordReader{ctx, tx, scope}) })
}
func (s *Store) readReady(ctx context.Context, network a.Digest, expected a.ExpectedState, callback func(context.Context, pgx.Tx) error) error {
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, true)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := state(ctx, tx, network, expected); err != nil {
		return err
	}
	if err := callback(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return a.ErrUnavailable
	}
	return nil
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}
type recordReader struct {
	ctx   context.Context
	q     querier
	scope a.Scope
}
type rawTx struct {
	recordReader
	tx             pgx.Tx
	effects        bool
	creationLimits a.CreationLimits
}
