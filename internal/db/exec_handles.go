// RD-1410: role-scoped handles for the separate execution-tracking database.
//
// The tracking database holds per-transaction operational state of the Reth
// execution path (bindings, status, history, the pending quota). It mirrors
// the audit database (RD-1147, audit_handles.go): a runtime handle that reads
// and writes tracking rows, and an owner handle that runs the tracking
// migrations and partition maintenance. The wrappers expose only those
// surfaces, so a main-DB call on a tracking handle is a compile error.

package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"privacy-proxy/internal/nodepolicy"
)

// ErrTrackingNetworkMismatch: the tracking database was initialised for
// another network (G40). OPS refuses to use it.
var ErrTrackingNetworkMismatch = errors.New("execution-tracking database belongs to another network")

// ErrTrackingUninitialised: tracking_meta has no row (the owner initialises it
// at startup), or the schema is missing (a recreated, unmigrated database).
var ErrTrackingUninitialised = errors.New("execution-tracking database is not initialised")

// TrackingMeta is the tracking database's network singleton.
type TrackingMeta struct {
	Network     nodepolicy.Network
	Incarnation uuid.UUID
	// CreatedAt: when this incarnation was initialised (database clock).
	CreatedAt time.Time
}

// ExecDB is the runtime handle of the execution-tracking database.
type ExecDB struct {
	pool *DB
}

// NewExecHandle wraps an open pool as the runtime tracking handle.
func NewExecHandle(pool *DB) *ExecDB { return &ExecDB{pool: pool} }

// Conn exposes the pool (pool identity for Server.Stop's double-close guards).
func (e *ExecDB) Conn() *sql.DB { return e.pool.Conn() }

// Close closes the wrapped pool.
func (e *ExecDB) Close() error { return e.pool.Close() }

// TrackingMeta reads the network singleton.
func (e *ExecDB) TrackingMeta(ctx context.Context) (TrackingMeta, error) {
	return readTrackingMeta(ctx, e.pool.conn)
}

// ExecAdminDB is the owner handle of the execution-tracking database.
type ExecAdminDB struct {
	pool *DB
}

// NewExecAdminHandle wraps an open pool as the owner tracking handle.
func NewExecAdminHandle(pool *DB) *ExecAdminDB { return &ExecAdminDB{pool: pool} }

// Conn exposes the pool (pool identity for Server.Stop's double-close guards).
func (e *ExecAdminDB) Conn() *sql.DB { return e.pool.Conn() }

// Close closes the wrapped pool.
func (e *ExecAdminDB) Close() error { return e.pool.Close() }

// MigrateExecOnly applies the tracking migration set
// (internal/db/migrations_exec), versioned in schema_version_exec. With
// dedicated set it refuses a database that holds the main or the audit schema
// (a DSN spelled differently than DATABASE_URL / AUDIT_*_DATABASE_URL but
// naming one of them); only an exact DATABASE_URL co-locates (development).
func (e *ExecAdminDB) MigrateExecOnly(ctx context.Context, execFS fs.FS, dedicated bool) error {
	if !dedicated {
		return e.pool.migrateFS(ctx, execFS, "schema_version_exec")
	}
	return e.pool.migrateFS(ctx, execFS, "schema_version_exec", refuseForeignSchema)
}

// refuseForeignSchema refuses to put the tracking schema into the main or the
// audit database.
func refuseForeignSchema(ctx context.Context, conn *pgx.Conn, _ int32) error {
	var foreign bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('users') IS NOT NULL OR to_regclass('access_logs') IS NOT NULL OR to_regclass('schema_version_audit') IS NOT NULL`).Scan(&foreign); err != nil {
		return err
	}
	if foreign {
		return fmt.Errorf("refusing to create the execution-tracking schema in a database that holds the main or the audit schema; point EXECUTION_ADMIN_DATABASE_URL at its own database")
	}
	return nil
}

// EnsureTrackingMeta records the network at the first start and otherwise
// checks it (G40): a tracking database recorded for another network is
// refused, never adopted.
func (e *ExecAdminDB) EnsureTrackingMeta(ctx context.Context, network nodepolicy.Network) (TrackingMeta, error) {
	if network.ChainID == 0 || network.ChainID > 1<<63-1 || network.DeploymentID == "" {
		return TrackingMeta{}, fmt.Errorf("invalid execution-tracking network")
	}
	if _, err := e.pool.conn.ExecContext(ctx, `INSERT INTO tracking_meta (chain_id, deployment_id) VALUES ($1, $2) ON CONFLICT (singleton) DO NOTHING`, int64(network.ChainID), network.DeploymentID); err != nil {
		return TrackingMeta{}, err
	}
	meta, err := readTrackingMeta(ctx, e.pool.conn)
	if err != nil {
		return TrackingMeta{}, err
	}
	if meta.Network != network {
		return TrackingMeta{}, ErrTrackingNetworkMismatch
	}
	return meta, nil
}

func readTrackingMeta(ctx context.Context, conn *sql.DB) (TrackingMeta, error) {
	var chainID int64
	var meta TrackingMeta
	err := conn.QueryRowContext(ctx, `SELECT chain_id, deployment_id, incarnation, created_at FROM tracking_meta`).Scan(&chainID, &meta.Network.DeploymentID, &meta.Incarnation, &meta.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) || isUndefinedTable(err) {
		return TrackingMeta{}, ErrTrackingUninitialised
	}
	if err != nil {
		return TrackingMeta{}, err
	}
	meta.Network.ChainID = uint64(chainID)
	return meta, nil
}

// isUndefinedTable reports Postgres 42P01 (relation does not exist).
func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// isInsufficientPrivilege reports Postgres 42501 (a view or table the role
// may not read).
func isInsufficientPrivilege(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}
