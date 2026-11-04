package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	migrationsexec "privacy-proxy/internal/db/migrations_exec"
	"privacy-proxy/internal/nodepolicy"
)

// executionTracking is the separate execution-tracking database of the Reth
// path (RD-1410, plan §4.11): the runtime and owner handles and the network
// singleton read at startup. Opened only in Reth mode.
type executionTracking struct {
	runtime *db.ExecDB
	admin   *db.ExecAdminDB
	meta    db.TrackingMeta
	// dedicated: the tracking database is not DATABASE_URL (development may
	// co-locate); its migrations then refuse a foreign schema.
	dedicated bool
	// payloadKeep: how long a payload bucket is kept after its last use
	// (nodeTxPayloadKeepFor the configured maximum age).
	payloadKeep time.Duration
}

// openExecutionTracking opens the tracking database the way the audit
// database is opened (RD-1147): resolved DSNs, never the main database in
// production, the owner pool migrates it and records or checks the network
// (G40), the runtime pool never runs DDL. A DSN equal to DATABASE_URL (dev and
// tests only) reuses the main pool.
func openExecutionTracking(cfg *config.Config, main *db.DB, network nodepolicy.Network) (*executionTracking, error) {
	if cfg.ExecutionAdminDatabaseURL == "" || cfg.ExecutionDatabaseURL == "" {
		return nil, fmt.Errorf("execution-tracking database URL unresolved: DATABASE_URL must be a parseable postgres:// URL so the <name>_exec default can be derived, or set EXECUTION_ADMIN_DATABASE_URL / EXECUTION_DATABASE_URL explicitly (RD-1410)")
	}
	// Never a separate audit database: the tracking migrations grant the owner
	// role every table, which would undo the audit database's append-only
	// seal. (Dev and tests may co-locate everything in DATABASE_URL.)
	for _, dsn := range []string{cfg.ExecutionDatabaseURL, cfg.ExecutionAdminDatabaseURL} {
		if dsn != cfg.DatabaseURL && (dsn == cfg.AuditDatabaseURL || dsn == cfg.AuditAdminDatabaseURL) {
			return nil, fmt.Errorf("RD-1410: the execution-tracking database must not be the audit database — EXECUTION_DATABASE_URL / EXECUTION_ADMIN_DATABASE_URL must not equal AUDIT_DATABASE_URL / AUDIT_ADMIN_DATABASE_URL")
		}
	}
	if cfg.Environment == "production" && (cfg.ExecutionDatabaseURL == cfg.DatabaseURL || cfg.ExecutionAdminDatabaseURL == cfg.DatabaseURL) {
		return nil, fmt.Errorf("RD-1410: in production the execution-tracking database must be separate from the main database — EXECUTION_DATABASE_URL / EXECUTION_ADMIN_DATABASE_URL must not equal DATABASE_URL (leave them unset to derive a separate <name>_exec database)")
	}
	open := func(dsn string, maxOpen, maxIdle int) (*db.DB, error) {
		if dsn == cfg.DatabaseURL {
			return main, nil
		}
		return db.NewWithoutMigrate(dsn, db.WithPool(maxOpen, maxIdle, cfg.DBConnMaxLifetime))
	}
	adminOpen, adminIdle := trackingAdminPool(cfg)
	adminPool, err := open(cfg.ExecutionAdminDatabaseURL, adminOpen, adminIdle)
	if err != nil {
		return nil, fmt.Errorf("failed to open execution-tracking admin database: %w", err)
	}
	t := &executionTracking{admin: db.NewExecAdminHandle(adminPool), dedicated: cfg.ExecutionAdminDatabaseURL != cfg.DatabaseURL}
	fail := func(err error) (*executionTracking, error) {
		t.close(main)
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := t.admin.MigrateExecOnly(ctx, migrationsexec.FS, t.dedicated); err != nil {
		return fail(fmt.Errorf("failed to apply execution-tracking migrations: %w", err))
	}
	if t.meta, err = t.admin.EnsureTrackingMeta(ctx, network); err != nil {
		return fail(fmt.Errorf("execution-tracking database: %w", err))
	}
	runtimePool := adminPool
	if cfg.ExecutionDatabaseURL != cfg.ExecutionAdminDatabaseURL {
		if runtimePool, err = open(cfg.ExecutionDatabaseURL, cfg.DBMaxOpenConns, cfg.DBMaxIdleConns); err != nil {
			return fail(fmt.Errorf("failed to open execution-tracking runtime database: %w", err))
		}
	}
	if runtimePool != main {
		warnIfPoolExceedsServer(runtimePool, "EXECUTION_DATABASE_URL")
	}
	t.runtime = db.NewExecHandle(runtimePool)
	// The runtime identity must see the same, migrated tracking database the
	// owner initialised (a runtime DSN pointing at another instance, or one
	// whose role cannot read it, refuses here instead of at the first write).
	if seen, err := t.runtime.TrackingMeta(ctx); err != nil || seen != t.meta {
		return fail(fmt.Errorf("execution-tracking runtime database does not match the one EXECUTION_ADMIN_DATABASE_URL initialised (check that both point at the same database): %w", errors.Join(err, db.ErrTrackingNetworkMismatch)))
	}
	switch {
	case cfg.ExecutionDatabaseURL == cfg.DatabaseURL:
		slog.Warn("the execution-tracking database is the main database: per-transaction tracking writes go to DATABASE_URL (development only)")
	case cfg.ExecutionDatabaseURL == cfg.ExecutionAdminDatabaseURL:
		slog.Warn("execution-tracking runtime and admin DSNs are identical: the runtime connects as the owner. Set EXECUTION_DATABASE_URL to connect as the restricted privacy_proxy_app role (RD-1410)")
	}
	slog.Info("execution tracking database ready (RD-1410)", "incarnation", t.meta.Incarnation)
	return t, nil
}

// trackingAdminPoolConns bounds the tracking owner's own pool: it runs
// migrations, partition maintenance and retention, a few statements at a time.
const trackingAdminPoolConns = 4

// trackingAdminPool sizes the tracking owner's pool (open, idle). When the
// runtime connects with the same DSN the one pool serves both and keeps the
// runtime size.
func trackingAdminPool(cfg *config.Config) (int, int) {
	if cfg.ExecutionAdminDatabaseURL == cfg.ExecutionDatabaseURL {
		return cfg.DBMaxOpenConns, cfg.DBMaxIdleConns
	}
	return trackingAdminPoolConns, trackingAdminPoolConns / 2
}

// close closes the pools that are not the main pool (reused in dev/tests).
func (t *executionTracking) close(main *db.DB) {
	if t == nil {
		return
	}
	mainConn := main.Conn()
	if t.runtime != nil && t.runtime.Conn() != mainConn && (t.admin == nil || t.runtime.Conn() != t.admin.Conn()) {
		t.runtime.Close()
	}
	if t.admin != nil && t.admin.Conn() != mainConn {
		t.admin.Close()
	}
}

// Tracking-database maintenance parameters (plan §4.10).
const (
	// trackingPartitionsAhead: daily status/history partitions kept ahead.
	trackingPartitionsAhead = 7
	// nodeTxMaxAge is the default maximum age of a transaction identity
	// (OPS_NODE_POLICY_MAX_AGE, 10 minutes): the lease keeper renews a
	// binding at most this long after admission.
	nodeTxMaxAge = 10 * time.Minute
	// nodeTxPayloadKeep is nodeTxPayloadKeepFor(nodeTxMaxAge).
	nodeTxPayloadKeep = nodeTxMaxAge + 64*time.Second + 5*time.Minute
)

// nodeTxPayloadKeepFor: a payload bucket is truncated once its last use
// ended this long ago — the maximum age (no renewal needs the raw transaction
// after it), the node's default finality bound (64 s) and a margin.
func nodeTxPayloadKeepFor(maxAge time.Duration) time.Duration {
	if maxAge <= 0 {
		return nodeTxPayloadKeep
	}
	return maxAge + 64*time.Second + 5*time.Minute
}

func (t *executionTracking) keep() time.Duration {
	if t.payloadKeep > 0 {
		return t.payloadKeep
	}
	return nodeTxPayloadKeep
}

// adopt returns the re-initialisation of a recreated tracking database (the
// surviving instance adopts it, G59): migrate, record the network, create the
// partitions, and return the new incarnation.
func (t *executionTracking) adopt(network nodepolicy.Network) func(context.Context) (uuid.UUID, error) {
	return func(ctx context.Context) (uuid.UUID, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		if err := t.admin.MigrateExecOnly(ctx, migrationsexec.FS, t.dedicated); err != nil {
			return uuid.Nil, err
		}
		meta, err := t.admin.EnsureTrackingMeta(ctx, network)
		if err != nil {
			return uuid.Nil, err
		}
		if err := ensureTrackingPartitions(ctx, t.admin, t.keep()); err != nil {
			return uuid.Nil, err
		}
		if seen, err := t.runtime.TrackingMeta(ctx); err != nil || seen != meta {
			return uuid.Nil, errors.Join(err, db.ErrTrackingNetworkMismatch)
		}
		return meta.Incarnation, nil
	}
}

// trackingRetention adapts the tracking database and the main-database
// effects markers to the retention manager (G41).
type trackingRetention struct {
	admin   *db.ExecAdminDB
	main    *db.DB
	network nodepolicy.Network
	keep    time.Duration
}

func (r trackingRetention) MaintainTracking(ctx context.Context, retention time.Duration) (audit.TrackingMaintenanceResult, error) {
	keep := r.keep
	if keep <= 0 {
		keep = nodeTxPayloadKeep
	}
	done, err := r.admin.MaintainTracking(ctx, trackingPartitionsAhead, retention, keep)
	return audit.TrackingMaintenanceResult{Created: done.Created, Dropped: done.Dropped, Truncated: done.Truncated, Skipped: done.Skipped}, err
}

// PruneNodeEffects prunes effects markers past retention. Markers must
// outlive every recovery source; the node does not report its manifest
// retention yet, so RETENTION_NODE_SUBMISSIONS alone bounds them.
func (r trackingRetention) PruneNodeEffects(ctx context.Context, olderThan time.Time) (int64, error) {
	return r.main.PruneNodeTxEffects(ctx, r.network, olderThan)
}

// ensureTrackingPartitions runs one maintenance pass and fails only when the
// partitions finalization needs (today, tomorrow) are missing; anything else
// it could not do (a lock timeout) is retried by the retention pass.
func ensureTrackingPartitions(ctx context.Context, admin *db.ExecAdminDB, keep time.Duration) error {
	_, err := admin.MaintainTracking(ctx, trackingPartitionsAhead, 0, keep)
	if err == nil {
		return nil
	}
	if ready, readyErr := admin.TrackingPartitionsReady(ctx); readyErr != nil || !ready {
		return errors.Join(err, readyErr)
	}
	slog.Warn("execution-tracking maintenance incomplete; retried by retention", "error", err)
	return nil
}
