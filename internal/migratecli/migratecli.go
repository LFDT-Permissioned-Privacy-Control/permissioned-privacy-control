// Package migratecli is the database migration command, shared by
// cmd/migrate and the server binary (`privacy-proxy migrate`), so the shipped
// image can run a migration without the server starting (for example audit
// migration 003, which rewrites access_logs, in a maintenance window).
package migratecli

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
	migrationsexec "privacy-proxy/internal/db/migrations_exec"
)

// Main runs the migration command with args (without the program name) and
// returns its exit code: 0 on success, 1 on a failure, 2 on bad usage.
func Main(args []string) int {
	// SIGINT / SIGTERM (Ctrl-C, a Job deadline) cancel the migration, so the
	// database rolls it back instead of finishing a table rewrite nobody waits
	// for.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	flags := flag.NewFlagSet("migrate", flag.ContinueOnError)
	auditOnly := flags.Bool("audit", false, "migrate the audit database (AUDIT_ADMIN_DATABASE_URL) instead of the main database")
	execOnly := flags.Bool("exec", false, "migrate the execution-tracking database (EXECUTION_ADMIN_DATABASE_URL) instead of the main database")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		// `migrate audit` would otherwise migrate the main database.
		slog.Error("unexpected arguments; use -audit or -exec", "arguments", flags.Args())
		return 2
	}

	if *auditOnly && *execOnly {
		slog.Error("-audit and -exec migrate different databases; run them one at a time")
		return 2
	}

	cfg := config.Load()
	if err := config.FileError(); err != nil {
		slog.Error("configuration file could not be loaded", "error", err)
		return 1
	}

	// The execution-tracking database of the Reth path (RD-1410), with the
	// same guards the server applies before it migrates it.
	if *execOnly {
		if cfg.ExecutionAdminDatabaseURL == "" {
			slog.Error("execution-tracking database URL unresolved: set EXECUTION_ADMIN_DATABASE_URL, or a parseable DATABASE_URL to derive <name>_exec")
			return 1
		}
		if cfg.IsProduction() && cfg.ExecutionAdminDatabaseURL == cfg.DatabaseURL {
			slog.Error("in production EXECUTION_ADMIN_DATABASE_URL must not equal DATABASE_URL (leave it unset to derive a separate <name>_exec database)")
			return 1
		}
		exec, err := openDBWithoutMigrate(cfg.ExecutionAdminDatabaseURL)
		if err != nil {
			slog.Error("failed to open execution-tracking database", "error", err)
			return 1
		}
		defer exec.Close()
		slog.Info("running execution-tracking database migrations")
		if err := db.NewExecAdminHandle(exec).MigrateExecOnly(ctx, migrationsexec.FS, cfg.ExecutionAdminDatabaseURL != cfg.DatabaseURL); err != nil {
			slog.Error("execution-tracking migration failed", "error", err)
			return 1
		}
		slog.Info("execution-tracking database is up to date")
		return 0
	}

	// The audit migrations can rewrite access_logs (003); running them here,
	// before the servers start, keeps that out of server start-up.
	if *auditOnly {
		// The same guards the server applies before it migrates the audit
		// database (RD-1147): a resolved DSN, and never the main database in
		// production.
		if cfg.AuditAdminDatabaseURL == "" {
			slog.Error("audit database URL unresolved: set AUDIT_ADMIN_DATABASE_URL, or a parseable DATABASE_URL to derive <name>_audit")
			return 1
		}
		if cfg.IsProduction() && cfg.AuditAdminDatabaseURL == cfg.DatabaseURL {
			slog.Error("in production AUDIT_ADMIN_DATABASE_URL must not equal DATABASE_URL (leave it unset to derive a separate <name>_audit database)")
			return 1
		}
		audit, err := openDBWithoutMigrate(cfg.AuditAdminDatabaseURL)
		if err != nil {
			slog.Error("failed to open audit database", "error", err)
			return 1
		}
		defer audit.Close()
		// By content, not only by DSN: run with just the audit owner's DSN, the
		// comparison above cannot see that it names the main database. Only a
		// development setup may co-locate them, and only as DATABASE_URL itself.
		if cfg.IsProduction() || cfg.AuditAdminDatabaseURL != cfg.DatabaseURL {
			var main bool
			if err := audit.Conn().QueryRowContext(ctx, `SELECT to_regclass('users') IS NOT NULL OR to_regclass('schema_version') IS NOT NULL`).Scan(&main); err != nil {
				slog.Error("failed to inspect the audit database", "error", err)
				return 1
			}
			if main {
				slog.Error("refusing to apply the audit migrations to a database that holds the main schema; point AUDIT_ADMIN_DATABASE_URL at the audit database")
				return 1
			}
		}
		slog.Info("running audit database migrations")
		if err := audit.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
			slog.Error("audit migration failed", "error", err)
			return 1
		}
		slog.Info("audit database is up to date")
		return 0
	}

	// Create a temporary DB connection just for migration status
	database, err := openDBWithoutMigrate(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		return 1
	}
	defer database.Close()

	// Check current status
	currentVersion, pending, err := database.GetMigrationStatus(ctx)
	if err != nil {
		slog.Warn("could not get migration status (may be first run)", "error", err)
	} else {
		slog.Info("current schema version", "version", currentVersion)
		slog.Info("pending migrations", "count", pending)
	}

	if pending == 0 && err == nil {
		slog.Info("database is up to date")
		return 0
	}

	slog.Info("running database migrations")

	err = database.MigrateWithProgress(ctx, func(sequence int32, name, direction, _ string) {
		slog.Info("applying migration", "sequence", sequence, "name", name, "direction", direction)
	})
	if err != nil {
		slog.Error("migration failed", "error", err)
		return 1
	}

	// Show final status
	finalVersion, _, err := database.GetMigrationStatus(ctx)
	if err != nil {
		slog.Warn("could not get final status", "error", err)
	} else {
		slog.Info("migrations completed", "schema_version", finalVersion)
	}
	return 0
}

// openDBWithoutMigrate opens a database connection without running migrations.
// This is used to check migration status before running them.
func openDBWithoutMigrate(databaseURL string) (*db.DB, error) {
	return db.NewWithoutMigrate(databaseURL)
}
