package main

import (
	"context"
	"flag"
	"log/slog"
	"os"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

func main() {
	ctx := context.Background()
	auditOnly := flag.Bool("audit", false, "migrate the audit database (AUDIT_ADMIN_DATABASE_URL) instead of the main database")
	flag.Parse()

	cfg := config.Load()

	// The audit migrations can rewrite access_logs (003); running them here,
	// before the servers start, keeps that out of server start-up.
	if *auditOnly {
		// The same guards the server applies before it migrates the audit
		// database (RD-1147): a resolved DSN, and never the main database in
		// production.
		if cfg.AuditAdminDatabaseURL == "" {
			slog.Error("audit database URL unresolved: set AUDIT_ADMIN_DATABASE_URL, or a parseable DATABASE_URL to derive <name>_audit")
			os.Exit(1)
		}
		if cfg.IsProduction() && cfg.AuditAdminDatabaseURL == cfg.DatabaseURL {
			slog.Error("in production AUDIT_ADMIN_DATABASE_URL must not equal DATABASE_URL (leave it unset to derive a separate <name>_audit database)")
			os.Exit(1)
		}
		audit, err := openDBWithoutMigrate(cfg.AuditAdminDatabaseURL)
		if err != nil {
			slog.Error("failed to open audit database", "error", err)
			os.Exit(1)
		}
		defer audit.Close()
		slog.Info("running audit database migrations")
		if err := audit.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
			slog.Error("audit migration failed", "error", err)
			os.Exit(1)
		}
		slog.Info("audit database is up to date")
		return
	}

	// Create a temporary DB connection just for migration status
	database, err := openDBWithoutMigrate(cfg.DatabaseURL)
	if err != nil {
		slog.Error("failed to open database", "error", err)
		os.Exit(1)
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
		os.Exit(0)
	}

	slog.Info("running database migrations")

	err = database.MigrateWithProgress(ctx, func(sequence int32, name, direction, _ string) {
		slog.Info("applying migration", "sequence", sequence, "name", name, "direction", direction)
	})
	if err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}

	// Show final status
	finalVersion, _, err := database.GetMigrationStatus(ctx)
	if err != nil {
		slog.Warn("could not get final status", "error", err)
	} else {
		slog.Info("migrations completed", "schema_version", finalVersion)
	}
}

// openDBWithoutMigrate opens a database connection without running migrations.
// This is used to check migration status before running them.
func openDBWithoutMigrate(databaseURL string) (*db.DB, error) {
	return db.NewWithoutMigrate(databaseURL)
}
