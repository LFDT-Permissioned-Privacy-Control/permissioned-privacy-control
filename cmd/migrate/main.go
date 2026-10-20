package main

import (
	"context"
	"log/slog"
	"os"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
)

func main() {
	ctx := context.Background()

	cfg := config.Load()

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
