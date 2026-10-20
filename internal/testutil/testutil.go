// Package testutil provides shared test utilities for setting up test databases
// and other common test infrastructure.
package testutil

import (
	"context"
	"os"
	"testing"

	"privacy-proxy/internal/db"
)

// SetupTestDB creates a test database connection with proper setup and cleanup.
// It uses testcontainers by default, or falls back to TEST_DATABASE_URL if set.
//
// Usage:
//
//	func TestFoo(t *testing.T) {
//	    database := testutil.SetupTestDB(t)
//	    // database is automatically closed when test completes
//	}
func SetupTestDB(t *testing.T) *db.DB {
	t.Helper()

	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := db.EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nError: %v", err)
		}
	}

	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Ensure cleanup on test completion
	t.Cleanup(func() {
		database.Close()
	})

	// Reset database to clean state
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	return database
}

// SetupTestDBWithMigrations creates a test database and runs migrations.
// This is the standard setup for most tests.
func SetupTestDBWithMigrations(t *testing.T) *db.DB {
	t.Helper()

	database := SetupTestDB(t)

	// Run migrations
	if err := database.Migrate(context.Background()); err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	return database
}
