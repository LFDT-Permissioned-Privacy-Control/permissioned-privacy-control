package db

import (
	"context"
	"os"
	"testing"
)

func setupTestDB(t *testing.T) *DB {
	// Check if TEST_DATABASE_URL is set (for CI/external PostgreSQL)
	dbURL := os.Getenv("TEST_DATABASE_URL")

	if dbURL == "" {
		// Use testcontainers for local development (no external PostgreSQL needed)
		var cleanup func()
		dbURL, cleanup = SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else {
		// Use external PostgreSQL (for CI or when explicitly set)
		if err := EnsureTestDatabase(dbURL); err != nil {
			t.Fatalf("PostgreSQL not available. Start it with: docker-compose up -d postgres\nOr: make docker-up\nError: %v", err)
		}
	}

	database, err := New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}

	// Reset database for fresh test (this drops all tables except schema_version and runs migrations)
	if err := ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}

	return database
}

func cleanupTestDB(t *testing.T, database *DB) {
	database.Close()
}

func TestLogAccess(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	// Log access (no policy required anymore - RBAC handles access control)
	if err := database.LogAccess(context.Background(), "did:privado:test_user", "eth_call", 200, "127.0.0.1"); err != nil {
		t.Fatalf("failed to log access: %v", err)
	}

	logs, err := database.GetAccessLogs(context.Background(), AccessLogFilter{Limit: 10})
	if err != nil {
		t.Fatalf("failed to get logs: %v", err)
	}

	if len(logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(logs))
	}

	if logs[0].ExternalID != "did:privado:test_user" {
		t.Errorf("got ExternalID %q, want did:privado:test_user", logs[0].ExternalID)
	}

	if logs[0].Method != "eth_call" {
		t.Errorf("got Method %q, want eth_call", logs[0].Method)
	}

	if logs[0].StatusCode != 200 {
		t.Errorf("got StatusCode %d, want 200", logs[0].StatusCode)
	}
}
