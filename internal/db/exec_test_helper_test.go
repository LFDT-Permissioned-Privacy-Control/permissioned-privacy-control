package db

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	migrationsexec "privacy-proxy/internal/db/migrations_exec"
	"privacy-proxy/internal/nodepolicy"
)

var execTestDatabaseSequence atomic.Uint64

var trackingTestNetwork = nodepolicy.Network{ChainID: 31337, DeploymentID: "tracking-test"}

// setupMainAndURL is setupTestDB that also returns the main database URL, so a
// test can create a sibling tracking database on the same server.
func setupMainAndURL(t *testing.T) (*DB, string) {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else if err := EnsureTestDatabase(dbURL); err != nil {
		t.Fatalf("PostgreSQL not available: %v", err)
	}
	database, err := New(dbURL)
	if err != nil {
		t.Fatalf("failed to create test DB: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	if err := ResetTestDatabase(database); err != nil {
		t.Fatalf("failed to reset test database: %v", err)
	}
	return database, dbURL
}

// newTrackingDatabase creates a fresh, empty sibling database of mainURL
// (what infra provisions as <name>_exec) and returns its URL.
func newTrackingDatabase(t *testing.T, mainURL string) string {
	t.Helper()
	u, err := url.Parse(mainURL)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(u.Path, "/")
	u.Path = fmt.Sprintf("/%s_exec_%d_%d", name, os.Getpid(), execTestDatabaseSequence.Add(1))
	execURL := u.String()
	if err := EnsureTestDatabase(execURL); err != nil {
		t.Fatalf("create tracking database: %v", err)
	}
	execName := strings.TrimPrefix(u.Path, "/")
	t.Cleanup(func() {
		// Registered before the pools' cleanups, so it runs after they close.
		main, err := NewWithoutMigrate(mainURL)
		if err != nil {
			t.Logf("drop tracking database: %v", err)
			return
		}
		defer main.Close()
		if _, err := main.conn.Exec(`DROP DATABASE IF EXISTS ` + execName + ` WITH (FORCE)`); err != nil {
			t.Logf("drop tracking database: %v", err)
		}
	})
	return execURL
}

// openTracking migrates the tracking database at execURL as the owner and
// opens the runtime handle on the same identity (the derived default).
func openTracking(t *testing.T, execURL string, network nodepolicy.Network) (*ExecDB, *ExecAdminDB, TrackingMeta) {
	t.Helper()
	pool, err := NewWithoutMigrate(execURL)
	if err != nil {
		t.Fatalf("open tracking database: %v", err)
	}
	t.Cleanup(func() { pool.Close() })
	admin := NewExecAdminHandle(pool)
	if err := admin.MigrateExecOnly(context.Background(), migrationsexec.FS, true); err != nil {
		t.Fatalf("migrate tracking database: %v", err)
	}
	meta, err := admin.EnsureTrackingMeta(context.Background(), network)
	if err != nil {
		t.Fatalf("tracking meta: %v", err)
	}
	if _, err := admin.MaintainTracking(context.Background(), 2, 0, time.Hour); err != nil {
		t.Fatalf("tracking partitions: %v", err)
	}
	return NewExecHandle(pool), admin, meta
}
