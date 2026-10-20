package server

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/db"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// sharedServerTestDBURL is set once by TestMain and read by every per-test
// helper via sharedTestDBURL(t). It points at the single Postgres testcontainer
// (or the external TEST_DATABASE_URL) used for the whole internal/server
// package run — eliminating the ~3s × ~200 fresh containers that previously
// dominated wall-clock time (RD-1010, mirroring internal/db's pattern).
var sharedServerTestDBURL string

// TestMain spins one Postgres for the whole package (or honours
// TEST_DATABASE_URL when set, the same as the prior per-helper logic), then
// tears it down after m.Run().
func TestMain(m *testing.M) {
	exitCode := func() int {
		if envURL := os.Getenv("TEST_DATABASE_URL"); envURL != "" {
			if err := db.EnsureTestDatabase(envURL); err != nil {
				log.Printf("TEST_DATABASE_URL set but DB not reachable (%v) — falling back to testcontainer", err)
			} else {
				sharedServerTestDBURL = envURL
				return m.Run()
			}
		}

		ctx := context.Background()
		pgC, err := postgres.RunContainer(ctx,
			testcontainers.WithImage("postgres:15-alpine"),
			postgres.WithDatabase("testdb"),
			postgres.WithUsername("testuser"),
			postgres.WithPassword("testpass"),
			testcontainers.WithWaitStrategy(
				wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).
					WithStartupTimeout(30*time.Second),
			),
		)
		if err != nil {
			log.Printf("testcontainer postgres failed (%v) — falling back to external PostgreSQL", err)
			fallback := "postgres://postgres:postgres@localhost:5432/privacy_proxy_test?sslmode=disable"
			if ensureErr := db.EnsureTestDatabase(fallback); ensureErr != nil {
				log.Fatalf("neither testcontainer nor external PostgreSQL available: testcontainer=%v external=%v", err, ensureErr)
			}
			sharedServerTestDBURL = fallback
			return m.Run()
		}
		defer func() { _ = pgC.Terminate(ctx) }()

		connStr, err := pgC.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			log.Fatalf("testcontainer connection string: %v", err)
		}
		sharedServerTestDBURL = connStr
		return m.Run()
	}()

	os.Exit(exitCode)
}

// sharedTestDBURL returns the package-shared Postgres URL initialised by
// TestMain. Replaces per-test `db.SetupTestContainer(t)` calls (RD-1010) —
// one container, many tests, with state reset between tests by the existing
// `db.ResetTestDatabase` / explicit `TRUNCATE` calls in each helper.
func sharedTestDBURL(t *testing.T) string {
	t.Helper()
	if sharedServerTestDBURL == "" {
		t.Fatal("sharedTestDBURL: TestMain did not initialise the package DB")
	}
	return sharedServerTestDBURL
}
