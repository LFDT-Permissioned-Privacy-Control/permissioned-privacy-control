package server

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	migrationsexec "privacy-proxy/internal/db/migrations_exec"
	"privacy-proxy/internal/nodepolicy"
)

var serverTrackingSequence atomic.Uint64

// testTracking is a fresh execution-tracking database for one test, a
// sibling of the package's shared test database (what infra provisions as
// <name>_exec).
type testTracking struct {
	url     string
	mainURL string
	runtime *db.ExecDB
	admin   *db.ExecAdminDB
	meta    db.TrackingMeta
}

func newTestTracking(tb testing.TB, network nodepolicy.Network) *testTracking {
	tb.Helper()
	mainURL := sharedServerTestDBURL
	if mainURL == "" {
		tb.Fatal("newTestTracking: TestMain did not initialise the package DB")
	}
	u, err := url.Parse(mainURL)
	if err != nil {
		tb.Fatal(err)
	}
	name := fmt.Sprintf("%s_exec_%d_%d", strings.TrimPrefix(u.Path, "/"), os.Getpid(), serverTrackingSequence.Add(1))
	u.Path = "/" + name
	if err := db.EnsureTestDatabase(u.String()); err != nil {
		tb.Fatalf("create tracking database: %v", err)
	}
	t := &testTracking{url: u.String(), mainURL: mainURL}
	tb.Cleanup(func() {
		if t.runtime != nil {
			t.runtime.Close()
		}
		main, err := db.NewWithoutMigrate(mainURL)
		if err != nil {
			return
		}
		defer main.Close()
		_, _ = main.Conn().Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`)
	})
	t.open(tb, network)
	return t
}

// open (re)connects and initialises the tracking database.
func (t *testTracking) open(tb testing.TB, network nodepolicy.Network) {
	tb.Helper()
	if t.runtime != nil {
		t.runtime.Close()
	}
	pool, err := db.NewWithoutMigrate(t.url)
	if err != nil {
		tb.Fatalf("open tracking database: %v", err)
	}
	t.runtime, t.admin = db.NewExecHandle(pool), db.NewExecAdminHandle(pool)
	t.meta, err = t.initialise(context.Background(), network)
	if err != nil {
		tb.Fatalf("initialise tracking database: %v", err)
	}
}

func (t *testTracking) initialise(ctx context.Context, network nodepolicy.Network) (db.TrackingMeta, error) {
	if err := t.admin.MigrateExecOnly(ctx, migrationsexec.FS, true); err != nil {
		return db.TrackingMeta{}, err
	}
	meta, err := t.admin.EnsureTrackingMeta(ctx, network)
	if err != nil {
		return db.TrackingMeta{}, err
	}
	_, err = t.admin.MaintainTracking(ctx, 2, 0, nodeTxPayloadKeep)
	return meta, err
}

// adopter is the production adoption step for this database.
func (t *testTracking) adopter(network nodepolicy.Network) func(context.Context) (uuid.UUID, error) {
	return (&executionTracking{runtime: t.runtime, admin: t.admin, dedicated: true}).adopt(network)
}

// count returns the number of rows of a tracking table.
func (t *testTracking) count(tb testing.TB, table string) int {
	tb.Helper()
	var n int
	if err := t.runtime.Conn().QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		tb.Fatal(err)
	}
	return n
}
