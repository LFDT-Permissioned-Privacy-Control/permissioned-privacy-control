package server

import (
	"errors"
	"testing"

	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

// TestOpenExecutionTrackingRefusesUnsafeLayouts: the tracking database is
// opened the audit way — never the main database in production, never a
// separate audit database, and never one recorded for another network; a
// runtime DSN that does not see the owner's database refuses at startup.
func TestOpenExecutionTrackingRefusesUnsafeLayouts(t *testing.T) {
	main, err := db.New(sharedTestDBURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer main.Close()
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "open-test"}
	tracking := newTestTracking(t, network)
	other := newTestTracking(t, nodepolicy.Network{ChainID: 31337, DeploymentID: "open-test-other"})
	base := func() *config.Config {
		return &config.Config{Environment: "development", DatabaseURL: sharedTestDBURL(t), AuditDatabaseURL: sharedTestDBURL(t) + "&audit=1", AuditAdminDatabaseURL: sharedTestDBURL(t) + "&audit=1", ExecutionDatabaseURL: tracking.url, ExecutionAdminDatabaseURL: tracking.url}
	}

	ok, err := openExecutionTracking(base(), main, network)
	if err != nil {
		t.Fatalf("a valid layout: %v", err)
	}
	if ok.meta != tracking.meta {
		t.Fatalf("opened %+v, want %+v", ok.meta, tracking.meta)
	}
	ok.close(main)

	for name, mutate := range map[string]func(*config.Config){
		"production main database": func(c *config.Config) {
			c.Environment = "production"
			c.ExecutionDatabaseURL, c.ExecutionAdminDatabaseURL = c.DatabaseURL, c.DatabaseURL
		},
		"separate audit database": func(c *config.Config) { c.ExecutionAdminDatabaseURL = c.AuditAdminDatabaseURL },
		"unresolved":              func(c *config.Config) { c.ExecutionDatabaseURL = "" },
		"runtime on another database": func(c *config.Config) {
			c.ExecutionDatabaseURL = other.url
		},
	} {
		c := base()
		mutate(c)
		if _, err := openExecutionTracking(c, main, network); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
	if _, err := openExecutionTracking(base(), main, nodepolicy.Network{ChainID: 1, DeploymentID: "elsewhere"}); !errors.Is(err, db.ErrTrackingNetworkMismatch) {
		t.Fatalf("another network: %v", err)
	}
}
