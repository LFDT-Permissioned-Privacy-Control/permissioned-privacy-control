package server

import (
	"testing"

	"privacy-proxy/internal/config"
)

// Review finding 11: the tracking owner's pool is small and fixed unless it
// is also the runtime pool (one DSN for both).
func TestTrackingAdminPoolIsSmallUnlessShared(t *testing.T) {
	cfg := &config.Config{DBMaxOpenConns: 50, DBMaxIdleConns: 50, ExecutionDatabaseURL: "postgres://app@exec/db", ExecutionAdminDatabaseURL: "postgres://owner@exec/db"}
	if open, idle := trackingAdminPool(cfg); open != 4 || idle != 2 {
		t.Fatalf("separate owner DSN: pool %d/%d, want 4/2", open, idle)
	}
	cfg.ExecutionAdminDatabaseURL = cfg.ExecutionDatabaseURL
	if open, idle := trackingAdminPool(cfg); open != 50 || idle != 50 {
		t.Fatalf("shared DSN: pool %d/%d, want the runtime size 50/50", open, idle)
	}
}
