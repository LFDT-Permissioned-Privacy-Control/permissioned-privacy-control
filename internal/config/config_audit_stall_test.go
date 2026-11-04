package config

import (
	"testing"
	"time"
)

// AUDIT_SEALING_STALL_LIMIT (finding 6 follow-up): how long audit sealing may
// make no progress before the instance reports not ready. Default 30
// minutes; an unparseable or out-of-range value refuses startup.
func TestAuditSealingStallLimit(t *testing.T) {
	if got := Load().AuditSealingStallLimit; got != 30*time.Minute {
		t.Fatalf("default %s, want 30m", got)
	}
	t.Setenv("AUDIT_SEALING_STALL_LIMIT", "2h")
	cfg := Load()
	if cfg.AuditSealingStallLimit != 2*time.Hour || cfg.validateAuditSealing() != nil {
		t.Fatalf("2h: %s %v", cfg.AuditSealingStallLimit, cfg.validateAuditSealing())
	}
	for _, v := range []string{"soon", "30s", "25h", "-5m", "0"} {
		t.Setenv("AUDIT_SEALING_STALL_LIMIT", v)
		if err := Load().validateAuditSealing(); err == nil {
			t.Errorf("AUDIT_SEALING_STALL_LIMIT=%q accepted", v)
		}
	}
	if err := (&Config{}).validateAuditSealing(); err != nil {
		t.Fatalf("a literal configuration takes the default: %v", err)
	}
}
