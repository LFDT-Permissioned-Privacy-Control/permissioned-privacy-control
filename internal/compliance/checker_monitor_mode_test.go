package compliance

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestCheckerCheck_MonitorMode covers RD-1044: under monitor mode a would-block
// violation is allowed to proceed but recorded (would_block=true), while
// sanctions stay hard-blocked even in monitor mode, and the
// fail-closed-on-log-failure invariant is preserved.
func TestCheckerCheck_MonitorMode(t *testing.T) {
	ctx := context.Background()

	const (
		orgID     = "org-1"
		userID    = "user-1"
		from      = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		to        = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		hexOneETH = "0xde0b6b3a7640000" // 1 ETH
	)

	// monitorConfig is enabledConfig(threshold) with monitor mode selected.
	monitorConfig := func(threshold float64) *ComplianceConfig {
		cfg := enabledConfig(threshold)
		cfg.EnforcementMode = EnforcementMonitor
		return cfg
	}

	nativeReq := &CheckRequest{OrgID: orgID, UserID: userID, From: from, To: to, Value: hexOneETH}

	t.Run("above threshold, no record -> allowed and recorded as would_block", func(t *testing.T) {
		store := &mockComplianceStore{
			config:        monitorConfig(100), // $100 threshold
			tokenPrice:    nativePrice(2000),  // 1 ETH = $2000 (above threshold)
			claimedRecord: nil,                // no travel rule record available
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("monitor mode must allow the transfer, got Allowed=false reason=%q", res.Reason)
		}
		if !res.Monitored {
			t.Errorf("expected Monitored=true")
		}
		if len(store.logs) != 1 {
			t.Fatalf("expected exactly 1 compliance log, got %d", len(store.logs))
		}
		got := store.logs[0]
		if got.Decision != "allowed" {
			t.Errorf("monitored row decision = %q, want \"allowed\"", got.Decision)
		}
		if !got.WouldBlock {
			t.Errorf("monitored row WouldBlock = false, want true")
		}
		if got.DenialReason == nil || !strings.Contains(*got.DenialReason, "exceeds threshold") {
			t.Errorf("monitored row should carry the would-block reason, got %v", got.DenialReason)
		}
	})

	t.Run("unknown price forbidden -> allowed and recorded as would_block", func(t *testing.T) {
		cfg := monitorConfig(100)
		cfg.UnknownPricePolicy = UnknownPriceForbidden
		store := &mockComplianceStore{
			config:     cfg,
			tokenPrice: nil, // no price configured -> resolveTokenPrice sentinel
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed || !res.Monitored {
			t.Fatalf("monitor mode should allow+mark monitored, got Allowed=%v Monitored=%v", res.Allowed, res.Monitored)
		}
		if len(store.logs) != 1 || !store.logs[0].WouldBlock {
			t.Fatalf("expected 1 would_block log, got %d logs", len(store.logs))
		}
	})

	// SAFETY (RD-1044): sanctions are NOT monitor-eligible. A sanctioned
	// address must stay hard-blocked even under monitor mode.
	t.Run("sanctioned recipient stays blocked under monitor mode", func(t *testing.T) {
		store := &mockComplianceStore{
			config:          monitorConfig(100),
			tokenPrice:      nativePrice(2000),
			sanctionedAddrs: map[string]bool{strings.ToLower(to): true},
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("sanctioned recipient MUST be blocked even in monitor mode")
		}
		if res.Monitored {
			t.Errorf("a sanctioned deny must not be marked Monitored")
		}
		if len(store.logs) != 1 || store.logs[0].Decision != "denied" || store.logs[0].WouldBlock {
			t.Fatalf("sanctioned deny should log decision=denied,would_block=false; got %+v", store.logs)
		}
	})

	// Control: enforce mode (the default) still blocks the same transfer.
	t.Run("enforce mode blocks above-threshold no-record (control)", func(t *testing.T) {
		store := &mockComplianceStore{
			config:        enabledConfig(100), // EnforcementMode unset -> enforce
			tokenPrice:    nativePrice(2000),
			claimedRecord: nil,
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed || res.Monitored {
			t.Fatalf("enforce mode must block, got Allowed=%v Monitored=%v", res.Allowed, res.Monitored)
		}
	})

	t.Run("cluster default monitor applies when per-org mode unset", func(t *testing.T) {
		store := &mockComplianceStore{
			config:        enabledConfig(100), // EnforcementMode == "" (unset)
			tokenPrice:    nativePrice(2000),
			claimedRecord: nil,
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)
		c.SetDefaultEnforcementMode(EnforcementMonitor)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Allowed || !res.Monitored {
			t.Fatalf("cluster default monitor should allow+mark monitored, got Allowed=%v Monitored=%v", res.Allowed, res.Monitored)
		}
	})

	t.Run("per-org enforce overrides cluster monitor default", func(t *testing.T) {
		cfg := enabledConfig(100)
		cfg.EnforcementMode = EnforcementEnforce
		store := &mockComplianceStore{config: cfg, tokenPrice: nativePrice(2000), claimedRecord: nil}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)
		c.SetDefaultEnforcementMode(EnforcementMonitor)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("per-org enforce must block despite a monitor cluster default")
		}
	})

	// Fail-closed-on-log-failure preserved: monitor mode must DENY if it cannot
	// persist the would-block audit row (no silent allow without a record).
	t.Run("monitor fails closed when the audit log write fails", func(t *testing.T) {
		store := &mockComplianceStore{
			config:        monitorConfig(100),
			tokenPrice:    nativePrice(2000),
			claimedRecord: nil,
			logErr:        fmt.Errorf("db down"),
		}
		c := NewChecker(store, 24*time.Hour, 15*time.Minute)

		res, err := c.Check(ctx, nativeReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Allowed {
			t.Fatalf("monitor mode must fail closed when the audit log write fails")
		}
		if !strings.Contains(res.Reason, "audit log unavailable") {
			t.Errorf("expected fail-closed reason, got %q", res.Reason)
		}
	})
}
