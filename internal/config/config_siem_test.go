package config

import "testing"

// SIEM delivery capacity (review finding 4): four concurrent senders by
// default, and a 500-event batch when the async audit buffer feeds the SIEM
// (4 × 500 / 50 ms ≈ 40,000 events/s against a 10,500/s target). An explicit
// SIEM_BATCH_SIZE always wins.
func TestSIEMDeliveryDefaults(t *testing.T) {
	cfg := Load()
	if cfg.SIEMBatchSize != 100 || cfg.SIEMSenders != 4 {
		t.Fatalf("synchronous defaults: batch %d senders %d, want 100 and 4", cfg.SIEMBatchSize, cfg.SIEMSenders)
	}
	t.Setenv("AUDIT_BUFFER_DIR", t.TempDir())
	if got := Load().SIEMBatchSize; got != 500 {
		t.Fatalf("buffered default batch %d, want 500", got)
	}
	t.Setenv("SIEM_BATCH_SIZE", "50")
	t.Setenv("SIEM_SENDERS", "8")
	cfg = Load()
	if cfg.SIEMBatchSize != 50 || cfg.SIEMSenders != 8 {
		t.Fatalf("explicit settings: batch %d senders %d, want 50 and 8", cfg.SIEMBatchSize, cfg.SIEMSenders)
	}
	if err := cfg.validateSIEM(); err != nil {
		t.Fatalf("valid SIEM settings refused: %v", err)
	}
	for _, v := range []string{"0", "-1", "33", "four"} {
		t.Setenv("SIEM_SENDERS", v)
		if err := Load().validateSIEM(); err == nil {
			t.Errorf("SIEM_SENDERS=%q accepted", v)
		}
	}
	t.Setenv("SIEM_SENDERS", "")
	for _, v := range []string{"0", "-1", "10001", "big"} {
		t.Setenv("SIEM_BATCH_SIZE", v)
		if err := Load().validateSIEM(); err == nil {
			t.Errorf("SIEM_BATCH_SIZE=%q accepted", v)
		}
	}
	if err := (&Config{}).validateSIEM(); err != nil {
		t.Fatalf("a literal configuration without SIEM settings takes the defaults: %v", err)
	}
}
