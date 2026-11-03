package server

import (
	"testing"

	"privacy-proxy/internal/config"
)

// Review finding 4: production warns at startup when a SIEM is configured
// without a fallback log, because undeliverable events are then dropped.
func TestSIEMWithoutFallbackIsReportedInProduction(t *testing.T) {
	for _, tc := range []struct {
		env, url, fallback string
		want               bool
	}{
		{"production", "https://siem.example.com/ingest", "", true},
		{"production", "https://siem.example.com/ingest", "/var/log/pp/siem-fallback.jsonl", false},
		{"production", "", "", false},
		{"development", "https://siem.example.com/ingest", "", false},
	} {
		cfg := &config.Config{Environment: tc.env, SIEMWebhookURL: tc.url, SIEMFallbackLogPath: tc.fallback}
		if got := siemDropsWithoutFallback(cfg); got != tc.want {
			t.Errorf("%+v: %v, want %v", tc, got, tc.want)
		}
	}
}

// The startup log names the SIEM endpoint by scheme and host only: a token in
// its path, query or user info never reaches the log.
func TestWebhookOriginKeepsTokensOutOfLogs(t *testing.T) {
	for raw, want := range map[string]string{
		"https://user:pw@siem.example.com:8088/services/collector?token=abc": "https://siem.example.com:8088",
		"https://siem.example.com/hook/SECRET":                               "https://siem.example.com",
		"::bad":                                                              "(unparseable)",
	} {
		if got := webhookOrigin(raw); got != want {
			t.Errorf("webhookOrigin(%q) = %q, want %q", raw, got, want)
		}
	}
}
