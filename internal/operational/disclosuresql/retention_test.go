package disclosuresql_test

import (
	"testing"
	"time"

	"privacy-proxy/internal/operational/disclosuresql"
)

func TestOperationalRetentionDurationsAreBounded(t *testing.T) {
	values := map[string]string{"RETENTION_DISCLOSURE_EVENTS": "48h", "RETENTION_DISCLOSURE_CASES": "720h", "RETENTION_CLEANUP_INTERVAL": "30m", "RETENTION_DISCLOSURE_CLEANUP_BATCH": "25"}
	r, err := disclosuresql.RetentionFromEnv(func(name string) string { return values[name] })
	if err != nil || r.Events != 48*time.Hour || r.Cases != 720*time.Hour || r.CleanupInterval != 30*time.Minute || r.Batch != 25 {
		t.Fatal("duration settings", r, err)
	}
	for name, bad := range map[string]string{"RETENTION_DISCLOSURE_EVENTS": "0", "RETENTION_DISCLOSURE_CASES": "24h", "RETENTION_CLEANUP_INTERVAL": "-1h", "RETENTION_DISCLOSURE_CLEANUP_BATCH": "1001"} {
		input := map[string]string{}
		for key, value := range values {
			input[key] = value
		}
		input[name] = bad
		if _, err := disclosuresql.RetentionFromEnv(func(name string) string { return input[name] }); err == nil {
			t.Fatal("invalid retention accepted", name)
		}
	}
}
