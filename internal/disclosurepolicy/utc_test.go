package disclosurepolicy

import (
	"testing"
	"time"
)

func TestProtectedUntilCanonicalUTC(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 333000, time.UTC)
	zone := time.FixedZone("bank-local", 3*60*60)
	for _, row := range []struct {
		name   string
		cap    int64
		record time.Time
		valid  int64
		want   time.Time
	}{
		{"recorded expiry", 1200, created.Add(time.Minute).In(zone), created.Add(time.Hour).Unix(), created.Add(time.Minute)},
		{"duration cap", 60, created.Add(time.Hour).In(zone), created.Add(2 * time.Hour).Unix(), created.Add(time.Minute)},
		{"rule expiry", 1200, created.Add(time.Hour).In(zone), created.Add(30 * time.Second).Unix(), time.Unix(created.Unix()+30, 0).UTC()},
	} {
		t.Run(row.name, func(t *testing.T) {
			rule := Rule{source: RuleSource{MaxCaseSeconds: row.cap, Validity: Validity{ExpiresAt: row.valid}}}
			got := rule.ProtectedUntil(created.In(zone), row.record)
			if !got.Equal(row.want) || got.Nanosecond() != row.want.Nanosecond() {
				t.Fatal("canonicalization changed the selected expiry instant or precision")
			}
			if got.Location() != time.UTC {
				t.Fatal("selected expiry is not canonical UTC")
			}
		})
	}
}
