package disclosurecase

import (
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/disclosurepolicy"
)

func TestValidRevocationTimeBounds(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		valid   bool
	}{{-1, false}, {0, true}, {disclosurepolicy.MaxUnixSeconds, true}, {disclosurepolicy.MaxUnixSeconds + 1, false}} {
		at := time.Unix(tc.seconds, 0)
		if got := validRevocationTime(&at); got != tc.valid {
			t.Fatalf("%d: got %v", tc.seconds, got)
		}
	}
	if validRevocationTime(nil) {
		t.Fatal("nil revocation time accepted")
	}
}

func TestCaseResponseIncludesRecordedRevocationTime(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	c := Case{RevokedAt: &at, RevokedBy: "private-actor", RevokeReason: "private-reason"}
	data, err := json.Marshal(c.Response())
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got["revokedAt"] != float64(at.Unix()) {
		t.Fatalf("revokedAt = %v", got["revokedAt"])
	}
	if _, ok := got["revokedBy"]; ok {
		t.Fatal("response exposed revoker")
	}
	if _, ok := got["revokeReason"]; ok {
		t.Fatal("response exposed reason")
	}
	c.RevokedAt = nil
	data, err = json.Marshal(c.Response())
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["revokedAt"]; ok {
		t.Fatal("unrevoked case has revocation time")
	}
}
