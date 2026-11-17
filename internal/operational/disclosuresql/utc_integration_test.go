package disclosuresql_test

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	c "privacy-proxy/internal/disclosurecase"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/operational/disclosuresql"
)

func TestCaseTimestampRoundTripUTC(t *testing.T) {
	_, appDSN, _, _ := database(t)
	store, err := disclosuresql.Open(t.Context(), appDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	snapshot := f.Snapshot(t, nil)
	var clock atomic.Int64
	clock.Store(f.Now)
	server, _ := server(t, snapshot, store, &clock, "utc-roundtrip")
	token := f.Token(t, snapshot, f.Subject, "Auditor")
	code, raw := request(t, server, token, "POST", "/api/v1/disclosure/cases", createRequest())
	var created c.CaseResponse
	if code != 201 || json.Unmarshal(raw, &created) != nil {
		t.Fatal("create case", code)
	}
	namespace, err := c.Namespace(snapshot.Metadata(), "utc-roundtrip")
	if err != nil {
		t.Fatal(err)
	}
	check := func(revoked bool) {
		t.Helper()
		row, err := store.Get(t.Context(), created.CaseID, namespace)
		if err != nil {
			t.Fatal(err)
		}
		if !row.CreatedAt.Equal(time.Unix(created.CreatedAt, 0)) || !row.ExpiresAt.Equal(time.Unix(created.ExpiresAt, 0)) {
			t.Fatal("SQL roundtrip changed the recorded instants")
		}
		if row.CreatedAt.Location() != time.UTC || row.ExpiresAt.Location() != time.UTC {
			t.Fatal("SQL case timestamps must be canonical UTC for protected source scopes")
		}
		if revoked && (row.RevokedAt == nil || row.RevokedAt.Location() != time.UTC) {
			t.Fatal("SQL revoked timestamp must be canonical UTC")
		}
	}
	check(false)
	code, _ = request(t, server, token, "POST", "/api/v1/disclosure/cases/"+created.CaseID+"/revoke", map[string]string{"reason": "end isolated test"})
	if code != 200 {
		t.Fatal("revoke case", code)
	}
	check(true)
}
