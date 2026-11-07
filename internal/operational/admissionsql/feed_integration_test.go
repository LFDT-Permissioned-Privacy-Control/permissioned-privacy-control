package admissionsql_test

import (
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	a "privacy-proxy/internal/admission"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/pricefeedpolicy"
	"privacy-proxy/internal/quotefeed"
)

// This is an actual HTTP feed -> immutable snapshot -> real shared Checker ->
// PostgreSQL commit, not production runtime-profile activation or a send stub.
func TestActualHTTPFeedIntoRealFinancialAdmission(t *testing.T) {
	d := setup(t)
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Query().Get("ids") != "ethereum" || r.URL.Query().Get("vs_currencies") != "usd" || r.URL.Query().Get("include_last_updated_at") != "true" {
			t.Error("qualified feed query")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ethereum": map[string]any{"usd": 1, "last_updated_at": f.Now - 10}})
	}))
	defer server.Close()
	src := dynamicSource()
	snapshot := f.ComplianceSnapshot(t, src)
	catalog, _ := snapshot.Compliance()
	definition, err := pricefeedpolicy.Normalize(pricefeedpolicy.Source{URI: server.URL + "/price", RefreshIntervalSeconds: 60, Format: "coingecko-simple"})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pricefeedpolicy.BuildPlan(definition, catalog)
	if err != nil {
		t.Fatal(err)
	}
	feed, err := quotefeed.New(quotefeed.Config{Source: definition, Plan: plan, Clock: func() time.Time { return time.Unix(f.Now, 0).UTC() }, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer feed.Close()
	if err := feed.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	ready := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		quote, _ := feed.Capture(t.Context())
		if q, ok := quote.Get("ethereum", "usd"); ok {
			if q.ProviderAsOf.Unix() != f.Now-10 {
				t.Fatal("fabricated provider timestamp")
			}
			ready = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ready {
		t.Fatal("actual periodic HTTP feed never published")
	}
	x := newFixtureQuotes(t, d, src, feed)
	if feed.Metadata().ComplianceDigest != x.one.Metadata().ComplianceDigest.String() {
		t.Fatal("source catalog pairing")
	}
	record := x.record(t, f.Actor(f.Subject))
	input := x.input(t, 41, big.NewInt(2e18), x.token, f.Org, false)
	result := check(t, x.one, input, true)
	if result.Decision().RecordID != record.ID {
		t.Fatal("feed-backed travel record")
	}
	var observed, provider time.Time
	var source string
	if err := d.owner.QueryRow(t.Context(), `SELECT quote_source,quote_observed_at,quote_as_of FROM ops_admission_v2.compliance_events WHERE network_key=$1`, x.key[:]).Scan(&source, &observed, &provider); err != nil || source != "price-feed/"+definition.Digest() || observed.Unix() != f.Now || provider.Unix() != f.Now-10 {
		t.Fatal("actual quote audit", err)
	}
	before := requests.Load()
	x.clock.Store(f.Now + 61)
	receipt, _ := result.Receipt()
	if !errors.Is(receipt.RequirePublishable(), a.ErrValuation) {
		t.Fatal("old provider quote published")
	}
	if requests.Load() != before {
		t.Fatal("financial gate performed provider HTTP")
	}
}
