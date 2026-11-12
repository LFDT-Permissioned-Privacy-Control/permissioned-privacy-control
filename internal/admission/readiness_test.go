package admission

import (
	"context"
	p "privacy-proxy/internal/compliancepolicy"
	"testing"
	"time"
)

type readinessQuotes struct{ snapshot QuoteSnapshot }

func (q readinessQuotes) Capture(context.Context) (QuoteSnapshot, error) { return q.snapshot, nil }

func TestQuoteReadinessUsesActualRequiredPolicyFreshness(t *testing.T) {
	at := time.Unix(1800000000, 0).UTC()
	org := &orgRuntime{policy: p.OrganizationPolicy{PriceMaxAgeSeconds: 60, Spec: p.SourceSpec{Settings: p.SourceSettings{Enabled: true, EnforcementMode: "enforce", UnknownPricePolicy: "forbidden", Currency: "eur"}}}, quoteIDs: map[string]bool{"ethereum": true}}
	s := &Service{clock: func() time.Time { return at }, orgs: map[string]*orgRuntime{"bank": org}}
	if s.CheckQuoteReadiness(t.Context()) == nil {
		t.Fatal("missing required feed accepted")
	}
	for _, test := range []struct {
		name   string
		quotes []Quote
		ready  bool
	}{
		{"fresh", []Quote{{ID: "ethereum", Currency: "eur", Value: 1, SourceID: "owned", FetchedAt: at, ProviderAsOf: at}}, true},
		{"stale-provider", []Quote{{ID: "ethereum", Currency: "eur", Value: 1, SourceID: "owned", FetchedAt: at, ProviderAsOf: at.Add(-61 * time.Second)}}, false},
		{"future", []Quote{{ID: "ethereum", Currency: "eur", Value: 1, SourceID: "owned", FetchedAt: at.Add(time.Second), ProviderAsOf: at}}, false},
		{"wrong-currency", []Quote{{ID: "ethereum", Currency: "usd", Value: 1, SourceID: "owned", FetchedAt: at, ProviderAsOf: at}}, false},
		{"missing", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := NewQuoteSnapshot(test.quotes)
			if err != nil {
				t.Fatal(err)
			}
			s.quotes = readinessQuotes{snapshot}
			if got := s.CheckQuoteReadiness(t.Context()) == nil; got != test.ready {
				t.Fatalf("ready=%v want=%v", got, test.ready)
			}
		})
	}
	s.quotes = nil
	org.policy.Spec.Settings.EnforcementMode = "monitor"
	if s.CheckQuoteReadiness(t.Context()) != nil {
		t.Fatal("monitor policy made a feed mandatory")
	}
	org.policy.Spec.Settings.EnforcementMode = "enforce"
	org.policy.Spec.Settings.UnknownPricePolicy = "allowed"
	if s.CheckQuoteReadiness(t.Context()) != nil {
		t.Fatal("unknown-price-allowed policy made a feed mandatory")
	}
	org.policy.Spec.Settings.UnknownPricePolicy = "forbidden"
	org.quoteIDs = map[string]bool{}
	if s.CheckQuoteReadiness(t.Context()) != nil {
		t.Fatal("manual-only prices made a feed mandatory")
	}
}
