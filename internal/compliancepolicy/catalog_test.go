package compliancepolicy_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	p "privacy-proxy/internal/compliancepolicy"
)

const org = "11111111-1111-1111-1111-111111111111"
const org2 = "22222222-2222-2222-2222-222222222222"
const tokenID = "33333333-3333-3333-3333-333333333333"

type index struct {
	ids   []string
	calls int
}

func (i *index) OrganizationIDs() []string { i.calls++; return i.ids }
func source() p.Source {
	return p.Source{APIVersion: p.APIVersion, Kind: p.Kind, Organizations: []p.OrganizationPolicy{{OrganizationID: org, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: p.SourceSpec{Settings: p.SourceSettings{Enabled: true, ThresholdFiat: 0.29, Currency: "eur", UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []p.SourceThreshold{}, TokenPrices: []p.SourceTokenPrice{}}}}, Sanctions: []p.SourceSanction{}}
}
func compile(t *testing.T, s p.Source) *p.Catalog {
	t.Helper()
	c, e := p.Compile(s, &index{ids: []string{org}}, p.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func TestComplianceCatalogCopiesAndInfersActualQuotePaths(t *testing.T) {
	s := source()
	idx := &index{ids: []string{org}}
	c, e := p.Compile(s, idx, p.DefaultLimits())
	if e != nil {
		t.Fatal(e)
	}
	if idx.calls != 1 || !slices.Contains(c.Requirements(), "inputs.price-quotes/v1") {
		t.Fatal("implicit native quote missing")
	}
	idx.ids[0] = org2
	s.Organizations[0].Spec.Settings.Currency = "usd"
	copy := c.DetachedSource()
	copy.Organizations[0].Spec.Settings.Currency = "chf"
	o, _ := c.OrgPolicy(org)
	if o.Spec.Settings.Currency != "eur" {
		t.Fatal("catalog authority escaped")
	}
	for _, prices := range []map[string]float64{{}, {"eur": 0}, {"usd": 1}, {"eur": 100}} {
		s := source()
		s.Organizations[0].Spec.TokenPrices = []p.SourceTokenPrice{{ID: tokenID, TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: prices}}
		c := compile(t, s)
		if slices.Contains(c.Requirements(), "inputs.price-quotes/v1") {
			t.Fatal("manual row invented system fallback")
		}
		view, _ := c.OrgPolicy(org)
		view.Spec.TokenPrices[0].PricesByCurrency["eur"] = 999
		again, _ := c.OrgPolicy(org)
		if again.Spec.TokenPrices[0].PricesByCurrency["eur"] == 999 {
			t.Fatal("manual map escaped")
		}
	}
	s = source()
	s.Organizations[0].Spec.TokenPrices = []p.SourceTokenPrice{{ID: tokenID, TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: "ethereum"}}
	if !slices.Contains(compile(t, s).Requirements(), "inputs.price-quotes/v1") {
		t.Fatal("configured quote missing")
	}
	s.Organizations[0].Spec.Settings.Enabled = false
	caps := compile(t, s).Requirements()
	if slices.Contains(caps, "operational.travel-rule/v1") || slices.Contains(caps, "inputs.price-quotes/v1") {
		t.Fatal("disabled policy invented provider use")
	}
}
func TestComplianceSourceClosedNumbersDurationsAndAggregateBounds(t *testing.T) {
	s := source()
	raw, _ := json.Marshal(s)
	for _, bad := range [][]byte{[]byte(strings.Replace(string(raw), `"sanctions":[]`, `"sanctions":null`, 1)), []byte(strings.Replace(string(raw), `"enabled":true`, `"Enabled":true`, 1)), []byte(strings.Replace(string(raw), `"kind":"CompliancePolicy"`, `"kind":"CompliancePolicy","kind":"CompliancePolicy"`, 1)), []byte(strings.Replace(string(raw), `"thresholdFiat":0.29`, `"thresholdFiat":0.290000000000000000001`, 1)), []byte(strings.Replace(string(raw), `"thresholdFiat":0.29`, `"thresholdFiat":1e-1000000000`, 1))} {
		if _, e := p.Decode(bad, p.DefaultLimits()); e == nil {
			t.Fatal("noncanonical source accepted")
		}
	}
	for _, change := range []func(*p.Source){func(s *p.Source) { s.Organizations = nil }, func(s *p.Source) { s.Organizations[0].OrganizationID = org2 }, func(s *p.Source) { s.Organizations[0].RecordMaxSeconds = 30*86400 + 1 }, func(s *p.Source) { s.Organizations[0].PriceMaxAgeSeconds = 86401 }, func(s *p.Source) { s.Organizations[0].Spec.Settings.ThresholdFiat = 0.291 }} {
		s := source()
		change(&s)
		if _, e := p.Compile(s, &index{ids: []string{org}}, p.DefaultLimits()); e == nil {
			t.Fatal("invalid policy accepted")
		}
	}
	for _, decimals := range []int{77, 78, 255} {
		s := source()
		s.Organizations[0].Spec.TokenPrices = []p.SourceTokenPrice{{ID: tokenID, TokenAddress: "native", Symbol: "ETH", Decimals: decimals, PricesByCurrency: map[string]float64{"eur": 1}}}
		_, e := p.Compile(s, &index{ids: []string{org}}, p.DefaultLimits())
		if decimals == 77 && e != nil || decimals > 77 && !errors.Is(e, p.ErrUnsupported) {
			t.Fatal("runtime decimal support", decimals, e)
		}
		if e := p.NormalizeSpec(&s.Organizations[0].Spec); e != nil {
			t.Fatal("legacy 0..255 validator changed", e)
		}
	}
	s = source()
	second := s.Organizations[0]
	second.OrganizationID = org2
	s.Organizations = append(s.Organizations, second)
	for i := range s.Organizations {
		s.Organizations[i].Spec.AddressThresholds = []p.SourceThreshold{{ID: tokenID, Address: "0x1111111111111111111111111111111111111111", ThresholdFiat: 1}}
	}
	limits := p.DefaultLimits()
	limits.MaxThresholds = 1
	if _, e := p.Compile(s, &index{ids: []string{org, org2}}, limits); e == nil {
		t.Fatal("per-org loop escaped aggregate bound")
	}
	limits = p.DefaultLimits()
	limits.MaxStringBytes = 10
	if _, e := p.Decode(raw, limits); e == nil {
		t.Fatal("string budget ignored")
	}
	limits = p.DefaultLimits()
	limits.MaxDocumentBytes = len(raw) - 1
	if _, e := p.Decode(raw, limits); e == nil {
		t.Fatal("raw budget ignored")
	}
}
func TestSanctionsScopeAndCanonicalDigest(t *testing.T) {
	s := source()
	addr := "0x1111111111111111111111111111111111111111"
	s.Sanctions = []p.SourceSanction{{ID: tokenID, Scope: "global", Address: addr}, {ID: "44444444-4444-4444-4444-444444444444", Scope: "organization", OrganizationID: org, Address: addr}}
	c := compile(t, s)
	if !c.IsSanctioned(org, addr) || !c.IsSanctioned(org2, addr) || !slices.Contains(c.Requirements(), "policy.sanctions/v1") {
		t.Fatal("sanctions scope missing")
	}
	slices.Reverse(s.Sanctions)
	if compile(t, s).Digest() != c.Digest() {
		t.Fatal("source order changed semantic digest")
	}
	s.Sanctions = append(s.Sanctions, s.Sanctions[0])
	if _, e := p.Compile(s, &index{ids: []string{org}}, p.DefaultLimits()); e == nil {
		t.Fatal("duplicate sanction accepted")
	}
	got := c.Sanctions()
	got[0].Address = "changed"
	if !c.IsSanctioned(org, addr) {
		t.Fatal("sanction escaped")
	}
}
