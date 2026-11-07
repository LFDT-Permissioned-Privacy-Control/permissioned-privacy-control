package pricefeedpolicy

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"privacy-proxy/internal/compliancepolicy"
)

type orgIndex []string

func (i orgIndex) OrganizationIDs() []string { return append([]string{}, i...) }
func catalog(t *testing.T, ids []string, native, enabled bool, currency string) *compliancepolicy.Catalog {
	t.Helper()
	org := "11111111-1111-1111-1111-111111111111"
	rows := []compliancepolicy.SourceTokenPrice{}
	if native {
		rows = append(rows, compliancepolicy.SourceTokenPrice{ID: uuid.NewString(), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{"usd": 1, "eur": 2}})
	}
	for i, id := range ids {
		rows = append(rows, compliancepolicy.SourceTokenPrice{ID: uuid.NewString(), TokenAddress: fmt.Sprintf("0x%040x", i+1), Symbol: "TOKEN", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: id})
	}
	s := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{{OrganizationID: org, RecordMaxSeconds: 3600, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Enabled: enabled, ThresholdFiat: 1, Currency: currency, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: rows}}}, Sanctions: []compliancepolicy.SourceSanction{}}
	c, err := compliancepolicy.Compile(s, orgIndex{org}, compliancepolicy.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func definition(t *testing.T, uri string) Definition {
	t.Helper()
	d, err := Normalize(Source{URI: uri, RefreshIntervalSeconds: 60, Format: "coingecko-simple"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestApprovedQueryOverridesIdentityAndPreservesNonsecretOptions(t *testing.T) {
	d := definition(t, "https://feed.test/price?ids=ignored&vs_currencies=gbp&include_last_updated_at=false&include_market_cap=true&precision=full&tenant=a%2Fb")
	p, err := BuildPlan(d, catalog(t, []string{"bitcoin"}, false, false, "eur"))
	if err != nil {
		t.Fatal(err)
	}
	requests := p.Requests()
	if len(requests) != 1 {
		t.Fatal("request count")
	}
	u, _ := url.Parse(requests[0].URI)
	q := u.Query()
	if q.Get("ids") != "bitcoin,ethereum" || q.Get("vs_currencies") != "eur" || q.Get("include_last_updated_at") != "true" || q.Get("include_market_cap") != "false" || q.Get("include_24hr_vol") != "false" || q.Get("include_24hr_change") != "false" || q.Get("precision") != "full" || q.Get("tenant") != "a/b" {
		t.Fatal("source query ownership")
	}
	requests[0].IDs[0] = "mutated"
	requests[0].URI = "bad"
	if p.Requests()[0].IDs[0] != "bitcoin" {
		t.Fatal("plan slice alias")
	}
	withManual, err := BuildPlan(d, catalog(t, nil, true, true, "usd"))
	if err != nil || len(withManual.IDs()) != 0 {
		t.Fatal("present native row acquired ethereum fallback", err)
	}
	// Disabled dynamic rows are still planned for admin quote/record use.
	disabled, err := BuildPlan(d, catalog(t, []string{"bitcoin"}, true, false, "usd"))
	if err != nil || len(disabled.IDs()) != 1 {
		t.Fatal("disabled row silently dropped")
	}
}
func TestURIQueryAndCredentialShapeAreClosed(t *testing.T) {
	for _, query := range []string{"names=bitcoin", "SYMBOLS=btc", "include_tokens=all", "IDs=bitcoin", "ids=a&ids=b", "tenant=a&Tenant=b", "precision=01", "precision=19", "Precision=full", "api_key=secret", "X_CG_PRO_API_KEY=secret", "x-cg-demo-api-key=secret", "token=secret", "bad=%xx", "tenant=line%0Abreak"} {
		if _, err := Normalize(Source{URI: "https://feed.test/price?" + query, RefreshIntervalSeconds: 60, Format: "coingecko-simple"}); err == nil {
			t.Fatal("invalid query accepted", query)
		}
	}
	for _, uri := range []string{"ftp://feed.test/price", "https:///price", "https://user:secret@feed.test/price", "https://feed.test/price#", "https://feed.test:70000/price"} {
		if _, err := Normalize(Source{URI: uri, RefreshIntervalSeconds: 60, Format: "coingecko-simple"}); err == nil {
			t.Fatal("invalid URI accepted", uri)
		}
	}
	s := Source{URI: "https://feed.test/price", RefreshIntervalSeconds: 60, Format: "coingecko-simple", Credential: &SecretRef{FromEnv: "OPS_PRICE_FEED_BANK"}}
	d, err := Normalize(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Credential.FromEnv = "mutated"
	copy := d.Source()
	copy.Credential.FromEnv = "other"
	if d.Source().Credential.FromEnv != "OPS_PRICE_FEED_BANK" {
		t.Fatal("secret ref alias")
	}
}
func TestPlanLimitsAndEncodedURIBatches(t *testing.T) {
	d := definition(t, "https://feed.test/price?tenant="+strings.Repeat("a", 1800))
	ids := []string{}
	for i := 0; i < MaxIDs; i++ {
		ids = append(ids, strings.Repeat("界", 31)+fmt.Sprintf("%07d", i))
	}
	p, err := BuildPlan(d, catalog(t, ids, true, true, "usd"))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	if len(p.Requests()) < 2 || len(p.Requests()) > MaxRequests {
		t.Fatal("batch count")
	}
	for _, r := range p.Requests() {
		if len(r.URI) > MaxRequestURIBytes || len(r.IDs) > MaxIDsPerRequest || len(r.IDs) == 0 {
			t.Fatal("encoded request cap")
		}
		for _, id := range r.IDs {
			if seen[id] {
				t.Fatal("duplicate batch ID")
			}
			seen[id] = true
		}
	}
	if len(seen) != MaxIDs {
		t.Fatal("lost planned ID")
	}
	ids = append(ids, "over-limit")
	if _, err := BuildPlan(d, catalog(t, ids, true, true, "usd")); err == nil {
		t.Fatal("ID cap")
	}
	if _, err := BuildPlan(d, catalog(t, []string{"a,b"}, true, true, "usd")); err == nil {
		t.Fatal("ambiguous comma ID")
	}
}
