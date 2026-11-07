package quotefeed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/compliancepolicy"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/pricefeedpolicy"
)

func testPlan(t *testing.T, uri string, credential bool) (pricefeedpolicy.Definition, pricefeedpolicy.Plan) {
	return testPlanIDs(t, uri, credential, 0)
}
func testPlanIDs(t *testing.T, uri string, credential bool, extraIDs int) (pricefeedpolicy.Definition, pricefeedpolicy.Plan) {
	t.Helper()
	source := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{}, Sanctions: []compliancepolicy.SourceSanction{}}
	for _, row := range []struct{ org, currency string }{{f.Org, "usd"}, {f.OtherOrg, "eur"}} {
		source.Organizations = append(source.Organizations, compliancepolicy.OrganizationPolicy{OrganizationID: row.org, RecordMaxSeconds: 3600, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Enabled: true, ThresholdFiat: 1, Currency: row.currency, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{{ID: uuid.NewString(), TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: "ethereum"}}}})
	}
	for i := 0; i < extraIDs; i++ {
		source.Organizations[0].Spec.TokenPrices = append(source.Organizations[0].Spec.TokenPrices, compliancepolicy.SourceTokenPrice{ID: uuid.NewString(), TokenAddress: fmt.Sprintf("0x%040x", i+1), Symbol: "TOKEN", Decimals: 18, PricesByCurrency: map[string]float64{}, CoingeckoID: fmt.Sprintf("coin-%03d", i)})
	}
	snapshot := f.ComplianceSnapshot(t, source)
	catalog, _ := snapshot.Compliance()
	s := pricefeedpolicy.Source{URI: uri, RefreshIntervalSeconds: 60, Format: "coingecko-simple"}
	if credential {
		s.Credential = &pricefeedpolicy.SecretRef{FromEnv: "OPS_PRICE_FEED_TEST"}
	}
	d, err := pricefeedpolicy.Normalize(s)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pricefeedpolicy.BuildPlan(d, catalog)
	if err != nil {
		t.Fatal(err)
	}
	return d, p
}
func TestActualHTTPImmutableRefreshAndCaptureHasNoIO(t *testing.T) {
	var calls atomic.Int64
	var failure atomic.Bool
	var clock atomic.Int64
	clock.Store(f.Now)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Query().Get("ids") != "ethereum" || r.URL.Query().Get("vs_currencies") != "eur,usd" || r.URL.Query().Get("include_last_updated_at") != "true" {
			t.Error("actual query binding")
		}
		if failure.Load() {
			w.WriteHeader(500)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ethereum": map[string]any{"usd": 1.001, "eur": 2.003, "last_updated_at": f.Now - 10}})
	}))
	defer server.Close()
	d, p := testPlan(t, server.URL+"/price", false)
	s, err := New(Config{Source: d, Plan: p, Clock: func() time.Time { return time.Unix(clock.Load(), 0).UTC() }, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	empty, err := s.Capture(t.Context())
	if err != nil || len(empty.Quotes()) != 0 {
		t.Fatal("cold snapshot")
	}
	s.cycle(t.Context())
	old, _ := s.Capture(t.Context())
	q, ok := old.Get("ethereum", "eur")
	if !ok || q.Value != 2.003 || q.ProviderAsOf.Unix() != f.Now-10 || q.FetchedAt.Unix() != f.Now {
		t.Fatal("provider observation")
	}
	clock.Store(f.Now + 30)
	s.cycle(t.Context())
	current, _ := s.Capture(t.Context())
	newQuote, _ := current.Get("ethereum", "eur")
	if newQuote.FetchedAt.Unix() != f.Now+30 || q.FetchedAt.Unix() != f.Now {
		t.Fatal("old snapshot mutation")
	}
	failure.Store(true)
	clock.Store(f.Now + 90)
	s.cycle(t.Context())
	after, _ := s.Capture(t.Context())
	still, _ := after.Get("ethereum", "eur")
	if !still.FetchedAt.Equal(newQuote.FetchedAt) || !still.ProviderAsOf.Equal(newQuote.ProviderAsOf) {
		t.Fatal("failure restamped cache")
	}
	before := calls.Load()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 32; i++ {
				snapshot, err := s.Capture(t.Context())
				if err != nil || len(snapshot.Quotes()) != 2 {
					t.Error("capture")
				}
			}
		}()
	}
	wg.Wait()
	if calls.Load() != before {
		t.Fatal("Capture performed HTTP")
	}
	failure.Store(false)
	clock.Store(f.Now + 40)
	stop := make(chan struct{})
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					snapshot, err := s.Capture(t.Context())
					if err != nil || len(snapshot.Quotes()) != 2 {
						t.Error("capture during publication")
						return
					}
				}
			}
		}()
	}
	s.cycle(t.Context())
	close(stop)
	wg.Wait()
	if q.FetchedAt.Unix() != f.Now {
		t.Fatal("captured observation changed during replacement")
	}
}
func TestParserCurrencyTimestampAndWorkBounds(t *testing.T) {
	now := time.Unix(f.Now, 0).UTC()
	valid := `{"ethereum":{"usd":1.005,"eur":2,"last_updated_at":1799999990}}`
	rows, err := parseBatch([]byte(valid), []string{"ethereum"}, []string{"usd", "eur"}, now, "fixture")
	if err != nil || len(rows) != 2 || rows[0].Value != 1.005 || rows[1].Value != 2 {
		t.Fatal("valid parse", err)
	}
	for _, raw := range []string{`{"ethereum":{"usd":1,"usd":2}}`, `{"ethereum":{"USD":1}}`, `{"other":{"usd":1}}`, `{"ethereum":{"usd":1,"last_updated_at":1800000001}}`, `{"ethereum":{"usd":1,"last_updated_at":1.5}}`, valid + `{}`, `{"ethereum":{"usd":` + strings.Repeat("1", 129) + `}}`, `{"` + strings.Repeat(`\u0061`, 101) + `":{}}`, `{"ethereum":{"usd":[1]}}`, `{"ethereum":{"usd":{},"last_updated_at":1799999990}}`, strings.Repeat(" ", MaxBodyBytes+1)} {
		if _, err := parseBatch([]byte(raw), []string{"ethereum"}, []string{"usd", "eur"}, now, "fixture"); err == nil {
			t.Fatal("invalid response accepted")
		}
	}
	for _, raw := range []string{`{}`, `{"ethereum":{"usd":1}}`, `{"ethereum":{"usd":null,"last_updated_at":1799999990}}`, `{"ethereum":{"usd":0,"last_updated_at":1799999990}}`, `{"ethereum":{"usd":1e300,"last_updated_at":1799999990}}`} {
		q, err := parseBatch([]byte(raw), []string{"ethereum"}, []string{"usd"}, now, "fixture")
		if err != nil || len(q) != 0 {
			t.Fatal("unavailable became price", err)
		}
	}
	if boundedLexemes([]byte(`{"` + strings.Repeat(`\u0061`, 101) + `":1}`)) {
		t.Fatal("escaped lexeme bound")
	}
	if boundedLexemes([]byte(strings.Repeat("[", 9) + strings.Repeat("]", 9))) {
		t.Fatal("depth bound")
	}
}

func TestProviderSecondsComparedBeforeTimeConstruction(t *testing.T) {
	for _, row := range []struct {
		seconds string
		valid   bool
	}{{"1800000000", true}, {"1800000001", false}, {"9223372036854775807", false}} {
		raw := []byte(`{"ethereum":{"usd":1,"last_updated_at":` + row.seconds + `}}`)
		quotes, err := parseBatch(raw, []string{"ethereum"}, []string{"usd"}, time.Unix(f.Now, 999999999).UTC(), "fixture")
		if (err == nil) != row.valid {
			t.Fatal("provider timestamp range", row.seconds, err)
		}
		if row.valid && (len(quotes) != 1 || quotes[0].ProviderAsOf.Unix() != f.Now) {
			t.Fatal("current provider timestamp lost")
		}
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLifecycleDeadlineSecretBindingAndRedirectRefusal(t *testing.T) {
	d, p := testPlan(t, "https://feed.test/price", true)
	var clock atomic.Int64
	clock.Store(f.Now)
	entered := make(chan struct{})
	var count atomic.Int64
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		count.Add(1)
		if r.Header.Get("x-cg-demo-api-key") != "test-only-secret" {
			t.Error("credential binding")
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > CycleTimeout {
			t.Error("missing cycle deadline")
		}
		close(entered)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	c := Config{Source: d, Plan: p, Clock: func() time.Time { return time.Unix(clock.Load(), 0).UTC() }, Transport: transport, CredentialBinding: CredentialBinding{FromEnv: "OPS_PRICE_FEED_TEST", Header: "x-cg-demo-api-key", Value: "test-only-secret"}}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	<-entered
	if s.Start(t.Context()) != ErrInvalid {
		t.Fatal("second poll loop accepted")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); s.Close() }()
	}
	wg.Wait()
	if count.Load() != 1 || s.Start(t.Context()) != ErrClosed {
		t.Fatal("lifecycle loop")
	}
	c.CredentialBinding.FromEnv = "OPS_PRICE_FEED_OTHER"
	if _, err := New(c); err != ErrInvalid {
		t.Fatal("unreferenced secret")
	}
	c.CredentialBinding.FromEnv = "OPS_PRICE_FEED_TEST"
	c.CredentialBinding.Value = "bad\x01control"
	if _, err := New(c); err != ErrInvalid {
		t.Fatal("invalid header value accepted")
	}
	var redirected atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 302) }))
	defer redirect.Close()
	d, p = testPlan(t, redirect.URL, false)
	s, err = New(Config{Source: d, Plan: p, Clock: func() time.Time { return time.Unix(f.Now, 0).UTC() }, AllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.cycle(t.Context())
	q, _ := s.Capture(t.Context())
	if len(q.Quotes()) != 0 || redirected.Load() != 0 {
		t.Fatal("followed redirect")
	}
}
func TestDefaultTransportSchemeAndNetworkMatrix(t *testing.T) {
	for _, row := range []struct {
		uri            string
		private, valid bool
	}{{"http://8.8.8.8/price", false, false}, {"http://8.8.8.8/price", true, false}, {"http://127.0.0.1/price", false, false}, {"http://127.0.0.1/price", true, true}, {"https://127.0.0.1/price", false, false}, {"https://127.0.0.1/price", true, true}, {"https://169.254.169.254/price", true, false}, {"https://[::ffff:169.254.169.254]/price", true, false}, {"https://0.0.0.0/price", true, false}, {"https://feed.test/price", false, true}} {
		if got := validateDestination(row.uri, row.private) == nil; got != row.valid {
			t.Fatal("network matrix", row.uri, row.private)
		}
	}
	tr := defaultTransport("https://feed.test/price", false)
	defer tr.CloseIdleConnections()
	if tr.Proxy != nil || tr.DialTLS != nil || tr.DialTLSContext != nil || tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("default transport bypass")
	}
}

func TestPrivateModeRejectsKnownIPv6MetadataBeforeAnyHTTP(t *testing.T) {
	for _, host := range []string{"[fd00:ec2::254]", "[FD00:0EC2:0000:0000:0000:0000:0000:0254]", "[fd20:ce::254]", "[fd20:ce::254%25en0]"} {
		for _, scheme := range []string{"http", "https"} {
			if validateDestination(scheme+"://"+host+"/price", true) != ErrInvalid {
				t.Fatal("metadata URL accepted", scheme, host)
			}
		}
	}
	for _, scheme := range []string{"http", "https"} {
		if validateDestination(scheme+"://[fd00:abcd::1]/price", true) != nil {
			t.Fatal("ordinary private IPv6 endpoint rejected", scheme)
		}
	}
}

// HTTP response read errors are unavailable; no observation may be fabricated.
func TestBodyLimitsAndFailureKeepTheValidEmptySnapshot(t *testing.T) {
	d, p := testPlan(t, "https://feed.test/price", false)
	for _, body := range []string{strings.Repeat("x", MaxBodyBytes+1), `{"ethereum":{"usd":1,"last_updated_at":1800000001}}`} {
		s, err := New(Config{Source: d, Plan: p, Clock: func() time.Time { return time.Unix(f.Now, 0).UTC() }, Transport: roundTripper(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBufferString(body)), Header: http.Header{}}, nil
		})})
		if err != nil {
			t.Fatal(err)
		}
		s.cycle(t.Context())
		snapshot, _ := s.Capture(t.Context())
		s.Close()
		if len(snapshot.Quotes()) != 0 {
			t.Fatal("invalid body changed quote")
		}
	}
}

func TestOneDeadlineAcrossRealPlannedBatchesAndCancellation(t *testing.T) {
	d, p := testPlanIDs(t, "https://feed.test/price", false, 101)
	if len(p.Requests()) != 2 {
		t.Fatal("fixture not actually batched")
	}
	deadlines := []time.Time{}
	s, err := New(Config{Source: d, Plan: p, Clock: func() time.Time { return time.Unix(f.Now, 0).UTC() }, Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Fatal("no deadline")
		}
		deadlines = append(deadlines, deadline)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.cycle(t.Context())
	if len(deadlines) != 2 || !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("batch reset total deadline")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls int
	s.client.Transport = roundTripper(func(r *http.Request) (*http.Response, error) { calls++; cancel(); return nil, r.Context().Err() })
	s.cycle(ctx)
	if calls != 1 {
		t.Fatal("continued batches after cancel")
	}
}
