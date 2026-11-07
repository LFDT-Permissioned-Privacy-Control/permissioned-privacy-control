package identitysql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/policybundle"
)

type storeProbe struct {
	b.Store
	calls *atomic.Int64
}

func (s storeProbe) InsertPending(ctx context.Context, scope b.Scope, p b.Pending, gate func() error) error {
	s.calls.Add(1)
	return s.Store.InsertPending(ctx, scope, p, gate)
}
func (s storeProbe) WithPending(ctx context.Context, scope b.Scope, hash b.Digest, recipient b.RecipientBinding, callback func(b.Pending, b.PendingTx) error, gate func() error) (b.Commit, error) {
	s.calls.Add(1)
	return s.Store.WithPending(ctx, scope, hash, recipient, callback, gate)
}
func (s storeProbe) WithFamily(ctx context.Context, scope b.Scope, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	s.calls.Add(1)
	return s.Store.WithFamily(ctx, scope, id, callback, gate)
}

type browserFixture struct {
	db                     *fixture
	origin                 string
	first, second          *httptest.Server
	serviceOne, serviceTwo *b.Service
	calls                  atomic.Int64
	client                 *http.Client
	muxes                  []*http.ServeMux
}
type browserTransport struct {
	first, second *httptest.Server
	origin        string
	round         atomic.Uint64
}

func (t *browserTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme+"://"+r.URL.Host != t.origin {
		return nil, http.ErrNotSupported
	}
	server := t.first
	if t.round.Add(1)%2 == 0 {
		server = t.second
	}
	copy := r.Clone(r.Context())
	u, _ := url.Parse(server.URL)
	copy.URL.Scheme, copy.URL.Host = u.Scheme, u.Host
	copy.Host = r.Host
	response, err := server.Client().Transport.RoundTrip(copy)
	if response != nil {
		response.Request = r
	}
	return response, err
}
func newBrowserFixture(t *testing.T) *browserFixture {
	return newBrowserFixtureSetup(t, nil, nil)
}
func newBrowserFixtureSetup(t *testing.T, wrap func(b.Store) b.Store, configure func(*browserFixture)) *browserFixture {
	t.Helper()
	oneMux, twoMux := http.NewServeMux(), http.NewServeMux()
	one, two := httptest.NewUnstartedServer(oneMux), httptest.NewUnstartedServer(twoMux)
	t.Cleanup(one.Close)
	t.Cleanup(two.Close)
	_, port, _ := strings.Cut(one.Listener.Addr().String(), ":")
	origin := "https://ops.test:" + port
	x := &browserFixture{origin: origin, first: one, second: two, muxes: []*http.ServeMux{oneMux, twoMux}}
	x.db = setupConfigured(t, func(s *brokerpolicy.Source) {
		s.WebOrigin = origin
		s.CompletionURI = origin + "/auth/complete"
		s.AzureProfiles[0].RedirectURI = origin + "/auth/azure/callback"
	})
	storeOne, storeTwo := b.Store(x.db.one), b.Store(x.db.two)
	if wrap != nil {
		storeOne, storeTwo = wrap(storeOne), wrap(storeTwo)
	}
	x.serviceOne = x.db.service(t, storeProbe{storeOne, &x.calls})
	x.serviceTwo = x.db.service(t, storeProbe{storeTwo, &x.calls})
	for i, mux := range []*http.ServeMux{oneMux, twoMux} {
		service := x.serviceOne
		if i == 1 {
			service = x.serviceTwo
		}
		h, err := identityhttp.New(identityhttp.Config{Snapshot: x.db.snapshot, Service: service, Clock: x.db.clock})
		if err != nil {
			t.Fatal(err)
		}
		h.Register(mux)
	}
	if configure != nil {
		configure(x)
	}
	for _, server := range []*httptest.Server{one, two} {
		server.Config.ReadHeaderTimeout = 5 * time.Second
		server.Config.ReadTimeout = 5 * time.Second
		server.Config.WriteTimeout = 25 * time.Second
		server.Config.IdleTimeout = 60 * time.Second
		server.Config.MaxHeaderBytes = 64 << 10
		server.StartTLS()
	}
	x.client = x.newClient(t, true)
	return x
}
func (x *browserFixture) newClient(t *testing.T, jar bool) *http.Client {
	t.Helper()
	client := &http.Client{Transport: &browserTransport{first: x.first, second: x.second, origin: x.origin}, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if jar {
		var err error
		client.Jar, err = cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	return client
}
func (x *browserFixture) request(t *testing.T, client *http.Client, method, path string, body any, change func(*http.Request)) (int, http.Header, []byte) {
	t.Helper()
	var raw []byte
	if text, ok := body.(string); ok {
		raw = []byte(text)
	} else if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequestWithContext(t.Context(), method, x.origin+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", x.origin)
	}
	if change != nil {
		change(req)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (24<<10)+1))
	if err != nil || len(data) > 24<<10 {
		t.Fatal("HTTP output limit", err)
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("auth response cache/type policy")
	}
	return response.StatusCode, response.Header.Clone(), data
}
func (x *browserFixture) start(t *testing.T, client *http.Client) string {
	t.Helper()
	status, _, raw := x.request(t, client, "POST", identityhttp.Prefix+"azure/start", map[string]string{"profileId": f.HumanProfile}, nil)
	if status != 200 {
		t.Fatal("actual HTTP start", status, string(raw))
	}
	var start struct {
		AuthorizationURL string `json:"authorizationUrl"`
		ExpiresAt        int64  `json:"expiresAt"`
	}
	if json.Unmarshal(raw, &start) != nil {
		t.Fatal("start response")
	}
	u, err := url.Parse(start.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	x.db.entra.SetNonce(u.Query().Get("nonce"))
	return u.Query().Get("state")
}
func (x *browserFixture) complete(t *testing.T, client *http.Client, state string) identityhttp.AccessDTO {
	t.Helper()
	status, _, raw := x.request(t, client, "POST", identityhttp.Prefix+"azure/complete", map[string]string{"state": state, "code": "http-fixture-code"}, nil)
	if status != 200 {
		t.Fatal("actual HTTP completion", status, string(raw))
	}
	var dto identityhttp.AccessDTO
	if json.Unmarshal(raw, &dto) != nil {
		t.Fatal("access DTO")
	}
	return dto
}
func expected(dto identityhttp.AccessDTO) map[string]string {
	return map[string]string{"expectedActorId": dto.ActorID, "expectedSessionId": dto.BrowserSessionID}
}
func renewal(dto identityhttp.AccessDTO) map[string]string {
	m := expected(dto)
	m["mode"] = "renew"
	return m
}
func TestActualAzureHTTPBroker(t *testing.T) {
	x := newBrowserFixture(t)
	t.Run("actual TLS two-pool login and current facts with cookies only for renewal", func(t *testing.T) {
		dto := x.complete(t, x.client, x.start(t, x.client))
		if dto.PrincipalKind != identity.Human || dto.Provider != "azure" || dto.TokenType != "Bearer" || !b.ValidUUID(dto.BrowserSessionID) {
			t.Fatal("wrong own-session response")
		}
		identityCatalog, _ := x.db.snapshot.Identity()
		v, _ := identity.NewVerifier(identityCatalog, x.db.clock)
		p, err := v.VerifyAccess(dto.AccessToken)
		if err != nil || p.ActorID() != dto.ActorID || len(p.Groups(d.Org)) != 1 {
			t.Fatal("not actual Core evidence", err)
		}
		u, _ := url.Parse(x.origin)
		cookies := x.client.Jar.Cookies(u)
		if len(cookies) != 2 {
			t.Fatal("access token cookie was used", len(cookies))
		}
		x.db.entra.SetRoles()
		before := x.db.entra.Grants.Load()
		status, headers, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(dto), nil)
		if status != 200 || len(headers.Values("Set-Cookie")) != 2 || x.db.entra.Grants.Load() != before+1 {
			t.Fatal("fresh renewal", status)
		}
		var fresh identityhttp.AccessDTO
		if json.Unmarshal(raw, &fresh) != nil || fresh.BrowserSessionID != dto.BrowserSessionID {
			t.Fatal("family changed on rotation")
		}
		p, err = v.VerifyAccess(fresh.AccessToken)
		if err != nil || len(p.Groups(d.Org)) != 0 {
			t.Fatal("stale provider facts", err)
		}
		x.db.entra.SetRoles("Reader")
	})
	t.Run("other actor AND same-actor replacement family cannot be renewed or logged out by stale context", func(t *testing.T) {
		for _, subject := range []string{d.Subject, d.AdminSubject} {
			x.db.entra.SetSubject(d.Subject)
			old := x.complete(t, x.client, x.start(t, x.client))
			x.db.entra.SetSubject(subject)
			replacement := x.complete(t, x.client, x.start(t, x.client))
			if old.BrowserSessionID == replacement.BrowserSessionID {
				t.Fatal("test did not replace session")
			}
			if subject == d.Subject && old.ActorID != replacement.ActorID {
				t.Fatal("same actor control")
			}
			if subject != d.Subject && old.ActorID == replacement.ActorID {
				t.Fatal("different actor control")
			}
			beforeCalls, beforeGrants := x.calls.Load(), x.db.entra.Grants.Load()
			for _, route := range []string{"renew", "logout"} {
				body := expected(old)
				if route == "renew" {
					body = renewal(old)
				}
				status, headers, _ := x.request(t, x.client, "POST", identityhttp.Prefix+route, body, nil)
				if status != 409 || len(headers.Values("Set-Cookie")) != 0 {
					t.Fatal("stale session changed replacement", route, status)
				}
			}
			if x.calls.Load() != beforeCalls || x.db.entra.Grants.Load() != beforeGrants {
				t.Fatal("context mismatch reached SQL/provider")
			}
			status, _, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"renew", renewal(replacement), nil)
			if status != 200 {
				t.Fatal("stale context revoked replacement", status)
			}
		}
		x.db.entra.SetSubject(d.Subject)
	})
	t.Run("browser origin host methods shape budgets and machine separation reject before state", func(t *testing.T) {
		beforeCalls, beforeGrants := x.calls.Load(), x.db.entra.Grants.Load()
		for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Del("Origin") }, func(r *http.Request) { r.Header.Set("Origin", "null") }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.test") }, func(r *http.Request) { r.Header.Add("Origin", x.origin) }, func(r *http.Request) { r.Host = "foreign.test" }} {
			status, headers, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"azure/start", map[string]string{"profileId": f.HumanProfile}, change)
			if status != 403 || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("origin/host bypass", status)
			}
		}
		for _, raw := range []string{`{"ProfileId":"azure"}`, `{"profileId":"azure","profileId":"azure"}`, `{"profileId":null}`, `{"profileId":"azure","redirectUri":"https://foreign.test"}`, strings.Repeat(" ", (2<<10)+1)} {
			status, headers, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"azure/start", raw, nil)
			if status != 400 || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("closed DTO/budget bypass", status)
			}
		}
		for _, method := range []string{"GET", "HEAD", "OPTIONS"} {
			status, headers, _ := x.request(t, x.client, method, identityhttp.Prefix+"azure/start", nil, nil)
			if status != 405 || headers.Get("Allow") != "POST" {
				t.Fatal("wrong method executed", method, status)
			}
		}
		status, _, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"service/exchange", map[string]string{"profileId": f.ServiceProfile, "upstreamAccessToken": x.db.entra.Access(true, nil)}, nil)
		if status != 403 {
			t.Fatal("browser machine mode accepted", status)
		}
		if x.calls.Load() != beforeCalls || x.db.entra.Grants.Load() != beforeGrants {
			t.Fatal("invalid request reached state/provider")
		}
	})
	t.Run("strict renewal variants and duplicate cookies", func(t *testing.T) {
		beforeCalls := x.calls.Load()
		for _, raw := range []string{`{"mode":"bootstrap","expectedActorId":"x"}`, `{"mode":"renew"}`, `{"mode":"other"}`, `{"mode":"bootstrap","expectedSessionId":null}`} {
			status, _, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"renew", raw, nil)
			if status != 400 {
				t.Fatal("renewal variant accepted", status)
			}
		}
		noJar := x.newClient(t, false)
		for _, cookie := range []string{identityhttp.RecipientCookie + "=x", identityhttp.RecipientCookie + "=" + strings.Repeat("A", 43) + "; " + identityhttp.RecipientCookie + "=" + strings.Repeat("A", 43), "other=" + strings.Repeat("a", (16<<10)+1)} {
			status, headers, _ := x.request(t, noJar, "POST", identityhttp.Prefix+"azure/start", map[string]string{"profileId": f.HumanProfile}, func(r *http.Request) { r.Header.Set("Cookie", cookie) })
			if status != 400 || len(headers.Values("Set-Cookie")) != 0 {
				t.Fatal("malformed cookie accepted", status)
			}
		}
		if x.calls.Load() != beforeCalls {
			t.Fatal("invalid cookie/variant reached store")
		}
	})
	t.Run("machine exchange has no browser session or cookie", func(t *testing.T) {
		noJar := x.newClient(t, false)
		before := count(t, x.db, "renewal_families")
		status, headers, raw := x.request(t, noJar, "POST", identityhttp.Prefix+"service/exchange", map[string]string{"profileId": f.ServiceProfile, "upstreamAccessToken": x.db.entra.Access(true, nil)}, func(r *http.Request) { r.Header.Del("Origin") })
		if status != 200 || len(headers.Values("Set-Cookie")) != 0 || bytes.Contains(raw, []byte("browserSessionId")) || bytes.Contains(raw, []byte("refresh")) {
			t.Fatal("machine leaked browser credential/state", status)
		}
		if count(t, x.db, "renewal_families") != before {
			t.Fatal("machine allocated family")
		}
	})
	t.Run("known logout clears both host cookies and blocks reuse", func(t *testing.T) {
		current := x.complete(t, x.client, x.start(t, x.client))
		u, _ := url.Parse(x.origin)
		saved := x.client.Jar.Cookies(u)
		status, headers, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"logout", expected(current), nil)
		if status != 204 || len(headers.Values("Set-Cookie")) != 2 || len(x.client.Jar.Cookies(u)) != 0 {
			t.Fatal("known logout", status)
		}
		stale := x.newClient(t, false)
		status, headers, _ = x.request(t, stale, "POST", identityhttp.Prefix+"renew", renewal(current), func(r *http.Request) {
			for _, c := range saved {
				r.AddCookie(c)
			}
		})
		if status != 401 || len(headers.Values("Set-Cookie")) != 0 {
			t.Fatal("revoked family renewed", status)
		}
	})
	t.Run("own session metadata is copied and fresh-gated", func(t *testing.T) {
		login := x.db.login(t, x.serviceOne, b.RecipientBinding{5})
		info, err := login.SessionInfo()
		if err != nil || info.ActorID != login.Metadata().ActorID || !b.ValidUUID(info.ID) {
			t.Fatal(err)
		}
		info.ID = uuid.NewString()
		again, _ := login.SessionInfo()
		if again.ID == info.ID {
			t.Fatal("session metadata escaped")
		}
		x.db.entra.Clock.Add(300)
		if _, err := login.SessionInfo(); err == nil {
			t.Fatal("expired metadata treated as delivery permit")
		}
		x.db.entra.Clock.Store(d.Now)
	})
	t.Run("session metadata rejects final fractional second of integral refresh expiry", func(t *testing.T) {
		var fractional atomic.Int64
		fractional.Store(int64(750 * time.Millisecond))
		clock := func() time.Time { return x.db.clock().Add(time.Duration(fractional.Load())) }
		store, err := identitysql.Open(t.Context(), x.db.appDSN, x.db.scope, clock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Close)
		s := x.db.serviceWithClock(t, store, clock)
		login := x.db.login(t, s, b.RecipientBinding{7})
		info, err := login.SessionInfo()
		if err != nil || info.AbsoluteExpiresAt.Nanosecond() == 0 {
			t.Fatal("fractional control", err)
		}
		_, handle := credentials(t, login)
		x.db.entra.Clock.Store(info.AbsoluteExpiresAt.Unix() - 60)
		renewed, err := s.RenewAzure(t.Context(), handle, b.RecipientBinding{7})
		if err != nil {
			t.Fatal(err)
		}
		x.db.entra.Clock.Store(info.AbsoluteExpiresAt.Unix())
		fractional.Store(0)
		if !clock().Before(info.AbsoluteExpiresAt) || renewed.RequireDeliverable() != nil {
			t.Fatal("fractional delivery control")
		}
		if _, err := renewed.SessionInfo(); err == nil {
			t.Fatal("already-expired integral refresh handle was deliverable")
		}
		x.db.entra.Clock.Store(d.Now)
	})
}

type httpFaultStore struct {
	b.Store
	mode    *atomic.Int64
	advance func()
}

func (s httpFaultStore) wrapper() wrappedStore {
	w := wrappedStore{Store: s.Store}
	switch s.mode.Load() {
	case 1:
		w.beforeGate = s.advance
	case 2:
		w.after = s.advance
	case 3:
		w.ambiguous = true
	}
	return w
}
func (s httpFaultStore) WithPending(ctx context.Context, scope b.Scope, hash b.Digest, recipient b.RecipientBinding, callback func(b.Pending, b.PendingTx) error, gate func() error) (b.Commit, error) {
	return s.wrapper().WithPending(ctx, scope, hash, recipient, callback, gate)
}
func (s httpFaultStore) WithFamily(ctx context.Context, scope b.Scope, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	return s.wrapper().WithFamily(ctx, scope, id, callback, gate)
}
func TestActualAzureHTTPFailureGates(t *testing.T) {
	var mode atomic.Int64
	var fixtureClock *atomic.Int64
	x := newBrowserFixtureSetup(t, func(store b.Store) b.Store {
		return httpFaultStore{Store: store, mode: &mode, advance: func() { fixtureClock.Add(300) }}
	}, func(x *browserFixture) { fixtureClock = &x.db.entra.Clock })
	for _, row := range []struct {
		name      string
		mode      int64
		status    int
		committed bool
	}{
		{"expiry after writes before commit rolls back", 1, 401, false},
		{"expiry after known commit suppresses output", 2, 401, true},
		{"unknown commit suppresses output", 3, 503, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			mode.Store(0)
			fixtureClock.Store(d.Now)
			client := x.newClient(t, true)
			state := x.start(t, client)
			before := count(t, x.db, "renewal_families")
			mode.Store(row.mode)
			status, headers, raw := x.request(t, client, "POST", identityhttp.Prefix+"azure/complete", map[string]string{"state": state, "code": "failure-gate"}, nil)
			if status != row.status || len(headers.Values("Set-Cookie")) != 0 || strings.Contains(string(raw), "accessToken") {
				t.Fatal("failed commit/expiry publication", status)
			}
			after := count(t, x.db, "renewal_families")
			if row.committed && after != before+1 || !row.committed && after != before {
				t.Fatal("actual commit state differs")
			}
			mode.Store(0)
			fixtureClock.Store(d.Now)
		})
	}
	t.Run("ambiguous logout retains cookies but committed revoke denies renewal", func(t *testing.T) {
		client := x.newClient(t, true)
		dto := x.complete(t, client, x.start(t, client))
		mode.Store(3)
		status, headers, _ := x.request(t, client, "POST", identityhttp.Prefix+"logout", expected(dto), nil)
		if status != 503 || len(headers.Values("Set-Cookie")) != 0 {
			t.Fatal("ambiguous logout cookies", status)
		}
		mode.Store(0)
		status, headers, _ = x.request(t, client, "POST", identityhttp.Prefix+"renew", renewal(dto), nil)
		if status != 401 || len(headers.Values("Set-Cookie")) != 0 {
			t.Fatal("committed revoke was undone", status)
		}
	})
}

func TestAzureHTTPStartupAndOutputBoundary(t *testing.T) {
	x := newBrowserFixture(t)
	for _, origin := range []string{"https://other.test"} {
		snapshot := f.Snapshot(t, func(_ *identity.SourceCatalog, s *brokerpolicy.Source) {
			s.WebOrigin = origin
			s.CompletionURI = origin + "/auth/complete"
		})
		if _, err := identityhttp.New(identityhttp.Config{Snapshot: snapshot, Service: x.serviceOne, Clock: x.db.clock}); err == nil {
			t.Fatal("mixed service/snapshot or unsupported hosting origin accepted")
		}
	}
	if _, err := identityhttp.New(identityhttp.Config{Snapshot: &policybundle.CatalogSnapshot{}, Service: x.serviceOne, Clock: x.db.clock}); err == nil {
		t.Fatal("empty snapshot accepted")
	}
	status, headers, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"azure/start", map[string]string{"profileId": f.HumanProfile}, nil)
	if status != 200 || len(headers.Values("Set-Cookie")) != 1 || strings.Contains(string(raw), "refresh") {
		t.Fatal("start output", status)
	}
	response := &http.Response{Header: headers}
	cookie := response.Cookies()[0]
	if cookie.Name != identityhttp.RecipientCookie || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode || cookie.Domain != "" || cookie.Path != "/" || cookie.MaxAge != int(b.FamilyLifetime.Seconds()) {
		t.Fatal("recipient cookie scope/lifetime")
	}
	var start struct{ AuthorizationURL string }
	if json.Unmarshal(raw, &start) != nil {
		t.Fatal("start output")
	}
	u, _ := url.Parse(start.AuthorizationURL)
	x.db.entra.SetNonce(u.Query().Get("nonce"))
	status, headers, _ = x.request(t, x.client, "POST", identityhttp.Prefix+"azure/complete", map[string]string{"state": u.Query().Get("state"), "code": "cookie-check"}, nil)
	if status != 200 || len(headers.Values("Set-Cookie")) != 2 {
		t.Fatal("complete output", status)
	}
	response.Header = headers
	for _, c := range response.Cookies() {
		if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Domain != "" || c.Path != "/" || c.MaxAge != int(b.FamilyLifetime.Seconds()) || !c.Expires.Equal(cookie.Expires) {
			t.Fatal("family absolute cookie cutoff")
		}
	}
}
