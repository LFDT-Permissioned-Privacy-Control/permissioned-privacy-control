package identitysql_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/identitysql"
	"privacy-proxy/internal/operational/ssohttp"
	"privacy-proxy/internal/operational/ssosql"
	m "privacy-proxy/internal/ssotransaction"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This relay observes actual fixture PostgreSQL COMMIT responses. It never
// fabricates success, changes SQL or uses an external database/credential.
type ssoCommitRelay struct {
	remaining   atomic.Int32
	messages    atomic.Int64
	mu          sync.Mutex
	hook        func() error
	cut         bool
	observed    chan error
	connections []net.Conn
	wg          sync.WaitGroup
}

func newSSOCommitRelay(t *testing.T, dsn string) (*ssoCommitRelay, string) {
	t.Helper()
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := &ssoCommitRelay{observed: make(chan error, 1)}
	upstream := u.Host
	p.wg.Go(func() {
		for {
			client, e := listener.Accept()
			if e != nil {
				return
			}
			server, e := net.DialTimeout("tcp", upstream, time.Second)
			if e != nil {
				client.Close()
				continue
			}
			p.mu.Lock()
			p.connections = append(p.connections, client, server)
			p.mu.Unlock()
			p.wg.Go(func() {
				defer client.Close()
				defer server.Close()
				go func() { _, _ = io.Copy(server, client); server.Close() }()
				for {
					var header [5]byte
					if _, e := io.ReadFull(server, header[:]); e != nil {
						return
					}
					n := int(binary.BigEndian.Uint32(header[1:]))
					if n < 4 || n > 1<<20 {
						return
					}
					payload := make([]byte, n-4)
					if _, e := io.ReadFull(server, payload); e != nil {
						return
					}
					p.messages.Add(1)
					if header[0] == 'C' && string(payload) == "COMMIT\x00" && p.remaining.Load() > 0 && p.remaining.Add(-1) == 0 {
						p.mu.Lock()
						hook, cut := p.hook, p.cut
						p.mu.Unlock()
						var hookErr error
						if hook != nil {
							hookErr = hook()
						}
						p.observed <- hookErr
						if cut {
							return
						}
					}
					if _, e := client.Write(header[:]); e != nil {
						return
					}
					if _, e := client.Write(payload); e != nil {
						return
					}
				}
			})
		}
	})
	t.Cleanup(func() {
		listener.Close()
		p.mu.Lock()
		for _, c := range p.connections {
			c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	u.Host = listener.Addr().String()
	return p, u.String()
}
func (p *ssoCommitRelay) arm(commits int32, cut bool, hook func() error) {
	p.mu.Lock()
	p.cut = cut
	p.hook = hook
	p.mu.Unlock()
	p.remaining.Store(commits)
}
func (p *ssoCommitRelay) wait(t *testing.T) {
	t.Helper()
	select {
	case e := <-p.observed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("actual commit seam never reached")
	}
}
func ssorelayHandler(t *testing.T, s *ssoFixture) (*browserFixture, *http.Client, *ssoCommitRelay) {
	t.Helper()
	relay, dsn := newSSOCommitRelay(t, s.appDSN)
	store, e := ssosql.OpenApp(t.Context(), ssosql.Config{DSN: dsn, Expected: s.scope, Clock: s.x.db.clock})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(store.Close)
	c := s.configs[0]
	c.Store = store
	h, e := ssohttp.New(c)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	view := &browserFixture{db: s.x.db, origin: s.x.origin, first: server, second: server}
	client := view.newClient(t, false)
	client.Jar = s.x.client.Jar
	return view, client, relay
}
func TestE1CommitOutputAndNoActionRetry(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{"11111111-1111-1111-1111-111111111111"}, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	start := x.db.entra.Clock.Load()
	t.Run("uncertain Ready commit leaves durable record but no code", func(t *testing.T) {
		id, _ := s.start(t, "app-a", "lost-code")
		view, client, relay := ssorelayHandler(t, s)
		relay.arm(2, true, nil)
		status, _, raw := view.request(t, client, "POST", ssohttp.Prefix+"flow", map[string]string{"action": "complete", "flowId": id, "expectedActorId": dto.ActorID, "expectedSessionId": dto.BrowserSessionID}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+dto.AccessToken) })
		relay.wait(t)
		if status != 503 || strings.Contains(string(raw), "redirectTo") || strings.Contains(string(raw), "code=") {
			t.Fatal("uncertain Ready published code", status, string(raw))
		}
		var phase int
		if e := x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != 2 {
			t.Fatal("Ready effect was not committed", phase, e)
		}
		status, _ = s.complete(t, id, dto)
		if status < 400 {
			t.Fatal("lost Ready response retried action")
		}
	})
	t.Run("uncertain Consume commits once but returns no token", func(t *testing.T) {
		code, pkce, id := s.ready(t, dto)
		view, _, relay := ssorelayHandler(t, s)
		temporary := *s
		temporary.x = view
		relay.arm(2, true, nil)
		status, raw := temporary.exchange(t, "app-a", code, pkce, nil)
		relay.wait(t)
		if status != 503 || strings.Contains(string(raw), dto.AccessToken) {
			t.Fatal("uncertain Consume returned token", status)
		}
		var phase int
		if e := x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != 3 {
			t.Fatal("Consume not committed", phase, e)
		}
		status, _ = s.exchange(t, "app-a", code, pkce, nil)
		if status < 400 {
			t.Fatal("uncertain Consume retried")
		}
	})
	t.Run("expiry immediately after Ready commit suppresses code", func(t *testing.T) {
		id, _ := s.start(t, "app-a", "expiry")
		view, client, relay := ssorelayHandler(t, s)
		relay.arm(2, false, func() error { x.db.entra.Clock.Store(start + 300); return nil })
		status, _, raw := view.request(t, client, "POST", ssohttp.Prefix+"flow", map[string]string{"action": "complete", "flowId": id, "expectedActorId": dto.ActorID, "expectedSessionId": dto.BrowserSessionID}, func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+dto.AccessToken) })
		relay.wait(t)
		x.db.entra.Clock.Store(start)
		if status < 400 || strings.Contains(string(raw), "redirectTo") {
			t.Fatal("expired prepared code published")
		}
		var phase int
		if e := x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != 2 {
			t.Fatal("expected durable Ready", phase, e)
		}
	})
	t.Run("rotation after Consume commit before recheck suppresses token", func(t *testing.T) {
		code, pkce, id := s.ready(t, dto)
		view, _, relay := ssorelayHandler(t, s)
		temporary := *s
		temporary.x = view
		u, _ := url.Parse(x.origin)
		var handle, recipient string
		for _, cookie := range x.client.Jar.Cookies(u) {
			if cookie.Name == identityhttp.RenewalCookie {
				handle = cookie.Value
			}
			if cookie.Name == identityhttp.RecipientCookie {
				recipient = cookie.Value
			}
		}
		binding, e := identityhttp.CentralRecipientBinding(recipient)
		if e != nil {
			t.Fatal(e)
		}
		relay.arm(2, false, func() error {
			_, e := x.serviceOne.RenewAzureForSession(context.Background(), handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID})
			return e
		})
		status, raw := temporary.exchange(t, "app-a", code, pkce, nil)
		relay.wait(t)
		if status < 400 || strings.Contains(string(raw), dto.AccessToken) {
			t.Fatal("rotated family token published")
		}
		var phase int
		if e := x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != 3 {
			t.Fatal("Consume not durable", phase, e)
		}
	})
}
func TestE1MalformedIngressHasNoSQL(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{"11111111-1111-1111-1111-111111111111"}, false)
	view, client, relay := ssorelayHandler(t, s)
	before := relay.messages.Load()
	for _, row := range []struct {
		path, body string
		change     func(*http.Request)
	}{{"token", "grant_type=authorization_code", func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}}, {"token", "bad=form", func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("app-a", url.QueryEscape(s.secretA))
		r.Header.Add("Authorization", r.Header.Get("Authorization"))
	}}, {"token", "grant_type=authorization_code&client_id=app-b&code=" + strings.Repeat("A", 43) + "&redirect_uri=https%3A%2F%2Fapp.test%2Fcallback&code_verifier=" + strings.Repeat("v", 43), func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth("app-a", url.QueryEscape(s.secretA))
	}}, {"flow", `{"action":"inspect","flowId":"11111111-1111-1111-1111-111111111111","extra":true}`, nil}, {"flow", `{"action":"inspect","action":"complete","flowId":"11111111-1111-1111-1111-111111111111"}`, nil}, {"flow", strings.Repeat(" ", 2049), nil}, {"flow", `{"action":"inspect","flowId":"11111111-1111-1111-1111-111111111111"}`, func(r *http.Request) { r.Header.Set("Origin", "https://other.test") }}} {
		status, _, raw := view.request(t, client, "POST", ssohttp.Prefix+row.path, row.body, row.change)
		if status < 400 {
			t.Fatal("malformed input accepted", row.path, string(raw))
		}
	}
	if after := relay.messages.Load(); after != before {
		t.Fatal("malformed ingress performed actual SQL", before, after)
	}
}
func TestE1ConcurrentConsumeOneWinner(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{"11111111-1111-1111-1111-111111111111"}, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	code, pkce, id := s.ready(t, dto)
	start := make(chan struct{})
	results := make(chan int, 2)
	for range 2 {
		go func() { <-start; status, _ := s.exchange(t, "app-a", code, pkce, nil); results <- status }()
	}
	close(start)
	a, z := <-results, <-results
	if (a == 200) == (z == 200) {
		t.Fatal("exactly one winner required", a, z)
	}
	var phase int
	if e := x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != int(m.Consumed) {
		t.Fatal("concurrent consume not durable", phase, e)
	}
}

func TestE1UncertainIdentityReadHasNoSession(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	proxy, dsn := newSSOCommitRelay(t, x.db.appDSN)
	store, e := identitysql.Open(t.Context(), dsn, x.db.scope, x.db.clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(store.Close)
	service := ssoService(t, x, store)
	u, _ := url.Parse(x.origin)
	var handle, recipient string
	for _, c := range x.client.Jar.Cookies(u) {
		if c.Name == identityhttp.RenewalCookie {
			handle = c.Value
		}
		if c.Name == identityhttp.RecipientCookie {
			recipient = c.Value
		}
	}
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		t.Fatal(e)
	}
	proxy.arm(1, true, nil)
	session, e := service.AuthenticateCurrentSession(t.Context(), handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID})
	proxy.wait(t)
	if e == nil || session != nil {
		t.Fatal("uncertain read COMMIT exposed session")
	}
	if _, e = x.serviceOne.AuthenticateCurrentSession(t.Context(), handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID}); e != nil {
		t.Fatal("uncertain read mutated actual family", e)
	}
}
func TestE1RevocationAfterConsumeWithholdsToken(t *testing.T) {
	x := newSSOAzureFixture(t, false)
	s := attachSSO(t, x, []string{"11111111-1111-1111-1111-111111111111"}, false)
	dto := x.complete(t, x.client, x.start(t, x.client))
	code, pkce, id := s.ready(t, dto)
	view, _, relay := ssorelayHandler(t, s)
	temporary := *s
	temporary.x = view
	u, _ := url.Parse(x.origin)
	var handle, recipient string
	for _, c := range x.client.Jar.Cookies(u) {
		if c.Name == identityhttp.RenewalCookie {
			handle = c.Value
		}
		if c.Name == identityhttp.RecipientCookie {
			recipient = c.Value
		}
	}
	binding, e := identityhttp.CentralRecipientBinding(recipient)
	if e != nil {
		t.Fatal(e)
	}
	relay.arm(2, false, func() error {
		return x.serviceOne.RevokeForSession(context.Background(), handle, binding, b.ExpectedSession{ActorID: dto.ActorID, SessionID: dto.BrowserSessionID})
	})
	status, raw := temporary.exchange(t, "app-a", code, pkce, nil)
	relay.wait(t)
	if status < 400 || strings.Contains(string(raw), dto.AccessToken) {
		t.Fatal("revoked session returned token")
	}
	var phase int
	if e = x.db.owner.QueryRow(t.Context(), `SELECT phase FROM ops_sso_v1.transactions WHERE id=$1::uuid`, id).Scan(&phase); e != nil || phase != 3 {
		t.Fatal("consume effect missing", phase, e)
	}
	status, _ = s.exchange(t, "app-a", code, pkce, nil)
	if status < 400 {
		t.Fatal("durable withheld consume replayed")
	}
}
