package identitysql_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	f "privacy-proxy/internal/brokertest"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
)

type blockedPrivadoInsert struct {
	b.MultiStore
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (s *blockedPrivadoInsert) InsertPrivadoLoginChallenge(ctx context.Context, scope b.Scope, p b.PrivadoChallengeRecord, gate func() error) error {
	s.calls.Add(1)
	select {
	case s.entered <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-s.release:
		return s.MultiStore.InsertPrivadoLoginChallenge(ctx, scope, p, gate)
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestActualPrivadoHTTPAdmissionSharedByServiceAcrossHandlers(t *testing.T) {
	var blocked *blockedPrivadoInsert
	x := newMultiHTTPFixture(t, func(x *multiHTTPFixture) {
		blocked = &blockedPrivadoInsert{MultiStore: x.privateOne, entered: make(chan struct{}, 16), release: make(chan struct{})}
		x.privateOne = blocked
	})
	var once sync.Once
	release := func() { once.Do(func() { close(blocked.release) }) }
	defer release()
	// A second real TLS handler shares the SAME service/provider instance, as
	// distinct from the separate-replica fixture's independently owned service2.
	alias, e := identityhttp.NewMulti(identityhttp.Config{Snapshot: x.db.snapshot, Service: x.serviceOne, Clock: x.db.clock})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewTLSServer(alias)
	defer server.Close()
	transport := &browserTransport{first: x.first, second: server, origin: x.origin}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func(method, path string, body any, cookies bool) (int, error) {
		raw, e := json.Marshal(body)
		if e != nil {
			return 0, e
		}
		if method == "GET" {
			raw = nil
		}
		r, e := http.NewRequestWithContext(t.Context(), method, x.origin+path, bytes.NewReader(raw))
		if e != nil {
			return 0, e
		}
		if method != "GET" {
			r.Header.Set("Origin", x.origin)
			r.Header.Set("Content-Type", "application/json")
		}
		if cookies {
			r.Header.Set("Cookie", identityhttp.RecipientCookie+"="+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{42}, 32))+"; "+identityhttp.RenewalCookie+"=public-invalid-mac")
		}
		response, e := client.Do(r)
		if e != nil {
			return 0, e
		}
		defer response.Body.Close()
		if _, e = readBounded(response.Body, 24<<10); e != nil {
			return 0, e
		}
		if response.StatusCode == 503 && len(response.Header.Values("Set-Cookie")) != 0 {
			return 0, fmt.Errorf("busy emitted cookies")
		}
		return response.StatusCode, nil
	}
	results := make(chan error, 8)
	for range 8 {
		go func() {
			status, e := request("POST", identityhttp.Prefix+"privado/start", map[string]string{"profileId": f.PrivadoRoleProfile}, false)
			if e == nil && status != 200 {
				e = fmt.Errorf("admitted start status%d", status)
			}
			results <- e
		}()
	}
	for range 8 {
		select {
		case <-blocked.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("eight legitimate requests were not admitted")
		}
	}
	for _, row := range []struct {
		path    string
		body    any
		cookies bool
	}{{"renew", map[string]string{"mode": "bootstrap"}, true}, {"privado/start", map[string]string{"profileId": f.PrivadoRoleProfile}, false}, {"renew", map[string]string{"mode": "renew", "expectedActorId": "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "expectedSessionId": uuid.NewString()}, true}, {"logout", map[string]string{"expectedActorId": "ops:p1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "expectedSessionId": uuid.NewString()}, true}} {
		status, e := request("POST", identityhttp.Prefix+row.path, row.body, row.cookies)
		if e != nil || status != 503 {
			t.Fatalf("ninth %s bypassed shared admission: status%d error%v", row.path, status, e)
		}
	}
	status, e := request("GET", identityhttp.Prefix+"privado/requests/"+uuid.NewString(), nil, true)
	if e != nil || status != 503 || blocked.calls.Load() != 8 {
		t.Fatal("public/sharedhandler admission escaped budget", status, blocked.calls.Load(), e)
	}
	release()
	for range 8 {
		if e := <-results; e != nil {
			t.Fatal(e)
		}
	}
	status, e = request("POST", identityhttp.Prefix+"privado/start", map[string]string{"profileId": f.PrivadoRoleProfile}, false)
	if e != nil || status != 200 || blocked.calls.Load() != 9 {
		t.Fatal("admission did not recover", status, blocked.calls.Load(), e)
	}
}
