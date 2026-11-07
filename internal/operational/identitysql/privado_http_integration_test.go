package identitysql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/brokerpolicy"
	f "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
	"privacy-proxy/internal/identityhttp"
	"privacy-proxy/internal/operational/identitysql"
)

type multiStoreProbe struct {
	b.MultiStore
	familyReads *atomic.Int64
}

func (s multiStoreProbe) ReadPrivadoFamily(ctx context.Context, scope b.Scope, id string) (b.Family, error) {
	s.familyReads.Add(1)
	return s.MultiStore.ReadPrivadoFamily(ctx, scope, id)
}

type multiHTTPFixture struct {
	*browserFixture
	proof                  *identitysql.ProofStore
	familyReads            atomic.Int64
	privateOne, privateTwo b.MultiStore
	privadoTransport       http.RoundTripper
}

func newMultiHTTPFixture(t *testing.T, configure func(*multiHTTPFixture)) *multiHTTPFixture {
	t.Helper()
	oneMux, twoMux := http.NewServeMux(), http.NewServeMux()
	one, two := httptest.NewUnstartedServer(oneMux), httptest.NewUnstartedServer(twoMux)
	t.Cleanup(one.Close)
	t.Cleanup(two.Close)
	_, port, _ := strings.Cut(one.Listener.Addr().String(), ":")
	origin := "https://ops.test:" + port
	x := &multiHTTPFixture{browserFixture: &browserFixture{origin: origin, first: one, second: two, muxes: []*http.ServeMux{oneMux, twoMux}}}
	x.db = setup(t)
	x.db.binding.Origin = origin
	x.db.snapshot = f.MultiSnapshot(t, func(_ *identity.SourceCatalog, s *brokerpolicy.SourceV2) {
		s.WebOrigin = origin
		s.CompletionURI = origin + "/auth/complete"
		s.AzureProfiles = []brokerpolicy.AzureBinding{}
		s.PrivadoProfiles = []brokerpolicy.PrivadoBinding{{ProfileID: f.PrivadoRoleProfile}}
	})
	var e error
	x.proof, e = identitysql.OpenProofV2(t.Context(), x.db.proofDSN, x.db.scope, x.db.clock)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.proof.Close)
	x.privateOne = multiStoreProbe{x.db.one, &x.familyReads}
	x.privateTwo = multiStoreProbe{x.db.two, &x.familyReads}
	if configure != nil {
		configure(x)
	}
	for i, store := range []b.MultiStore{x.privateOne, x.privateTwo} {
		service, e := b.NewMulti(b.MultiConfig{Snapshot: x.db.snapshot, Clock: x.db.clock, Store: store, PublicProofStore: x.proof, AccessSigningBinding: b.AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, RenewalKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_REFRESH_TEST", Value: bytes.Repeat([]byte{1}, 32)}}, EncryptionKeyBindings: []b.SecretBinding{{FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Value: bytes.Repeat([]byte{2}, 32)}}, ServiceBinding: x.db.binding, ExpectedState: x.db.scope.State, PrivadoTransport: x.privadoTransport})
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(service.Close)
		if i == 0 {
			x.serviceOne = service
		} else {
			x.serviceTwo = service
		}
		handler, e := identityhttp.NewMulti(identityhttp.Config{Snapshot: x.db.snapshot, Service: service, Clock: x.db.clock})
		if e != nil {
			t.Fatal(e)
		}
		handler.Register(x.muxes[i])
	}
	for _, server := range []*httptest.Server{one, two} {
		server.Config.ReadHeaderTimeout = 5 * time.Second
		server.Config.ReadTimeout = 20 * time.Second
		server.Config.WriteTimeout = 25 * time.Second
		server.Config.IdleTimeout = 30 * time.Second
		server.Config.MaxHeaderBytes = 32 << 10
		server.StartTLS()
	}
	x.client = x.newClient(t, true)
	return x
}

type privadoStartDTO struct {
	RequestID       string  `json:"requestId"`
	RequestURI      string  `json:"requestUri"`
	ExpiresAt       int64   `json:"expiresAt"`
	SourceProfile   string  `json:"sourceProfile"`
	ExpectedActorID *string `json:"expectedActorId"`
}

func (x *multiHTTPFixture) startPrivado(t *testing.T, holder *string) privadoStartDTO {
	t.Helper()
	body := map[string]any{"profileId": f.PrivadoRoleProfile}
	if holder != nil {
		body["expectedHolderDid"] = *holder
	}
	status, header, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/start", body, nil)
	if status != 200 || len(header.Values("Set-Cookie")) != 1 {
		t.Fatal("actual private start", status, string(raw))
	}
	var out privadoStartDTO
	if json.Unmarshal(raw, &out) != nil || !b.ValidUUID(out.RequestID) || out.RequestURI != x.origin+identityhttp.Prefix+"privado/requests/"+out.RequestID || out.SourceProfile != f.PrivadoRoleProfile {
		t.Fatal("start DTO", string(raw))
	}
	return out
}
func TestActualPrivadoHTTPPublicBoundary(t *testing.T) {
	x := newMultiHTTPFixture(t, nil)
	start := x.startPrivado(t, nil)
	if start.ExpectedActorID != nil {
		t.Fatal("unknown holder was selected implicitly")
	}
	var original []byte
	for _, cookieHeader := range []string{"", identityhttp.RecipientCookie + "=invalid; " + identityhttp.RenewalCookie + "=invalid"} {
		status, headers, raw := x.request(t, x.newClient(t, false), "GET", identityhttp.Prefix+"privado/requests/"+start.RequestID, nil, func(r *http.Request) {
			r.Header.Set("Origin", "https://wallet.test")
			r.Header.Set("Cookie", cookieHeader)
			r.Header.Set("Authorization", "not a valid credential")
		})
		if status != 200 || headers.Get("Access-Control-Allow-Origin") != "*" || headers.Get("Access-Control-Allow-Credentials") != "" || len(headers.Values("Set-Cookie")) != 0 {
			t.Fatal("public request boundary", status, headers, string(raw))
		}
		if original == nil {
			original = raw
		} else if !bytes.Equal(original, raw) {
			t.Fatal("public request depends on browser credentials")
		}
	}
	if x.familyReads.Load() != 0 {
		t.Fatal("public request read families")
	}
	var request map[string]any
	if json.Unmarshal(original, &request) != nil || request["id"] != start.RequestID {
		t.Fatal("not actual provider request")
	}
	body := request["body"].(map[string]any)
	if body["callbackUrl"] != x.origin+identityhttp.Prefix+"privado/proofs/"+start.RequestID || len(body["scope"].([]any)) != 1 {
		t.Fatal("wrong selected query")
	}
	status, headers, raw := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/preview", map[string]string{"requestId": start.RequestID}, nil)
	if status != 200 || len(headers.Values("Set-Cookie")) != 0 || !bytes.Contains(raw, []byte(`"status":"waiting"`)) {
		t.Fatal("waiting preview", status, string(raw))
	}
	for _, row := range []struct {
		path, method, requestedHeaders string
		status                         int
	}{{"requests/", "GET", "", 204}, {"proofs/", "POST", "Content-Type", 204}, {"proofs/", "GET", "", 403}, {"proofs/", "POST", "Authorization", 403}, {"proofs/", "POST", "Content-Type,Authorization", 403}} {
		status, h, _ := x.request(t, x.newClient(t, false), "OPTIONS", identityhttp.Prefix+"privado/"+row.path+start.RequestID, nil, func(r *http.Request) {
			r.Header.Set("Origin", "https://wallet.test")
			r.Header.Set("Access-Control-Request-Method", row.method)
			if row.requestedHeaders != "" {
				r.Header.Set("Access-Control-Request-Headers", row.requestedHeaders)
			}
		})
		if status != row.status || h.Get("Access-Control-Allow-Origin") != "*" || h.Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("preflight boundary", row, status, h)
		}
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain; charset=ascii") }, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }} {
		status, h, _ := x.request(t, x.newClient(t, false), "POST", identityhttp.Prefix+"privado/proofs/"+start.RequestID, "invalid compact", func(r *http.Request) {
			r.Header.Set("Origin", "https://wallet.test")
			r.Header.Set("Cookie", identityhttp.RenewalCookie+"=invalid")
			change(r)
		})
		if status < 400 || len(h.Values("Set-Cookie")) != 0 || h.Get("Access-Control-Allow-Origin") != "*" {
			t.Fatal("invalid public proof accepted", status, h)
		}
	}
	status, h, _ := x.request(t, x.client, "POST", identityhttp.Prefix+"privado/preview", map[string]string{"requestId": start.RequestID}, func(r *http.Request) { r.Header.Set("Origin", "https://wallet.test") })
	if status != 403 || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("private preview weakened", status, h)
	}
	if x.familyReads.Load() != 0 {
		t.Fatal("public callbacks read families")
	}
}
func TestActualPrivadoHTTPWrongSourceAndRecipient(t *testing.T) {
	x := newMultiHTTPFixture(t, nil)
	holder := f.PublicFixtureDID(t, 41)
	start := x.startPrivado(t, &holder)
	if start.ExpectedActorID == nil {
		t.Fatal("explicit expected holder not pinned")
	}
	status, _, _ := x.request(t, x.newClient(t, true), "POST", identityhttp.Prefix+"privado/preview", map[string]string{"requestId": start.RequestID}, nil)
	if status != 401 {
		t.Fatal("foreign browser received preview", status)
	}
	if _, e := identityhttp.New(identityhttp.Config{Snapshot: x.db.snapshot, Service: x.serviceOne, Clock: x.db.clock}); e == nil {
		t.Fatal("legacy HTTP constructor mounted multi")
	}
	if _, e := b.New(b.Config{Snapshot: x.db.snapshot, Clock: x.db.clock, Store: x.db.one, AzureProvider: x.db.provider, AccessSigningBinding: b.AccessSigningBinding{IssuerID: "ops", KeyID: "test", PrivateKey: f.SigningKey()}, ExpectedState: x.db.scope.State}); e == nil {
		t.Fatal("legacy service constructor accepted multi")
	}
	status, h, _ := x.request(t, x.client, "GET", identityhttp.Prefix+"privado/requests/"+uuid.NewString(), nil, nil)
	if status != 401 || h.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("unknown public flow", status)
	}
}

// Kept here so the browser harness can reject a commit response after real
// execution while retaining net/http deadline support via Unwrap.
type captureAuthResponse struct {
	*httptest.ResponseRecorder
	actual http.ResponseWriter
}

func (w *captureAuthResponse) Unwrap() http.ResponseWriter { return w.actual }
func readBounded(r io.Reader, max int) ([]byte, error) {
	raw, e := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if e != nil || len(raw) > max {
		return nil, b.ErrInvalid
	}
	return raw, nil
}
