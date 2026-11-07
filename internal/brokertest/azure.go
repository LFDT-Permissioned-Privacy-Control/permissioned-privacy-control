package brokertest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	f "privacy-proxy/internal/disclosuretest"
)

// Entra maps the fixed production HTTPS issuer endpoints to an owned local TLS
// server. It produces real RSA signatures; no verifier is replaced or bypassed.
type Entra struct {
	Server               *httptest.Server
	Key                  *rsa.PrivateKey
	Clock                atomic.Int64
	Grants, KeyReads     atomic.Int64
	mu                   sync.Mutex
	nonce                string
	roles                []string
	errorCode            string
	errorStatus          int
	refreshID            bool
	subject, redirectURI string
	keyWait              <-chan struct{}
	keyStarted, keyEnded chan<- struct{}
}

func NewEntra(t testing.TB) *Entra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := &Entra{Key: key, roles: []string{"Reader"}, subject: f.Subject, redirectURI: BrokerSource().AzureProfiles[0].RedirectURI}
	e.Clock.Store(f.Now)
	e.Server = httptest.NewTLSServer(http.HandlerFunc(e.serve))
	t.Cleanup(e.Server.Close)
	return e
}
func (e *Entra) SetNonce(nonce string)     { e.mu.Lock(); defer e.mu.Unlock(); e.nonce = nonce }
func (e *Entra) SetSubject(subject string) { e.mu.Lock(); defer e.mu.Unlock(); e.subject = subject }
func (e *Entra) SetRedirectURI(uri string) { e.mu.Lock(); defer e.mu.Unlock(); e.redirectURI = uri }
func (e *Entra) SetRoles(roles ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.roles = append([]string{}, roles...)
}
func (e *Entra) SetGrantError(code string, status int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errorCode = code
	e.errorStatus = status
}
func (e *Entra) SetRefreshID(enabled bool) { e.mu.Lock(); defer e.mu.Unlock(); e.refreshID = enabled }
func (e *Entra) WaitForKeys(wait <-chan struct{}, started, ended chan<- struct{}) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.keyWait, e.keyStarted, e.keyEnded = wait, started, ended
}

type mappedTransport struct {
	base        http.RoundTripper
	destination *url.URL
}

func (t mappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != "login.microsoftonline.com" {
		return nil, http.ErrNotSupported
	}
	copy := r.Clone(r.Context())
	copy.URL.Scheme = t.destination.Scheme
	copy.URL.Host = t.destination.Host
	copy.Host = r.URL.Host
	return t.base.RoundTrip(copy)
}
func (e *Entra) Transport() http.RoundTripper {
	destination, _ := url.Parse(e.Server.URL)
	return mappedTransport{e.Server.Client().Transport, destination}
}
func (e *Entra) Sign(claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "ms-test"
	raw, err := token.SignedString(e.Key)
	if err != nil {
		panic(err)
	}
	return raw
}
func (e *Entra) Access(service bool, mutate func(jwt.MapClaims)) string {
	e.mu.Lock()
	roles := append([]string{}, e.roles...)
	subject := e.subject
	e.mu.Unlock()
	now := e.Clock.Load()
	claims := jwt.MapClaims{"iss": "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", "aud": Audience, "sub": "access-subject", "oid": subject, "tid": f.Tenant, "azp": HumanClient, "ver": "2.0", "iat": now, "nbf": now, "exp": now + 3600, "scp": "access", "roles": roles}
	if service {
		delete(claims, "scp")
		claims["azp"] = ServiceClient
		claims["idtyp"] = "app"
		claims["oid"] = f.AdminSubject
		claims["roles"] = []string{"Service"}
	}
	if mutate != nil {
		mutate(claims)
	}
	return e.Sign(claims)
}
func (e *Entra) idToken(nonce string, refresh bool) string {
	e.mu.Lock()
	subject := e.subject
	e.mu.Unlock()
	now := e.Clock.Load()
	claims := jwt.MapClaims{"iss": "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", "aud": HumanClient, "sub": "initial-oidc-subject", "oid": subject, "tid": f.Tenant, "iat": now, "exp": now + 3600, "auth_time": f.Now - 100}
	if !refresh {
		claims["nonce"] = nonce
	}
	return e.Sign(claims)
}
func (e *Entra) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	root := "https://login.microsoftonline.com/" + f.Tenant
	switch r.URL.Path {
	case "/" + f.Tenant + "/v2.0/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": root + "/v2.0", "authorization_endpoint": root + "/oauth2/v2.0/authorize", "token_endpoint": root + "/oauth2/v2.0/token", "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
	case "/common/discovery/v2.0/keys":
		e.KeyReads.Add(1)
		e.mu.Lock()
		wait, started, ended := e.keyWait, e.keyStarted, e.keyEnded
		e.mu.Unlock()
		if wait != nil {
			if started != nil {
				select {
				case started <- struct{}{}:
				default:
				}
			}
			defer func() {
				if ended != nil {
					select {
					case ended <- struct{}{}:
					default:
					}
				}
			}()
			select {
			case <-wait:
			case <-r.Context().Done():
				return
			case <-time.After(12 * time.Second):
				return
			}
		}
		pub := e.Key.PublicKey
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "ms-test", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())}}})
	case "/" + f.Tenant + "/oauth2/v2.0/token":
		e.Grants.Add(1)
		if r.Method != "POST" || r.ParseForm() != nil {
			w.WriteHeader(400)
			return
		}
		if r.Form.Get("client_id") != HumanClient || r.Form.Get("client_secret") != "test-only-secret" || r.Header.Get("Authorization") != "" {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_client"})
			return
		}
		e.mu.Lock()
		code, status, nonce, refreshID, redirect := e.errorCode, e.errorStatus, e.nonce, e.refreshID, e.redirectURI
		e.mu.Unlock()
		if code != "" {
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": code, "error_description": "fixture-only sensitive response must not be returned"})
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != redirect {
				w.WriteHeader(400)
				return
			}
		case "refresh_token":
			if r.Form.Get("refresh_token") == "" {
				w.WriteHeader(400)
				return
			}
		default:
			w.WriteHeader(400)
			return
		}
		// RFC6749 section6: omitted refresh scope keeps the original grant.
		// Pinned oauth2.TokenSource deliberately uses that ordinary form.
		if scope := r.Form.Get("scope"); scope != "" && !strings.Contains(scope, "api://"+Audience+"/access") && r.Form.Get("grant_type") == "refresh_token" {
			w.WriteHeader(400)
			return
		}
		response := map[string]any{"access_token": e.Access(false, nil), "refresh_token": "fixture-refresh-material", "token_type": "Bearer", "expires_in": 3600}
		if r.Form.Get("grant_type") == "authorization_code" {
			response["id_token"] = e.idToken(nonce, false)
		} else if refreshID {
			response["id_token"] = e.idToken("", true)
		}
		_ = json.NewEncoder(w).Encode(response)
	default:
		w.WriteHeader(404)
	}
}
