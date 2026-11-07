package azure_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	b "privacy-proxy/internal/brokertest"
	f "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/identitybroker/azure"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func provider(t *testing.T) (*azure.ProviderSet, *b.Entra) {
	t.Helper()
	snapshot := b.Snapshot(t, nil)
	catalog, ok := snapshot.AuthBroker()
	if !ok {
		t.Fatal("real shared broker compiler missing")
	}
	server := b.NewEntra(t)
	p, err := azure.New(t.Context(), azure.Config{Catalog: catalog, Clock: func() time.Time { return time.Unix(server.Clock.Load(), 0).UTC() }, ClientSecrets: map[string]string{"OPS_BROKER_AZURE_TEST": "test-only-secret"}, Transport: server.Transport()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, server
}
func TestActualCodeAndFreshRefreshUseVerifiedOwnAPIRoles(t *testing.T) {
	p, server := provider(t)
	nonce := "test-only-nonce"
	verifier := strings.Repeat("a", 43)
	server.SetNonce(nonce)
	authorize, err := p.AuthorizationURL(b.HumanProfile, "state-secret", nonce, verifier)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorize)
	q := u.Query()
	challenge := sha256.Sum256([]byte(verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(challenge[:]) || q.Get("code_challenge_method") != "S256" || q.Get("nonce") != nonce || !strings.Contains(q.Get("scope"), "api://"+b.Audience+"/access") {
		t.Fatal("source-bound PKCE/OIDC scope")
	}
	evidence, err := p.ExchangeCode(t.Context(), b.HumanProfile, "one-use-code", verifier, nonce)
	if err != nil || !evidence.Valid() || len(evidence.Facts()) != 1 || evidence.Facts()[0].Value != "Reader" {
		t.Fatal("actual initial evidence", err)
	}
	server.SetRoles()
	server.Clock.Add(60)
	fresh, err := p.Refresh(t.Context(), b.HumanProfile, evidence.RefreshToken(), evidence.Continuity(f.Now))
	if err != nil || !fresh.Valid() || len(fresh.Facts()) != 0 {
		t.Fatal("refresh without ID token did not remove role", err)
	}
	server.SetRoles("Admin")
	server.SetRefreshID(true)
	server.Clock.Add(60)
	fresh, err = p.Refresh(t.Context(), b.HumanProfile, fresh.RefreshToken(), fresh.Continuity(f.Now))
	if err != nil || len(fresh.Facts()) != 1 || fresh.Facts()[0].Value != "Admin" {
		t.Fatal("optional nonce-free refresh ID token", err)
	}
	if server.Grants.Load() != 3 {
		t.Fatal("access TokenSource cache bypassed new grant", server.Grants.Load())
	}
	if server.KeyReads.Load() != 1 {
		t.Fatal("shared signature-key cache not reused", server.KeyReads.Load())
	}
}
func TestGrantFailureIsOneRequestAndSanitized(t *testing.T) {
	p, server := provider(t)
	server.SetGrantError("invalid_grant", 400)
	_, err := p.Refresh(t.Context(), b.HumanProfile, "still-stored-refresh", azure.Continuity{})
	if !errors.Is(err, azure.ErrRelogin) || server.Grants.Load() != 1 || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("grant error/retry", err, server.Grants.Load())
	}
	server.SetGrantError("invalid_client", 401)
	_, err = p.ExchangeCode(t.Context(), b.HumanProfile, "code", strings.Repeat("a", 43), "nonce")
	if !errors.Is(err, azure.ErrProvider) || server.Grants.Load() != 2 {
		t.Fatal("hidden auth-style retry", err, server.Grants.Load())
	}
}
func TestServiceAndHumanTokenBoundaries(t *testing.T) {
	p, server := provider(t)
	evidence, err := p.VerifyService(t.Context(), b.ServiceProfile, server.Access(true, nil))
	if err != nil || !evidence.Valid() || evidence.Identity().Subject != f.AdminSubject {
		t.Fatal("actual service proof", err)
	}
	for _, mutate := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["aud"] = b.HumanClient }, func(c jwt.MapClaims) { c["azp"] = b.HumanClient }, func(c jwt.MapClaims) { c["tid"] = f.OtherOrg }, func(c jwt.MapClaims) { c["scp"] = "access" }, func(c jwt.MapClaims) { delete(c, "idtyp") }, func(c jwt.MapClaims) { c["nbf"] = f.Now + 31 }, func(c jwt.MapClaims) { c["iat"] = f.Now + 31 }, func(c jwt.MapClaims) { c["exp"] = int64(9223372036854775807) }} {
		if _, err := p.VerifyService(t.Context(), b.ServiceProfile, server.Access(true, mutate)); err == nil {
			t.Fatal("invalid service source token accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := p.VerifyService(ctx, b.ServiceProfile, server.Access(true, nil)); err == nil {
		t.Fatal("canceled provider operation accepted")
	}
}

func TestActualInitialAndRefreshIDContinuity(t *testing.T) {
	snapshot := b.Snapshot(t, nil)
	catalog, _ := snapshot.AuthBroker()
	server := b.NewEntra(t)
	server.SetNonce("original-nonce")
	var replacementID string
	transport := transportFunc(func(r *http.Request) (*http.Response, error) {
		response, err := server.Transport().RoundTrip(r)
		if err != nil || r.Method != "POST" || replacementID == "" {
			return response, err
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, err
		}
		var object map[string]any
		if err := json.Unmarshal(body, &object); err != nil {
			return nil, err
		}
		object["id_token"] = replacementID
		raw, _ := json.Marshal(object)
		response.Body = io.NopCloser(strings.NewReader(string(raw)))
		response.ContentLength = int64(len(raw))
		return response, nil
	})
	p, err := azure.New(t.Context(), azure.Config{Catalog: catalog, Clock: func() time.Time { return time.Unix(server.Clock.Load(), 0) }, ClientSecrets: map[string]string{"OPS_BROKER_AZURE_TEST": "test-only-secret"}, Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", "aud": b.HumanClient, "sub": "initial-oidc-subject", "oid": f.Subject, "tid": f.Tenant, "iat": f.Now, "exp": f.Now + 3600, "auth_time": f.Now - 100, "nonce": "original-nonce"}
	}
	for _, mutate := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["aud"] = []string{b.HumanClient, "foreign"} }, func(c jwt.MapClaims) { c["aud"] = b.Audience }, func(c jwt.MapClaims) { c["nonce"] = "wrong" }, func(c jwt.MapClaims) { c["oid"] = f.AdminSubject }, func(c jwt.MapClaims) { c["tid"] = f.OtherOrg }} {
		c := claims()
		mutate(c)
		replacementID = server.Sign(c)
		if _, err := p.ExchangeCode(t.Context(), b.HumanProfile, "code", strings.Repeat("a", 43), "original-nonce"); err == nil {
			t.Fatal("mismatched initial proof accepted")
		}
	}
	replacementID = ""
	evidence, err := p.ExchangeCode(t.Context(), b.HumanProfile, "code", strings.Repeat("a", 43), "original-nonce")
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(jwt.MapClaims){func(c jwt.MapClaims) { c["sub"] = "another-oidc-subject" }, func(c jwt.MapClaims) { c["nonce"] = "wrong" }, func(c jwt.MapClaims) { c["auth_time"] = f.Now - 99 }, func(c jwt.MapClaims) { c["oid"] = f.AdminSubject }} {
		c := claims()
		delete(c, "nonce")
		mutate(c)
		replacementID = server.Sign(c)
		if _, err := p.Refresh(t.Context(), b.HumanProfile, evidence.RefreshToken(), evidence.Continuity(f.Now)); err == nil {
			t.Fatal("mismatched refresh continuity accepted")
		}
	}
}
func TestCanceledJWKSWaitStillHasFiniteOwnedHTTPDeadline(t *testing.T) {
	p, server := provider(t)
	release, started, ended := make(chan struct{}), make(chan struct{}, 1), make(chan struct{}, 1)
	defer close(release)
	server.WaitForKeys(release, started, ended)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := p.VerifyService(ctx, b.ServiceProfile, server.Access(true, nil)); result <- err }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("actual TLS key request not observed")
	}
	cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled wait minted proof")
		}
	case <-time.After(time.Second):
		t.Fatal("caller ignored cancellation")
	}
	// go-oidc owns a background singleflight. The HTTP client's own ten-second
	// deadline must cancel its actual TLS request even after our caller leaves.
	select {
	case <-ended:
	case <-time.After(azure.ProviderTimeout + time.Second):
		t.Fatal("SDK background request exceeded owned HTTP deadline")
	}
}

func TestActualIDExpiryDuringSecondTLSKeyFetch(t *testing.T) {
	for _, advance := range []bool{false, true} {
		t.Run(map[bool]string{false: "still_valid", true: "exact_expiry"}[advance], func(t *testing.T) {
			snapshot := b.Snapshot(t, nil)
			catalog, _ := snapshot.AuthBroker()
			server := b.NewEntra(t)
			idKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			id := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{"iss": "https://login.microsoftonline.com/" + f.Tenant + "/v2.0", "aud": b.HumanClient, "sub": "initial-oidc-subject", "oid": f.Subject, "tid": f.Tenant, "iat": f.Now, "exp": f.Now + 1, "nonce": "original-nonce"})
			id.Header["kid"] = "second-id-key"
			compact, err := id.SignedString(idKey)
			if err != nil {
				t.Fatal(err)
			}
			transport := transportFunc(func(r *http.Request) (*http.Response, error) {
				response, err := server.Transport().RoundTrip(r)
				if err != nil {
					return response, err
				}
				secondKeyFetch := strings.HasSuffix(r.URL.Path, "/keys") && server.KeyReads.Load() == 2
				if r.Method != "POST" && !secondKeyFetch {
					return response, nil
				}
				raw, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					return nil, err
				}
				var object map[string]any
				if err := json.Unmarshal(raw, &object); err != nil {
					return nil, err
				}
				if r.Method == "POST" {
					object["id_token"] = compact
				} else {
					object["keys"] = append(object["keys"].([]any), map[string]any{"kty": "RSA", "kid": "second-id-key", "alg": "RS256", "use": "sig", "n": base64.RawURLEncoding.EncodeToString(idKey.PublicKey.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(idKey.PublicKey.E)).Bytes())})
					if advance {
						server.Clock.Add(1)
					}
				}
				raw, _ = json.Marshal(object)
				response.Body = io.NopCloser(strings.NewReader(string(raw)))
				response.ContentLength = int64(len(raw))
				return response, nil
			})
			p, err := azure.New(t.Context(), azure.Config{Catalog: catalog, Clock: func() time.Time { return time.Unix(server.Clock.Load(), 0) }, ClientSecrets: map[string]string{"OPS_BROKER_AZURE_TEST": "test-only-secret"}, Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			_, err = p.ExchangeCode(t.Context(), b.HumanProfile, "code", strings.Repeat("a", 43), "original-nonce")
			if advance && err == nil {
				t.Fatal("ID token at exact expiry accepted after actual SDK/TLS/JWKS work")
			}
			if !advance && err != nil {
				t.Fatal("still-valid control denied", err)
			}
			if server.KeyReads.Load() != 2 {
				t.Fatal("test did not use separate actual access and ID key fetches", server.KeyReads.Load())
			}
		})
	}
}
