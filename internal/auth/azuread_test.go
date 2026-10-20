package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock OIDC infrastructure
// ---------------------------------------------------------------------------

// mockOIDCServer serves a fake OIDC discovery document, JWKS, and token
// endpoint. It signs id_tokens with a test RSA key.
type mockOIDCServer struct {
	*httptest.Server
	key    *rsa.PrivateKey
	keyID  string
	issuer string

	// tokenEndpointHandler can be overridden per test to customise the
	// token response (e.g. missing id_token, invalid signature, etc.).
	tokenEndpointHandler http.HandlerFunc
}

func newMockOIDCServer(t *testing.T) *mockOIDCServer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	m := &mockOIDCServer{
		key:   key,
		keyID: "test-key-1",
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		disc := map[string]interface{}{
			"issuer":                 m.issuer,
			"authorization_endpoint": m.issuer + "/authorize",
			"token_endpoint":         m.issuer + "/token",
			"jwks_uri":               m.issuer + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(disc)
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     m.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		}
		jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if m.tokenEndpointHandler != nil {
			m.tokenEndpointHandler(w, r)
			return
		}
		// Default: 400 — individual tests set the handler
		http.Error(w, "no token handler configured", http.StatusBadRequest)
	})

	srv := httptest.NewServer(mux)
	m.Server = srv
	m.issuer = srv.URL
	return m
}

// signIDToken creates a signed JWT id_token with the given claims.
func (m *mockOIDCServer) signIDToken(t *testing.T, claims map[string]interface{}) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: m.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
	)
	require.NoError(t, err)

	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	jws, err := signer.Sign(payload)
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)
	return compact
}

// tokenResponse writes a standard OAuth2 token response that includes the
// given id_token.
func tokenResponse(w http.ResponseWriter, idToken string) {
	resp := map[string]interface{}{
		"access_token":  "mock-access-token",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "mock-refresh-token",
		"id_token":      idToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ---------------------------------------------------------------------------
// AzureADAuthenticator tests
// ---------------------------------------------------------------------------

func TestExchangeCode_Success(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	expectedNonce := "test-nonce-123"
	expectedOID := "00000000-0000-0000-0000-000000000042"

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[string]interface{}{
			"iss":                m.issuer,
			"sub":               expectedOID,
			"aud":               "test-client-id",
			"exp":               jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat":               jwt.NewNumericDate(now),
			"nonce":             expectedNonce,
			"oid":               expectedOID,
			"tid":               "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
			"email":             "user@example.com",
			"name":              "Test User",
			"preferred_username": "user@example.com",
		}
		tokenResponse(w, m.signIDToken(t, claims))
	}

	identity, err := authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", expectedNonce)
	require.NoError(t, err)
	assert.Equal(t, expectedOID, identity.OID)
	assert.Equal(t, "aaaabbbb-cccc-dddd-eeee-ffffffffffff", identity.TenantID)
	assert.Equal(t, "user@example.com", identity.Email)
	assert.Equal(t, "Test User", identity.Name)
	assert.Equal(t, "user@example.com", identity.PreferredUsername)
}

func TestExchangeCode_NonceMismatch(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[string]interface{}{
			"iss":   m.issuer,
			"sub":   "some-oid",
			"aud":   "test-client-id",
			"exp":   jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat":   jwt.NewNumericDate(now),
			"nonce": "wrong-nonce",
			"oid":   "some-oid",
		}
		tokenResponse(w, m.signIDToken(t, claims))
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", "expected-nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce mismatch")
}

func TestExchangeCode_MissingOID(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	nonce := "test-nonce"
	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[string]interface{}{
			"iss":   m.issuer,
			"sub":   "some-sub",
			"aud":   "test-client-id",
			"exp":   jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat":   jwt.NewNumericDate(now),
			"nonce": nonce,
			"tid":   "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
			// NOTE: no "oid" claim
		}
		tokenResponse(w, m.signIDToken(t, claims))
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "oid claim missing")
}

func TestExchangeCode_MissingTID(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	nonce := "test-nonce"
	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[string]any{
			"iss":   m.issuer,
			"sub":   "some-oid",
			"aud":   "test-client-id",
			"exp":   jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat":   jwt.NewNumericDate(now),
			"nonce": nonce,
			"oid":   "some-oid",
			// NOTE: no "tid" claim
		}
		tokenResponse(w, m.signIDToken(t, claims))
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", nonce)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tid claim missing")
}

func TestExchangeCode_ExpiredIDToken(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		past := time.Now().Add(-2 * time.Hour)
		claims := map[string]interface{}{
			"iss":   m.issuer,
			"sub":   "some-oid",
			"aud":   "test-client-id",
			"exp":   jwt.NewNumericDate(past), // expired
			"iat":   jwt.NewNumericDate(past.Add(-1 * time.Hour)),
			"nonce": "nonce",
			"oid":   "some-oid",
		}
		tokenResponse(w, m.signIDToken(t, claims))
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id_token verification failed")
}

func TestExchangeCode_InvalidSignature(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	// Sign with a different key than what the JWKS advertises
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		now := time.Now()
		claims := map[string]interface{}{
			"iss":   m.issuer,
			"sub":   "some-oid",
			"aud":   "test-client-id",
			"exp":   jwt.NewNumericDate(now.Add(1 * time.Hour)),
			"iat":   jwt.NewNumericDate(now),
			"nonce": "nonce",
			"oid":   "some-oid",
		}

		signer, signErr := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: wrongKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
		)
		require.NoError(t, signErr)

		payload, _ := json.Marshal(claims)
		jws, signErr := signer.Sign(payload)
		require.NoError(t, signErr)
		compact, _ := jws.CompactSerialize()

		tokenResponse(w, compact)
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id_token verification failed")
}

func TestExchangeCode_TokenEndpointError(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "authorization code expired",
		})
	}

	_, err = authn.ExchangeCode(context.Background(), "bad-code", "http://localhost/callback", "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "code exchange failed")
}

func TestExchangeCode_MissingIDTokenInResponse(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	m.tokenEndpointHandler = func(w http.ResponseWriter, r *http.Request) {
		// Return a valid token response without id_token
		resp := map[string]interface{}{
			"access_token":  "mock-access-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "mock-refresh-token",
			// no id_token
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}

	_, err = authn.ExchangeCode(context.Background(), "auth-code", "http://localhost/callback", "nonce")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "id_token missing")
}

func TestAzureSubject(t *testing.T) {
	assert.Equal(t, "azuread:abc-123", AzureSubject("abc-123"))
}

func TestGetAuthorizationURL(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	url := authn.GetAuthorizationURL("http://localhost/callback", "test-state", "test-nonce")
	assert.Contains(t, url, "client_id=test-client-id")
	assert.Contains(t, url, "redirect_uri=")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "nonce=test-nonce")
	assert.Contains(t, url, "scope=")
}

// ---------------------------------------------------------------------------
// VerifyAccessToken tests (RD-1120 — service-principal / client-credentials)
// ---------------------------------------------------------------------------

func TestVerifyAccessToken_Success(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	oid := "11111111-2222-3333-4444-555555555555"
	tid := "aaaabbbb-cccc-dddd-eeee-ffffffffffff"
	now := time.Now()
	// A service-principal access token has no nonce; aud defaults to clientID.
	raw := m.signIDToken(t, map[string]interface{}{
		"iss":   m.issuer,
		"aud":   "test-client-id",
		"exp":   jwt.NewNumericDate(now.Add(1 * time.Hour)),
		"iat":   jwt.NewNumericDate(now),
		"oid":   oid,
		"tid":   tid,
		"appid": "99999999-0000-0000-0000-000000000000",
	})

	identity, err := authn.VerifyAccessToken(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, oid, identity.OID)
	assert.Equal(t, tid, identity.TenantID)
}

func TestVerifyAccessToken_CustomAudience(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)
	authn.SetServicePrincipalAudience("api://privacy-proxy")

	now := time.Now()
	mint := func(aud string) string {
		return m.signIDToken(t, map[string]interface{}{
			"iss": m.issuer, "aud": aud,
			"exp": jwt.NewNumericDate(now.Add(time.Hour)), "iat": jwt.NewNumericDate(now),
			"oid": "oid-1", "tid": "tid-1",
		})
	}

	// The configured custom audience is accepted.
	_, err = authn.VerifyAccessToken(context.Background(), mint("api://privacy-proxy"))
	require.NoError(t, err)

	// Once a custom SP audience is set, the bare clientID is NOT accepted —
	// guards against a token minted for a different resource being replayed.
	_, err = authn.VerifyAccessToken(context.Background(), mint("test-client-id"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestVerifyAccessToken_Rejections(t *testing.T) {
	m := newMockOIDCServer(t)
	defer m.Close()

	authn, err := NewAzureADAuthenticatorFromIssuer("test-client-id", "test-client-secret", m.issuer)
	require.NoError(t, err)

	now := time.Now()
	valid := map[string]interface{}{
		"iss": m.issuer, "aud": "test-client-id",
		"exp": jwt.NewNumericDate(now.Add(time.Hour)), "iat": jwt.NewNumericDate(now),
		"oid": "oid-1", "tid": "tid-1",
	}
	clone := func(mut func(map[string]interface{})) map[string]interface{} {
		c := map[string]interface{}{}
		for k, v := range valid {
			c[k] = v
		}
		mut(c)
		return c
	}

	t.Run("empty token", func(t *testing.T) {
		_, err := authn.VerifyAccessToken(context.Background(), "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("expired", func(t *testing.T) {
		raw := m.signIDToken(t, clone(func(c map[string]interface{}) {
			c["exp"] = jwt.NewNumericDate(now.Add(-time.Hour))
			c["iat"] = jwt.NewNumericDate(now.Add(-2 * time.Hour))
		}))
		_, err := authn.VerifyAccessToken(context.Background(), raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("wrong audience", func(t *testing.T) {
		raw := m.signIDToken(t, clone(func(c map[string]interface{}) { c["aud"] = "some-other-api" }))
		_, err := authn.VerifyAccessToken(context.Background(), raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})

	t.Run("missing oid", func(t *testing.T) {
		raw := m.signIDToken(t, clone(func(c map[string]interface{}) { delete(c, "oid") }))
		_, err := authn.VerifyAccessToken(context.Background(), raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "oid claim missing")
	})

	t.Run("missing tid", func(t *testing.T) {
		raw := m.signIDToken(t, clone(func(c map[string]interface{}) { delete(c, "tid") }))
		_, err := authn.VerifyAccessToken(context.Background(), raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "tid claim missing")
	})

	t.Run("invalid signature", func(t *testing.T) {
		wrongKey, kerr := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, kerr)
		signer, serr := jose.NewSigner(
			jose.SigningKey{Algorithm: jose.RS256, Key: wrongKey},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", m.keyID),
		)
		require.NoError(t, serr)
		payload, _ := json.Marshal(valid)
		jws, serr := signer.Sign(payload)
		require.NoError(t, serr)
		raw, _ := jws.CompactSerialize()
		_, err := authn.VerifyAccessToken(context.Background(), raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verification failed")
	})
}
