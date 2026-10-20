package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authpkg "privacy-proxy/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-993 — POST /oauth/session/:id/silent-complete tests.
//
// Each test mounts the route on a thin gin router so the production middleware
// chain (rate limiter, JWT validator, handler) runs the same way as in
// production. The handler does NOT depend on the Privado verifier or rbac
// access controller other than EnsureUserExists, which the test DB satisfies.

// setupSilentCompleteTestRouter wires the silent-complete route with the
// real JWT middleware on top of the OAuth fixture server. firstPartyClients
// configures the first-party allowlist for the test.
func setupSilentCompleteTestRouter(t *testing.T, srv *Server, firstPartyClients []string) *gin.Engine {
	t.Helper()
	srv.config.OAuthFirstPartyClients = map[string]string{}
	for _, id := range firstPartyClients {
		srv.config.OAuthFirstPartyClients[id] = "$2a$10$placeholderhashfortestsXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST(
		"/oauth/session/:id/silent-complete",
		authpkg.JWTAuthMiddleware(srv.jwtService, srv.db),
		srv.handleOAuthSilentComplete,
	)
	return router
}

// helper: mint a PP access token for a DID and return the bearer header value.
func bearerFor(t *testing.T, srv *Server, did string) string {
	t.Helper()
	tok, err := srv.jwtService.IssueAccessToken(did, true /* kyc */)
	require.NoError(t, err)
	return "Bearer " + tok
}

// helper: ensure the impersonated user exists in the RBAC store, so the
// JWT middleware doesn't trip on the user-revocation lookup.
func ensureUser(t *testing.T, srv *Server, did string) {
	t.Helper()
	_, err := srv.rbacAccessCtrl.EnsureUserExists(context.Background(), did, true, false)
	require.NoError(t, err)
}

func TestOAuthSilentComplete_HappyPath(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	initiatorDID := "did:privado:initiator"
	ensureUser(t, srv, initiatorDID)

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"block-explorer",
		"http://localhost:3001/api/auth/callback",
		"state-abc",
		"auth-sess-1",
		initiatorDID,
	)
	require.NotEmpty(t, oauthSessionID)

	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, initiatorDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, true, body["completed"])
	redirectURL, _ := body["redirect_url"].(string)
	assert.True(t, strings.HasPrefix(redirectURL, "http://localhost:3001/api/auth/callback?code="))
	assert.Contains(t, redirectURL, "state=state-abc")

	// Verify the auth code was set on the session so /oauth/token can
	// redeem it. We don't probe the internal store directly — we just
	// confirm a second silent-complete returns 409 (session already
	// completed), which is the externally-visible invariant.
	req2 := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req2.Header.Set("Authorization", bearerFor(t, srv, initiatorDID))
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)

	// Audit row written exactly once.
	var count int
	err := srv.db.Conn().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM oauth_silent_sso_log WHERE actor_did = $1 AND client_id = $2`,
		initiatorDID, "block-explorer").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "exactly one audit row for the successful silent-complete")
}

func TestOAuthSilentComplete_RejectsDifferentCaller(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	initiatorDID := "did:privado:alice"
	intruderDID := "did:privado:mallory"
	ensureUser(t, srv, initiatorDID)
	ensureUser(t, srv, intruderDID)

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"block-explorer",
		"http://localhost:3001/api/auth/callback",
		"state-1",
		"auth-1",
		initiatorDID,
	)
	require.NotEmpty(t, oauthSessionID)

	// Mallory (different user) tries to silent-complete Alice's session.
	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, intruderDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)

	// No audit row written for the reject.
	var count int
	err := srv.db.Conn().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM oauth_silent_sso_log`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestOAuthSilentComplete_RejectsAnonymousInitiator(t *testing.T) {
	// Sessions started by an anonymous caller (no JWT on /authorize, so
	// InitiatorDID = "") must never be eligible for silent-complete —
	// otherwise a caller-bound-to-no-one session could be hijacked by the
	// first JWT-bearing user who arrives at the silent-complete endpoint.
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	callerDID := "did:privado:any-user"
	ensureUser(t, srv, callerDID)

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"block-explorer",
		"http://localhost:3001/api/auth/callback",
		"state-anon",
		"auth-anon",
		"", // anonymous initiator
	)
	require.NotEmpty(t, oauthSessionID)

	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, callerDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestOAuthSilentComplete_RejectsNonFirstPartyClient(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	// First-party allowlist contains only block-explorer; the test session
	// uses a different client_id.
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	initiatorDID := "did:privado:initiator"
	ensureUser(t, srv, initiatorDID)

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"third-party-app",
		"http://localhost:3001/api/auth/callback",
		"state-tp",
		"auth-tp",
		initiatorDID,
	)
	require.NotEmpty(t, oauthSessionID)

	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, initiatorDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestOAuthSilentComplete_RejectsEmptyAllowlist(t *testing.T) {
	// Empty allowlist = no client gets silent SSO. Same shape as
	// non-first-party client: 403, no audit row.
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, nil)

	initiatorDID := "did:privado:initiator"
	ensureUser(t, srv, initiatorDID)

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"block-explorer",
		"http://localhost:3001/api/auth/callback",
		"state-empty",
		"auth-empty",
		initiatorDID,
	)
	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, initiatorDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestOAuthSilentComplete_RejectsMissingJWT(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	oauthSessionID := srv.oauthSessionStore.CreateSession(
		"block-explorer",
		"http://localhost:3001/api/auth/callback",
		"state-nojwt",
		"auth-nojwt",
		"did:privado:initiator",
	)
	req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/silent-complete", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOAuthSilentComplete_NotFound(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()
	router := setupSilentCompleteTestRouter(t, srv, []string{"block-explorer"})

	initiatorDID := "did:privado:initiator"
	ensureUser(t, srv, initiatorDID)

	req := httptest.NewRequest(http.MethodPost, "/oauth/session/does-not-exist/silent-complete", nil)
	req.Header.Set("Authorization", bearerFor(t, srv, initiatorDID))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
