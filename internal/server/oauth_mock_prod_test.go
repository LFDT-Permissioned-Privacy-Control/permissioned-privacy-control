//go:build !mockauth

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1444: a production build (no mockauth tag) never accepts a mock login on
// the OAuth path, whatever the config says, as on the wallet path. These run
// with mock login switched on outside ENVIRONMENT=production, the
// configuration under which the OAuth path used to accept one.
func TestOAuth_ProductionBuildRefusesMockLogin(t *testing.T) {
	srv := setupTestServerForOAuth(t)
	defer srv.db.Close()
	defer srv.oauthSessionStore.Stop()
	defer srv.sessionStore.Stop()

	srv.config.AllowMockLogin = true
	srv.config.Environment = "development"

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/oauth/callback", srv.handleOAuthCallback)
	router.POST("/oauth/session/:id/mock-complete", srv.handleOAuthMockComplete)
	router.GET("/oauth/session/:id/info", srv.handleOAuthSessionInfo)

	pendingSession := func(t *testing.T) (oauthSessionID, authSessionID string) {
		t.Helper()
		authReq, err := srv.privadoVerifier.CreateAuthorizationRequest("did:privado:verifier:test", "http://localhost/cb", "test")
		require.NoError(t, err)
		authSessionID = srv.sessionStore.CreateSession(authReq)
		require.NotEmpty(t, authSessionID)
		oauthSessionID = srv.oauthSessionStore.CreateSession("client", "http://localhost/cb", "state", authSessionID, "")
		require.NotEmpty(t, oauthSessionID)
		return oauthSessionID, authSessionID
	}

	t.Run("a mock token at the callback goes to the verifier", func(t *testing.T) {
		mock := srv.privadoVerifier.(*mockPrivadoVerifier)
		verified := ""
		prev := mock.verifyFunc
		mock.verifyFunc = func(_ context.Context, jwzToken string, _ *protocol.AuthorizationRequestMessage, _ string) (string, error) {
			verified = jwzToken
			return "", fmt.Errorf("JWZ verification failed: not a JWZ token")
		}
		defer func() { mock.verifyFunc = prev }()

		oauthSessionID, authSessionID := pendingSession(t)
		const token = "mock.did:privado:org_admin"
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/callback?session="+authSessionID+"&oauth_session="+oauthSessionID,
			strings.NewReader(`{"token":"`+token+`"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, token, verified, "the mock token must be verified like any other token")
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		session := srv.oauthSessionStore.GetSession(oauthSessionID)
		require.NotNil(t, session)
		assert.Empty(t, session.Code, "no authorization code may be minted")
	})

	t.Run("mock-complete is refused", func(t *testing.T) {
		oauthSessionID, _ := pendingSession(t)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete",
			strings.NewReader(`{"did":"did:privado:org_admin"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
		session := srv.oauthSessionStore.GetSession(oauthSessionID)
		require.NotNil(t, session)
		assert.Empty(t, session.Code, "no authorization code may be minted")
	})

	t.Run("the login page is not offered mock login", func(t *testing.T) {
		oauthSessionID, _ := pendingSession(t)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil))

		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, false, resp["allow_mock"])
	})
}
