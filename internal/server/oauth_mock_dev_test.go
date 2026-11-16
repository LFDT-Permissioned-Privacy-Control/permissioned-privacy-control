//go:build mockauth

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

// A mockauth build accepts mock logins on the OAuth path when mock login is
// switched on outside production (RD-1444 keeps this; production builds are
// covered by TestOAuth_ProductionBuildRefusesMockLogin).
func TestOAuth_MockauthBuildMockLogin(t *testing.T) {
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
	mockComplete := func(oauthSessionID string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth/session/"+oauthSessionID+"/mock-complete", nil))
		return w
	}

	t.Run("the callback takes the DID from a mock token", func(t *testing.T) {
		mock := srv.privadoVerifier.(*mockPrivadoVerifier)
		prev := mock.verifyFunc
		mock.verifyFunc = func(context.Context, string, *protocol.AuthorizationRequestMessage, string) (string, error) {
			return "", fmt.Errorf("the verifier must not see a mock token")
		}
		defer func() { mock.verifyFunc = prev }()

		oauthSessionID, authSessionID := pendingSession(t)
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth/callback?session="+authSessionID+"&oauth_session="+oauthSessionID,
			strings.NewReader(`{"token":"mock.did:privado:test_user_123"}`))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		session := srv.oauthSessionStore.GetSession(oauthSessionID)
		require.NotNil(t, session)
		assert.NotEmpty(t, session.Code)
		assert.Equal(t, "did:privado:test_user_123", session.UserDID)
	})

	t.Run("the login page is offered mock login", func(t *testing.T) {
		oauthSessionID, _ := pendingSession(t)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oauth/session/"+oauthSessionID+"/info", nil))

		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["allow_mock"])
	})

	t.Run("mock-complete completes the session", func(t *testing.T) {
		oauthSessionID, _ := pendingSession(t)
		w := mockComplete(oauthSessionID)

		require.Equal(t, http.StatusOK, w.Code)
		var resp map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, true, resp["ok"])
		assert.Contains(t, resp["did"].(string), "did:privado:mock_")
		session := srv.oauthSessionStore.GetSession(oauthSessionID)
		require.NotNil(t, session)
		assert.NotEmpty(t, session.Code)
	})

	t.Run("mock-complete returns 409 when the session is already completed", func(t *testing.T) {
		oauthSessionID, _ := pendingSession(t)
		require.Equal(t, http.StatusOK, mockComplete(oauthSessionID).Code)
		assert.Equal(t, http.StatusConflict, mockComplete(oauthSessionID).Code)
	})

	t.Run("mock-complete returns 404 for an unknown session", func(t *testing.T) {
		assert.Equal(t, http.StatusNotFound, mockComplete("nonexistent").Code)
	})
}
