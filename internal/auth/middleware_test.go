package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockRevocationChecker implements RevocationChecker for testing
type mockRevocationChecker struct {
	revokedTokens map[string]bool
}

func (m *mockRevocationChecker) IsAccessTokenRevoked(_ context.Context, tokenID string) (bool, error) {
	return m.revokedTokens[tokenID], nil
}

func TestJWTAuthMiddleware_ValidToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Setup router with middleware
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		subject, _ := c.Get("subject")
		kyc, _ := c.Get("kyc")
		c.JSON(http.StatusOK, gin.H{
			"subject": subject,
			"kyc":     kyc,
		})
	})

	// Make request with valid token
	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestJWTAuthMiddleware_MissingHeader(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_InvalidToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid.token.here")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_ExpiredToken(t *testing.T) {
	// Create service with negative TTL (expired immediately)
	service, err := NewJWTService("test-secret", "test-refresh-secret", -1*time.Hour, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue an expired token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestJWTAuthMiddleware_RevokedToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	// Issue a token
	token, err := service.IssueAccessToken("did:privado:test123", true)
	require.NoError(t, err)

	// Create mock revocation checker with token revoked
	tokenID := getTokenID(token)
	mockDB := &mockRevocationChecker{
		revokedTokens: map[string]bool{
			tokenID: true,
		},
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, mockDB), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestJWTAuthMiddleware_BearerSchemeCaseInsensitive pins RD-1217: the
// Authorization auth-scheme is case-insensitive per RFC 7235 §2.1 (RFC 6750
// inherits it), so every spelling of "bearer" with a valid token must be
// accepted — not just the exact "Bearer".
func TestJWTAuthMiddleware_BearerSchemeCaseInsensitive(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	token, err := service.IssueAccessToken("did:privado:case", true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	for _, scheme := range []string{"Bearer", "bearer", "BEARER", "BeArEr"} {
		t.Run("scheme="+scheme, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/test", nil)
			req.Header.Set("Authorization", scheme+" "+token)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equalf(t, http.StatusOK, w.Code, "scheme %q with a valid token must be accepted (RFC 7235 §2.1)", scheme)
		})
	}
}

// TestJWTAuthMiddleware_CaseInsensitiveSchemeStillValidatesToken is the
// fail-closed guard for RD-1217: accepting the scheme case-insensitively must
// NOT relax token validation — an invalid token under a lowercase scheme is
// still rejected.
func TestJWTAuthMiddleware_CaseInsensitiveSchemeStillValidatesToken(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "ok"})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "bearer not.a.valid.token")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a lowercase scheme must still reject an invalid token (fail-closed)")
}

// RD-1008: middleware reads JWT from the access cookie when the Authorization
// header is absent. The Bearer header takes precedence when both are
// present (preserves API-client behaviour); cookie alone is what unblocks
// silent SSO browser navigations.

func TestJWTAuthMiddleware_CookieFallback(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	token, err := service.IssueAccessToken("did:privado:cookie-user", true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		subject, _ := c.Get("subject")
		c.JSON(http.StatusOK, gin.H{"subject": subject})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "cookie-only auth must succeed")
}

func TestJWTAuthMiddleware_BearerWinsOverCookie(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	bearerTok, err := service.IssueAccessToken("did:privado:bearer-user", true)
	require.NoError(t, err)
	cookieTok, err := service.IssueAccessToken("did:privado:cookie-user", false)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/test", JWTAuthMiddleware(service, nil), func(c *gin.Context) {
		subject, _ := c.Get("subject")
		c.JSON(http.StatusOK, gin.H{"subject": subject})
	})

	req := httptest.NewRequest("POST", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+bearerTok)
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: cookieTok})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "did:privado:bearer-user",
		"Bearer header must take precedence when both transports carry a token")
}

func TestOptionalJWTAuthMiddleware_CookieFallback(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)
	token, err := service.IssueAccessToken("did:privado:initiator", true)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/oauth/authorize", OptionalJWTAuthMiddleware(service, nil), func(c *gin.Context) {
		subject, _ := c.Get("subject")
		c.JSON(http.StatusOK, gin.H{"subject": subject})
	})

	// Browser-navigation case: no Authorization header, only the cookie.
	// Pre-RD-1008 this would have left subject empty (anonymous), which is
	// what made initiatorDID empty server-side and broke silent SSO.
	req := httptest.NewRequest("GET", "/oauth/authorize", nil)
	req.AddCookie(&http.Cookie{Name: AccessCookieName, Value: token})
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "did:privado:initiator",
		"OptionalJWT must capture subject from the cookie so /oauth/authorize can set initiatorDID")
}

func TestOptionalJWTAuthMiddleware_AnonymousStillPasses(t *testing.T) {
	service, err := NewJWTService("test-secret", "test-refresh-secret", 30*time.Minute, 7*24*time.Hour)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/oauth/authorize", OptionalJWTAuthMiddleware(service, nil), func(c *gin.Context) {
		// subject must be empty for the anonymous case so the OAuth flow
		// falls through to interactive Privado.
		_, ok := c.Get("subject")
		c.JSON(http.StatusOK, gin.H{"authenticated": ok})
	})

	req := httptest.NewRequest("GET", "/oauth/authorize", nil) // no header, no cookie
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":false`)
}

func TestSetAndClearAccessCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("SetAccessCookie writes HttpOnly Lax cookie with correct ttl", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)

		SetAccessCookie(c, "the-jwt", 30*time.Minute)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		ck := cookies[0]
		assert.Equal(t, AccessCookieName, ck.Name)
		assert.Equal(t, "the-jwt", ck.Value)
		assert.Equal(t, "/", ck.Path)
		assert.True(t, ck.HttpOnly, "must be HttpOnly so XSS can't lift the token")
		assert.Equal(t, http.SameSiteLaxMode, ck.SameSite,
			"Lax enables cross-subdomain top-level navigation under same eTLD+1")
		assert.Equal(t, int((30 * time.Minute).Seconds()), ck.MaxAge)
	})

	t.Run("ClearAccessCookie sets MaxAge<0 to delete on the client", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/", nil)

		ClearAccessCookie(c)

		cookies := w.Result().Cookies()
		require.Len(t, cookies, 1)
		ck := cookies[0]
		assert.Equal(t, AccessCookieName, ck.Name)
		assert.Equal(t, "", ck.Value)
		assert.Less(t, ck.MaxAge, 0)
	})
}
