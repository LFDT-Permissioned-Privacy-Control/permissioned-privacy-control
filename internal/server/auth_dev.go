//go:build mockauth

package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/config"
)

// tryMockLogin handles mock JWZ tokens for testing.
// This implementation is only included in non-production builds.
func (s *Server) tryMockLogin(c *gin.Context, jwzToken string) (string, error) {
	if !s.mockLoginEnabled() || len(jwzToken) <= 5 || jwzToken[:5] != "mock." {
		return "", nil // Not a mock token or not allowed
	}

	// Extract DID from mock token
	// Mock token format: mock.{userDID} or mock.jwz.token.{userDID}
	parts := strings.Split(jwzToken, ".")
	var userDID string
	if len(parts) >= 2 {
		// Get the last part which should be the DID
		userDID = parts[len(parts)-1]
		// If DID doesn't have expected prefix, it might be the full mock token
		if !strings.HasPrefix(userDID, "did:") {
			userDID = "did:privado:" + userDID
		}
	}

	if userDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid mock token format"})
		return "", fmt.Errorf("invalid mock token format")
	}

	return userDID, nil
}

// mockLoginEnabled reports whether this build and config accept mock logins.
// Production builds compile the stub in auth_prod.go, which always says no.
func (s *Server) mockLoginEnabled() bool {
	return s.config.AllowMockLogin && !s.config.IsProduction()
}

// DemoAutoAuthDelay returns how long demo mode waits before completing a
// pending login with a new demo identity; 0 means never. Production builds
// compile the stub in auth_prod.go, which always returns 0.
func DemoAutoAuthDelay(cfg *config.Config) time.Duration {
	if cfg.IsProduction() {
		return 0
	}
	return cfg.DemoAutoAuthDelay
}

// handleOAuthMockComplete handles POST /oauth/session/:id/mock-complete
// Dev-only: instantly completes an OAuth session with a mock DID, bypassing Privado verification.
//
// @Summary      Complete an OAuth session with a mock DID (dev only)
// @Description  Available only in non-production builds with mock login enabled. Instantly completes a pending OAuth session with a mock DID (optionally supplied in the body), bypassing Privado verification, and mints the authorization code. Rate-limited.
// @Tags         OAuth SSO
// @Accept       json
// @Produce      json
// @Param        id path string true "OAuth session ID"
// @Param        request body object false "optional {\"did\":\"did:...\"} to complete as a specific mock identity"
// @Success      200 {object} apimodels.OAuthMockCompleteResponse
// @Failure      403 {object} apimodels.APIError "mock login not available"
// @Failure      404 {object} apimodels.APIError "session not found or expired"
// @Failure      409 {object} apimodels.APIError "session already completed"
// @Failure      500 {object} apimodels.APIError "failed to complete session"
// @Router       /oauth/session/{id}/mock-complete [post]
func (s *Server) handleOAuthMockComplete(c *gin.Context) {
	if !s.mockLoginEnabled() {
		c.JSON(http.StatusForbidden, gin.H{"error": "mock login not available"})
		return
	}

	oauthSessionID := c.Param("id")
	oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
	if oauthSession == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found or expired"})
		return
	}
	if oauthSession.Code != "" {
		c.JSON(http.StatusConflict, gin.H{"error": "session already completed"})
		return
	}

	// Accept optional DID from request body (for dev identity picker)
	var body struct {
		DID string `json:"did"`
	}
	_ = c.ShouldBindJSON(&body) // ignore errors — body is optional

	mockDID := body.DID
	if mockDID == "" {
		mockDID = fmt.Sprintf("did:privado:mock_%d", time.Now().UnixNano())
	}
	kyc := false
	if s.rbacAccessCtrl != nil {
		if user, err := s.rbacAccessCtrl.EnsureUserExists(c.Request.Context(), mockDID, kyc, false); err == nil && user != nil {
			kyc = user.KYC
		}
	}

	code := generateSecureCode()
	if err := s.oauthSessionStore.SetCode(oauthSessionID, code, mockDID, kyc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete session"})
		return
	}

	if oauthSession.AuthSessionID != "" {
		_ = s.sessionStore.CompleteSession(oauthSession.AuthSessionID, "", "")
	}

	c.JSON(http.StatusOK, apimodels.OAuthMockCompleteResponse{OK: true, DID: mockDID})
}

// scheduleDemoAutoAuth schedules automatic session completion for demo mode.
// Spawns a goroutine that completes the session with a mock DID after the configured delay.
func (s *Server) scheduleDemoAutoAuth(sessionID string) {
	delay := DemoAutoAuthDelay(s.config)
	if delay <= 0 {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if session still pending (may have been completed or expired)
		session := s.sessionStore.GetSession(sessionID)
		if session == nil || session.Completed {
			return
		}

		// Generate mock DID and issue tokens
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc, false); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		accessToken, err := s.jwtService.IssueAccessToken(mockDID, kyc)
		if err != nil {
			slog.Error("demo auto-auth: failed to issue access token", "error", err)
			return
		}
		refreshToken, err := s.jwtService.IssueRefreshToken(mockDID)
		if err != nil {
			slog.Error("demo auto-auth: failed to issue refresh token", "error", err)
			return
		}

		tokenHash := auth.HashToken(refreshToken)
		expiresAt := time.Now().Add(RefreshTokenTTL)
		if err := s.db.SaveRefreshToken(context.Background(), tokenHash, mockDID, expiresAt); err != nil {
			slog.Error("demo auto-auth: failed to save refresh token", "error", err)
			return
		}

		if err := s.sessionStore.CompleteSession(sessionID, accessToken, refreshToken); err != nil {
			slog.Error("demo auto-auth: failed to complete session", "error", err)
			return
		}

		slog.Info("demo auto-auth: session completed", "session_id", sessionID, "did", mockDID)
	}()
}

// scheduleOAuthDemoAutoAuth schedules automatic OAuth session completion for demo mode
func (s *Server) scheduleOAuthDemoAutoAuth(oauthSessionID, authSessionID string) {
	delay := DemoAutoAuthDelay(s.config)
	if delay <= 0 {
		return
	}

	go func() {
		time.Sleep(delay)

		// Check if OAuth session still pending
		oauthSession := s.oauthSessionStore.GetSession(oauthSessionID)
		if oauthSession == nil || oauthSession.Code != "" {
			return
		}

		// Generate mock DID and complete the OAuth flow
		mockDID := fmt.Sprintf("did:privado:demo_%d", time.Now().UnixNano())
		kyc := false
		if s.rbacAccessCtrl != nil {
			if user, err := s.rbacAccessCtrl.EnsureUserExists(context.Background(), mockDID, kyc, false); err == nil && user != nil {
				kyc = user.KYC
			}
		}

		// Generate authorization code
		code := generateSecureCode()
		if err := s.oauthSessionStore.SetCode(oauthSessionID, code, mockDID, kyc); err != nil {
			slog.Error("demo OAuth auto-auth: failed to set code", "error", err)
			return
		}

		// Mark auth session as completed
		if err := s.sessionStore.CompleteSession(authSessionID, "", ""); err != nil {
			slog.Error("demo OAuth auto-auth: failed to complete auth session", "error", err)
		}

		slog.Info("demo OAuth auto-auth: session completed", "session_id", oauthSessionID, "did", mockDID)
	}()
}
