//go:build mockauth

package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// tryMockLogin handles mock JWZ tokens for testing.
// This implementation is only included in non-production builds.
func (s *Server) tryMockLogin(c *gin.Context, jwzToken string) (string, error) {
	if !s.config.AllowMockLogin || len(jwzToken) <= 5 || jwzToken[:5] != "mock." {
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
