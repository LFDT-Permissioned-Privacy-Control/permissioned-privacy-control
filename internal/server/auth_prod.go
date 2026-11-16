//go:build !mockauth

package server

import (
	"github.com/gin-gonic/gin"
)

// tryMockLogin handles mock JWZ tokens.
// In production builds, this is a no-op to ensure mock auth cannot be used.
func (s *Server) tryMockLogin(c *gin.Context, jwzToken string) (string, error) {
	return "", nil
}

// mockLoginEnabled reports whether this build accepts mock logins. Production
// builds never do, whatever ALLOW_MOCK_LOGIN and ENVIRONMENT say (RD-1444).
func (s *Server) mockLoginEnabled() bool {
	return false
}
