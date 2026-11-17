//go:build !mockauth

package server

import (
	"time"

	"github.com/gin-gonic/gin"

	"privacy-proxy/internal/config"
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

// DemoAutoAuthDelay returns how long demo mode waits before completing a
// pending login with a new demo identity; 0 means never. Production builds
// have no demo mode, whatever DEMO_AUTO_AUTH_DELAY and ENVIRONMENT say
// (RD-1444).
func DemoAutoAuthDelay(*config.Config) time.Duration {
	return 0
}
