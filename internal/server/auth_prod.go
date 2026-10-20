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
