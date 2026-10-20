//go:build !mockauth

package server

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// handleGetTestIdentities is a no-op in production builds.
func (s *Server) handleGetTestIdentities(c *gin.Context) {
	c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
}
