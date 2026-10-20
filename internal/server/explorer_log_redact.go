package server

import (
	"regexp"

	"github.com/gin-gonic/gin"
)

// ethAddressPattern matches Ethereum addresses (0x followed by 40 hex chars).
// Case-insensitive to catch both checksummed and lowercased forms.
var ethAddressPattern = regexp.MustCompile(`(?i)0x[0-9a-fA-F]{40}`)

// explorerLogRedactionMiddleware replaces Ethereum addresses in the request path
// with a placeholder for logging purposes. This prevents real addresses from
// leaking into server access logs and network traces.
//
// How it works: Gin's default logger reads c.Request.URL.Path at log time.
// This middleware rewrites that field AFTER routing (so the handler sees the
// real address via c.Param) but BEFORE the deferred logger fires.
//
// Gin processes middlewares in order: the logger middleware (from gin.Default)
// defers its log write until after c.Next() returns. Because this middleware
// is added to the explorer group (which runs inside the logger's c.Next()),
// the path rewrite happens before the logger's deferred write executes.
func explorerLogRedactionMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Process the request first so the handler sees the real path
		c.Next()

		// After the handler completes, redact addresses from the path that
		// Gin's logger will read. The default logger uses c.Request.URL.Path.
		c.Request.URL.Path = ethAddressPattern.ReplaceAllString(c.Request.URL.Path, "0x[REDACTED]")
	}
}

