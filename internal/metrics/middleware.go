package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// HTTPMiddleware returns a Gin middleware that records HTTP request metrics.
// Uses c.FullPath() for route normalization to avoid high-cardinality label values.
func (m *Metrics) HTTPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()

		c.Next()

		duration := time.Since(start).Seconds()
		status := strconv.Itoa(c.Writer.Status())

		// FullPath returns the route pattern (e.g. "/api/v1/admin/orgs/:id"),
		// not the actual path. Returns "" for unmatched routes (404).
		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}

		method := c.Request.Method

		m.HTTPRequestsTotal.WithLabelValues(method, path, status).Inc()
		m.HTTPRequestDuration.WithLabelValues(method, path).Observe(duration)
	}
}
