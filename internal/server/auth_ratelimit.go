package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthRateLimiter provides IP-based rate limiting for auth endpoints.
// Uses a sliding window algorithm to track requests per IP.
type AuthRateLimiter struct {
	mu           sync.RWMutex
	requests     map[string][]time.Time // IP -> request timestamps
	maxRequests  int                    // max requests per window
	windowSize   time.Duration          // sliding window size
	cleanupEvery time.Duration
	stopCleanup  chan struct{}
}

// AuthRateLimiterConfig holds configuration for auth rate limiting.
type AuthRateLimiterConfig struct {
	MaxRequests  int           // max requests per window (default: 10)
	WindowSize   time.Duration // sliding window size (default: 1 minute)
	CleanupEvery time.Duration // cleanup interval (default: 5 minutes)
}

// DefaultAuthRateLimiterConfig returns default configuration for production.
// Use DevAuthRateLimiterConfig for development/testing.
func DefaultAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		MaxRequests:  10,
		WindowSize:   time.Minute,
		CleanupEvery: 5 * time.Minute,
	}
}

// DevAuthRateLimiterConfig returns relaxed configuration for development/testing.
// Allows 1000 requests per minute to avoid rate limiting issues during tests.
func DevAuthRateLimiterConfig() AuthRateLimiterConfig {
	return AuthRateLimiterConfig{
		MaxRequests:  1000,
		WindowSize:   time.Minute,
		CleanupEvery: 5 * time.Minute,
	}
}

// NewAuthRateLimiter creates a new IP-based rate limiter for auth endpoints.
func NewAuthRateLimiter(cfg AuthRateLimiterConfig) *AuthRateLimiter {
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = 10
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = time.Minute
	}
	if cfg.CleanupEvery <= 0 {
		cfg.CleanupEvery = 5 * time.Minute
	}

	rl := &AuthRateLimiter{
		requests:     make(map[string][]time.Time),
		maxRequests:  cfg.MaxRequests,
		windowSize:   cfg.WindowSize,
		cleanupEvery: cfg.CleanupEvery,
		stopCleanup:  make(chan struct{}),
	}

	go rl.cleanup()

	return rl
}

// Middleware returns a Gin middleware that rate limits requests by IP.
func (rl *AuthRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()

		if !rl.Allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "too many requests, please try again later",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// Allow checks if a request from the given IP is allowed and records it.
func (rl *AuthRateLimiter) Allow(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-rl.windowSize)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Get existing timestamps for this IP
	timestamps := rl.requests[ip]

	// Filter out old timestamps
	validTimestamps := make([]time.Time, 0, len(timestamps))
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}

	// Check if we're at the limit
	if len(validTimestamps) >= rl.maxRequests {
		rl.requests[ip] = validTimestamps // Update with filtered list
		return false
	}

	// Add current request and allow
	validTimestamps = append(validTimestamps, now)
	rl.requests[ip] = validTimestamps
	return true
}

// cleanup periodically removes old entries.
func (rl *AuthRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.doCleanup()
		case <-rl.stopCleanup:
			return
		}
	}
}

// doCleanup removes IPs with no recent requests.
func (rl *AuthRateLimiter) doCleanup() {
	now := time.Now()
	cutoff := now.Add(-rl.windowSize * 2) // Keep 2 windows of history

	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, timestamps := range rl.requests {
		// Filter old timestamps
		valid := make([]time.Time, 0, len(timestamps))
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}

		if len(valid) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = valid
		}
	}
}

// Stop stops the cleanup goroutine.
func (rl *AuthRateLimiter) Stop() {
	close(rl.stopCleanup)
}
