package redis

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// Client is an alias for the go-redis Client type.
type Client = redis.Client

const (
	// maxRetries is the number of connection attempts before giving up.
	maxRetries = 10
	// retryInterval is the delay between connection attempts.
	retryInterval = 2 * time.Second

	// circuitBreakerThreshold is the number of consecutive failures before
	// the circuit breaker opens and operations start failing immediately.
	circuitBreakerThreshold = 5
	// circuitBreakerCooldown is how long the breaker stays open before
	// allowing a probe request through to test if Redis recovered.
	circuitBreakerCooldown = 10 * time.Second
)

// NewClient creates a shared Redis client from a URL.
// The URL must include a password — unprotected Redis is rejected.
// The client retries the initial connection up to 10 times (20s total)
// to handle startup ordering when Redis is not yet ready.
// A circuit breaker is attached to fast-fail operations when Redis is
// unreachable, preventing timeout cascades under load.
func NewClient(redisURL string) (*Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("invalid REDIS_URL: %w", err)
	}
	if opts.Password == "" {
		return nil, fmt.Errorf("REDIS_URL must include a password (e.g., redis://:password@host:6379/0)")
	}

	// Attach circuit breaker so operations fail fast when Redis is down,
	// instead of blocking on connection timeouts.
	opts.Limiter = NewCircuitBreaker(circuitBreakerThreshold, circuitBreakerCooldown)

	client := redis.NewClient(opts)

	// Retry initial connection — Redis may not be ready at startup
	// (e.g. external Redis still booting, or built-in Redis starting in parallel).
	var lastErr error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if err := client.Ping(context.Background()).Err(); err != nil {
			lastErr = err
			if attempt < maxRetries {
				slog.Warn("redis not ready, retrying",
					"attempt", attempt,
					"max", maxRetries,
					"next_retry_in", retryInterval,
					"error", err)
				time.Sleep(retryInterval)
			}
			continue
		}
		return client, nil
	}

	client.Close()
	return nil, fmt.Errorf("redis connection failed after %d attempts: %w", maxRetries, lastErr)
}
