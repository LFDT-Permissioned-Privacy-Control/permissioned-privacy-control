package redis

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrCircuitOpen is returned when the circuit breaker is open (Redis unreachable).
// Callers should treat this as a cache miss / temporary unavailability.
var ErrCircuitOpen = errors.New("redis circuit breaker is open")

// circuitState represents the state of the circuit breaker.
type circuitState int

const (
	stateClosed   circuitState = iota // Normal operation
	stateOpen                         // Fast-failing, Redis assumed down
	stateHalfOpen                     // Probing — one request allowed through
)

// CircuitBreaker implements go-redis's Limiter interface as a circuit breaker.
// When consecutive Redis failures exceed the threshold, the breaker opens and
// all operations fail immediately (no timeout wait). After a cooldown period,
// one probe request is allowed through — if it succeeds, the breaker closes.
type CircuitBreaker struct {
	mu sync.Mutex

	state            circuitState
	consecutiveFails int
	lastFailTime     time.Time

	// Configuration
	failThreshold int           // consecutive failures before opening
	cooldown      time.Duration // how long to stay open before probing
}

// NewCircuitBreaker creates a circuit breaker for Redis operations.
//   - failThreshold: consecutive failures before the breaker opens (e.g. 5)
//   - cooldown: time to wait in open state before allowing a probe (e.g. 10s)
func NewCircuitBreaker(failThreshold int, cooldown time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failThreshold: failThreshold,
		cooldown:      cooldown,
	}
}

// Allow implements the go-redis Limiter interface.
// Returns nil if the operation is allowed, ErrCircuitOpen if the breaker is open.
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case stateClosed:
		return nil

	case stateOpen:
		// Check if cooldown has elapsed — transition to half-open
		if time.Since(cb.lastFailTime) >= cb.cooldown {
			cb.state = stateHalfOpen
			slog.Info("redis circuit breaker: half-open, probing")
			return nil
		}
		return ErrCircuitOpen

	case stateHalfOpen:
		// Only one probe at a time — reject concurrent requests while probing
		return ErrCircuitOpen
	}

	return nil
}

// ReportResult implements the go-redis Limiter interface.
// Connection failures count as failures. Normal Redis responses (nil, context
// cancellation, etc.) count as successes — they mean Redis is responsive.
func (cb *CircuitBreaker) ReportResult(result error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Treat the following as success (Redis is reachable):
	//   - nil: operation succeeded
	//   - redis.Nil: key not found (normal cache miss)
	//   - context.Canceled / context.DeadlineExceeded: caller gave up, not a Redis fault
	if result == nil ||
		errors.Is(result, redis.Nil) ||
		errors.Is(result, context.Canceled) ||
		errors.Is(result, context.DeadlineExceeded) {
		if cb.state == stateHalfOpen {
			slog.Info("redis circuit breaker: closed (probe succeeded)")
		}
		cb.state = stateClosed
		cb.consecutiveFails = 0
		return
	}

	// Connection/network/protocol failure
	cb.consecutiveFails++
	cb.lastFailTime = time.Now()

	if cb.state == stateHalfOpen {
		// Probe failed — back to open
		cb.state = stateOpen
		slog.Warn("redis circuit breaker: open (probe failed)", "error", result)
		return
	}

	if cb.consecutiveFails >= cb.failThreshold {
		cb.state = stateOpen
		slog.Warn("redis circuit breaker: open",
			"consecutive_failures", cb.consecutiveFails,
			"cooldown", cb.cooldown,
			"error", result)
	}
}
