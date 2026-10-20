package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestCircuitBreaker_ClosedState(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() in closed state, got: %v", err)
	}

	cb.ReportResult(nil)
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() after success, got: %v", err)
	}
}

// TestCircuitBreaker_RedisNilIsSuccess verifies that cache misses (redis.Nil)
// don't trip the breaker — they're normal responses, not connection failures.
func TestCircuitBreaker_RedisNilIsSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	// Report 10 cache misses — should never trip the breaker
	for i := 0; i < 10; i++ {
		cb.Allow()
		cb.ReportResult(redis.Nil)
	}

	if err := cb.Allow(); err != nil {
		t.Fatalf("breaker tripped on cache misses: %v", err)
	}
}

// TestCircuitBreaker_ContextErrorsAreSuccess verifies that context cancellation
// and deadline exceeded don't trip the breaker — the caller gave up, not a Redis fault.
func TestCircuitBreaker_ContextErrorsAreSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	for i := 0; i < 10; i++ {
		cb.Allow()
		cb.ReportResult(context.Canceled)
		cb.Allow()
		cb.ReportResult(context.DeadlineExceeded)
	}

	if err := cb.Allow(); err != nil {
		t.Fatalf("breaker tripped on context errors: %v", err)
	}
}

func TestCircuitBreaker_OpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	redisErr := errors.New("connection refused")

	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(redisErr)
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() below threshold, got: %v", err)
	}

	// Third failure trips the breaker
	cb.ReportResult(redisErr)

	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("expected ErrCircuitOpen after threshold, got: %v", err)
	}
}

func TestCircuitBreaker_SuccessResetsCounter(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)
	redisErr := errors.New("connection refused")

	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(nil) // success resets

	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(redisErr)

	if err := cb.Allow(); err != nil {
		t.Fatalf("expected Allow() after reset, got: %v", err)
	}
}

func TestCircuitBreaker_HalfOpenProbeSuccess(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	redisErr := errors.New("connection refused")

	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(redisErr)

	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatal("expected open")
	}

	time.Sleep(60 * time.Millisecond)

	if err := cb.Allow(); err != nil {
		t.Fatalf("expected half-open probe to be allowed, got: %v", err)
	}

	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatal("expected concurrent request rejected during probe")
	}

	cb.ReportResult(nil)

	if err := cb.Allow(); err != nil {
		t.Fatalf("expected closed after probe success, got: %v", err)
	}
}

func TestCircuitBreaker_HalfOpenProbeFail(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	redisErr := errors.New("connection refused")

	cb.Allow()
	cb.ReportResult(redisErr)
	cb.Allow()
	cb.ReportResult(redisErr)

	time.Sleep(60 * time.Millisecond)

	if err := cb.Allow(); err != nil {
		t.Fatalf("expected probe allowed, got: %v", err)
	}

	cb.ReportResult(redisErr)

	if err := cb.Allow(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatal("expected open after probe failure")
	}
}
