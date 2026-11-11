// Package historyfacts binds current read facts to one original verified
// request. Operational adapters supply facts; they never supply permissions.
package historyfacts

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalid     = errors.New("invalid history facts")
	ErrUnavailable = errors.New("history facts unavailable")
	ErrTooBroad    = errors.New("history facts exceed limit")
)

const MaxOperationTime = 20 * time.Second
const MaxChargedBytes = 16 << 20

// Fence retains no context values or acquisition child. The original caller's
// cancellation and the earlier absolute deadline also constrain later checks
// made with another parent, including Background.
type Fence struct {
	deadline time.Time
	done     <-chan struct{}
}

func NewFence(ctx context.Context, timeout time.Duration) (Fence, error) {
	if ctx == nil || timeout <= 0 || timeout > MaxOperationTime {
		return Fence{}, ErrInvalid
	}
	d := time.Now().Add(timeout)
	if original, ok := ctx.Deadline(); ok && original.Before(d) {
		d = original
	}
	f := Fence{d, ctx.Done()}
	if f.Check() != nil {
		return Fence{}, ErrUnavailable
	}
	return f, nil
}

func (f Fence) Check() error {
	if f.deadline.IsZero() || !time.Now().Before(f.deadline) {
		return ErrUnavailable
	}
	select {
	case <-f.done:
		return ErrUnavailable
	default:
		return nil
	}
}

// Bind creates only a short-lived cancellation bridge, stopped by cancel.
func (f Fence) Bind(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || f.Check() != nil {
		return nil, nil, ErrUnavailable
	}
	ctx, cancel := context.WithDeadline(parent, f.deadline)
	if f.done != nil {
		go func() {
			select {
			case <-f.done:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel, nil
}
