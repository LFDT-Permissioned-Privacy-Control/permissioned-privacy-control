package disclosurecase

import (
	"context"
	"time"
)

// A response outlives Read's acquisition child. Retain only the original
// caller's cancellation and the original absolute bound, never that child.
type dataReadFence struct {
	deadline time.Time
	done     <-chan struct{}
}

func newDataReadFence(parent context.Context) (dataReadFence, error) {
	if parent == nil || parent.Err() != nil {
		return dataReadFence{}, ErrUnavailable
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := parent.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	return dataReadFence{deadline, parent.Done()}, nil
}

func (f *dataReadFence) clip(lifetime time.Duration) {
	deadline := time.Now().Add(lifetime)
	if deadline.Before(f.deadline) {
		f.deadline = deadline
	}
}

func (f dataReadFence) check() error {
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
