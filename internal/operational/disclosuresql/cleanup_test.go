package disclosuresql

import (
	"context"
	"testing"
	"time"
)

type waitingCleanup struct {
	deadline bool
	canceled bool
}

func (w *waitingCleanup) wait(ctx context.Context) error {
	_, w.deadline = ctx.Deadline()
	if !w.deadline {
		return context.Canceled
	}
	<-ctx.Done()
	w.canceled = ctx.Err() == context.DeadlineExceeded
	return ctx.Err()
}
func (w *waitingCleanup) Rollback(ctx context.Context) error { return w.wait(ctx) }
func (w *waitingCleanup) Close(ctx context.Context) error    { return w.wait(ctx) }
func TestStalledFailureCleanupGetsFiniteFreshDeadline(t *testing.T) {
	for _, operation := range []func(*waitingCleanup){func(w *waitingCleanup) { rollback(w) }, func(w *waitingCleanup) { closeConnection(w) }} {
		waiting := &waitingCleanup{}
		started := time.Now()
		operation(waiting)
		if !waiting.deadline || !waiting.canceled || time.Since(started) > 2*time.Second {
			t.Fatal("cleanup can wait beyond its cancellation budget")
		}
	}
}
