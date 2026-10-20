package server

import (
	"testing"

	"privacy-proxy/internal/db"
)

// A db-less reconciler (disabled) must treat Kick() as a no-op, never panic,
// and never block — the send path calls it unconditionally.
func TestVisibilityReconciler_KickNilAndDisabledIsNoOp(t *testing.T) {
	var nilR *VisibilityReconciler
	nilR.Kick() // nil receiver

	disabled := NewVisibilityReconciler(nil, DefaultVisibilityReconcilerConfig()) // db == nil
	for i := 0; i < 5; i++ {
		disabled.Kick() // must not block or panic even without a running loop
	}
}

// Kick() is non-blocking and coalescing: with a size-1 buffer and no drain
// goroutine consuming, repeated kicks collapse to a single queued signal
// rather than blocking the caller (the send hot path).
func TestVisibilityReconciler_KickCoalescesAndDoesNotBlock(t *testing.T) {
	// Non-nil db sentinel so Kick() is not the disabled no-op (it only nil-checks
	// db, never dereferences it here). The loop is never started, so nothing
	// consumes r.kick; the size-1 buffer + default case must absorb all kicks.
	r := &VisibilityReconciler{db: &db.DB{}, kick: make(chan struct{}, 1)}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.Kick()
		}
		close(done)
	}()

	<-done // would deadlock if Kick blocked once the buffer filled

	// Exactly one signal is queued (coalesced), not 1000.
	if got := len(r.kick); got != 1 {
		t.Fatalf("want 1 coalesced kick queued, got %d", got)
	}
}
