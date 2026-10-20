package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The reconciler's `db` field is *db.DB concrete. These tests focus on
// the goroutine lifecycle — start/stop/idempotency — using a nil DB
// (which Start treats as a no-op). End-to-end coverage of the
// promotion path runs in the integration suite (testcontainer).

func TestVisibilityReconciler_NilDBIsNoOp(t *testing.T) {
	r := NewVisibilityReconciler(nil, DefaultVisibilityReconcilerConfig())
	// Start should not spawn a goroutine when db is nil.
	r.Start(context.Background())
	r.Stop() // must not panic
}

func TestVisibilityReconciler_StopIsIdempotent(t *testing.T) {
	r := NewVisibilityReconciler(nil, DefaultVisibilityReconcilerConfig())
	r.Stop()
	r.Stop() // second call must not panic
}

func TestVisibilityReconciler_ConfigDefaults(t *testing.T) {
	r := NewVisibilityReconciler(nil, VisibilityReconcilerConfig{})
	require.NotNil(t, r)
	assert.Equal(t, 5*time.Second, r.interval)
	assert.Equal(t, 100, r.batch)
}

func TestVisibilityReconciler_DefaultsConfigIsSane(t *testing.T) {
	cfg := DefaultVisibilityReconcilerConfig()
	assert.GreaterOrEqual(t, cfg.Interval, time.Second)
	assert.LessOrEqual(t, cfg.Interval, 30*time.Second)
	assert.GreaterOrEqual(t, cfg.BatchSize, 10)
	assert.LessOrEqual(t, cfg.BatchSize, 1000)
}

// TestVisibilityReconciler_StartStopDoesNotPanic confirms the lifecycle
// can be exercised without a real DB. Start spawns nothing (nil db),
// Stop must still close cleanly.
func TestVisibilityReconciler_StartStopDoesNotPanic(t *testing.T) {
	r := NewVisibilityReconciler(nil, VisibilityReconcilerConfig{
		Interval:  10 * time.Millisecond,
		BatchSize: 1,
	})
	r.Start(context.Background())
	time.Sleep(20 * time.Millisecond)
	r.Stop()
}

// errAlwaysFail is a helper for code that wants to assert error
// propagation through the reconciler's mark-failed branch. Kept here
// because the integration test (which actually exercises the DB path)
// imports it.
var errAlwaysFail = errors.New("always fail")
