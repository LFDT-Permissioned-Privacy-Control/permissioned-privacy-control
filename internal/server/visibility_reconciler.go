package server

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"privacy-proxy/internal/db"
)

// VisibilityReconciler is the M7 outbox drain: it promotes
// pending_tx_visibility rows into tx_visible_to. Each promotion is one
// DB transaction. Failures bump attempt_count on the pending row and
// are retried on the next tick; once attempt_count reaches
// db.MaxVisibilityAttempts the row is parked in dead-letter and surfaced
// via the metric for operator review.
//
// Draining is event-driven: the send path calls Kick() right after it
// enqueues a row, so recipient visibility is materialized within
// milliseconds on the happy path — not after a fixed poll delay. The
// periodic ticker is retained only as a BACKSTOP for cases a kick cannot
// cover: a missed/coalesced signal, a promotion that failed and must be
// retried, and rows left in the outbox from a prior DB outage (drained on
// the startup tick). So the interval is a safety-net cadence, not the
// steady-state visibility latency.
//
// Lifecycle: one instance per Server, constructed and started during
// server construction (server.New / NewWithVerifier), stopped via Stop()
// on shutdown. The reconciler holds no in-memory state — restart is safe
// (next tick picks up where the previous one left off).
type VisibilityReconciler struct {
	db        *db.DB
	interval  time.Duration
	batch     int
	kick      chan struct{} // coalescing signal: Kick() -> immediate drain
	stop      chan struct{}
	done      chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

// VisibilityReconcilerConfig holds tunables. Defaults are conservative;
// production can tighten the interval if outbox lag becomes an SLO.
type VisibilityReconcilerConfig struct {
	// Interval between backstop ticks. Draining is normally event-driven
	// (Kick() on enqueue), so this is only the retry/recovery cadence for
	// failed promotions and outbox rows left by a prior outage — not the
	// steady-state visibility latency. 5s is a conservative default.
	Interval time.Duration

	// BatchSize caps how many pending rows are processed per tick. Keeps
	// a single tick's wall-clock cost bounded if a burst of writes hit
	// the outbox during a DB outage and now need to drain.
	BatchSize int
}

// DefaultVisibilityReconcilerConfig returns the production defaults.
func DefaultVisibilityReconcilerConfig() VisibilityReconcilerConfig {
	return VisibilityReconcilerConfig{
		Interval:  5 * time.Second,
		BatchSize: 100,
	}
}

// NewVisibilityReconciler constructs but does not start the reconciler.
// Pass nil db to disable (no-op Start). The Start method must be called
// to begin the ticker goroutine.
func NewVisibilityReconciler(database *db.DB, cfg VisibilityReconcilerConfig) *VisibilityReconciler {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	return &VisibilityReconciler{
		db:       database,
		interval: cfg.Interval,
		batch:    cfg.BatchSize,
		kick:     make(chan struct{}, 1), // buffered+coalescing: many enqueues collapse to one pending drain
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Kick requests an immediate drain. It is non-blocking and coalescing: if a
// drain is already pending, extra kicks are dropped (the next tick sees all
// due rows anyway). Safe on a nil or db-less (disabled) reconciler. Called by
// the send path after enqueuing a pending_tx_visibility row so recipient
// visibility is materialized promptly instead of waiting for the backstop tick.
func (r *VisibilityReconciler) Kick() {
	if r == nil || r.db == nil {
		return
	}
	select {
	case r.kick <- struct{}{}:
	default: // a drain is already queued; nothing to add
	}
}

// Start spawns the ticker goroutine. Idempotent. No-op when db is nil.
func (r *VisibilityReconciler) Start(ctx context.Context) {
	if r == nil || r.db == nil {
		return
	}
	r.startOnce.Do(func() {
		go r.run(ctx)
	})
}

// Stop signals the ticker goroutine and waits for it to drain. Safe to
// call multiple times; safe to call without Start.
func (r *VisibilityReconciler) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		close(r.stop)
	})
	// Wait for the goroutine to exit if Start was called.
	select {
	case <-r.done:
	default:
		// done is only closed if run() exits; if Start was never called,
		// done is unused. Use a non-blocking check to avoid hanging
		// callers that stopped a never-started reconciler.
	}
}

func (r *VisibilityReconciler) run(ctx context.Context) {
	defer close(r.done)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// Run one tick immediately on startup so a recent shutdown doesn't
	// leave the outbox empty-then-stale for `interval` seconds.
	r.tick(ctx)

	for {
		select {
		case <-r.stop:
			return
		case <-ctx.Done():
			return
		case <-r.kick: // event-driven: send path enqueued a row (happy path)
			r.tick(ctx)
		case <-ticker.C: // backstop: retries + outage recovery
			r.tick(ctx)
		}
	}
}

// tick processes one batch of pending rows. Each row is promoted in its
// own DB transaction; one row's failure does not block the next.
func (r *VisibilityReconciler) tick(ctx context.Context) {
	rows, err := r.db.ListDuePendingTxVisibility(ctx, r.batch)
	if err != nil {
		slog.Warn("visibility reconciler: list failed", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	var promoted, failed int
	for _, row := range rows {
		if err := r.db.PromotePendingTxVisibility(ctx, row); err != nil {
			failed++
			if markErr := r.db.MarkPendingTxVisibilityFailed(ctx, row.ID, err); markErr != nil {
				slog.Warn("visibility reconciler: mark-failed update failed",
					"pending_id", row.ID, "promote_err", err, "mark_err", markErr)
			} else {
				slog.Warn("visibility reconciler: promotion failed",
					"pending_id", row.ID,
					"tx_hash", row.TxHash,
					"attempt", row.AttemptCount+1,
					"err", err)
			}
			continue
		}
		promoted++
	}

	if promoted > 0 || failed > 0 {
		slog.Debug("visibility reconciler: tick complete",
			"promoted", promoted, "failed", failed, "batch", len(rows))
	}
}
