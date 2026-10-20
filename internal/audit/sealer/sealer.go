// Package sealer drains the durable audit buffer (internal/audit/buffer) in
// sequence order and seals each entry into the tamper-evident chain via a
// caller-supplied SealFunc, then deletes sealed entries from the buffer.
//
// A single Sealer is the only writer of its chain — this is what removes the
// per-request chain mutex + 2 Postgres round-trips from the request hot path
// (RD-1112) and avoids the multi-writer chain fork.
//
// Crash-safety: the resume point is the chain's durable high-water (the max
// sealed buffer sequence already in Postgres), NOT in-memory state and NOT
// buffer membership. So a crash between the chain commit and the buffer delete
// cannot double-seal — entries at or below the high-water are skipped on the
// next drain. SealFunc must additionally be idempotent on the sequence (e.g.
// INSERT ... ON CONFLICT (buffer_seq) DO NOTHING) as defense in depth.
package sealer

import (
	"context"
	"log/slog"
	"time"

	"privacy-proxy/internal/audit/buffer"
)

// Drainer is the subset of *buffer.Buffer the sealer needs.
type Drainer interface {
	Drain(afterSeq uint64, max int) ([]buffer.Entry, error)
	DeleteThrough(throughSeq uint64) error
}

// SealFunc persists one buffered record into the durable chain, idempotently
// keyed by seq. Returning an error stops the current batch; the entry (and the
// rest of the batch) is retried on the next tick.
type SealFunc func(ctx context.Context, seq uint64, data []byte) error

// HighWaterFunc returns the highest buffer sequence already durably sealed in
// the chain (0 if none) — the crash-safe resume point.
type HighWaterFunc func(ctx context.Context) (uint64, error)

// Config tunes the seal loop.
type Config struct {
	Batch    int           // max entries sealed per tick (default 500)
	Interval time.Duration // delay between ticks (default 1s)
}

// Sealer drains a buffer into a chain via SealFunc.
type Sealer struct {
	buf       Drainer
	seal      SealFunc
	highWater HighWaterFunc
	cfg       Config
	done      chan struct{} // closed when Run returns
}

// New constructs a Sealer with defaults applied.
func New(buf Drainer, seal SealFunc, highWater HighWaterFunc, cfg Config) *Sealer {
	if cfg.Batch <= 0 {
		cfg.Batch = 500
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}
	return &Sealer{buf: buf, seal: seal, highWater: highWater, cfg: cfg, done: make(chan struct{})}
}

// Wait blocks until Run has returned (after ctx cancellation), so the caller
// can safely close the buffer without racing an in-flight tick.
func (s *Sealer) Wait() { <-s.done }

// Run drives the seal loop until ctx is cancelled (sealing once immediately).
func (s *Sealer) Run(ctx context.Context) {
	defer close(s.done)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		if _, err := s.Tick(ctx); err != nil {
			slog.Error("audit sealer tick failed (will retry next tick)", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Tick seals one batch and returns the number of entries sealed. Crash-safe:
// it resumes from the chain high-water, so already-sealed entries are never
// re-sealed even if a previous run died before deleting them from the buffer.
func (s *Sealer) Tick(ctx context.Context) (int, error) {
	hw, err := s.highWater(ctx)
	if err != nil {
		return 0, err
	}
	entries, err := s.buf.Drain(hw, s.cfg.Batch)
	if err != nil {
		return 0, err
	}

	var lastSealed uint64
	sealed := 0
	for _, e := range entries {
		if err := s.seal(ctx, e.Seq, e.Data); err != nil {
			// Stop the batch; the failed entry and the rest are retried next
			// tick. Do NOT advance past it (preserves chain order).
			slog.Error("audit seal failed; will retry", "seq", e.Seq, "error", err)
			break
		}
		lastSealed = e.Seq
		sealed++
	}

	// Clean up the buffer through the durable high-water OR what we just sealed,
	// whichever is greater. Deleting through hw reclaims any orphans left by a
	// prior crash between the chain commit and the buffer delete (those entries
	// are already in Postgres and skipped by Drain, so they'd otherwise leak).
	// Buffer cleanup is safe to lag or fail: the Postgres high-water, not buffer
	// membership, is the source of truth for what's sealed.
	cleanThrough := hw
	if lastSealed > cleanThrough {
		cleanThrough = lastSealed
	}
	if cleanThrough > 0 {
		if err := s.buf.DeleteThrough(cleanThrough); err != nil {
			slog.Warn("audit buffer delete-through failed (not a loss; retried next tick)",
				"through", cleanThrough, "error", err)
		}
	}
	return sealed, nil
}
