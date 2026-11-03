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
//
// Throughput (RD-1410): a tick drains the whole backlog, batch
// after batch, and a configured SealBatch writes each batch at once; a failed
// batch falls back to per-record sealing for that batch, so failure semantics
// (seal everything before a failing entry, stop there) are unchanged.
package sealer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/audit/buffer"
)

// ErrChainAhead means the sealed chain's high-water is above every sequence
// this buffer ever allocated: another writer shares the chain (two instances
// with one chain name) or the buffer was not seeded. The sealer then neither
// drains nor deletes, because entries at or below that high-water would be
// skipped as sealed and deleted unsealed.
var ErrChainAhead = errors.New("audit chain high-water is ahead of this buffer")

// Drainer is the subset of *buffer.Buffer the sealer needs.
type Drainer interface {
	Drain(afterSeq uint64, max int) ([]buffer.Entry, error)
	DeleteThrough(throughSeq uint64) error
}

// Seeder is implemented by buffers whose allocator is seeded from the chain
// (*buffer.Buffer).
type Seeder interface {
	SeedFloor(floor uint64) error
	Seeded() bool
	AllocatedThrough() uint64
}

// BatchSealFunc persists a whole batch into the chain atomically, in order:
// either every entry is sealed or none is.
type BatchSealFunc func(ctx context.Context, entries []buffer.Entry) error

// SealFunc persists one buffered record into the durable chain, idempotently
// keyed by seq. Returning an error stops the current batch; the entry (and the
// rest of the batch) is retried on the next tick.
type SealFunc func(ctx context.Context, seq uint64, data []byte) error

// HighWaterFunc returns the highest buffer sequence already durably sealed in
// the chain (0 if none) — the crash-safe resume point.
type HighWaterFunc func(ctx context.Context) (uint64, error)

// Config tunes the seal loop.
type Config struct {
	Batch    int           // max entries per batch (default 2000); a tick drains batch after batch
	Interval time.Duration // delay between ticks once the buffer is drained (default 1s)
	// SealBatch, when set, writes each batch at once; SealFunc remains the
	// per-record fallback for a batch that fails.
	SealBatch BatchSealFunc
}

// Sealer drains a buffer into a chain via SealFunc.
type Sealer struct {
	buf       Drainer
	seal      SealFunc
	highWater HighWaterFunc
	cfg       Config
	done      chan struct{} // closed when Run returns

	// Run's goroutine owns the fields below (Tick is not concurrent).
	started   bool   // the first tick checked the chain against the buffer
	attempted uint64 // highest sequence this sealer seeded or tried to seal
	ahead     error  // sticky: another writer was seen on the chain
	// perRecordFrom is the sequence of a record that failed alone: batches
	// starting at or before it are sealed record by record, so a record that
	// can never be stored does not burn a batch's worth of ids every tick.
	perRecordFrom uint64
}

// New constructs a Sealer with defaults applied.
func New(buf Drainer, seal SealFunc, highWater HighWaterFunc, cfg Config) *Sealer {
	if cfg.Batch <= 0 {
		cfg.Batch = 2000
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

// Seed raises a seeded buffer's allocation floor to the chain's high-water,
// so a drained-and-reopened or recreated buffer never reuses a sequence the
// chain already sealed. It is a no-op for buffers that do not seed.
func (s *Sealer) Seed(ctx context.Context) error {
	seeder, ok := s.buf.(Seeder)
	if !ok || seeder.Seeded() {
		return nil
	}
	hw, err := s.highWater(ctx)
	if err != nil {
		return fmt.Errorf("audit buffer seed: %w", err)
	}
	return seeder.SeedFloor(hw)
}

// Tick drains the buffer batch by batch until it is empty, a seal fails or
// ctx ends, and returns the number of entries sealed. Crash-safe: it resumes
// from the chain high-water, so already-sealed entries are never re-sealed
// even if a previous run died before deleting them from the buffer.
func (s *Sealer) Tick(ctx context.Context) (int, error) {
	if err := s.Seed(ctx); err != nil {
		return 0, err
	}
	if s.ahead != nil {
		return 0, s.ahead
	}
	hw, err := s.highWater(ctx)
	if err != nil {
		return 0, err
	}
	// The chain may only hold what this sealer sealed: at the first tick
	// nothing above what the buffer allocated (its floor came from the chain),
	// afterwards nothing above what this sealer itself tried to seal. Anything
	// more is another writer on the chain, and draining from its high-water
	// would skip and delete this buffer's own unsealed entries. The refusal
	// holds until restart.
	limit := s.attempted
	if !s.started {
		if seeder, ok := s.buf.(Seeder); ok {
			limit = seeder.AllocatedThrough()
		} else {
			limit = hw
		}
	}
	if hw > limit {
		s.ahead = fmt.Errorf("%w: chain high-water %d, this sealer accounts for %d", ErrChainAhead, hw, limit)
		slog.Error("audit sealer stopped: another writer is sealing this chain; its own entries are kept in the buffer", "error", s.ahead)
		return 0, s.ahead
	}
	s.started = true
	s.attempted = max(s.attempted, hw)
	sealed := 0
	for ctx.Err() == nil {
		entries, err := s.buf.Drain(hw, s.cfg.Batch)
		if err != nil {
			return sealed, err
		}
		n, last, failed := s.sealBatch(ctx, entries)
		sealed += n
		// Clean up the buffer through the durable high-water OR what we just
		// sealed, whichever is greater. Deleting through hw reclaims any orphans
		// left by a prior crash between the chain commit and the buffer delete
		// (those entries are already in Postgres and skipped by Drain, so
		// they'd otherwise leak). Buffer cleanup is safe to lag or fail: the
		// Postgres high-water, not buffer membership, is the source of truth
		// for what's sealed.
		hw = max(hw, last)
		if hw > 0 {
			if err := s.buf.DeleteThrough(hw); err != nil {
				slog.Warn("audit buffer delete-through failed (not a loss; retried next tick)",
					"through", hw, "error", err)
			}
		}
		if failed || len(entries) < s.cfg.Batch {
			break
		}
	}
	return sealed, nil
}

// sealBatch seals entries in order: at once through SealBatch when set,
// otherwise (or when the batch write fails) one by one, stopping at the first
// failure without advancing past it (preserves chain order). It returns how
// many were sealed, the last sealed sequence and whether a seal failed.
func (s *Sealer) sealBatch(ctx context.Context, entries []buffer.Entry) (int, uint64, bool) {
	if len(entries) == 0 {
		return 0, 0, false
	}
	if s.cfg.SealBatch != nil && entries[0].Seq > s.perRecordFrom {
		s.attempted = max(s.attempted, entries[len(entries)-1].Seq)
		err := s.cfg.SealBatch(ctx, entries)
		if err == nil {
			return len(entries), entries[len(entries)-1].Seq, false
		}
		slog.Error("audit batch seal failed; sealing that batch record by record", "first_seq", entries[0].Seq, "count", len(entries), "error", err)
	}
	var last uint64
	for i, e := range entries {
		s.attempted = max(s.attempted, e.Seq)
		if err := s.seal(ctx, e.Seq, e.Data); err != nil {
			slog.Error("audit seal failed; will retry", "seq", e.Seq, "error", err)
			s.perRecordFrom = e.Seq
			return i, last, true
		}
		last = e.Seq
	}
	return len(entries), last, false
}
