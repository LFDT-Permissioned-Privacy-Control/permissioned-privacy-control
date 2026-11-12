// Package sealer drains the durable audit buffer (internal/audit/buffer) in
// sequence order and seals each entry into the tamper-evident chain via a
// caller-supplied SealFunc, then deletes sealed entries from the buffer.
//
// One Sealer per buffer removes the per-request chain mutex + 2 Postgres
// round-trips from the request hot path (RD-1112).
//
// Crash-safety: the resume point is the durable high-water of the sequences
// this buffer allocated (the max sealed buffer sequence already in Postgres),
// NOT in-memory state and NOT buffer membership. So a crash between the chain
// commit and the buffer delete cannot double-seal — entries at or below the
// high-water are skipped on the next drain. With allocation ranges
// (Config.RangeBase, RD-1410) the high-water is read per range, which only
// this buffer writes, so other instances sealing the same chain never move
// this buffer's resume point. A unique buffer sequence in the chain makes a
// double seal fail loudly as defense in depth.
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
	"sync/atomic"
	"time"

	"privacy-proxy/internal/audit/buffer"
)

// ErrChainAhead means the high-water of this buffer's own sequences is above
// every sequence it allocated or tried to seal: something else wrote under
// its sequences (with ranges, only an audit database restored from a backup
// hands a range out twice; without ranges, another writer on the chain), or
// the buffer was not seeded. The sealer then neither drains nor deletes,
// because entries at or below that high-water would be skipped as sealed and
// deleted unsealed.
var ErrChainAhead = errors.New("audit chain high-water is ahead of this buffer")

// Drainer is the subset of *buffer.Buffer the sealer needs.
type Drainer interface {
	Drain(afterSeq uint64, max int) ([]buffer.Entry, error)
	DeleteThrough(throughSeq uint64) error
}

// Rekeyer moves an entry to a fresh sequence of the current range
// (*buffer.Buffer).
type Rekeyer interface {
	Rekey(seq uint64) (uint64, error)
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
	// Settle, when set, runs after the chain check at the start of every tick
	// and again at its end, with the chain high-water the tick last read or
	// sealed through. On the first tick it also receives the buffer entries at
	// or below that high-water: sealed before a restart but not yet deleted,
	// so possibly never handed on. It never runs while the chain is refused
	// (ErrChainAhead) and must return promptly.
	Settle SettleFunc

	// RangeBase, when set, is the sequence just below this run's allocation
	// range (buffer.SeedRange). Entries at or below it were written by
	// earlier runs; they are worked through range by range, each from its
	// own range's sealed high-water (RangeHighWater), before any entry of
	// this run, and the high-water function then covers this run's range only.
	RangeBase uint64
	// RangeHighWater returns the highest sequence sealed in allocation range
	// index (for range 0, the sequences numbered per chain before ranges
	// existed: the chain's own), 0 if none. Required with RangeBase.
	RangeHighWater func(ctx context.Context, index uint64) (uint64, error)
	// Verify, when set, compares earlier entries with what the audit
	// database stores under their sequences (in any chain), before entries
	// at or below their range's high-water are deleted as sealed and when an
	// entry of range 0 fails to seal on its own. Range 0 was numbered per
	// chain, so instances sharing a chain shared its high-water: there an
	// entry whose sequence holds another record, or none, is moved to this
	// run's range (Rekeyer) and sealed there. In a later range another
	// record under the sequence means the range was handed out twice (a
	// restored audit database): the sealer stops (ErrChainAhead).
	Verify func(ctx context.Context, entries []buffer.Entry) ([]Verdict, error)
	// OnMove, when set, is told that an entry moved from one sequence to
	// another (so the caller drops what it tracked under the old one).
	OnMove func(from, to uint64)
	// DegradedAfter is how long the sealer may go without progress while
	// entries wait before State reports it degraded (default 1 minute):
	// reported and logged, still sealing when it can.
	DegradedAfter time.Duration
	// StallAfter is how long the sealer may go without progress while
	// entries wait before State reports it stopped (stalled; default 30
	// minutes, AUDIT_SEALING_STALL_LIMIT). The buffer is durable, so an
	// audit-database outage shorter than this loses nothing.
	StallAfter time.Duration
	// Now is the clock (tests); time.Now by default.
	Now func() time.Time
}

// Verdict is what the audit database stores under an entry's sequence.
type Verdict int

// Verdicts returned by Config.Verify.
const (
	// Sealed: the entry's own record (no record left to seal: also a
	// corrupt entry, which is never sealed).
	Sealed Verdict = iota + 1
	// Missing: nothing is stored under the sequence.
	Missing
	// Foreign: another record is stored under the sequence.
	Foreign
)

// Stop reasons reported by State.
const (
	// ReasonChainRefused: the chain holds rows in this buffer's own sequence
	// space that it never wrote; sealing stopped until restart.
	ReasonChainRefused = "chain_refused"
	// ReasonStalled: no sealing progress for StallAfter while entries wait.
	// Before that, without progress for DegradedAfter, State is Degraded.
	ReasonStalled = "stalled"
)

// State is the sealer's health, safe to read from any goroutine.
type State struct {
	Stopped bool
	Reason  string
	// Degraded: no progress for DegradedAfter while entries wait, not yet
	// stopped.
	Degraded bool
	// LastProgress is the end of the last tick that met no failure.
	LastProgress time.Time
	// Backlog approximates the entries of this run not sealed yet.
	Backlog uint64
}

// SettleFunc follows up seals whose outcome the sealer could not observe. It
// returns the lowest buffer sequence it still has to follow up (0 for none):
// the sealer then keeps that entry and every later one in the buffer, so a
// crash before the follow-up finds them again on restart. An error wrapping
// ErrChainAhead (a chain row under this buffer's sequence holds another
// writer's record) stops the sealer like a foreign high-water.
type SettleFunc func(ctx context.Context, highWater uint64, recovered []buffer.Entry) (keepFrom uint64, err error)

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
	// keepFrom is the lowest sequence Settle still follows up (0: none); the
	// buffer keeps it and everything after it.
	keepFrom uint64
	// perRecordFrom is the sequence of a record that failed alone: batches
	// starting at or before it are sealed record by record, so a record that
	// can never be stored does not burn a batch's worth of ids every tick.
	perRecordFrom uint64
	// earlierDone: the buffer held no entry at or below RangeBase at the
	// start of a tick (new entries are always above it).
	earlierDone bool
	// tickFailed: a seal failed during the current tick.
	tickFailed bool
	// loggedLevel: the State last logged (0 sealing, 1 degraded, 2 stopped).
	loggedLevel int

	// Read by State from other goroutines.
	refused       atomic.Bool
	lastProgress  atomic.Int64 // unix nanoseconds
	sealedThrough atomic.Uint64
	earlierWait   atomic.Bool
}

// New constructs a Sealer with defaults applied.
func New(buf Drainer, seal SealFunc, highWater HighWaterFunc, cfg Config) *Sealer {
	if cfg.Batch <= 0 {
		cfg.Batch = 2000
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Second
	}
	if cfg.StallAfter <= 0 {
		cfg.StallAfter = 30 * time.Minute
	}
	if cfg.DegradedAfter <= 0 || cfg.DegradedAfter > cfg.StallAfter {
		cfg.DegradedAfter = min(time.Minute, cfg.StallAfter)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Sealer{buf: buf, seal: seal, highWater: highWater, cfg: cfg, done: make(chan struct{})}
	s.lastProgress.Store(cfg.Now().UnixNano())
	s.sealedThrough.Store(cfg.RangeBase)
	s.earlierWait.Store(cfg.RangeBase > 0)
	return s
}

// State reports whether sealing has stopped: the chain was refused, or no
// tick has met no failure for StallAfter while entries wait.
func (s *Sealer) State() State {
	last := time.Unix(0, s.lastProgress.Load())
	st := State{LastProgress: last}
	if a, ok := s.buf.(interface{ AllocatedThrough() uint64 }); ok {
		if allocated, sealed := a.AllocatedThrough(), s.sealedThrough.Load(); allocated > sealed {
			st.Backlog = allocated - sealed
		}
	}
	waiting := st.Backlog > 0 || s.earlierWait.Load()
	idle := s.cfg.Now().Sub(last)
	switch {
	case s.refused.Load():
		st.Stopped, st.Reason = true, ReasonChainRefused
	case waiting && idle > s.cfg.StallAfter:
		st.Stopped, st.Reason = true, ReasonStalled
	case waiting && idle > s.cfg.DegradedAfter:
		st.Degraded = true
	}
	return st
}

// logStateChange logs the transitions of State, once each: degraded (WARN),
// stopped (ERROR) and recovered (INFO).
func (s *Sealer) logStateChange() {
	st := s.State()
	level := 0
	switch {
	case st.Stopped:
		level = 2
	case st.Degraded:
		level = 1
	}
	prev := s.loggedLevel
	s.loggedLevel = level
	switch {
	case level == prev:
	case level == 2:
		slog.Error("audit sealing stopped: the instance reports not ready; entries stay in the buffer", "reason", st.Reason, "last_progress", st.LastProgress, "backlog", st.Backlog)
	case level == 1:
		slog.Warn("audit sealing degraded: no entry reached the audit database recently; entries stay in the buffer", "last_progress", st.LastProgress, "backlog", st.Backlog, "not_ready_after", s.cfg.StallAfter)
	default:
		slog.Info("audit sealing recovered")
	}
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
		if ctx.Err() != nil {
			return
		}
		if _, err := s.Tick(ctx); err != nil && ctx.Err() == nil {
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
func (s *Sealer) Tick(ctx context.Context) (sealed int, err error) {
	s.tickFailed = false
	defer func() {
		if err == nil && !s.tickFailed {
			s.lastProgress.Store(s.cfg.Now().UnixNano())
		}
		s.logStateChange()
	}()
	if err := s.Seed(ctx); err != nil {
		return 0, err
	}
	if s.ahead != nil {
		return 0, s.ahead
	}
	if s.cfg.RangeBase > 0 && !s.earlierDone {
		n, done, err := s.sealEarlier(ctx)
		if err != nil || !done {
			return n, err
		}
		sealed = n
	}
	hw, err := s.highWater(ctx)
	if err != nil {
		return sealed, err
	}
	hw = max(hw, s.cfg.RangeBase)
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
		s.refused.Store(true)
		slog.Error("audit sealer stopped: rows are stored under this buffer's own sequences that it never wrote; its own entries are kept in the buffer", "error", s.ahead)
		return sealed, s.ahead
	}
	first := !s.started
	s.started = true
	s.attempted = max(s.attempted, hw)
	if s.cfg.Settle != nil {
		var recovered []buffer.Entry
		if first {
			recovered = s.recovered(hw)
		}
		if err := s.settle(ctx, hw, recovered); err != nil {
			return sealed, err
		}
	}
	for ctx.Err() == nil {
		entries, err := s.buf.Drain(hw, s.cfg.Batch)
		if err != nil {
			return sealed, err
		}
		n, last, failed := s.sealBatch(ctx, entries)
		sealed += n
		if n > 0 {
			s.progressed()
		}
		// Clean up the buffer through the durable high-water OR what we just
		// sealed, whichever is greater. Deleting through hw reclaims any orphans
		// left by a prior crash between the chain commit and the buffer delete
		// (those entries are already in Postgres and skipped by Drain, so
		// they'd otherwise leak). Buffer cleanup is safe to lag or fail: the
		// Postgres high-water, not buffer membership, is the source of truth
		// for what's sealed.
		hw = max(hw, last)
		s.sealedThrough.Store(hw)
		through := hw
		if s.keepFrom > 0 && s.keepFrom <= through {
			through = s.keepFrom - 1 // still being followed up by Settle
		}
		if through > 0 {
			if err := s.buf.DeleteThrough(through); err != nil {
				slog.Warn("audit buffer delete-through failed (not a loss; retried next tick)",
					"through", through, "error", err)
			}
		}
		if failed || len(entries) < s.cfg.Batch {
			break
		}
	}
	if s.cfg.Settle != nil {
		if err := s.settle(ctx, hw, nil); err != nil {
			return sealed, err
		}
	}
	return sealed, nil
}

// settle runs the Settle hook, records what it still follows up, and turns a
// foreign record under this buffer's sequence into the sticky refusal.
func (s *Sealer) settle(ctx context.Context, hw uint64, recovered []buffer.Entry) error {
	keep, err := s.cfg.Settle(ctx, hw, recovered)
	s.keepFrom = keep
	if errors.Is(err, ErrChainAhead) {
		s.ahead = err
		s.refused.Store(true)
		slog.Error("audit sealer stopped: the chain holds another record under this buffer's sequence; its own entries are kept in the buffer", "error", err)
		return err
	}
	return nil
}

// sealEarlier works through the entries of earlier runs (at or below
// RangeBase), lowest first. Each allocation range was written by one buffer,
// this one, in sequence order, so the range's sealed high-water separates its
// sealed entries (deleted, after Settle saw them) from its unsealed ones
// (sealed now, in order), whatever other instances wrote elsewhere in the
// chain. It reports done once no earlier entry is left; only then may the
// current range's cleanup run, because DeleteThrough removes everything below
// the sequence it is given.
func (s *Sealer) sealEarlier(ctx context.Context) (int, bool, error) {
	sealed := 0
	for ctx.Err() == nil {
		head, err := s.buf.Drain(0, 1)
		if err != nil {
			return sealed, false, err
		}
		if len(head) == 0 || head[0].Seq > s.cfg.RangeBase {
			s.earlierDone = true
			s.earlierWait.Store(false)
			return sealed, true, nil
		}
		first := head[0].Seq
		index := first >> buffer.RangeShift
		end := min((index+1)<<buffer.RangeShift-1, s.cfg.RangeBase)
		hw, err := s.cfg.RangeHighWater(ctx, index)
		if err != nil {
			return sealed, false, err
		}
		if hw >= first {
			// At or below the range's high-water: sealed by an earlier run and
			// not yet deleted (a crash between its commit and its delete),
			// unless Verify says otherwise.
			deleted, err := s.settleEarlier(ctx, first, min(hw, end), hw, index)
			if err != nil || !deleted {
				if err == nil {
					s.tickFailed = true // Settle still follows them up: no progress
				}
				return sealed, false, err
			}
			s.progressed()
			continue
		}
		entries, err := s.buf.Drain(first-1, s.cfg.Batch)
		if err != nil {
			return sealed, false, err
		}
		for i, e := range entries {
			if e.Seq > end {
				entries = entries[:i]
				break
			}
		}
		if index == 0 && s.cfg.Verify != nil {
			// Range 0 above the chain's own high-water: other chains may
			// hold these sequences (old per-chain numbering), and a renamed
			// chain may hold these very records. Settle that before sealing,
			// so a collision does not fail the batch one entry per tick.
			changed, hold, err := s.sortLegacy(ctx, entries)
			if err != nil || hold {
				return sealed, false, err
			}
			if changed {
				s.progressed()
				continue
			}
		}
		n, last, failed := s.sealBatch(ctx, entries)
		sealed += n
		if last > 0 {
			// Every entry at or below last is sealed: lower ranges are gone
			// and this one was sealed in order from first.
			if err := s.buf.DeleteThrough(last); err != nil {
				return sealed, false, err
			}
			s.progressed()
		}
		if failed {
			return sealed, false, s.locateFailed(ctx, index)
		}
	}
	return sealed, false, ctx.Err()
}

// settleEarlier handles one batch of earlier entries in [first, through], at
// or below their range's high-water hw: Verify classifies them, moved and
// sealed entries are dealt with, Settle sees the sealed ones, and the batch
// is deleted (as far as Settle allows). It reports whether anything was
// deleted.
func (s *Sealer) settleEarlier(ctx context.Context, first, through, hw, index uint64) (bool, error) {
	entries, err := s.buf.Drain(first-1, s.cfg.Batch)
	if err != nil {
		return false, err
	}
	for i, e := range entries {
		if e.Seq > through {
			entries = entries[:i]
			break
		}
	}
	if len(entries) == 0 {
		return false, nil
	}
	through = entries[len(entries)-1].Seq
	recovered := entries
	if s.cfg.Verify != nil {
		verdicts, err := s.cfg.Verify(ctx, entries)
		if err != nil {
			return false, err
		}
		recovered = make([]buffer.Entry, 0, len(entries))
		for i, e := range entries {
			switch v := verdicts[i]; {
			case v == Sealed:
				recovered = append(recovered, e)
			case index == 0:
				// Numbered per chain before ranges: another instance sealed
				// this chain past it, so the high-water says nothing about it.
				if err := s.move(e.Seq, "its sequence is below a shared chain's high-water but holds another record or none"); err != nil {
					return false, err
				}
			case v == Foreign:
				s.ahead = fmt.Errorf("%w: buffer sequence %d of an earlier run holds another record", ErrChainAhead, e.Seq)
				s.refused.Store(true)
				slog.Error("audit sealer stopped: an allocation range of an earlier run holds another writer's records (was the audit database restored?); its own entries are kept in the buffer", "error", s.ahead)
				return false, s.ahead
			}
			// Missing in a range of its own: sealed and pruned since, or a
			// corrupt entry that is never sealed.
		}
	}
	if s.cfg.Settle != nil {
		if err := s.settle(ctx, hw, recovered); err != nil {
			return false, err
		}
		if s.keepFrom > 0 && s.keepFrom <= through {
			through = s.keepFrom - 1
		}
	}
	if through < first {
		return false, nil
	}
	return true, s.buf.DeleteThrough(through)
}

// sortLegacy classifies a batch of range-0 entries above their chain's
// high-water before it is sealed: entries whose sequence holds another
// record move to this run's range, and a leading run of entries that hold
// their own record (sealed under an earlier chain name) is settled and
// deleted. It reports whether it changed the buffer (the caller drains
// again), or whether Settle holds own records back (the tick ends); otherwise
// the batch starts with an unsealed entry and is sealed.
func (s *Sealer) sortLegacy(ctx context.Context, entries []buffer.Entry) (changed, hold bool, err error) {
	verdicts, err := s.cfg.Verify(ctx, entries)
	if err != nil {
		return false, false, err
	}
	for i, e := range entries {
		if verdicts[i] == Foreign {
			if err := s.move(e.Seq, "another chain's record holds its sequence"); err != nil {
				return changed, false, err
			}
			changed = true
		}
	}
	// Own records at the head of the batch: everything below them is gone,
	// so they can be deleted once Settle has seen them.
	var head []buffer.Entry
	for i, e := range entries {
		if verdicts[i] == Foreign {
			continue
		}
		if verdicts[i] != Sealed {
			break
		}
		head = append(head, e)
	}
	if len(head) > 0 {
		deleted, err := s.deleteOwn(ctx, head)
		if err != nil {
			return changed, false, err
		}
		if !deleted {
			s.tickFailed = true // Settle still follows them up: no progress
			return changed, true, nil
		}
		changed = true
	}
	return changed, false, nil
}

// deleteOwn deletes earlier entries found sealed (the lowest in the buffer),
// after Settle has seen them; it reports whether it deleted any.
func (s *Sealer) deleteOwn(ctx context.Context, own []buffer.Entry) (bool, error) {
	through := own[len(own)-1].Seq
	if s.cfg.Settle != nil {
		if err := s.settle(ctx, through, own); err != nil {
			return false, err
		}
		if s.keepFrom > 0 && s.keepFrom <= through {
			through = s.keepFrom - 1
		}
	}
	if through < own[0].Seq {
		return false, nil
	}
	return true, s.buf.DeleteThrough(through)
}

// locateFailed handles the earlier entry of range 0 that just failed to seal
// on its own: when its sequence holds another chain's record it moves to this
// run's range; when it holds its own record (sealed under an earlier chain
// name) it is deleted.
func (s *Sealer) locateFailed(ctx context.Context, index uint64) error {
	seq := s.perRecordFrom
	if s.cfg.Verify == nil || index != 0 || seq == 0 {
		return nil
	}
	entries, err := s.buf.Drain(seq-1, 1)
	if err != nil || len(entries) == 0 || entries[0].Seq != seq {
		return err
	}
	verdicts, err := s.cfg.Verify(ctx, entries)
	if err != nil {
		return err
	}
	switch verdicts[0] {
	case Sealed:
		// The lowest entry: everything below it is gone already.
		_, err := s.deleteOwn(ctx, entries)
		return err
	case Foreign:
		return s.move(seq, "another chain's record holds its sequence")
	}
	return nil
}

// move moves an earlier entry to this run's range (Rekeyer).
func (s *Sealer) move(seq uint64, why string) error {
	rekeyer, ok := s.buf.(Rekeyer)
	if !ok {
		return fmt.Errorf("audit sealer: entry %d must move (%s) but the buffer cannot rekey", seq, why)
	}
	moved, err := rekeyer.Rekey(seq)
	if err != nil {
		return err
	}
	if s.cfg.OnMove != nil {
		s.cfg.OnMove(seq, moved)
	}
	slog.Warn("audit sealer: an entry numbered before allocation ranges moved to this run's range", "seq", seq, "moved_to", moved, "reason", why)
	return nil
}

// progressed records sealing progress (a batch sealed or settled).
func (s *Sealer) progressed() {
	s.lastProgress.Store(s.cfg.Now().UnixNano())
}

// recovered returns the buffer entries at or below hw. It runs before the
// first DeleteThrough, which removes them.
func (s *Sealer) recovered(hw uint64) []buffer.Entry {
	var out []buffer.Entry
	var after uint64
	for {
		entries, err := s.buf.Drain(after, s.cfg.Batch)
		if err != nil {
			slog.Error("audit sealer: could not read sealed entries back from the buffer for SIEM follow-up", "error", err)
			return out
		}
		if len(entries) == 0 {
			return out
		}
		for _, e := range entries {
			if e.Seq > hw {
				return out
			}
			out = append(out, e)
		}
		after = entries[len(entries)-1].Seq
		if len(entries) < s.cfg.Batch {
			return out
		}
	}
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
			s.tickFailed = true
			return i, last, true
		}
		last = e.Seq
	}
	return len(entries), last, false
}
