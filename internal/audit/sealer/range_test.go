package sealer

import (
	"context"
	"errors"
	"testing"
	"time"

	"privacy-proxy/internal/audit/buffer"
)

const rangeWidth = uint64(1) << buffer.RangeShift

// rangeRecorder is a mock chain shared by every instance: it records sealed
// sequences and answers per-range high-waters, as access_logs does.
type rangeRecorder struct {
	recorder
	// stored overrides what the database holds under a sequence; otherwise a
	// sealed sequence holds the entry's own record and any other none.
	stored map[uint64]Verdict
}

func (r *rangeRecorder) rangeHighWater(_ context.Context, index uint64) (uint64, error) {
	var hw uint64
	for _, s := range r.sealed {
		if s>>buffer.RangeShift == index && s > hw {
			hw = s
		}
	}
	return hw, nil
}

func (r *rangeRecorder) verify(_ context.Context, entries []buffer.Entry) ([]Verdict, error) {
	out := make([]Verdict, len(entries))
	for i, e := range entries {
		out[i] = Missing
		if v, ok := r.stored[e.Seq]; ok {
			out[i] = v
			continue
		}
		for _, s := range r.sealed {
			if s == e.Seq {
				out[i] = Sealed
			}
		}
	}
	return out, nil
}

// layeredBuffer builds a buffer holding entries of three runs: legacy
// (range 0) 1..4, range 1 (base+1..base+3), and the current run in range 2.
func layeredBuffer(t *testing.T) (*buffer.Buffer, uint64) {
	t.Helper()
	dir := t.TempDir()
	b, err := buffer.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 4)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = buffer.Open(dir, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SeedRange(rangeWidth, 2*rangeWidth-1); err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 3)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = buffer.Open(dir, buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SeedRange(2*rangeWidth, 3*rangeWidth-1); err != nil {
		t.Fatal(err)
	}
	appendN(t, b, 2)
	t.Cleanup(func() { _ = b.Close() })
	return b, 2 * rangeWidth
}

func appendN(t *testing.T, b *buffer.Buffer, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := b.Append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
}

func rangedSealer(b *buffer.Buffer, rec *rangeRecorder, base uint64, cfg Config) *Sealer {
	cfg.RangeBase = base
	cfg.RangeHighWater = rec.rangeHighWater
	cfg.Verify = rec.verify
	current := func(ctx context.Context) (uint64, error) { return rec.rangeHighWater(ctx, base>>buffer.RangeShift) }
	return New(b, rec.seal, current, cfg)
}

// Review findings 1 and 2: entries of earlier runs resume from their own
// range's high-water (the chain may hold anything else, written by other
// instances), are sealed before this run's entries, and nothing is sealed
// twice or lost.
func TestEarlierRunsResumeFromTheirOwnRange(t *testing.T) {
	b, base := layeredBuffer(t)
	// Sealed before: legacy 1..2 and range 1's first entry, plus rows of
	// other instances in higher ranges (the chain-wide high-water is far
	// above everything this buffer holds).
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2, rangeWidth + 1, 5*rangeWidth + 7}}}
	s := rangedSealer(b, rec, base, Config{})
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []uint64{1, 2, rangeWidth + 1, 5*rangeWidth + 7, 3, 4, rangeWidth + 2, rangeWidth + 3, base + 1, base + 2}
	if len(rec.sealed) != len(want) {
		t.Fatalf("sealed %v, want %v", rec.sealed, want)
	}
	for i := range want {
		if rec.sealed[i] != want[i] {
			t.Fatalf("sealed %v, want %v", rec.sealed, want)
		}
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d entries left", pending)
	}
}

// Critic finding 1: an earlier entry that cannot be sealed yet is never
// deleted by the cleanup of this run's range, and holds this run's entries
// back (chain order).
func TestUnsealedEarlierEntrySurvivesCurrentRangeCleanup(t *testing.T) {
	b, base := layeredBuffer(t)
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2, 3, 4}, failAt: rangeWidth + 2}}
	s := rangedSealer(b, rec, base, Config{})
	for i := 0; i < 3; i++ {
		if _, err := s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending, _ := b.PendingCount(); pending != 4 {
		t.Fatalf("%d entries left, want range 1's last two and this run's two", pending)
	}
	rec.failAt = 0
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []uint64{1, 2, 3, 4, rangeWidth + 1, rangeWidth + 2, rangeWidth + 3, base + 1, base + 2}
	if len(rec.sealed) != len(want) || rec.sealed[len(rec.sealed)-1] != base+2 {
		t.Fatalf("sealed %v, want %v", rec.sealed, want)
	}
}

// Finding 2's wedge, left by the old per-chain numbering: a legacy entry
// whose sequence another chain's row holds is moved into this run's range and
// sealed there instead of failing forever.
func TestDisplacedLegacyEntryMovesIntoTheCurrentRange(t *testing.T) {
	b, base := layeredBuffer(t)
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2, rangeWidth + 3}, failAt: 3}, stored: map[uint64]Verdict{3: Foreign}}
	s := rangedSealer(b, rec, base, Config{})
	for i := 0; i < 3; i++ {
		if _, err := s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d entries left", pending)
	}
	if last := rec.sealed[len(rec.sealed)-1]; last != base+3 {
		t.Fatalf("sealed %v: the displaced entry should be sealed last, as %d", rec.sealed, base+3)
	}
}

// Finding 6: a refused chain stops sealing at once; no progress for longer
// than the stall bound while entries wait reads as stalled; both are visible
// through State, and recovery clears a stall.
func TestStateReportsRefusalAndStall(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	clock := func() time.Time { return now }
	b := newBuf(t, 2)
	defer b.Close()
	down := errors.New("audit database unreachable")
	rec := &recorder{}
	var fail error
	hw := func(ctx context.Context) (uint64, error) {
		if fail != nil {
			return 0, fail
		}
		return rec.highWater(ctx)
	}
	s := New(b, rec.seal, hw, Config{StallAfter: time.Minute, Now: clock})
	if st := s.State(); st.Stopped {
		t.Fatalf("a new sealer reads as stopped: %+v", st)
	}
	fail = down
	_, _ = s.Tick(context.Background())
	now = now.Add(2 * time.Minute)
	if st := s.State(); !st.Stopped || st.Reason != ReasonStalled {
		t.Fatalf("no progress for two minutes with entries waiting: %+v", st)
	}
	fail = nil
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := s.State(); st.Stopped {
		t.Fatalf("after recovery: %+v", st)
	}
	rec.sealed = append(rec.sealed, 50) // a row in this buffer's space it never wrote
	_, _ = s.Tick(context.Background())
	if st := s.State(); !st.Stopped || st.Reason != ReasonChainRefused {
		t.Fatalf("refused chain: %+v", st)
	}
}

// Review of the fix, finding 1: range 0 was numbered per chain, so a shared
// chain's high-water says nothing about this buffer's legacy entries. Entries
// below it that hold another record, or none, are moved and sealed; only its
// own records are deleted as sealed. No SIEM is involved.
func TestLegacyEntriesBelowASharedChainsHighWaterAreSealed(t *testing.T) {
	b, base := layeredBuffer(t)
	// Another instance sealed legacy 1..10 on the shared chain; of this
	// buffer's legacy entries only 2 is its own record there.
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}}, stored: map[uint64]Verdict{1: Foreign, 3: Foreign, 4: Missing}}
	s := rangedSealer(b, rec, base, Config{})
	for i := 0; i < 3; i++ {
		if _, err := s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d entries left", pending)
	}
	// 1, 3 and 4 moved to this run's range after its two own entries.
	var moved int
	for _, seq := range rec.sealed[10:] {
		if seq > base+2 {
			moved++
		}
	}
	if moved != 3 {
		t.Fatalf("sealed %v: want the three displaced legacy entries sealed in this run's range", rec.sealed)
	}
}

// Finding 2 of the fix review: in a range of its own, another record under an
// earlier entry's sequence (a range handed out twice after a restore) stops
// sealing and deletes nothing.
func TestForeignRecordInAnEarlierRangeStopsSealing(t *testing.T) {
	b, base := layeredBuffer(t)
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2, 3, 4, rangeWidth + 1, rangeWidth + 2, rangeWidth + 3}}, stored: map[uint64]Verdict{rangeWidth + 2: Foreign}}
	s := rangedSealer(b, rec, base, Config{})
	if _, err := s.Tick(context.Background()); !errors.Is(err, ErrChainAhead) {
		t.Fatalf("tick: %v, want ErrChainAhead", err)
	}
	if pending, _ := b.PendingCount(); pending != 5 {
		t.Fatalf("%d entries left, want range 1's three and this run's two", pending)
	}
	if st := s.State(); !st.Stopped || st.Reason != ReasonChainRefused {
		t.Fatalf("state %+v", st)
	}
}

// Finding 3 of the fix review: a long tick that keeps sealing is progress,
// not a stall.
func TestLongDrainingTickIsNotAStall(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	b := newBufConcurrent(t, 50)
	defer b.Close()
	rec := &recorder{}
	var s *Sealer
	var stalledDuringTick bool
	seal := func(ctx context.Context, seq uint64, data []byte) error {
		now = now.Add(40 * time.Second)
		if s.State().Stopped {
			stalledDuringTick = true
		}
		return rec.seal(ctx, seq, data)
	}
	s = New(b, seal, rec.highWater, Config{Batch: 1, StallAfter: time.Minute, Now: func() time.Time { return now }})
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if stalledDuringTick || len(rec.sealed) != 50 {
		t.Fatalf("stalled while sealing: %v, sealed %d", stalledDuringTick, len(rec.sealed))
	}
}

// Finding 4 of the fix review: earlier entries Settle keeps back (its read
// fails) are no progress, so a lasting failure reads as a stall.
func TestEarlierEntriesHeldBySettleAreNoProgress(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	b, base := layeredBuffer(t)
	rec := &rangeRecorder{recorder: recorder{sealed: []uint64{1, 2}}}
	hold := func(context.Context, uint64, []buffer.Entry) (uint64, error) { return 1, nil }
	s := rangedSealer(b, rec, base, Config{Settle: hold, StallAfter: time.Minute, Now: func() time.Time { return now }})
	for i := 0; i < 3; i++ {
		if _, err := s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Minute)
	}
	if st := s.State(); !st.Stopped || st.Reason != ReasonStalled {
		t.Fatalf("held earlier entries for three minutes: %+v", st)
	}
	if pending, _ := b.PendingCount(); pending != 9 {
		t.Fatalf("%d entries left, want all 9 kept", pending)
	}
}

// Fix re-review, finding A: a whole backlog of legacy entries that collide
// with another chain's rows moves in one tick, before any of it is tried
// (one failing batch per entry and tick would hold the current range back).
func TestCollidingLegacyBacklogMovesInOneTick(t *testing.T) {
	b, base := layeredBuffer(t)
	rec := &rangeRecorder{stored: map[uint64]Verdict{1: Foreign, 2: Foreign, 3: Foreign, 4: Foreign}}
	var moves [][2]uint64
	s := rangedSealer(b, rec, base, Config{OnMove: func(from, to uint64) { moves = append(moves, [2]uint64{from, to}) }})
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d entries left after one tick", pending)
	}
	if len(moves) != 4 || moves[0][0] != 1 || moves[3][1] != base+6 {
		t.Fatalf("moves %v", moves)
	}
	for _, seq := range rec.sealed {
		if seq < rangeWidth {
			t.Fatalf("sealed %v: a colliding legacy sequence was sealed", rec.sealed)
		}
	}
}
