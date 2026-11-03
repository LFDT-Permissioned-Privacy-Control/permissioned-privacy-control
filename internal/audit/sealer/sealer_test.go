package sealer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"privacy-proxy/internal/audit/buffer"
)

// recorder is a mock chain: it records sealed sequences in order and reports
// its own high-water, mimicking the Postgres max(buffer_seq) resume point.
type recorder struct {
	sealed []uint64
	failAt uint64 // if non-zero, seal(seq==failAt) errors
}

func (r *recorder) seal(_ context.Context, seq uint64, _ []byte) error {
	if r.failAt != 0 && seq == r.failAt {
		return errors.New("simulated chain write failure")
	}
	r.sealed = append(r.sealed, seq)
	return nil
}

func (r *recorder) highWater(_ context.Context) (uint64, error) {
	var max uint64
	for _, s := range r.sealed {
		if s > max {
			max = s
		}
	}
	return max, nil
}

func newBuf(t *testing.T, n int) *buffer.Buffer {
	t.Helper()
	b, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	for i := 1; i <= n; i++ {
		if _, err := b.Append([]byte(fmt.Sprintf("rec-%d", i))); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	return b
}

// newBufConcurrent appends n entries from many goroutines, so Pebble group
// commit keeps a large backlog quick to build (each synced append alone costs
// a full fsync on macOS).
func newBufConcurrent(t *testing.T, n int) *buffer.Buffer {
	t.Helper()
	b, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	var wg sync.WaitGroup
	work := make(chan int, n)
	for i := 1; i <= n; i++ {
		work <- i
	}
	close(work)
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if _, err := b.Append([]byte(fmt.Sprintf("rec-%d", i))); err != nil {
					t.Errorf("append: %v", err)
				}
			}
		}()
	}
	wg.Wait()
	return b
}

func TestSealerSealsAllInOrder(t *testing.T) {
	b := newBuf(t, 10)
	defer b.Close()
	rec := &recorder{}
	s := New(b, rec.seal, rec.highWater, Config{Batch: 1000})

	n, err := s.Tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if n != 10 {
		t.Fatalf("sealed want 10 got %d", n)
	}
	for i, seq := range rec.sealed {
		if seq != uint64(i+1) {
			t.Fatalf("seal order broken at %d: seq %d", i, seq)
		}
	}
	if pc, _ := b.PendingCount(); pc != 0 {
		t.Fatalf("buffer should be drained, %d left", pc)
	}
}

// TestSealerCrashResumeNoDoubleSeal is the load-bearing crash-safety test: a
// seal failure mid-batch must stop cleanly, and resuming from the high-water
// must seal the remainder exactly once — no gaps, no duplicates, order kept.
func TestSealerCrashResumeNoDoubleSeal(t *testing.T) {
	b := newBuf(t, 10)
	defer b.Close()
	rec := &recorder{failAt: 6} // chain write dies at seq 6
	s := New(b, rec.seal, rec.highWater, Config{Batch: 1000})

	// Tick 1: seals 1..5, fails at 6, stops. Buffer still holds 6..10.
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatalf("tick1: %v", err)
	}
	if len(rec.sealed) != 5 || rec.sealed[4] != 5 {
		t.Fatalf("tick1 should seal 1..5, got %v", rec.sealed)
	}
	if pc, _ := b.PendingCount(); pc != 5 {
		t.Fatalf("buffer should retain 6..10, got %d pending", pc)
	}

	// Recover: the transient failure clears.
	rec.failAt = 0

	// Tick 2: must resume from high-water (5) and seal 6..10 exactly once.
	if _, err := s.Tick(context.Background()); err != nil {
		t.Fatalf("tick2: %v", err)
	}

	if len(rec.sealed) != 10 {
		t.Fatalf("after resume want 10 sealed got %d (%v)", len(rec.sealed), rec.sealed)
	}
	for i, seq := range rec.sealed {
		if seq != uint64(i+1) {
			t.Fatalf("resume broke order/dup at %d: got seq %d (full: %v)", i, seq, rec.sealed)
		}
	}
	if pc, _ := b.PendingCount(); pc != 0 {
		t.Fatalf("buffer should be fully drained after resume, %d left", pc)
	}
}

// batchRecorder seals whole batches, optionally failing one batch call.
type batchRecorder struct {
	recorder
	batches   int
	failBatch int // 1-based batch call to fail; 0 = never
}

func (r *batchRecorder) sealBatch(_ context.Context, entries []buffer.Entry) error {
	r.batches++
	if r.failBatch != 0 && r.batches == r.failBatch {
		return errors.New("simulated batch write failure")
	}
	for _, e := range entries {
		r.sealed = append(r.sealed, e.Seq)
	}
	return nil
}

// G65 (RD-1410): one tick drains the whole backlog in batches, not
// one batch per tick (P0: the sealer capped at 500 records/s), and each batch
// is one write.
func TestTickDrainsTheWholeBacklogInBatches(t *testing.T) {
	b := newBufConcurrent(t, 5000)
	defer b.Close()
	rec := &batchRecorder{}
	s := New(b, rec.seal, rec.highWater, Config{Batch: 2000, SealBatch: rec.sealBatch})
	n, err := s.Tick(context.Background())
	if err != nil || n != 5000 {
		t.Fatalf("tick sealed %d %v, want all 5000", n, err)
	}
	if rec.batches != 3 {
		t.Fatalf("%d batch writes, want 3 (2000+2000+1000)", rec.batches)
	}
	for i, seq := range rec.sealed {
		if seq != uint64(i+1) {
			t.Fatalf("order broken at %d: %d", i, seq)
		}
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d left in the buffer", pending)
	}
}

// A failed batch falls back to per-record sealing for that batch, so every
// entry before a failing one is still sealed and the failing one stops the
// tick (today's semantics, preserving chain order).
func TestFailedBatchFallsBackToPerRecordSealing(t *testing.T) {
	b := newBuf(t, 10)
	defer b.Close()
	rec := &batchRecorder{failBatch: 1}
	rec.failAt = 6
	s := New(b, rec.seal, rec.highWater, Config{Batch: 100, SealBatch: rec.sealBatch})
	n, err := s.Tick(context.Background())
	if err != nil || n != 5 {
		t.Fatalf("tick sealed %d %v, want 5 (1..5 per record, stop at 6)", n, err)
	}
	rec.failAt = 0
	if n, err := s.Tick(context.Background()); err != nil || n != 5 {
		t.Fatalf("resume sealed %d %v", n, err)
	}
	for i, seq := range rec.sealed {
		if seq != uint64(i+1) {
			t.Fatalf("order broken at %d: %v", i, rec.sealed)
		}
	}
}

// G66, the sealer side: a drained buffer reopened (or a recreated empty one)
// is seeded from the chain's high-water before any append, so the next event
// is sealed instead of being skipped and deleted as "already sealed".
func TestSealerSeedsTheBufferFromTheChainHighWater(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	for i := uint64(1); i <= 7; i++ { // the chain already sealed 1..7 elsewhere
		rec.sealed = append(rec.sealed, i)
	}
	b, err := buffer.Open(t.TempDir(), buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s := New(b, rec.seal, rec.highWater, Config{})
	if _, err := b.Append([]byte("before seeding")); !errors.Is(err, buffer.ErrNotSeeded) {
		t.Fatalf("append before seeding: %v", err)
	}
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	seq, err := b.Append([]byte("first"))
	if err != nil || seq != 8 {
		t.Fatalf("first append %d %v, want 8", seq, err)
	}
	if n, err := s.Tick(ctx); err != nil || n != 1 || rec.sealed[len(rec.sealed)-1] != 8 {
		t.Fatalf("tick sealed %d %v %v", n, err, rec.sealed)
	}
}

// The drained-restart case end to end: append, seal and drain to empty,
// close and reopen, append, tick: the second event is sealed.
func TestDrainedRestartSealsTheNextEvent(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	rec := &recorder{}
	b, err := buffer.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Append([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if n, err := New(b, rec.seal, rec.highWater, Config{}).Tick(ctx); err != nil || n != 1 {
		t.Fatalf("first tick %d %v", n, err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = buffer.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Append([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if n, err := New(b, rec.seal, rec.highWater, Config{}).Tick(ctx); err != nil || n != 1 || len(rec.sealed) != 2 {
		t.Fatalf("second event not sealed: %d %v %v", n, err, rec.sealed)
	}
}

// A chain high-water above everything this buffer ever allocated means
// another writer shares the chain: the sealer refuses to drain or delete.
func TestSealerRefusesWhenTheChainIsAheadOfTheBuffer(t *testing.T) {
	b := newBuf(t, 3)
	defer b.Close()
	rec := &recorder{sealed: []uint64{50}}
	if _, err := New(b, rec.seal, rec.highWater, Config{}).Tick(context.Background()); !errors.Is(err, ErrChainAhead) {
		t.Fatalf("tick: %v, want ErrChainAhead", err)
	}
	if pending, _ := b.PendingCount(); pending != 3 {
		t.Fatalf("%d pending: entries were deleted on a foreign high-water", pending)
	}
}

// G66 at the sealer: a tick never seals or deletes past an append that is
// still being written, and seals both, in order, once it lands.
func TestTickWaitsForAnAppendStillBeingWritten(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	b, err := buffer.Open(t.TempDir(), buffer.WithBeforeSetForTest(func(seq uint64) error {
		if seq == 1 {
			close(entered)
			<-release
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := b.Append([]byte("slow")); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	if _, err := b.Append([]byte("fast")); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s := New(b, rec.seal, rec.highWater, Config{})
	if n, err := s.Tick(context.Background()); err != nil || n != 0 {
		t.Fatalf("tick sealed %d %v past an append still being written", n, err)
	}
	close(release)
	wg.Wait()
	if n, err := s.Tick(context.Background()); err != nil || n != 2 || rec.sealed[0] != 1 || rec.sealed[1] != 2 {
		t.Fatalf("after the write landed: %d %v %v", n, err, rec.sealed)
	}
}

// A restart with unsealed entries resumes from the last persisted one: the
// entries are all still sealed, in order.
func TestRestartWithUnsealedEntriesSealsThemAll(t *testing.T) {
	dir := t.TempDir()
	b, err := buffer.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := b.Append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = buffer.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	rec := &recorder{}
	if n, err := New(b, rec.seal, rec.highWater, Config{}).Tick(context.Background()); err != nil || n != 3 {
		t.Fatalf("after restart sealed %d %v", n, err)
	}
	if seq, err := b.Append([]byte("y")); err != nil || seq != 4 {
		t.Fatalf("next sequence %d %v, want 4", seq, err)
	}
}

// Once running, a chain high-water beyond what this sealer sealed stops it
// for good, even after this buffer allocates past that high-water, and
// nothing of its own is deleted.
func TestChainAheadStaysRefusedOnceSeen(t *testing.T) {
	b := newBuf(t, 3)
	defer b.Close()
	rec := &recorder{}
	s := New(b, rec.seal, rec.highWater, Config{})
	if n, err := s.Tick(context.Background()); err != nil || n != 3 {
		t.Fatalf("first tick %d %v", n, err)
	}
	rec.sealed = append(rec.sealed, 50) // another writer sealed up to 50
	if _, err := s.Tick(context.Background()); !errors.Is(err, ErrChainAhead) {
		t.Fatalf("tick: %v, want ErrChainAhead", err)
	}
	for i := 0; i < 60; i++ {
		if _, err := b.Append([]byte("own")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Tick(context.Background()); !errors.Is(err, ErrChainAhead) {
		t.Fatalf("after allocating past 50: %v, want ErrChainAhead still", err)
	}
	if pending, _ := b.PendingCount(); pending != 60 {
		t.Fatalf("%d pending, want the 60 own entries kept", pending)
	}
}

// A record that fails on its own is not retried as part of a batch on every
// tick (each batch attempt reserves ids for the whole batch).
func TestFailingRecordIsRetriedAloneNotInBatches(t *testing.T) {
	b := newBuf(t, 5)
	defer b.Close()
	rec := &batchRecorder{failBatch: 1}
	rec.failAt = 3
	s := New(b, rec.seal, rec.highWater, Config{SealBatch: rec.sealBatch})
	for i := 0; i < 3; i++ {
		if _, err := s.Tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if rec.batches != 1 {
		t.Fatalf("%d batch attempts over 3 ticks with a failing record, want 1", rec.batches)
	}
	rec.failAt = 0
	if n, err := s.Tick(context.Background()); err != nil || n != 3 || len(rec.sealed) != 5 {
		t.Fatalf("after the record could be stored: %d %v %v", n, err, rec.sealed)
	}
}
