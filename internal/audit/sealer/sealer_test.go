package sealer

import (
	"context"
	"errors"
	"fmt"
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
