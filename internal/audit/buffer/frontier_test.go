package buffer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// G66 (RD-1410): Append allocates its sequence
// before its write lands, so a higher sequence can be persisted (and sealed)
// while a lower one is still being written. Drain and DeleteThrough must never
// pass the completed-publication frontier, or the lower entry is deleted
// unsealed.
func TestDrainAndDeleteNeverPassAnAppendStillBeingWritten(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	release := make(chan struct{})
	entered := make(chan struct{})
	b.beforeSet = func(seq uint64) error {
		if seq == 1 {
			close(entered)
			<-release
		}
		return nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := b.Append([]byte("slow")); err != nil {
			t.Error(err)
		}
	}()
	<-entered
	if seq, err := b.Append([]byte("fast")); err != nil || seq != 2 {
		t.Fatalf("second append %d %v", seq, err)
	}
	if entries, err := b.Drain(0, 10); err != nil || len(entries) != 0 {
		t.Fatalf("drained %v %v past an append still being written", entries, err)
	}
	// The sealer deletes through what it believes sealed: clamped.
	if err := b.DeleteThrough(2); err != nil {
		t.Fatal(err)
	}
	close(release)
	wg.Wait()
	entries, err := b.Drain(0, 10)
	if err != nil || len(entries) != 2 || entries[0].Seq != 1 || entries[1].Seq != 2 {
		t.Fatalf("after the slow write: %v %v, want seq 1 and 2", entries, err)
	}
}

// A failed write completes its sequence (a hole), so it never blocks the
// entries after it.
func TestFailedAppendDoesNotBlockTheFrontier(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.beforeSet = func(seq uint64) error {
		if seq == 1 {
			return errors.New("injected write failure")
		}
		return nil
	}
	if _, err := b.Append([]byte("lost")); err == nil {
		t.Fatal("injected failure not reported")
	}
	if _, err := b.Append([]byte("kept")); err != nil {
		t.Fatal(err)
	}
	entries, err := b.Drain(0, 10)
	if err != nil || len(entries) != 1 || entries[0].Seq != 2 {
		t.Fatalf("drain %v %v, want seq 2", entries, err)
	}
}

// Codex review 5.1: after a full drain and reopen, allocation continues above
// every sequence ever handed out, so a new entry is never mistaken for one the
// chain already sealed.
func TestSequenceSurvivesAFullDrainAndReopen(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := b.Append([]byte(fmt.Sprintf("e%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.DeleteThrough(3); err != nil {
		t.Fatal(err)
	}
	if pending, _ := b.PendingCount(); pending != 0 {
		t.Fatalf("%d pending after a full drain", pending)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if seq, err := b.Append([]byte("after reopen")); err != nil || seq != 4 {
		t.Fatalf("append after reopen: seq %d %v, want 4", seq, err)
	}
}

// A buffer opened with RequireSeed refuses appends until its floor is known,
// and its first sequence is above the floor (a recreated, empty directory
// while the chain already sealed up to N).
func TestRequireSeedRefusesAppendsUntilSeeded(t *testing.T) {
	b, err := Open(t.TempDir(), RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Append([]byte("early")); !errors.Is(err, ErrNotSeeded) {
		t.Fatalf("unseeded append: %v, want ErrNotSeeded", err)
	}
	if err := b.SeedFloor(41); err != nil {
		t.Fatal(err)
	}
	if seq, err := b.Append([]byte("first")); err != nil || seq != 42 {
		t.Fatalf("first append after seeding: %d %v, want 42", seq, err)
	}
	if err := b.SeedFloor(100); err == nil {
		t.Fatal("seeding after appends must be refused: it would skip in-flight sequences")
	}
	if got := b.AllocatedThrough(); got != 42 {
		t.Fatalf("allocated through %d", got)
	}
}

// The persisted high-water never decreases, even when DeleteThrough is asked
// for less than before.
func TestHighWaterIsMonotone(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := b.Append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.DeleteThrough(5); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteThrough(2); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if got := b.AllocatedThrough(); got != 5 {
		t.Fatalf("recovered floor %d, want 5", got)
	}
}

// TestAppendBatchIsOneDurableContiguousWrite: a batch gets contiguous
// sequences after earlier appends, is drained in order, and a failed batch
// stores nothing and never holds the frontier back.
func TestAppendBatchIsOneDurableContiguousWrite(t *testing.T) {
	dir := t.TempDir()
	fail := false
	b, err := Open(dir, WithBeforeSetForTest(func(seq uint64) error {
		if fail && seq == 5 {
			return errors.New("injected")
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Append([]byte("a")); err != nil {
		t.Fatal(err)
	}
	seqs, err := b.AppendBatch([][]byte{[]byte("b"), []byte("c"), []byte("d")})
	if err != nil || len(seqs) != 3 || seqs[0] != 2 || seqs[2] != 4 {
		t.Fatalf("batch seqs %v %v", seqs, err)
	}
	fail = true
	if _, err := b.AppendBatch([][]byte{[]byte("e"), []byte("f")}); err == nil {
		t.Fatal("injected failure not reported")
	}
	fail = false
	if seq, err := b.Append([]byte("g")); err != nil || seq != 7 {
		t.Fatalf("append after a failed batch: %d %v", seq, err)
	}
	entries, err := b.Drain(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, string(e.Data))
	}
	if strings.Join(got, "") != "abcdg" {
		t.Fatalf("drained %q, want abcdg (the failed batch stored nothing; its holes do not block)", got)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
}
