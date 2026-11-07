package buffer

import (
	"bytes"
	"testing"
)

func TestBoundedDrainRejectsBeforePartialCopyWithoutChangingLegacyDrain(t *testing.T) {
	b, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := b.Append(bytes.Repeat([]byte{1}, 3000)); err != nil {
		t.Fatal(err)
	}
	if rows, err := b.DrainBounded(0, 10, 2048, 4096); err == nil || rows != nil {
		t.Fatal("oversized value became a partial batch", err)
	}
	legacy, err := b.Drain(0, 10)
	if err != nil || len(legacy) != 1 || len(legacy[0].Data) != 3000 {
		t.Fatal("legacy drain changed", err)
	}
	if err := b.DeleteThrough(legacy[0].Seq); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := b.Append(bytes.Repeat([]byte{2}, 800)); err != nil {
			t.Fatal(err)
		}
	}
	if rows, err := b.DrainBounded(0, 10, 1024, 1024); err == nil || rows != nil {
		t.Fatal("aggregate budget returned partial data", err)
	}
	if n, err := b.PendingCount(); err != nil || n != 2 {
		t.Fatal("bounded read removed entries", n, err)
	}
}

func TestBoundedDrainUsesCompletedFrontierWithConcurrentAppend(t *testing.T) {
	entered, resume := make(chan struct{}), make(chan struct{})
	b, err := Open(t.TempDir(), WithBeforeSetForTest(func(seq uint64) error {
		if seq == 1 {
			close(entered)
			<-resume
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	done := make(chan error, 1)
	go func() { _, err := b.Append([]byte("first")); done <- err }()
	<-entered
	if _, err := b.Append([]byte("second")); err != nil {
		close(resume)
		t.Fatal(err)
	}
	if b.AllocatedThrough() != 2 {
		close(resume)
		t.Fatal("second allocation did not complete independently")
	}
	if rows, err := b.DrainBounded(0, 10, 2048, 4096); err != nil || len(rows) != 0 {
		close(resume)
		t.Fatal("passed incomplete publication frontier", rows, err)
	}
	close(resume)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rows, err := b.DrainBounded(0, 10, 2048, 4096)
	if err != nil || len(rows) != 2 || rows[0].Seq != 1 || rows[1].Seq != 2 {
		t.Fatal(rows, err)
	}
}
