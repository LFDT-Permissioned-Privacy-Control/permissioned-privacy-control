package buffer

import (
	"errors"
	"testing"
)

// RD-1410 review findings 1 and 2: a buffer numbers this run's entries in
// the allocation range it was given, above every entry it already holds, and
// keeps its earlier entries under their own sequences.
func TestSeedRangeNumbersNewEntriesInTheRange(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := b.Append([]byte("earlier")); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(dir, RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.SeedRange(2, 100); err == nil {
		t.Fatal("a range at or below the buffer's own entries must be refused")
	}
	const base = 1 << 40
	if err := b.SeedRange(base, base+3); err != nil {
		t.Fatal(err)
	}
	if seq, err := b.Append([]byte("new")); err != nil || seq != base+1 {
		t.Fatalf("first append %d %v, want %d", seq, err, base+1)
	}
	if seqs, err := b.AppendBatch([][]byte{[]byte("x"), []byte("y")}); err != nil || seqs[1] != base+3 {
		t.Fatalf("batch %v %v", seqs, err)
	}
	if _, err := b.Append([]byte("past the range")); !errors.Is(err, ErrRangeExhausted) {
		t.Fatalf("append past the range: %v, want ErrRangeExhausted", err)
	}
	if _, err := b.AppendBatch([][]byte{[]byte("z")}); !errors.Is(err, ErrRangeExhausted) {
		t.Fatalf("batch past the range: %v, want ErrRangeExhausted", err)
	}
	entries, err := b.Drain(0, 10)
	if err != nil || len(entries) != 6 || entries[0].Seq != 1 || entries[3].Seq != base+1 {
		t.Fatalf("entries %+v %v", entries, err)
	}
	if err := b.SeedRange(base*2, base*3); err == nil {
		t.Fatal("seeding after appends must be refused")
	}
}

// Rekey moves one entry to the next sequence of the current range in one
// synced write: it is never lost and never present twice, also across a
// reopen.
func TestRekeyMovesAnEntryIntoTheCurrentRange(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Append([]byte("legacy")); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(dir, RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	const base = 1 << 40
	if err := b.SeedRange(base, base+100); err != nil {
		t.Fatal(err)
	}
	moved, err := b.Rekey(1)
	if err != nil || moved != base+1 {
		t.Fatalf("rekey %d %v, want %d", moved, err, base+1)
	}
	if _, err := b.Rekey(1); err == nil {
		t.Fatal("rekeying a sequence that is no longer there must fail")
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	entries, err := b.Drain(0, 10)
	if err != nil || len(entries) != 1 || entries[0].Seq != base+1 || string(entries[0].Data) != "legacy" {
		t.Fatalf("after reopen: %+v %v", entries, err)
	}
}
