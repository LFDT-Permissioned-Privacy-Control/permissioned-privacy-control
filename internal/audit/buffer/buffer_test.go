package buffer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBufferAppendDrainRecover(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	const n = 50
	for i := 1; i <= n; i++ {
		seq, err := b.Append([]byte(fmt.Sprintf("entry-%d", i)))
		if err != nil {
			t.Fatalf("append: %v", err)
		}
		if seq != uint64(i) {
			t.Fatalf("seq must be monotonic + gap-free: want %d got %d", i, seq)
		}
	}

	if pc, _ := b.PendingCount(); pc != n {
		t.Fatalf("pending want %d got %d", n, pc)
	}

	entries, err := b.Drain(0, 1000)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(entries) != n {
		t.Fatalf("drain count want %d got %d", n, len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Fatalf("drain order broken at %d: seq %d", i, e.Seq)
		}
		if want := fmt.Sprintf("entry-%d", i+1); string(e.Data) != want {
			t.Fatalf("data want %q got %q", want, e.Data)
		}
	}

	// Simulate crash: close and reopen. Entries must survive (WAL replay),
	// and the sequence must continue past the last persisted value.
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, err = Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer b.Close()

	if pc, _ := b.PendingCount(); pc != n {
		t.Fatalf("after reopen pending want %d got %d", n, pc)
	}
	seq, err := b.Append([]byte("entry-after-restart"))
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if seq != uint64(n+1) {
		t.Fatalf("seq after reopen want %d got %d", n+1, seq)
	}

	// Seal-and-delete the first 10; the rest remain, order preserved.
	if err := b.DeleteThrough(10); err != nil {
		t.Fatalf("delete-through: %v", err)
	}
	rest, err := b.Drain(0, 1000)
	if err != nil {
		t.Fatalf("drain after delete: %v", err)
	}
	if len(rest) != n+1-10 {
		t.Fatalf("after delete want %d got %d", n+1-10, len(rest))
	}
	if rest[0].Seq != 11 {
		t.Fatalf("first surviving seq want 11 got %d", rest[0].Seq)
	}
}

func TestBufferDrainAfterSeq(t *testing.T) {
	dir := t.TempDir()
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer b.Close()

	for i := 1; i <= 20; i++ {
		if _, err := b.Append([]byte("x")); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	entries, err := b.Drain(15, 1000) // after seq 15 → 16..20
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	if len(entries) != 5 || entries[0].Seq != 16 {
		t.Fatalf("drain afterSeq broken: %d entries, first seq %d", len(entries), entries[0].Seq)
	}
}

// TestOpenRejectsUnwritableDirWithActionableError covers the prod deploy failure
// mode: the non-root runtime user can't write a root-owned volume. Open must
// fail fast with an operator-actionable message (name the uid + the fix), not a
// bare EACCES from deep inside Pebble. (RD-1112)
func TestOpenRejectsUnwritableDirWithActionableError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root bypasses directory permissions; cannot simulate an unwritable dir")
	}
	// A read-only (r-x) parent: this process cannot create the buffer dir inside it.
	ro := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(ro, 0o500); err != nil {
		t.Fatalf("mkdir readonly: %v", err)
	}

	_, err := Open(filepath.Join(ro, "auditbuf"))
	if err == nil {
		t.Fatal("Open must fail when the buffer dir is not writable")
	}
	if !errors.Is(err, fs.ErrPermission) {
		t.Errorf("error should wrap fs.ErrPermission, got: %v", err)
	}
	// The message must be operator-actionable: name the runtime uid and the fix.
	for _, want := range []string{"not writable", "uid", "fsGroup"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q; got: %v", want, err)
		}
	}
}
