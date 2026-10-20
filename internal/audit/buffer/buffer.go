// Package buffer provides a durable, ordered, append-only staging buffer for
// audit-log entries, backed by an embedded Pebble (LSM) store (RD-1112).
//
// The proxy hot path appends each audit entry here with an fsync'd commit and
// returns immediately — removing the synchronous hash-chain write (a global
// mutex held across two Postgres round-trips) from request latency. A single
// background sealer drains entries in sequence order, builds the tamper-evident
// hash chain, writes them to the dedicated audit Postgres, and only then
// deletes the drained entries.
//
// Durability: every Append commits with pebble.Sync (WAL fsync), so an entry
// survives a process crash; on Open, Pebble replays its WAL and the buffer
// resumes from the last persisted sequence — nothing buffered is lost across a
// restart of the proxy or the sealer.
//
// Ordering: entries are keyed by a per-buffer monotonic uint64 sequence
// (big-endian, so byte order == numeric order), allocated atomically. A failed
// write leaves an unused sequence number (a harmless hole) — the sealer drains
// the keys that actually exist, in order. Ordering is by this sequence, never
// wall-clock, so a skewed host clock cannot reorder the chain. (The verifier's
// gap/count check is on the SEALED Postgres chain via signed checkpoints, not
// on this internal buffer sequence.)
package buffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"

	"github.com/cockroachdb/pebble"
)

// entryPrefix segregates entry keys from any future metadata keys sharing the
// store. An entry key is entryPrefix || big-endian(seq), fixed width.
const (
	entryPrefix = byte('e')
	entryKeyLen = 1 + 8
)

// Buffer is a durable, ordered, append-only staging buffer for audit entries.
type Buffer struct {
	db  *pebble.DB
	seq atomic.Uint64 // last allocated sequence (0 = empty); monotonic
}

// Entry is a buffered audit record paired with its sequence number.
type Entry struct {
	Seq  uint64
	Data []byte
}

func entryKey(seq uint64) []byte {
	k := make([]byte, entryKeyLen)
	k[0] = entryPrefix
	binary.BigEndian.PutUint64(k[1:], seq)
	return k
}

func seqFromKey(k []byte) uint64 { return binary.BigEndian.Uint64(k[1:]) }

func validEntryKey(k []byte) bool { return len(k) == entryKeyLen && k[0] == entryPrefix }

func prefixBounds() *pebble.IterOptions {
	return &pebble.IterOptions{LowerBound: []byte{entryPrefix}, UpperBound: []byte{entryPrefix + 1}}
}

// Open opens (or creates) the buffer at dir and recovers the last persisted
// sequence so Append continues monotonically across restarts.
func Open(dir string) (*Buffer, error) {
	// Fail fast with an actionable error if the dir isn't usable, rather than
	// deep inside Pebble with a bare EACCES (the common non-root-volume case).
	if err := ensureWritableDir(dir); err != nil {
		return nil, err
	}
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("open audit buffer: %w", err)
	}
	b := &Buffer{db: db}
	if err := b.recoverSeq(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return b, nil
}

// ensureWritableDir creates the buffer directory if needed and verifies the
// current process can actually write in it. The proxy runs as a non-root user
// (uid 1000 in the shipped image); a freshly-mounted Docker volume or Kubernetes
// PVC is root-owned, so without provisioning pebble.Open would fail deep inside
// with a bare EACCES. The async buffer is a fail-hard dependency, so surfacing
// the fix here turns a cryptic boot failure into an operator-actionable one
// (RD-1112 prod deploy).
func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return bufferDirError(dir, err)
	}
	// MkdirAll is a no-op on an existing (possibly root-owned) dir, so only a
	// real create proves this process can use it.
	probe, err := os.CreateTemp(dir, ".writable-probe-*")
	if err != nil {
		return bufferDirError(dir, err)
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return nil
}

// bufferDirError wraps a buffer-dir preparation failure, adding a deployment
// hint on the permission case so the operator knows the volume must be owned by
// (or writable by) the proxy's runtime uid.
func bufferDirError(dir string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("audit buffer dir %q is not writable by the proxy's runtime user (uid %d): %w — "+
			"mount a volume owned by that uid (on Docker a named volume inherits the image's pre-owned buffer dir; "+
			"on Kubernetes set the pod securityContext fsGroup to gid %d)", dir, os.Getuid(), err, os.Getgid())
	}
	return fmt.Errorf("prepare audit buffer dir %q: %w", dir, err)
}

// recoverSeq sets seq to the highest persisted entry sequence (0 if empty).
func (b *Buffer) recoverSeq() error {
	it, err := b.db.NewIter(prefixBounds())
	if err != nil {
		return fmt.Errorf("audit buffer recover: %w", err)
	}
	defer it.Close()
	if it.Last() && validEntryKey(it.Key()) {
		b.seq.Store(seqFromKey(it.Key()))
	}
	return it.Error()
}

// Append durably stores data and returns its assigned sequence. The write is
// fsync'd before returning, so the entry survives a crash. The sequence
// advances only on success, keeping persisted sequences contiguous.
func (b *Buffer) Append(data []byte) (uint64, error) {
	// Atomic sequence allocation with NO lock held across the write, so
	// concurrent appends are not serialized — this lets Pebble's WAL
	// group-commit amortize the fsync across simultaneous writers. (A
	// per-append mutex defeats group commit and collapses throughput to one
	// F_FULLFSYNC per record — measured ~5x slower than the sync PG path it
	// was meant to beat; RD-1112.) Pebble keys are sequence-ordered regardless
	// of write order. A failed Set just leaves an unused sequence number,
	// harmless: the sealer drains the keys that actually exist, in order.
	seq := b.seq.Add(1)
	if err := b.db.Set(entryKey(seq), data, pebble.Sync); err != nil {
		return 0, fmt.Errorf("audit buffer append: %w", err)
	}
	return seq, nil
}

// Drain returns up to max buffered entries in ascending sequence order, starting
// after afterSeq (pass 0 to start from the beginning). The sealer uses this to
// read the next batch to chain and persist.
func (b *Buffer) Drain(afterSeq uint64, max int) ([]Entry, error) {
	it, err := b.db.NewIter(&pebble.IterOptions{
		LowerBound: entryKey(afterSeq + 1),
		UpperBound: []byte{entryPrefix + 1},
	})
	if err != nil {
		return nil, fmt.Errorf("audit buffer drain: %w", err)
	}
	defer it.Close()
	var out []Entry
	for it.First(); it.Valid() && len(out) < max; it.Next() {
		if !validEntryKey(it.Key()) {
			continue
		}
		v := it.Value()
		data := make([]byte, len(v))
		copy(data, v)
		out = append(out, Entry{Seq: seqFromKey(it.Key()), Data: data})
	}
	return out, it.Error()
}

// DeleteThrough removes all entries with sequence <= throughSeq. The sealer
// calls this only after the batch is durably committed to the audit Postgres,
// so deletion never outruns the sealed chain.
func (b *Buffer) DeleteThrough(throughSeq uint64) error {
	if err := b.db.DeleteRange(entryKey(0), entryKey(throughSeq+1), pebble.Sync); err != nil {
		return fmt.Errorf("audit buffer delete-through: %w", err)
	}
	return nil
}

// PendingCount returns the number of buffered (un-sealed) entries — for the
// unsealed-lag metric.
func (b *Buffer) PendingCount() (int, error) {
	it, err := b.db.NewIter(prefixBounds())
	if err != nil {
		return 0, err
	}
	defer it.Close()
	n := 0
	for it.First(); it.Valid(); it.Next() {
		if validEntryKey(it.Key()) {
			n++
		}
	}
	return n, it.Error()
}

// Close flushes and closes the underlying store.
func (b *Buffer) Close() error { return b.db.Close() }
