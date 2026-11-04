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
//
// Never deleting an unsealed append (RD-1410):
//   - Completed-publication frontier. A sequence is allocated before its write
//     lands, so a higher sequence can be persisted while a lower one is still
//     being written. Drain and DeleteThrough never pass the frontier: the
//     highest sequence at and below which every allocated sequence has
//     completed (written, or failed and left as a hole).
//   - Allocation high-water. DeleteThrough, the only operation that removes
//     entries, records in the same synced batch a never-decreasing high-water
//     key (outside the entry range). On Open the allocator resumes above
//     max(high-water, last entry), so after a full drain and reopen a new
//     entry never reuses a sequence the chain already sealed.
//   - External seed. A buffer opened with RequireSeed refuses appends until
//     it is seeded: with SeedRange (the server), the allocation range this run
//     drew from the audit database, so every sequence it allocates is unique
//     across all instances and runs, which also covers a recreated, empty
//     buffer directory; or with SeedFloor, the sealed high-water of a chain it
//     alone writes.
package buffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"

	"github.com/cockroachdb/pebble"
)

// entryPrefix segregates entry keys from any future metadata keys sharing the
// store. An entry key is entryPrefix || big-endian(seq), fixed width.
const (
	entryPrefix = byte('e')
	entryKeyLen = 1 + 8
)

// RangeShift is the width of one allocation range (SeedRange): range n holds
// sequences n<<RangeShift + 1 .. (n+1)<<RangeShift - 1, and range 0 the
// sequences buffers numbered per chain before ranges existed.
const RangeShift = 40

// highWaterKey holds the persisted allocation high-water. Its prefix sorts
// outside the entry range, so Drain and DeleteThrough never touch it.
var highWaterKey = []byte{'h'}

// ErrNotSeeded is returned by Append on a RequireSeed buffer before it is seeded.
var ErrNotSeeded = errors.New("audit buffer is not seeded: the sealed chain's high-water is not known yet")

// ErrRangeExhausted is returned when this run's allocation range is used up;
// a restart draws a new one.
var ErrRangeExhausted = errors.New("audit buffer allocation range exhausted: restart the instance to draw a new range")

// Buffer is a durable, ordered, append-only staging buffer for audit entries.
type Buffer struct {
	db *pebble.DB

	mu       sync.Mutex
	next     uint64              // last allocated (or seeded) sequence
	top      uint64              // last sequence of this run's range (0: unbounded)
	frontier uint64              // every sequence <= frontier has completed
	done     map[uint64]struct{} // completed sequences above the frontier
	seeded   bool
	appended bool // seeding is refused once an append has been allocated

	deleteMu sync.Mutex // serialises DeleteThrough and owns hw
	hw       uint64     // persisted allocation high-water

	beforeSet func(seq uint64) error // test seam: runs before an entry's write
}

type options struct {
	requireSeed bool
	beforeSet   func(seq uint64) error
}

// Option configures Open.
type Option func(*options)

// RequireSeed makes Append refuse (ErrNotSeeded) until SeedFloor is called
// with the sealed chain's high-water. Use it wherever the sealed chain lives
// outside the buffer (the server: the audit database).
func RequireSeed() Option { return func(o *options) { o.requireSeed = true } }

// WithBeforeSetForTest runs fn before each entry's write (a test seam to delay
// or fail one sequence's write). Never used in production.
func WithBeforeSetForTest(fn func(seq uint64) error) Option {
	return func(o *options) { o.beforeSet = fn }
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
func Open(dir string, opts ...Option) (*Buffer, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	// Fail fast with an actionable error if the dir isn't usable, rather than
	// deep inside Pebble with a bare EACCES (the common non-root-volume case).
	if err := ensureWritableDir(dir); err != nil {
		return nil, err
	}
	db, err := pebble.Open(dir, &pebble.Options{})
	if err != nil {
		return nil, fmt.Errorf("open audit buffer: %w", err)
	}
	b := &Buffer{db: db, done: map[uint64]struct{}{}, seeded: !o.requireSeed, beforeSet: o.beforeSet}
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

// recoverSeq resumes allocation above max(persisted high-water, last entry):
// every sequence ever persisted is at or below that, because only
// DeleteThrough removes entries and it records the high-water atomically.
// Nothing is in flight after Open, so the frontier starts there too.
func (b *Buffer) recoverSeq() error {
	value, closer, err := b.db.Get(highWaterKey)
	switch {
	case err == nil:
		if len(value) != 8 {
			_ = closer.Close()
			return fmt.Errorf("audit buffer recover: high-water key has %d bytes, want 8", len(value))
		}
		b.hw = binary.BigEndian.Uint64(value)
		_ = closer.Close()
	case !errors.Is(err, pebble.ErrNotFound):
		return fmt.Errorf("audit buffer recover high-water: %w", err)
	}
	it, err := b.db.NewIter(prefixBounds())
	if err != nil {
		return fmt.Errorf("audit buffer recover: %w", err)
	}
	defer it.Close()
	floor := b.hw
	if it.Last() && validEntryKey(it.Key()) {
		floor = max(floor, seqFromKey(it.Key()))
	}
	b.next, b.frontier = floor, floor
	return it.Error()
}

// SeedFloor raises the allocator and the frontier to at least floor (the
// sealed chain's high-water) and marks the buffer seeded. It must run before
// the first append: raising the floor under in-flight appends would skip them.
func (b *Buffer) SeedFloor(floor uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.appended {
		return errors.New("audit buffer seed refused: appends have already been allocated")
	}
	if floor > b.next {
		if b.next > b.hw {
			// Entries in (hw, floor] are now treated as sealed and will be
			// deleted: the chain already holds those positions, so these
			// entries reused sequences (a buffer restored from an older copy).
			slog.Warn("audit buffer floor raised above entries still in the buffer; they are treated as sealed",
				"local_last", b.next, "chain_high_water", floor)
		}
		b.next, b.frontier = floor, floor
	}
	b.seeded = true
	return nil
}

// SeedRange gives a buffer this run's allocation range: new entries are
// numbered base+1 .. top. Entries already in the buffer (earlier runs) keep
// their sequences. It refuses a range that does not start at or above every
// sequence this buffer has allocated or persisted (the audit database handed a
// range out again, as after a restore), and must run before the first append.
func (b *Buffer) SeedRange(base, top uint64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.appended {
		return errors.New("audit buffer seed refused: appends have already been allocated")
	}
	if top <= base {
		return fmt.Errorf("audit buffer seed refused: empty range %d..%d", base+1, top)
	}
	if base < b.next {
		return fmt.Errorf("audit buffer seed refused: range %d..%d does not start above this buffer's own sequence %d", base+1, top, b.next)
	}
	b.next, b.frontier, b.top = base, base, top
	b.seeded = true
	return nil
}

// Seeded reports whether appends are accepted.
func (b *Buffer) Seeded() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.seeded
}

// AllocatedThrough is the highest sequence allocated or seeded so far. A
// sealed chain high-water above it means another writer shares the chain.
func (b *Buffer) AllocatedThrough() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

func (b *Buffer) completedThrough() uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.frontier
}

func (b *Buffer) complete(seq uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if seq != b.frontier+1 {
		b.done[seq] = struct{}{}
		return
	}
	b.frontier = seq
	for {
		if _, ok := b.done[b.frontier+1]; !ok {
			return
		}
		delete(b.done, b.frontier+1)
		b.frontier++
	}
}

// Append durably stores data and returns its assigned sequence. The write is
// fsync'd before returning, so the entry survives a crash.
func (b *Buffer) Append(data []byte) (uint64, error) {
	// Allocation takes a short lock but NO lock is held across the write, so
	// concurrent appends are not serialized — this lets Pebble's WAL
	// group-commit amortize the fsync across simultaneous writers. (A
	// per-append mutex defeats group commit and collapses throughput to one
	// F_FULLFSYNC per record — measured ~5x slower than the sync PG path it
	// was meant to beat; RD-1112.) A failed write leaves a harmless hole; its
	// sequence still completes, so it never holds the frontier back.
	b.mu.Lock()
	if !b.seeded {
		b.mu.Unlock()
		return 0, ErrNotSeeded
	}
	if b.top > 0 && b.next >= b.top {
		b.mu.Unlock()
		return 0, ErrRangeExhausted
	}
	b.next++
	seq := b.next
	b.appended = true
	b.mu.Unlock()
	defer b.complete(seq)
	if b.beforeSet != nil {
		if err := b.beforeSet(seq); err != nil {
			return 0, fmt.Errorf("audit buffer append: %w", err)
		}
	}
	if err := b.db.Set(entryKey(seq), data, pebble.Sync); err != nil {
		return 0, fmt.Errorf("audit buffer append: %w", err)
	}
	return seq, nil
}

// AppendBatch durably stores every entry of data in one fsync'd write and
// returns their sequences, which are contiguous and in order. Either every
// entry is stored or none is (one Pebble batch); the sequences of a failed
// batch complete as holes, like a failed Append, so they never hold the
// frontier back.
func (b *Buffer) AppendBatch(data [][]byte) ([]uint64, error) {
	if len(data) == 0 {
		return nil, nil
	}
	b.mu.Lock()
	if !b.seeded {
		b.mu.Unlock()
		return nil, ErrNotSeeded
	}
	if b.top > 0 && b.top-b.next < uint64(len(data)) {
		b.mu.Unlock()
		return nil, ErrRangeExhausted
	}
	first := b.next + 1
	b.next += uint64(len(data))
	b.appended = true
	b.mu.Unlock()
	seqs := make([]uint64, len(data))
	for i := range data {
		seqs[i] = first + uint64(i)
	}
	defer func() {
		for _, seq := range seqs {
			b.complete(seq)
		}
	}()
	batch := b.db.NewBatch()
	defer batch.Close()
	for i, entry := range data {
		if b.beforeSet != nil {
			if err := b.beforeSet(seqs[i]); err != nil {
				return nil, fmt.Errorf("audit buffer append: %w", err)
			}
		}
		if err := batch.Set(entryKey(seqs[i]), entry, nil); err != nil {
			return nil, fmt.Errorf("audit buffer append: %w", err)
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return nil, fmt.Errorf("audit buffer append: %w", err)
	}
	return seqs, nil
}

// Rekey moves the entry stored under seq to the next sequence of this run's
// range, in one synced write (the new key is set and the old one deleted
// together), and returns the new sequence. The sealer uses it for an earlier
// entry whose sequence another chain's row already holds, so it can be sealed
// at all.
func (b *Buffer) Rekey(seq uint64) (uint64, error) {
	value, closer, err := b.db.Get(entryKey(seq))
	if err != nil {
		return 0, fmt.Errorf("audit buffer rekey %d: %w", seq, err)
	}
	data := append([]byte(nil), value...)
	_ = closer.Close()
	b.mu.Lock()
	if !b.seeded {
		b.mu.Unlock()
		return 0, ErrNotSeeded
	}
	if b.top > 0 && b.next >= b.top {
		b.mu.Unlock()
		return 0, ErrRangeExhausted
	}
	b.next++
	moved := b.next
	b.appended = true
	b.mu.Unlock()
	defer b.complete(moved)
	batch := b.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(entryKey(moved), data, nil); err != nil {
		return 0, fmt.Errorf("audit buffer rekey: %w", err)
	}
	if err := batch.Delete(entryKey(seq), nil); err != nil {
		return 0, fmt.Errorf("audit buffer rekey: %w", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return 0, fmt.Errorf("audit buffer rekey: %w", err)
	}
	return moved, nil
}

// Drain returns up to max buffered entries in ascending sequence order, starting
// after afterSeq (pass 0 to start from the beginning). The sealer uses this to
// read the next batch to chain and persist.
//
// Drain never returns an entry above the completed-publication frontier.
func (b *Buffer) Drain(afterSeq uint64, max int) ([]Entry, error) {
	frontier := b.completedThrough()
	if afterSeq >= frontier {
		return nil, nil
	}
	it, err := b.db.NewIter(&pebble.IterOptions{
		LowerBound: entryKey(afterSeq + 1),
		UpperBound: entryKey(frontier + 1),
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

// DeleteThrough removes all entries with sequence <= throughSeq, clamped to
// the completed-publication frontier. The sealer calls this only after the
// batch is durably committed to the audit Postgres, so deletion never outruns
// the sealed chain. The same synced batch records the allocation high-water,
// which never decreases.
func (b *Buffer) DeleteThrough(throughSeq uint64) error {
	throughSeq = min(throughSeq, b.completedThrough())
	b.deleteMu.Lock()
	defer b.deleteMu.Unlock()
	if throughSeq <= b.hw {
		return nil // everything at or below the high-water is already deleted
	}
	hw := throughSeq
	batch := b.db.NewBatch()
	defer batch.Close()
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], hw)
	if err := batch.DeleteRange(entryKey(0), entryKey(throughSeq+1), nil); err != nil {
		return fmt.Errorf("audit buffer delete-through: %w", err)
	}
	if err := batch.Set(highWaterKey, value[:], nil); err != nil {
		return fmt.Errorf("audit buffer delete-through: %w", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("audit buffer delete-through: %w", err)
	}
	b.hw = hw
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
