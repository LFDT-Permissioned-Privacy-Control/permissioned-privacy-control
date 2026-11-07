package activitylog

import (
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
)

type Receipt struct {
	recordID string
	sequence uint64
}

// Receipt identifies a local synced append only; it is not a SQL-seal receipt.
func (r *Receipt) RecordID() string {
	if r == nil {
		return ""
	}
	return r.recordID
}
func (r *Receipt) Sequence() uint64 {
	if r == nil {
		return 0
	}
	return r.sequence
}

type Slot struct {
	owner *Recorder
	used  atomic.Bool
}
type Recorder struct {
	cfg        Config
	buffer     *buffer.Buffer
	run        RunStore
	sealer     *sealer.Sealer
	mu         sync.Mutex
	entries    int
	bytes      int64
	held       int
	ordinal    uint64
	appends    map[*Slot]time.Time
	spaceAt    time.Time
	spaceOK    bool
	fault      error
	sticky     bool
	closing    bool
	running    bool
	changed    chan struct{}
	done       chan struct{}
	runCancel  context.CancelFunc
	closeOnce  sync.Once
	closedDone chan struct{}
	closeErr   error
}

func interfaceNil(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}
func New(ctx context.Context, c Config, store Store) (*Recorder, error) {
	return newRecorder(ctx, c, store, nil)
}
func newRecorder(ctx context.Context, c Config, store Store, options []buffer.Option) (*Recorder, error) {
	key, err := c.Network.Key()
	if err != nil || interfaceNil(store) || !CanonicalUUID(c.SourceID) || !CanonicalUUID(c.ProducerID) || !CanonicalUUID(c.ExpectedGeneration) || c.Clock == nil || !filepath.IsAbs(c.BufferDirectory) || !c.Limits.Valid() || len(c.Methods) < 1 || len(c.Methods) > 512 {
		return nil, ErrInvalid
	}
	for i, m := range c.Methods {
		if !ValidMethod(m) || i > 0 && c.Methods[i-1] >= m {
			return nil, ErrInvalid
		}
	}
	c.Methods = slices.Clone(c.Methods)
	wanted := StoreMetadata{NetworkKey: Digest(key), SourceID: c.SourceID, Generation: c.ExpectedGeneration, Configuration: c.Configuration, Format: Format()}
	if store.Metadata() != wanted {
		return nil, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	opts := append([]buffer.Option{buffer.RequireSeed()}, options...)
	b, err := buffer.Open(c.BufferDirectory, opts...)
	if err != nil {
		return nil, ErrUnavailable
	}
	ok := false
	defer func() {
		if !ok {
			_ = b.Close()
		}
	}()
	r := &Recorder{cfg: c, buffer: b, appends: map[*Slot]time.Time{}, changed: make(chan struct{}), done: make(chan struct{}), closedDone: make(chan struct{})}
	var after uint64
	for {
		if ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		batch, err := b.DrainBounded(after, 512, MaxEncodedBytes, MaxBatchBytes)
		if err != nil {
			return nil, ErrQuarantined
		}
		if len(batch) == 0 {
			break
		}
		for _, entry := range batch {
			record, err := DecodeSpool(entry.Data)
			if err != nil {
				return nil, ErrQuarantined
			}
			e := record.Fields()
			if e.Network != hex.EncodeToString(key[:]) || e.ProducerID != c.ProducerID || entry.Seq>>buffer.RangeShift == 0 {
				return nil, ErrQuarantined
			}
			if r.entries >= c.Limits.BufferedEntries || int64(len(entry.Data)) > c.Limits.BufferedBytes-r.bytes {
				return nil, ErrTooBroad
			}
			r.entries++
			r.bytes += int64(len(entry.Data))
			after = entry.Seq
		}
	}
	requestedRun := uuid.NewString()
	run, err := store.StartRun(ctx, RunRequest{ProducerID: c.ProducerID, RunID: requestedRun, AllocatedThrough: b.AllocatedThrough()})
	if err != nil {
		return nil, err
	}
	if interfaceNil(run) {
		return nil, ErrUnavailable
	}
	binding := run.Binding()
	if binding.Metadata != wanted || binding.ProducerID != c.ProducerID || binding.RunID != requestedRun || binding.RangeIndex < 1 || binding.RangeIndex > 8388607 || binding.Base != binding.RangeIndex<<buffer.RangeShift || binding.Top != binding.Base+(1<<buffer.RangeShift)-1 || binding.Base < b.AllocatedThrough() {
		return nil, ErrUnavailable
	}
	r.run = run
	for after = 0; ; {
		if ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		batch, err := b.DrainBounded(after, 512, MaxEncodedBytes, MaxBatchBytes)
		if err != nil {
			return nil, ErrQuarantined
		}
		if len(batch) == 0 {
			break
		}
		verdicts, err := run.Verify(ctx, batch)
		if err != nil {
			return nil, err
		}
		if len(verdicts) != len(batch) {
			return nil, ErrUnavailable
		}
		for _, v := range verdicts {
			if v != sealer.Sealed && v != sealer.Missing {
				return nil, ErrQuarantined
			}
		}
		after = batch[len(batch)-1].Seq
	}
	if b.SeedRange(binding.Base, binding.Top) != nil {
		return nil, ErrUnavailable
	}
	r.sampleSpace()
	if !r.spaceOK {
		return nil, ErrUnavailable
	}
	bridge := &strictDrainer{recorder: r}
	r.sealer = sealer.New(bridge, func(ctx context.Context, seq uint64, data []byte) error {
		err := run.SealOne(ctx, seq, data)
		r.noteStoreError(err)
		return err
	}, run.HighWater, sealer.Config{Batch: c.Limits.SealBatch, Interval: time.Second, SealBatch: func(ctx context.Context, entries []buffer.Entry) error {
		err := run.SealBatch(ctx, entries)
		r.noteStoreError(err)
		return err
	}, Settle: r.settle, RangeBase: binding.Base, RangeHighWater: run.RangeHighWater, Verify: func(ctx context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
		v, err := run.Verify(ctx, entries)
		r.noteStoreError(err)
		return v, err
	}})
	ok = true
	return r, nil
}
func (r *Recorder) signal() { close(r.changed); r.changed = make(chan struct{}) }
func (r *Recorder) noteStoreError(err error) {
	if err != nil && (errors.Is(err, ErrQuarantined) || errors.Is(err, ErrInvalid) || errors.Is(err, sealer.ErrChainAhead)) {
		r.fail(err, true)
	}
}
func (r *Recorder) fail(err error, sticky bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sticky {
		return
	}
	r.fault = err
	r.sticky = sticky
	r.signal()
}
func (r *Recorder) healthyLocked(now time.Time) error {
	if r.fault != nil {
		return r.fault
	}
	if r.closing || !r.spaceOK || now.Sub(r.spaceAt) > time.Second {
		return ErrUnavailable
	}
	for _, started := range r.appends {
		if now.Sub(started) > time.Second {
			return ErrUnavailable
		}
	}
	if r.sealer != nil && r.sealer.State().Stopped {
		return ErrUnavailable
	}
	return nil
}
func (r *Recorder) Healthy() error {
	if r == nil {
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.healthyLocked(time.Now())
}
func (r *Recorder) Reserve() (*Slot, error) {
	if r == nil {
		return nil, ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.healthyLocked(time.Now()) != nil || r.held >= r.cfg.Limits.InFlight || r.entries >= r.cfg.Limits.BufferedEntries || MaxEncodedBytes > r.cfg.Limits.BufferedBytes-r.bytes {
		return nil, ErrUnavailable
	}
	r.held++
	r.entries++
	r.bytes += MaxEncodedBytes
	return &Slot{owner: r}, nil
}
func (s *Slot) Complete(c Completion) (*Receipt, error) {
	if s == nil || s.owner == nil || !s.used.CompareAndSwap(false, true) {
		return nil, ErrInvalid
	}
	r := s.owner
	r.mu.Lock()
	r.ordinal++
	ordinal := r.ordinal
	r.mu.Unlock()
	b := r.run.Binding()
	policy := ""
	if c.PolicyDigest != (Digest{}) {
		policy = hex.EncodeToString(c.PolicyDigest[:])
	}
	e := Envelope{Version: 1, Kind: 1, Network: hex.EncodeToString(b.Metadata.NetworkKey[:]), Generation: b.Metadata.Generation, Configuration: hex.EncodeToString(b.Metadata.Configuration[:]), ProducerID: b.ProducerID, RunID: b.RunID, RecordID: uuid.NewString(), Ordinal: strconv.FormatUint(ordinal, 10), ObservedMicros: r.cfg.Clock().UTC().Truncate(time.Microsecond).UnixMicro(), ActorID: c.ActorID, DataOrg: c.DataOrganizationID, Policy: policy, Method: c.Method, IP: c.TrustedIP, HTTP: c.HTTPStatus, RPCError: detachError(c.RPCErrorCode), Outcome: string(c.Outcome), Status: status(string(c.Outcome))}
	if !slices.Contains(r.cfg.Methods, c.Method) || !validEnvelope(e, false) {
		r.releaseUnused()
		return nil, ErrInvalid
	}
	record := toRecord(e)
	raw, err := EncodeSpool(record)
	if err != nil {
		r.releaseUnused()
		return nil, err
	}
	if _, err = SealEnvelope(record, b.Top); err != nil {
		r.releaseUnused()
		return nil, err
	}
	r.mu.Lock()
	r.bytes -= MaxEncodedBytes - int64(len(raw))
	r.appends[s] = time.Now()
	r.mu.Unlock()
	seq, err := r.buffer.Append(raw) // deliberately synchronous and uncancellable
	r.mu.Lock()
	delete(r.appends, s)
	r.held--
	r.signal()
	r.mu.Unlock()
	if err != nil {
		r.fail(ErrUnavailable, true)
		return nil, ErrUnavailable
	}
	return &Receipt{recordID: e.RecordID, sequence: seq}, nil
}
func (r *Recorder) releaseUnused() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.held--
	r.entries--
	r.bytes -= MaxEncodedBytes
	r.signal()
}
func (r *Recorder) sampleSpace() {
	var s unix.Statfs_t
	err := unix.Statfs(r.cfg.BufferDirectory, &s)
	minimum := max(int64(256<<20), 2*r.cfg.Limits.BufferedBytes)
	ok := err == nil && s.Bsize > 0 && uint64(s.Bavail) >= (uint64(minimum)+uint64(s.Bsize)-1)/uint64(s.Bsize)
	r.mu.Lock()
	r.spaceAt = time.Now()
	r.spaceOK = ok
	r.mu.Unlock()
}
func (r *Recorder) settle(ctx context.Context, hw uint64, entries []buffer.Entry) (uint64, error) {
	keep, err := r.run.Settle(ctx, hw, entries)
	if err != nil {
		r.fail(err, errors.Is(err, sealer.ErrChainAhead) || errors.Is(err, ErrQuarantined) || errors.Is(err, ErrInvalid))
	}
	return keep, err
}
func (r *Recorder) Run(ctx context.Context) error {
	if r == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	if r.running || r.closing {
		r.mu.Unlock()
		return ErrUnavailable
	}
	r.running = true
	runCtx, cancel := context.WithCancel(ctx)
	r.runCancel = cancel
	r.mu.Unlock()
	defer cancel()
	defer close(r.done)
	// One fixed health loop; Append is always executed by the bounded caller.
	healthDone := make(chan struct{})
	go func() {
		defer close(healthDone)
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-tick.C:
				r.sampleSpace()
			}
		}
	}()
	r.sealer.Run(runCtx)
	cancel()
	<-healthDone
	return nil
}

// Close stops new reservations, waits for the TRUE completion of all existing
// slots and the seal loop, and only then closes Pebble. Expiry preserves the
// exclusive ownership; the caller can retry Close after the blocked work ends.
func (r *Recorder) Close(ctx context.Context) error {
	if r == nil {
		return ErrInvalid
	}
	r.mu.Lock()
	r.closing = true
	r.signal()
	r.mu.Unlock()
	// Exactly one lifecycle worker also owns a potentially uncancellable
	// Pebble.Close. Timeout never creates another worker or closes active IO.
	r.closeOnce.Do(func() {
		go func() {
			for {
				r.mu.Lock()
				held, changed := r.held, r.changed
				r.mu.Unlock()
				if held == 0 {
					break
				}
				<-changed
			}
			r.mu.Lock()
			running, cancel := r.running, r.runCancel
			r.mu.Unlock()
			if cancel != nil {
				cancel()
			}
			if running {
				<-r.done
			}
			err := r.buffer.Close()
			r.mu.Lock()
			r.closeErr = err
			r.mu.Unlock()
			close(r.closedDone)
		}()
	})
	select {
	case <-ctx.Done():
		return ErrUnavailable
	case <-r.closedDone:
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.closeErr != nil {
			return ErrUnavailable
		}
		return nil
	}
}

// strictDrainer is the owned B1 bridge around the unchanged generic sealer.
// In particular, Missing is NEVER a license to delete a restored/pruned spool.
type strictDrainer struct{ recorder *Recorder }

func (d *strictDrainer) Drain(after uint64, max int) ([]buffer.Entry, error) {
	r := d.recorder
	entries, err := r.buffer.DrainBounded(after, min(max, r.cfg.Limits.SealBatch), MaxEncodedBytes, MaxBatchBytes)
	if err != nil {
		r.fail(ErrQuarantined, true)
	}
	return entries, err
}
func (d *strictDrainer) SeedFloor(n uint64) error { return d.recorder.buffer.SeedFloor(n) }
func (d *strictDrainer) Seeded() bool             { return d.recorder.buffer.Seeded() }
func (d *strictDrainer) AllocatedThrough() uint64 { return d.recorder.buffer.AllocatedThrough() }
func (d *strictDrainer) DeleteThrough(through uint64) error {
	r := d.recorder
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for {
		batch, err := r.buffer.DrainBounded(0, r.cfg.Limits.SealBatch, MaxEncodedBytes, MaxBatchBytes)
		if err != nil {
			r.fail(ErrQuarantined, true)
			return err
		}
		n := 0
		for n < len(batch) && batch[n].Seq <= through {
			n++
		}
		batch = batch[:n]
		if n == 0 {
			return nil
		}
		verdicts, err := r.run.Verify(ctx, batch)
		if err != nil {
			r.fail(err, errors.Is(err, ErrQuarantined) || errors.Is(err, sealer.ErrChainAhead) || errors.Is(err, ErrInvalid))
			return err
		}
		if len(verdicts) != len(batch) {
			r.fail(ErrQuarantined, true)
			return ErrQuarantined
		}
		var bytes int64
		for i, v := range verdicts {
			if v != sealer.Sealed {
				err := ErrQuarantined
				if v == sealer.Foreign {
					err = sealer.ErrChainAhead
				}
				r.fail(err, true)
				return err
			}
			bytes += int64(len(batch[i].Data))
		}
		// Delete ONLY the last sequence actually captured and exactly verified.
		if err := r.buffer.DeleteThrough(batch[n-1].Seq); err != nil {
			r.fail(ErrUnavailable, false)
			return err
		}
		r.mu.Lock()
		r.entries -= n
		r.bytes -= bytes
		if r.entries < 0 || r.bytes < 0 {
			r.fault = ErrQuarantined
			r.sticky = true
		}
		if !r.sticky {
			r.fault = nil
		}
		r.signal()
		r.mu.Unlock()
		if batch[n-1].Seq >= through {
			return nil
		}
	}
}

// Metadata returns the immutable selected source binding, without credentials,
// filesystem paths, clock or mutable configuration.
func (r *Recorder) Metadata() StoreMetadata {
	if r == nil {
		return StoreMetadata{}
	}
	return r.run.Binding().Metadata
}
func (r *Recorder) Methods() []string {
	if r == nil {
		return nil
	}
	return slices.Clone(r.cfg.Methods)
}
func (r *Recorder) Bounds() Limits {
	if r == nil {
		return Limits{}
	}
	return r.cfg.Limits
}
