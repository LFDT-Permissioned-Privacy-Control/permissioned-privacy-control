package activitylog

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/networkidentity"
)

// This in-memory test Store isolates actual Pebble/lifecycle behavior. Actual
// SQL role/seal/hash/recovery qualification lives in activitysql's PG tests.
type testStore struct {
	mu       sync.Mutex
	metadata StoreMetadata
	next     uint64
	sealed   map[uint64]string
	forced   *sealer.Verdict
}
type testRun struct {
	store   *testStore
	binding RunBinding
}

func (s *testStore) Metadata() StoreMetadata { return s.metadata }
func (s *testStore) StartRun(_ context.Context, r RunRequest) (RunStore, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = max(s.next, r.AllocatedThrough>>40) + 1
	return &testRun{s, RunBinding{Metadata: s.metadata, ProducerID: r.ProducerID, RunID: r.RunID, RangeIndex: s.next, Base: s.next << 40, Top: (s.next << 40) + (1 << 40) - 1}}, nil
}
func (r *testRun) Binding() RunBinding { return r.binding }
func (r *testRun) HighWater(ctx context.Context) (uint64, error) {
	return r.RangeHighWater(ctx, r.binding.RangeIndex)
}
func (r *testRun) RangeHighWater(_ context.Context, index uint64) (uint64, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	var hw uint64
	for seq := range r.store.sealed {
		if seq>>40 == index {
			hw = max(hw, seq)
		}
	}
	return hw, nil
}
func (r *testRun) Verify(_ context.Context, entries []buffer.Entry) ([]sealer.Verdict, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	out := []sealer.Verdict{}
	for _, e := range entries {
		if r.store.forced != nil {
			out = append(out, *r.store.forced)
			continue
		}
		record, err := DecodeSpool(e.Data)
		if err != nil {
			return nil, err
		}
		body, _ := SealEnvelope(record, e.Seq)
		got, ok := r.store.sealed[e.Seq]
		v := sealer.Missing
		if ok {
			v = sealer.Sealed
			if got != string(body) {
				v = sealer.Foreign
			}
		}
		out = append(out, v)
	}
	return out, nil
}
func (r *testRun) SealOne(ctx context.Context, seq uint64, data []byte) error {
	return r.SealBatch(ctx, []buffer.Entry{{Seq: seq, Data: data}})
}
func (r *testRun) SealBatch(_ context.Context, entries []buffer.Entry) error {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()
	for _, e := range entries {
		record, err := DecodeSpool(e.Data)
		if err != nil {
			return err
		}
		body, _ := SealEnvelope(record, e.Seq)
		if old, ok := r.store.sealed[e.Seq]; ok && old != string(body) {
			return sealer.ErrChainAhead
		}
		r.store.sealed[e.Seq] = string(body)
	}
	return nil
}
func (r *testRun) Settle(ctx context.Context, _ uint64, entries []buffer.Entry) (uint64, error) {
	v, err := r.Verify(ctx, entries)
	if err != nil {
		return 0, err
	}
	for i, verdict := range v {
		if verdict == sealer.Foreign {
			return entries[i].Seq, sealer.ErrChainAhead
		}
		if verdict != sealer.Sealed {
			return entries[i].Seq, nil
		}
	}
	return 0, nil
}
func recorderFixture(t *testing.T) (Config, *testStore) {
	t.Helper()
	network := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: "0x0000000000000000000000000000000000000000000000000000000000000001", DeploymentID: "recorder-test"}
	key, _ := network.Key()
	c := Config{Network: network, SourceID: uuid.NewString(), ProducerID: uuid.NewString(), ExpectedGeneration: uuid.NewString(), Configuration: Digest{1}, Methods: []string{"eth_call"}, Clock: func() time.Time { return time.Unix(1700000000, 123456789) }, BufferDirectory: t.TempDir(), Limits: Limits{InFlight: 4, BufferedEntries: 8, BufferedBytes: 8 * MaxEncodedBytes, SealBatch: 4}}
	s := &testStore{metadata: StoreMetadata{NetworkKey: Digest(key), SourceID: c.SourceID, Generation: c.ExpectedGeneration, Configuration: c.Configuration, Format: Format()}, sealed: map[uint64]string{}}
	return c, s
}
func completion() Completion {
	return Completion{Method: "eth_call", HTTPStatus: 200, Outcome: Success}
}

func TestRecorderUncancellableAppendRetainsSlotAndCloseOwnership(t *testing.T) {
	c, store := recorderFixture(t)
	c.Limits.InFlight = 1
	entered, release := make(chan struct{}), make(chan struct{})
	r, err := newRecorder(t.Context(), c, store, []buffer.Option{buffer.WithBeforeSetForTest(func(uint64) error { close(entered); <-release; return nil })})
	if err != nil {
		t.Fatal(err)
	}
	slot, err := r.Reserve()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := slot.Complete(completion()); done <- err }()
	<-entered
	if _, err := r.Reserve(); err == nil {
		t.Fatal("replacement slot while actual Append is blocked")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := r.Close(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("close must time out without claiming drain", err)
	}
	if other, err := buffer.Open(c.BufferDirectory); err == nil {
		other.Close()
		t.Fatal("timed-out Close released active Pebble ownership")
	}
	if _, err := slot.Complete(completion()); !errors.Is(err, ErrInvalid) {
		t.Fatal("slot reused", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := r.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestRecorderCompletedPublicationFrontierAndOriginalTime(t *testing.T) {
	c, store := recorderFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	r, err := newRecorder(t.Context(), c, store, []buffer.Option{buffer.WithBeforeSetForTest(func(seq uint64) error {
		if seq&((1<<40)-1) == 1 {
			close(entered)
			<-release
		}
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(t.Context())
	one, _ := r.Reserve()
	two, _ := r.Reserve()
	done := make(chan error, 1)
	go func() { _, err := one.Complete(completion()); done <- err }()
	<-entered
	receipt, err := two.Complete(completion())
	if err != nil || receipt.Sequence() != r.run.Binding().Base+2 {
		t.Fatal(receipt, err)
	}
	if page, err := r.buffer.DrainBounded(0, 4, MaxEncodedBytes, MaxBatchBytes); err != nil || len(page) != 0 {
		t.Fatal("uncompleted frontier crossed", page, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	page, err := r.buffer.DrainBounded(0, 4, MaxEncodedBytes, MaxBatchBytes)
	if err != nil || len(page) != 2 {
		t.Fatal(page, err)
	}
	for i, entry := range page {
		record, err := DecodeSpool(entry.Data)
		if err != nil || record.Fields().ObservedMicros != 1700000000123456 || record.Fields().Ordinal != strconv.Itoa(i+1) {
			t.Fatal(record.Fields(), err)
		}
	}
	if _, err := r.sealer.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries != 0 || r.bytes != 0 || r.held != 0 {
		t.Fatal("credits not released after actual verified deletion", r.entries, r.bytes, r.held)
	}
}
func TestRecorderStrictDeleteNeverTreatsMissingAsSealed(t *testing.T) {
	c, store := recorderFixture(t)
	r, err := New(t.Context(), c, store)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(t.Context())
	slot, _ := r.Reserve()
	receipt, err := slot.Complete(completion())
	if err != nil {
		t.Fatal(err)
	}
	page, _ := r.buffer.DrainBounded(0, 4, MaxEncodedBytes, MaxBatchBytes)
	if err := r.run.SealBatch(t.Context(), page); err != nil {
		t.Fatal(err)
	}
	missing := sealer.Missing
	store.mu.Lock()
	store.forced = &missing
	store.mu.Unlock()
	if err := (&strictDrainer{r}).DeleteThrough(receipt.Sequence() + 100); !errors.Is(err, ErrQuarantined) {
		t.Fatal("missing incorrectly deleted", err)
	}
	page, err = r.buffer.DrainBounded(0, 4, MaxEncodedBytes, MaxBatchBytes)
	if err != nil || len(page) != 1 {
		t.Fatal("original spool lost", page, err)
	}
	if r.Healthy() == nil {
		t.Fatal("quarantined recorder remained ready")
	}
}
func TestRecorderInvalidCompletionAndAppendFailureAccounting(t *testing.T) {
	t.Run("invalid releases unused reservation", func(t *testing.T) {
		c, s := recorderFixture(t)
		r, err := New(t.Context(), c, s)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(t.Context())
		slot, _ := r.Reserve()
		bad := completion()
		bad.Method = "unconfigured"
		if _, err := slot.Complete(bad); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.entries != 0 || r.bytes != 0 || r.held != 0 {
			t.Fatal("unused credits leaked")
		}
	})
	t.Run("actual append failure latches and retains uncertain credit", func(t *testing.T) {
		c, s := recorderFixture(t)
		r, err := newRecorder(t.Context(), c, s, []buffer.Option{buffer.WithBeforeSetForTest(func(uint64) error { return errors.New("public test injected local write failure") })})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close(t.Context())
		slot, _ := r.Reserve()
		if _, err := slot.Complete(completion()); err == nil {
			t.Fatal("failed append reported receipt")
		}
		if _, err := r.Reserve(); err == nil {
			t.Fatal("failed recorder admitted work")
		}
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.entries != 1 || r.bytes < 1 || r.held != 0 {
			t.Fatal("uncertain actual bytes/entry not retained")
		}
	})
}

func TestRecorderAll256ActualOutstandingAppendsStayBounded(t *testing.T) {
	c, s := recorderFixture(t)
	c.Limits = DefaultLimits()
	entered := make(chan struct{}, 256)
	release := make(chan struct{})
	r, err := newRecorder(t.Context(), c, s, []buffer.Option{buffer.WithBeforeSetForTest(func(uint64) error { entered <- struct{}{}; <-release; return nil })})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithCancel(t.Context())
	runDone := make(chan error, 1)
	go func() { runDone <- r.Run(runCtx) }()
	slots := make([]*Slot, 256)
	for i := range slots {
		slots[i], err = r.Reserve()
		if err != nil {
			t.Fatal("finite slot", i, err)
		}
	}
	done := make(chan error, 256)
	for _, slot := range slots {
		go func() { _, err := slot.Complete(completion()); done <- err }()
	}
	for range slots {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("actual append did not enter bounded IO")
		}
	}
	if _, err := r.Reserve(); err == nil {
		t.Fatal("257th append admitted")
	}
	time.Sleep(1100 * time.Millisecond)
	if r.Healthy() == nil {
		t.Fatal("actual >1s blocked appends remained healthy")
	}
	ctx, closeCancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	if err := r.Close(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("close falsely drained outstanding appends", err)
	}
	closeCancel()
	close(release)
	for range slots {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	cancel()
	<-runDone
	if err := r.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRecorderColdMetadataTypedNilAndZeroChecks(t *testing.T) {
	c, s := recorderFixture(t)
	var nilStore *testStore
	if _, err := New(t.Context(), c, nilStore); !errors.Is(err, ErrInvalid) {
		t.Fatal("typed nil store", err)
	}
	s.metadata.Format = Digest{}
	if _, err := New(t.Context(), c, s); err == nil {
		t.Fatal("zero/wrong format accepted")
	}
	s.metadata.Format = Format()
	c.Methods = []string{"eth_call", "eth_call"}
	if _, err := New(t.Context(), c, s); !errors.Is(err, ErrInvalid) {
		t.Fatal("duplicate method config", err)
	}
}
