package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// siemCapture records every event handed to the SIEM forwarder.
type siemCapture struct {
	mu     sync.Mutex
	events []audit.SIEMEvent
}

func (c *siemCapture) Send(e audit.SIEMEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
}

func (c *siemCapture) byHash() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for _, e := range c.events {
		out[e.EntryHash]++
	}
	return out
}

// ambiguousStore commits through the real audit database and then reports
// the write as failed, as a connection lost after COMMIT would.
type ambiguousStore struct {
	*db.AuditDB
	batchCommitsThenFails  int
	batchFailsWithoutWrite int
	singleCommitsThenFails int
}

func (s *ambiguousStore) SealBufferedAccessLogs(ctx context.Context, chain db.BatchAuditChain, records []db.BufferedAccessLog, name string) ([]db.SealedAccessLog, error) {
	if s.batchFailsWithoutWrite > 0 {
		s.batchFailsWithoutWrite--
		return nil, errors.New("connection reset before the batch was written")
	}
	sealed, err := s.AuditDB.SealBufferedAccessLogs(ctx, chain, records, name)
	if err == nil && s.batchCommitsThenFails > 0 {
		s.batchCommitsThenFails--
		return nil, errors.New("connection reset after COMMIT")
	}
	return sealed, err
}

func (s *ambiguousStore) SealBufferedAccessLog(ctx context.Context, chain db.RBACAuditChain, rec db.AccessLogRecord, seq uint64, name string) (string, error) {
	hash, err := s.AuditDB.SealBufferedAccessLog(ctx, chain, rec, seq, name)
	if err == nil && s.singleCommitsThenFails > 0 {
		s.singleCommitsThenFails--
		return "", errors.New("connection reset after COMMIT")
	}
	return hash, err
}

type sealingHarness struct {
	t       *testing.T
	db      *db.DB
	store   *ambiguousStore
	capture *siemCapture
	name    string
	dir     string
	closed  map[*buffer.Buffer]bool
}

func newSealingHarness(t *testing.T) *sealingHarness {
	t.Helper()
	database := nodePolicyTestDB(t)
	return &sealingHarness{t: t, db: database, store: &ambiguousStore{AuditDB: db.NewAuditHandle(database)}, capture: &siemCapture{}, name: "siem-" + uuid.NewString()[:8], dir: t.TempDir()}
}

// open starts a sealing instance on the harness's buffer directory, as a
// (re)started server would.
func (h *sealingHarness) open(batch bool) (*buffer.Buffer, *sealer.Sealer, *accessLogSealing) {
	h.t.Helper()
	buf, err := buffer.Open(h.dir, buffer.RequireSeed())
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { h.close(buf) })
	head, err := h.store.GetLatestAccessLogHashForChain(context.Background(), h.name)
	if err != nil {
		h.t.Fatal(err)
	}
	sealing := &accessLogSealing{auditDB: h.store, chain: audit.NewHashChain(head), name: h.name, siem: h.capture}
	cfg := sealer.Config{Batch: 16, Settle: sealing.settle}
	if batch {
		cfg.SealBatch = sealing.sealBatch
	}
	s := sealer.New(buf, sealing.seal, sealing.highWater, cfg)
	if err := s.Seed(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	return buf, s, sealing
}

// close closes a buffer once, as the crashed or stopped instance's.
func (h *sealingHarness) close(buf *buffer.Buffer) {
	h.t.Helper()
	if h.closed == nil {
		h.closed = map[*buffer.Buffer]bool{}
	}
	if h.closed[buf] {
		return
	}
	h.closed[buf] = true
	if err := buf.Close(); err != nil {
		h.t.Fatal(err)
	}
}

func (h *sealingHarness) append(buf *buffer.Buffer, n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		rec := db.AccessLogRecord{ExternalID: fmt.Sprintf("did:test:siem-%d", i), Method: "eth_sendRawTransaction", StatusCode: 200, IPAddress: "127.0.0.1", CorrelationID: uuid.NewString()}
		data, err := json.Marshal(rec)
		if err != nil {
			h.t.Fatal(err)
		}
		if _, err := buf.Append(data); err != nil {
			h.t.Fatal(err)
		}
	}
}

func (h *sealingHarness) drain(s *sealer.Sealer) {
	h.t.Helper()
	for i := 0; i < 6; i++ {
		_, _ = s.Tick(context.Background())
	}
}

type chainRow struct {
	seq  uint64
	hash string
}

func (h *sealingHarness) rows() []chainRow {
	h.t.Helper()
	rows, err := h.db.Conn().QueryContext(context.Background(), `SELECT buffer_seq, entry_hash FROM access_logs WHERE chain_name=$1 ORDER BY id`, h.name)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []chainRow
	for rows.Next() {
		var r chainRow
		if err := rows.Scan(&r.seq, &r.hash); err != nil {
			h.t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

// assertForwarded checks every sealed row reached the SIEM forwarder at least
// once (exactly once when exact) with its stored hash, and that the chain
// verifies.
func (h *sealingHarness) assertForwarded(want int, exact bool) {
	h.t.Helper()
	rows := h.rows()
	if len(rows) != want {
		h.t.Fatalf("%d rows sealed, want %d", len(rows), want)
	}
	got := h.capture.byHash()
	for _, r := range rows {
		if got[r.hash] == 0 || (exact && got[r.hash] != 1) {
			h.t.Fatalf("row %d was handed to the SIEM forwarder %d times", r.seq, got[r.hash])
		}
	}
	res, err := audit.NewVerifier(h.db.Conn(), h.db).Verify(context.Background(), audit.ChainAccessLogs)
	if err != nil || !res.OK {
		h.t.Fatalf("chain does not verify: %+v %v", res, err)
	}
}

// A batch that committed but reported failure: its per-record re-seal fails
// on the unique buffer sequence, the high-water passes it, and without
// settling those rows would be in the chain but never forwarded.
func TestAmbiguousBatchCommitIsForwardedToSIEM(t *testing.T) {
	h := newSealingHarness(t)
	h.store.batchCommitsThenFails = 1
	buf, s, _ := h.open(true)
	h.append(buf, 10)
	h.drain(s)
	h.assertForwarded(10, false)
}

func TestFailedBatchIsForwardedOnceBySealingRecordByRecord(t *testing.T) {
	h := newSealingHarness(t)
	h.store.batchFailsWithoutWrite = 1
	buf, s, _ := h.open(true)
	h.append(buf, 10)
	h.drain(s)
	h.assertForwarded(10, true)
}

func TestAmbiguousSingleSealIsForwardedToSIEM(t *testing.T) {
	h := newSealingHarness(t)
	h.store.singleCommitsThenFails = 1
	buf, s, _ := h.open(false)
	h.append(buf, 5)
	h.drain(s)
	h.assertForwarded(5, false)
}

// A restart after rows were sealed but before they were forwarded and deleted
// from the buffer: the next instance forwards them from the buffer entries at
// or below the chain's high-water.
func TestRowsSealedBeforeARestartAreForwarded(t *testing.T) {
	h := newSealingHarness(t)
	buf, _, sealing := h.open(true)
	h.append(buf, 6)
	entries, err := buf.Drain(0, 100)
	if err != nil {
		t.Fatal(err)
	}
	records := make([]db.BufferedAccessLog, 0, len(entries))
	for _, e := range entries {
		var rec db.AccessLogRecord
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			t.Fatal(err)
		}
		records = append(records, db.BufferedAccessLog{Seq: e.Seq, Record: rec})
	}
	// Sealed by the instance that then crashed: in the chain, never forwarded,
	// still in the buffer.
	if _, err := h.store.AuditDB.SealBufferedAccessLogs(context.Background(), sealing.chain, records, h.name); err != nil {
		t.Fatal(err)
	}
	h.close(buf)
	_, s, _ := h.open(true)
	h.drain(s)
	h.assertForwarded(6, true)
}

// A row under one of this buffer's sequences that holds another record (a
// second writer on the chain) is not forwarded as this instance's event, and
// the sealer stops without deleting this instance's own, unsealed entry.
func TestSettleNeverForwardsAnotherWritersRow(t *testing.T) {
	h := newSealingHarness(t)
	buf, _, sealing := h.open(true)
	h.append(buf, 1)
	foreign := db.AccessLogRecord{ExternalID: "did:test:someone-else", Method: "eth_call", StatusCode: 200, CorrelationID: "foreign"}
	if _, err := h.store.AuditDB.SealBufferedAccessLog(context.Background(), sealing.chain, foreign, 1, h.name); err != nil {
		t.Fatal(err)
	}
	h.close(buf)
	reopened, s, _ := h.open(true)
	if _, err := s.Tick(context.Background()); !errors.Is(err, sealer.ErrChainAhead) {
		t.Fatalf("tick: %v, want ErrChainAhead", err)
	}
	if n := len(h.capture.byHash()); n != 0 {
		t.Fatalf("another writer's row was forwarded (%d events)", n)
	}
	if pending, _ := reopened.PendingCount(); pending != 1 {
		t.Fatalf("%d buffer entries left: this instance's own record was deleted", pending)
	}
}

// lateStore reports a committed row only from the second read on, as a commit
// that becomes visible after its client saw an error.
type lateStore struct {
	accessLogStore
	reads int
	row   db.SealedAccessLogRow
}

func (s *lateStore) SealedAccessLogsBySeq(context.Context, string, []uint64) ([]db.SealedAccessLogRow, error) {
	s.reads++
	if s.reads == 1 {
		return nil, nil
	}
	return []db.SealedAccessLogRow{s.row}, nil
}

func TestUnsettledRecordWaitsForALateVisibleCommit(t *testing.T) {
	capture := &siemCapture{}
	rec := db.AccessLogRecord{ExternalID: "did:test:late", Method: "eth_call", StatusCode: 200, CorrelationID: "late"}
	store := &lateStore{row: db.SealedAccessLogRow{Seq: 7, ExternalID: rec.ExternalID, Method: rec.Method, StatusCode: rec.StatusCode, CorrelationID: rec.CorrelationID, EntryHash: "hash-7"}}
	sealing := &accessLogSealing{auditDB: store, name: "late", siem: capture}
	sealing.unsettle(7, rec)
	// Not visible yet; 7 is above the high-water, and its buffer entry is kept.
	if keep, err := sealing.settle(context.Background(), 6, nil); err != nil || keep != 7 {
		t.Fatalf("keep %d, %v", keep, err)
	}
	if len(capture.byHash()) != 0 || len(sealing.unsettled) != 1 {
		t.Fatal("an unseen record was dropped or forwarded")
	}
	if keep, err := sealing.settle(context.Background(), 6, nil); err != nil || keep != 0 {
		t.Fatalf("keep %d, %v", keep, err)
	}
	if capture.byHash()["hash-7"] != 1 || len(sealing.unsettled) != 0 {
		t.Fatalf("the late commit was not forwarded once: %v", capture.byHash())
	}
	// A sequence at or below the high-water that is not in the chain is dropped.
	sealing.unsettle(3, rec)
	store.row.Seq = 99
	if keep, err := sealing.settle(context.Background(), 5, nil); err != nil || keep != 0 || len(sealing.unsettled) != 0 {
		t.Fatalf("an unresolvable record stays unsettled: keep %d, %v", keep, err)
	}
}

// failingReadStore cannot read back sealed records.
type failingReadStore struct {
	accessLogStore
	reads int
}

func (s *failingReadStore) SealedAccessLogsBySeq(context.Context, string, []uint64) ([]db.SealedAccessLogRow, error) {
	s.reads++
	return nil, errors.New("audit database unreachable")
}

// A failed read keeps the unsettled entries in the buffer and is retried at
// most once a second, not twice per tick.
func TestSettleReadFailureKeepsEntriesAndBacksOff(t *testing.T) {
	store := &failingReadStore{}
	sealing := &accessLogSealing{auditDB: store, name: "down", siem: &siemCapture{}}
	sealing.unsettle(4, db.AccessLogRecord{ExternalID: "did:test:down", Method: "eth_call"})
	sealing.unsettle(9, db.AccessLogRecord{ExternalID: "did:test:down", Method: "eth_call"})
	for i := 0; i < 3; i++ {
		if keep, err := sealing.settle(context.Background(), 100, nil); err != nil || keep != 4 {
			t.Fatalf("keep %d, %v", keep, err)
		}
	}
	if store.reads != 1 || len(sealing.unsettled) != 2 {
		t.Fatalf("reads %d, unsettled %d", store.reads, len(sealing.unsettled))
	}
}
