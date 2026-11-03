package db_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// eventMix is the gate-2 audit mix (RD-1410): one request record and
// one ops.system.finalized-shaped system record with populated params per
// transaction, about 170 B and 526 B buffered.
func eventMix(i int) db.AccessLogRecord {
	did := fmt.Sprintf("did:test:mix-user-%03d", i%300)
	correlation := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
	if i%2 == 0 {
		return db.AccessLogRecord{ExternalID: did, Method: "eth_sendRawTransaction", StatusCode: 200, IPAddress: "127.0.0.1", CorrelationID: correlation, OrgID: "11111111-1111-4111-8111-111111111111"}
	}
	status := 403
	return db.AccessLogRecord{ExternalID: did, Method: "ops.system.finalized", StatusCode: 200, ResponseStatus: &status, CorrelationID: correlation, OrgID: "11111111-1111-4111-8111-111111111111", DenialReason: "",
		Params: []byte(fmt.Sprintf(`{"tx_hash":"0x%064x","context_id":"%s","generation":1,"actor":"system:identity-renewal"}`, i, correlation))}
}

// batchSealer is the production pair the server installs: a batch seal
// through SealBufferedAccessLogs and the per-record fallback, both on one
// chain, plus a counter of batch writes.
type batchSealer struct {
	auditDB *db.AuditDB
	chain   *audit.HashChain
	name    string
	batches atomic.Int64
}

func (b *batchSealer) sealBatch(ctx context.Context, entries []buffer.Entry) error {
	b.batches.Add(1)
	records := make([]db.BufferedAccessLog, 0, len(entries))
	for _, e := range entries {
		var rec db.AccessLogRecord
		if err := json.Unmarshal(e.Data, &rec); err != nil {
			continue
		}
		records = append(records, db.BufferedAccessLog{Seq: e.Seq, Record: rec})
	}
	_, err := b.auditDB.SealBufferedAccessLogs(ctx, b.chain, records, b.name)
	return err
}

func (b *batchSealer) seal(ctx context.Context, seq uint64, data []byte) error {
	var rec db.AccessLogRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil
	}
	_, err := b.auditDB.SealBufferedAccessLog(ctx, b.chain, rec, seq, b.name)
	return err
}

func (b *batchSealer) highWater(ctx context.Context) (uint64, error) {
	return b.auditDB.GetMaxAccessLogBufferSeq(ctx, b.name)
}

func newBatchSealer(t *testing.T, database *db.DB, name string) *batchSealer {
	t.Helper()
	auditDB := db.NewAuditHandle(database)
	seed, err := auditDB.GetLatestAccessLogHashForChain(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return &batchSealer{auditDB: auditDB, chain: audit.NewHashChain(seed), name: name}
}

func fillConcurrently(t *testing.T, buf *buffer.Buffer, from, n int) {
	t.Helper()
	var wg sync.WaitGroup
	for w := 0; w < 64; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := from + w; i < from+n; i += 64 {
				data, _ := json.Marshal(eventMix(i))
				if _, err := buf.Append(data); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
}

func verifyAccessChain(t *testing.T, database *db.DB, rows int) {
	t.Helper()
	res, err := audit.NewVerifier(database.Conn(), database).Verify(context.Background(), audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK || res.ScannedRows != int64(rows) {
		t.Fatalf("chain not OK: ok=%v reason=%s id=%d scanned=%d want %d", res.OK, res.FirstMismatchReason, res.FirstMismatchID, res.ScannedRows, rows)
	}
}

// G65 (RD-1410), structural and always on: a backlog of the
// real event mix seals in one tick, in a handful of multi-row writes instead
// of one INSERT per record and 500 records per 1 s tick (P0: 92-159 records/s
// in the full server), and the result is a valid chain.
func TestSealerKeepsUpAtRealEventMix(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	buf, err := buffer.Open(t.TempDir(), buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	b := newBatchSealer(t, database, "access_logs")
	s := sealer.New(buf, b.seal, b.highWater, sealer.Config{Batch: 2000, SealBatch: b.sealBatch})
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	const n = 5000
	fillConcurrently(t, buf, 0, n)
	started := time.Now()
	sealed, err := s.Tick(ctx)
	if err != nil || sealed != n {
		t.Fatalf("one tick sealed %d %v, want %d", sealed, err, n)
	}
	t.Logf("sealed %d records in %s with %d batch writes", n, time.Since(started).Round(time.Millisecond), b.batches.Load())
	if got := b.batches.Load(); got != 3 {
		t.Fatalf("%d batch writes for %d records, want 3", got, n)
	}
	verifyAccessChain(t, database, n)
	// The sealed rows carry the same content the request path buffered.
	var params, method string
	if err := database.Conn().QueryRowContext(ctx, `SELECT method, COALESCE(request_params,'') FROM access_logs WHERE buffer_seq=2`).Scan(&method, &params); err != nil {
		t.Fatal(err)
	}
	if method != "ops.system.finalized" && method != "eth_sendRawTransaction" {
		t.Fatalf("method %q", method)
	}
	if method == "ops.system.finalized" && !strings.HasPrefix(params, `{"tx_hash"`) {
		t.Fatalf("params stored as %q, want the JSON text", params)
	}
}

// G66 against the real audit table: the drained-restart case and the
// recreated-directory case. After a full drain and reopen, and after the
// buffer directory is lost while the chain is at high-water N, the next event
// gets a sequence above everything sealed and is sealed.
func TestAuditBufferNeverDeletesUnsealedAppend(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	b := newBatchSealer(t, database, "access_logs")
	open := func(dir string) (*buffer.Buffer, *sealer.Sealer) {
		buf, err := buffer.Open(dir, buffer.RequireSeed())
		if err != nil {
			t.Fatal(err)
		}
		s := sealer.New(buf, b.seal, b.highWater, sealer.Config{SealBatch: b.sealBatch})
		if err := s.Seed(ctx); err != nil {
			t.Fatal(err)
		}
		return buf, s
	}
	appendOne := func(buf *buffer.Buffer, i int) uint64 {
		data, _ := json.Marshal(eventMix(i))
		seq, err := buf.Append(data)
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}
	dir := t.TempDir()
	buf, s := open(dir)
	appendOne(buf, 0)
	if n, err := s.Tick(ctx); err != nil || n != 1 {
		t.Fatalf("first tick %d %v", n, err)
	}
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}
	// Drained restart: same directory, reopened empty.
	buf, s = open(dir)
	if seq := appendOne(buf, 1); seq != 2 {
		t.Fatalf("after a drained restart the next sequence is %d, want 2", seq)
	}
	if n, err := s.Tick(ctx); err != nil || n != 1 {
		t.Fatalf("drained restart: the second event was not sealed (%d %v)", n, err)
	}
	if err := buf.Close(); err != nil {
		t.Fatal(err)
	}
	// Recreated directory: an empty one, while the chain is at high-water 2.
	buf, s = open(t.TempDir())
	defer buf.Close()
	if seq := appendOne(buf, 2); seq != 3 {
		t.Fatalf("a recreated buffer started at %d, want 3 (above the sealed high-water)", seq)
	}
	if n, err := s.Tick(ctx); err != nil || n != 1 {
		t.Fatalf("recreated directory: the event was not sealed (%d %v)", n, err)
	}
	verifyAccessChain(t, database, 3)
}

// TestSealerSustainedRateMicrobenchmark is the timed half of G65: 10,500
// appends/s (2 records × 5,250 tx/s) for 10 s with the sealer running, the
// buffer must stay bounded and drain promptly. A microbenchmark against the
// test Postgres, gated: OPS_PERF=1.
func TestSealerSustainedRateMicrobenchmark(t *testing.T) {
	if os.Getenv("OPS_PERF") != "1" {
		t.Skip("set OPS_PERF=1 to run the sealer rate microbenchmark")
	}
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	buf, err := buffer.Open(t.TempDir(), buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	b := newBatchSealer(t, database, "access_logs")
	s := sealer.New(buf, b.seal, b.highWater, sealer.Config{SealBatch: b.sealBatch})
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	runCtx, stop := context.WithCancel(ctx)
	go s.Run(runCtx)
	defer func() { stop(); s.Wait() }()
	const rate, seconds = 10_500, 10
	start := time.Now()
	var wg sync.WaitGroup
	var failed atomic.Int64
	for i := 0; i < rate*seconds; i++ {
		if d := time.Until(start.Add(time.Duration(i) * time.Second / rate)); d > 0 {
			time.Sleep(d)
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data, _ := json.Marshal(eventMix(i))
			if _, err := buf.Append(data); err != nil {
				failed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	offeredFor := time.Since(start)
	sealedAtEnd, _ := b.highWater(ctx)
	backlog := int64(rate*seconds) - int64(sealedAtEnd)
	drainStart := time.Now()
	for {
		hw, _ := b.highWater(ctx)
		if hw >= uint64(rate*seconds) || time.Since(drainStart) > 30*time.Second {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	drain := time.Since(drainStart)
	t.Logf("offered %d records in %s (%.0f/s), backlog at end %d, drained in %s, %d batch writes, %d append failures",
		rate*seconds, offeredFor.Round(time.Millisecond), float64(rate*seconds)/offeredFor.Seconds(), backlog, drain.Round(time.Millisecond), b.batches.Load(), failed.Load())
	if failed.Load() != 0 || backlog > rate || drain > 5*time.Second {
		t.Fatalf("the sealer did not keep up: backlog %d (> 1 s of appends) or drain %s", backlog, drain)
	}
}

// A record that Postgres text cannot store as sent (a NUL byte, an oversize
// method) is made storable before hashing, so it seals, in a batch, and the
// chain verifies, instead of failing on every tick.
func TestUnstorableFieldsAreCleanedBeforeSealing(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()
	buf, err := buffer.Open(t.TempDir(), buffer.RequireSeed())
	if err != nil {
		t.Fatal(err)
	}
	defer buf.Close()
	b := newBatchSealer(t, database, "access_logs")
	s := sealer.New(buf, b.seal, b.highWater, sealer.Config{SealBatch: b.sealBatch})
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	for _, rec := range []db.AccessLogRecord{
		{ExternalID: "did:test:nul", Method: "eth_call\x00", StatusCode: 404},
		{ExternalID: "did:test:long", Method: strings.Repeat("m", 300), StatusCode: 404, CorrelationID: strings.Repeat("c", 200)},
		eventMix(1),
	} {
		data, _ := json.Marshal(rec)
		if _, err := buf.Append(data); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.Tick(ctx); err != nil || n != 3 || b.batches.Load() != 1 {
		t.Fatalf("sealed %d %v in %d batch writes, want 3 in 1", n, err, b.batches.Load())
	}
	verifyAccessChain(t, database, 3)
	var method string
	if err := database.Conn().QueryRowContext(ctx, `SELECT method FROM access_logs WHERE buffer_seq=1`).Scan(&method); err != nil || method != "eth_call�" {
		t.Fatalf("stored method %q %v", method, err)
	}
}
