package server

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// Review findings 1 and 2: several instances with an async audit buffer share
// one audit database. Each test runs two buffers (two instances) through the
// production sealing wiring against one audit database, with one shared or
// two distinct chain names, and asserts that every record is sealed exactly
// once and every chain verifies.

type auditInstance struct {
	t     *testing.T
	store *db.AuditDB
	chain string
	dir   string
	buf   *buffer.Buffer
	seal  *sealer.Sealer
}

func startAuditInstance(t *testing.T, store *db.AuditDB, chain, dir string) *auditInstance {
	t.Helper()
	inst := &auditInstance{t: t, store: store, chain: chain, dir: dir}
	inst.restart()
	return inst
}

// restart (re)opens the instance's buffer directory as a starting server does.
func (i *auditInstance) restart() {
	i.t.Helper()
	if i.buf != nil {
		if err := i.buf.Close(); err != nil {
			i.t.Fatal(err)
		}
	}
	buf, s, _, err := openAccessLogSealing(context.Background(), i.store, i.dir, i.chain, nil, nil)
	if err != nil {
		i.t.Fatal(err)
	}
	i.buf, i.seal = buf, s
	i.t.Cleanup(func() {
		if i.buf == buf {
			_ = buf.Close()
			i.buf = nil
		}
	})
}

func (i *auditInstance) append(n int, tag string) {
	i.t.Helper()
	for k := 0; k < n; k++ {
		rec := db.AccessLogRecord{ExternalID: fmt.Sprintf("did:test:%s-%d", tag, k), Method: "eth_call", StatusCode: 200, IPAddress: "127.0.0.1", CorrelationID: uuid.NewString()}
		data, err := json.Marshal(rec)
		if err != nil {
			i.t.Fatal(err)
		}
		if _, err := i.buf.Append(data); err != nil {
			i.t.Fatal(err)
		}
	}
}

func (i *auditInstance) tick() {
	i.t.Helper()
	for k := 0; k < 3; k++ {
		if _, err := i.seal.Tick(context.Background()); err != nil {
			i.t.Fatalf("%s tick: %v", i.chain, err)
		}
	}
}

func (i *auditInstance) pending() int {
	i.t.Helper()
	n, err := i.buf.PendingCount()
	if err != nil {
		i.t.Fatal(err)
	}
	return n
}

// assertSealed checks that exactly the records tagged with each prefix are in
// the audit database, once each, and that every chain verifies.
func assertSealed(t *testing.T, database *db.DB, want map[string]int) {
	t.Helper()
	for tag, n := range want {
		var got, distinct int
		if err := database.Conn().QueryRowContext(context.Background(),
			`SELECT count(*), count(DISTINCT correlation_id) FROM access_logs WHERE external_id LIKE $1`, "did:test:"+tag+"-%").Scan(&got, &distinct); err != nil {
			t.Fatal(err)
		}
		if got != n || distinct != n {
			t.Fatalf("%s: %d rows (%d distinct records) sealed, want %d once each", tag, got, distinct, n)
		}
	}
	res, err := audit.NewVerifier(database.Conn(), database).Verify(context.Background(), audit.ChainAccessLogs)
	if err != nil || !res.OK {
		t.Fatalf("the chains do not verify: %+v %v", res, err)
	}
}

// Finding 1 at startup: instance B restarts with unsealed records while A,
// on the same chain name, has sealed that chain further meanwhile.
func TestSharedChainRestartKeepsUnsealedRecords(t *testing.T) {
	database := nodePolicyTestDB(t)
	store := db.NewAuditHandle(database)
	a := startAuditInstance(t, store, "access_logs", t.TempDir())
	b := startAuditInstance(t, store, "access_logs", t.TempDir())
	b.append(3, "b")
	a.append(10, "a")
	a.tick()
	b.restart()
	b.tick()
	if p := b.pending(); p != 0 {
		t.Fatalf("%d of B's records still buffered", p)
	}
	assertSealed(t, database, map[string]int{"a": 10, "b": 3})
}

// Finding 1 while running: A seals part of the shared chain between B's
// appends and B's tick.
func TestSharedChainRunningInstancesBothSeal(t *testing.T) {
	database := nodePolicyTestDB(t)
	store := db.NewAuditHandle(database)
	a := startAuditInstance(t, store, "access_logs", t.TempDir())
	b := startAuditInstance(t, store, "access_logs", t.TempDir())
	b.tick()
	b.append(5, "b")
	a.append(3, "a")
	a.tick()
	b.tick()
	a.append(2, "a2")
	b.append(2, "b2")
	b.tick()
	a.tick()
	assertSealed(t, database, map[string]int{"a": 3, "b": 5, "a2": 2, "b2": 2})
}

// Finding 2: two instances with distinct chain names both seal; neither
// collides with the other's buffer sequences.
func TestDistinctChainsBothSeal(t *testing.T) {
	database := nodePolicyTestDB(t)
	store := db.NewAuditHandle(database)
	a := startAuditInstance(t, store, "inst-a", t.TempDir())
	a.append(5, "a")
	a.tick()
	b := startAuditInstance(t, store, "inst-b", t.TempDir())
	b.append(3, "b")
	b.tick()
	a.append(2, "a2")
	a.tick()
	if p := b.pending(); p != 0 {
		t.Fatalf("%d of B's records still buffered", p)
	}
	assertSealed(t, database, map[string]int{"a": 5, "b": 3, "a2": 2})
}

// Fix review, finding 1: two instances of the earlier release shared the
// default chain and numbered their entries the old way (per chain, from 1).
// A sealed 1..5; B still buffers its own 1..3. After the upgrade B's entries
// are below the shared chain's high-water but are not B's records there: they
// are sealed into B's new range, with no SIEM involved, and nothing is lost.
func TestLegacySharedChainLeftoversAreSealedAfterUpgrade(t *testing.T) {
	database := nodePolicyTestDB(t)
	store := db.NewAuditHandle(database)
	ctx := context.Background()
	records := func(tag string, n int) []db.BufferedAccessLog {
		out := make([]db.BufferedAccessLog, n)
		for k := range out {
			out[k] = db.BufferedAccessLog{Seq: uint64(k + 1), Record: db.AccessLogRecord{ExternalID: fmt.Sprintf("did:test:%s-%d", tag, k), Method: "eth_call", StatusCode: 200, IPAddress: "127.0.0.1", CorrelationID: uuid.NewString()}}
		}
		return out
	}
	if _, err := store.SealBufferedAccessLogs(ctx, audit.NewHashChain(""), records("a", 5), "access_logs"); err != nil {
		t.Fatal(err)
	}
	dirB := t.TempDir()
	legacy, err := buffer.Open(dirB)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records("b", 3) {
		data, err := json.Marshal(r.Record)
		if err != nil {
			t.Fatal(err)
		}
		if seq, err := legacy.Append(data); err != nil || seq != r.Seq {
			t.Fatalf("legacy append %d %v", seq, err)
		}
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	b := startAuditInstance(t, store, "access_logs", dirB)
	b.tick()
	if p := b.pending(); p != 0 {
		t.Fatalf("%d of B's records still buffered", p)
	}
	assertSealed(t, database, map[string]int{"a": 5, "b": 3})
}

// Fix re-review, finding B: an entry that moved to a new sequence is no
// longer followed up under its old one (another record is stored there).
func TestMovedEntryIsNotSettledUnderItsOldSequence(t *testing.T) {
	sealing := &accessLogSealing{siem: &siemCapture{}}
	sealing.unsettle(3, db.AccessLogRecord{ExternalID: "did:test:moved", Method: "eth_call"})
	sealing.moved(3, 1<<40+7)
	if len(sealing.unsettled) != 0 {
		t.Fatalf("still unsettled: %v", sealing.unsettled)
	}
}
