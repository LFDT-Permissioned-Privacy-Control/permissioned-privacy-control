package db_test

// RD-1112 v0.12.0 coverage gaps: real-DB integration of the audit WRITE path.
//
// The package-level units (sealer, buffer, checkpoint, verifier, reanchor)
// already have in-memory-fake unit tests. These tests close the gap by driving
// the WIRED path end-to-end against a real, migrated Postgres (migrations
// 062/063/064 applied by the harness) plus a real Pebble buffer — the same
// pieces server.go wires together at startup — and asserting the persisted
// outcome, not a fake's recorded calls.
//
// Reuses setupIntegrityTestDB from audit_integrity_test.go (same db_test
// package), which spins a Postgres testcontainer, runs all migrations, and
// resets data tables for isolation.

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// dbCheckpointAdapter mirrors server.checkpointAdapter (which is unexported, so
// it cannot be reused from a test): it bridges *db.DB to the audit package's
// CheckpointStore, CheckpointReader and ReAnchorStore interfaces. This is the
// SAME mapping the server installs in production (server.go ~L113-150) — the
// test drives the real adapter funcs (GetAccessLogChainStats,
// WriteAuditChainCheckpoint, GetLatestAuditChainCheckpoint, UpsertAuditChainAnchor,
// WriteAuditChainReAnchor) against the real DB.
type dbCheckpointAdapter struct{ db *db.DB }

func (a dbCheckpointAdapter) ChainStats(ctx context.Context, chainName string) (int64, int64, string, error) {
	return a.db.GetAccessLogChainStats(ctx, chainName)
}

func (a dbCheckpointAdapter) WriteCheckpoint(ctx context.Context, c audit.Checkpoint) error {
	return a.db.WriteAuditChainCheckpoint(ctx, db.AuditChainCheckpointRow{
		ChainName: c.ChainName, HeadID: c.HeadID, HeadHash: c.HeadHash,
		RowCount: c.RowCount, KeyID: c.KeyID, Signature: c.Signature, CreatedAt: c.CreatedAt,
	})
}

func (a dbCheckpointAdapter) LatestCheckpoint(ctx context.Context, chainName string) (*audit.Checkpoint, error) {
	row, err := a.db.GetLatestAuditChainCheckpoint(ctx, chainName)
	if err != nil || row == nil {
		return nil, err
	}
	return &audit.Checkpoint{
		ChainName: row.ChainName, HeadID: row.HeadID, HeadHash: row.HeadHash,
		RowCount: row.RowCount, KeyID: row.KeyID, Signature: row.Signature, CreatedAt: row.CreatedAt,
	}, nil
}

func (a dbCheckpointAdapter) SetAnchor(ctx context.Context, chainName string, lastID int64, lastHash string) error {
	return a.db.UpsertAuditChainAnchor(ctx, chainName, lastID, lastHash)
}

func (a dbCheckpointAdapter) WriteReAnchor(ctx context.Context, r audit.ReAnchor) error {
	return a.db.WriteAuditChainReAnchor(ctx, r.ChainName, r.Reason, r.Actor,
		r.FromHeadID, r.FromHash, r.ToHeadID, r.ToHash, r.KeyID, r.Signature, r.CreatedAt)
}

// makeSealFn builds the production seal closure for one chain — the same shape
// server.go installs: deserialize the buffered JSON record, seal it into the
// access_logs chain via SealBufferedAccessLog tagged with its buffer_seq and
// chain_name. A corrupt record is skipped (not fatal), matching production.
func makeSealFn(database *db.DB, chain db.RBACAuditChain, chainName string) sealer.SealFunc {
	return func(ctx context.Context, seq uint64, data []byte) error {
		var rec db.AccessLogRecord
		if err := json.Unmarshal(data, &rec); err != nil {
			return nil // skip corrupt record; high-water advances past it
		}
		_, err := database.SealBufferedAccessLog(ctx, chain, rec, seq, chainName)
		return err
	}
}

// appendRec serializes an AccessLogRecord the way the proxy hot path does (the
// JSON shape SealBufferedAccessLog deserializes) and appends it to the buffer.
func appendRec(t *testing.T, buf *buffer.Buffer, rec db.AccessLogRecord) uint64 {
	t.Helper()
	data, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	seq, err := buf.Append(data)
	if err != nil {
		t.Fatalf("buffer append: %v", err)
	}
	return seq
}

// countChainRows returns how many access_logs rows exist for chainName.
func countChainRows(t *testing.T, database *db.DB, chainName string) int64 {
	t.Helper()
	var n int64
	if err := database.Conn().QueryRowContext(context.Background(),
		`SELECT count(*) FROM access_logs WHERE chain_name = $1`, chainName).Scan(&n); err != nil {
		t.Fatalf("count rows for %q: %v", chainName, err)
	}
	return n
}

// TestAuditWritePath_BufferSealerChain_Integration drives the full async audit
// write path against a real Pebble buffer + real Postgres (RD-1112 gap #1):
//
//  1. Append N records to a REAL buffer (fsync'd Pebble), like the hot path.
//  2. Run the REAL sealer (sealer.New + Tick) wired to SealBufferedAccessLog +
//     GetMaxAccessLogBufferSeq — the exact funcs server.go installs.
//  3. Assert N access_logs rows are written in buffer order with a valid hash
//     chain (the audit.Verifier passes).
//  4. Assert idempotency: re-running the sealer does NOT double-write, because
//     the buffer_seq high-water resume skips already-sealed entries.
func TestAuditWritePath_BufferSealerChain_Integration(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const chainName = "access_logs" // default chain_name on the column
	const n = 12

	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close() })

	// Seed the in-process chain from the DB exactly like server startup:
	// GetLatestAccessLogHashForChain → NewHashChain.
	seed, err := database.GetLatestAccessLogHashForChain(ctx, chainName)
	if err != nil {
		t.Fatalf("seed chain: %v", err)
	}
	chain := audit.NewHashChain(seed)

	// Append N distinct records to the durable buffer (hot-path side).
	for i := 0; i < n; i++ {
		appendRec(t, buf, db.AccessLogRecord{
			ExternalID:    fmt.Sprintf("did:test:user-%02d", i),
			Method:        "eth_blockNumber",
			StatusCode:    200,
			IPAddress:     "203.0.113.10",
			CorrelationID: fmt.Sprintf("corr-%02d", i),
		})
	}

	sealFn := makeSealFn(database, chain, chainName)
	highWater := func(ctx context.Context) (uint64, error) {
		return database.GetMaxAccessLogBufferSeq(ctx, chainName)
	}
	s := sealer.New(buf, sealFn, highWater, sealer.Config{Batch: 500})

	// One drain seals all N (batch > n).
	sealed, err := s.Tick(ctx)
	if err != nil {
		t.Fatalf("sealer Tick: %v", err)
	}
	if sealed != n {
		t.Fatalf("expected %d entries sealed, got %d", n, sealed)
	}

	// N rows written for this chain.
	if got := countChainRows(t, database, chainName); got != n {
		t.Fatalf("expected %d access_logs rows, got %d", n, got)
	}

	// Rows are in buffer order: buffer_seq ascending == id ascending, and the
	// external_id we encoded with the seq order is monotonic by id.
	rows, err := database.Conn().QueryContext(ctx,
		`SELECT external_id, buffer_seq FROM access_logs WHERE chain_name = $1 ORDER BY id ASC`, chainName)
	if err != nil {
		t.Fatalf("read back rows: %v", err)
	}
	defer rows.Close()
	var i int
	var prevSeq int64 = -1
	for rows.Next() {
		var extID string
		var seq int64
		if err := rows.Scan(&extID, &seq); err != nil {
			t.Fatalf("scan: %v", err)
		}
		wantID := fmt.Sprintf("did:test:user-%02d", i)
		if extID != wantID {
			t.Fatalf("row %d: external_id=%q, want %q (chain not sealed in buffer order)", i, extID, wantID)
		}
		if seq <= prevSeq {
			t.Fatalf("row %d: buffer_seq %d not strictly increasing (prev %d)", i, seq, prevSeq)
		}
		prevSeq = seq
		i++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate rows: %v", err)
	}
	if i != n {
		t.Fatalf("read back %d rows, want %d", i, n)
	}

	// The sealed chain must verify (valid hash chain end-to-end).
	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected sealed chain OK, got FAIL reason=%s id=%d stored=%s expect=%s",
			res.FirstMismatchReason, res.FirstMismatchID, res.FirstMismatchHash, res.FirstMismatchExpect)
	}
	if res.ScannedRows != n {
		t.Fatalf("verifier scanned %d rows, want %d", res.ScannedRows, n)
	}

	// Idempotency: re-run the sealer. The buffer still holds entries that were
	// NOT delete-through'd this run (Tick deletes through high-water at the END
	// of the drain, so a fresh sealer over the same buffer will see them again),
	// but the buffer_seq high-water makes Drain(hw, ...) return nothing —
	// nothing is re-sealed and no duplicate rows appear.
	sealedAgain, err := s.Tick(ctx)
	if err != nil {
		t.Fatalf("sealer Tick (2nd): %v", err)
	}
	if sealedAgain != 0 {
		t.Fatalf("expected 0 entries on idempotent re-seal, got %d", sealedAgain)
	}
	if got := countChainRows(t, database, chainName); got != n {
		t.Fatalf("re-seal double-wrote: expected %d rows, got %d", n, got)
	}

	// And a brand-new sealer (fresh in-memory state, same DB + buffer) must also
	// be a no-op — the high-water lives in Postgres, not the sealer.
	s2 := sealer.New(buf, makeSealFn(database, audit.NewHashChain(""), chainName), highWater, sealer.Config{Batch: 500})
	sealedFresh, err := s2.Tick(ctx)
	if err != nil {
		t.Fatalf("fresh sealer Tick: %v", err)
	}
	if sealedFresh != 0 {
		t.Fatalf("fresh sealer re-sealed %d entries (high-water not honored)", sealedFresh)
	}
	if got := countChainRows(t, database, chainName); got != n {
		t.Fatalf("fresh sealer double-wrote: expected %d rows, got %d", n, got)
	}
}

// TestAuditWritePath_CheckpointTailTruncation_Alarm proves the signed-checkpoint
// truncation guard catches TAIL truncation that a plain hash-walk cannot
// (RD-1112 gap #2 / security review #1):
//
//  1. Write a chained run of rows (via the buffer→sealer path, real DB).
//  2. Write a signed checkpoint pinning the head (via WriteAuditChainCheckpoint
//     with an HMAC key — the same key class the checkpoint worker uses).
//  3. DELETE the most recent rows (tail truncation — downstream-hash-free, so a
//     plain walk stays OK).
//  4. Run the Verifier WITH checkpoint verification enabled → it must alarm with
//     ReasonChainTruncated.
//
// A control assertion confirms a plain hash-walk (no checkpoint guard) reports
// OK on the same truncated chain — i.e. the checkpoint is what makes the
// difference.
func TestAuditWritePath_CheckpointTailTruncation_Alarm(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const chainName = "access_logs"
	const n = 8

	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close() })

	chain := audit.NewHashChain("")
	for i := 0; i < n; i++ {
		appendRec(t, buf, db.AccessLogRecord{
			ExternalID: fmt.Sprintf("did:ckpt:%02d", i),
			Method:     "eth_chainId",
			StatusCode: 200,
			IPAddress:  "203.0.113.20",
		})
	}
	s := sealer.New(buf, makeSealFn(database, chain, chainName),
		func(ctx context.Context) (uint64, error) { return database.GetMaxAccessLogBufferSeq(ctx, chainName) },
		sealer.Config{Batch: 500})
	if sealed, err := s.Tick(ctx); err != nil || sealed != n {
		t.Fatalf("seal: sealed=%d err=%v (want %d, nil)", sealed, err, n)
	}

	// Write a signed checkpoint at the current head, using the production
	// CheckpointWorker against the real DB adapter + an HMAC signer.
	signer := audit.NewHMACSigner("test-key", []byte("checkpoint-hmac-secret-32bytes!!"))
	adapter := dbCheckpointAdapter{db: database}
	worker := audit.NewCheckpointWorker(adapter, signer, []audit.ChainName{audit.ChainName(chainName)}, 0)
	if err := worker.Checkpoint(ctx, audit.ChainName(chainName)); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	// Sanity: a checkpoint now exists pinning the head.
	cp, err := adapter.LatestCheckpoint(ctx, chainName)
	if err != nil || cp == nil {
		t.Fatalf("expected a checkpoint, got cp=%v err=%v", cp, err)
	}
	checkpointHead := cp.HeadID

	// Tail-truncate: delete the 3 most recent rows. Nothing downstream of them
	// exists, so the hash walk alone would still report OK.
	if _, err := database.Conn().ExecContext(ctx,
		`DELETE FROM access_logs WHERE id IN (
			SELECT id FROM access_logs WHERE chain_name = $1 ORDER BY id DESC LIMIT 3)`,
		chainName); err != nil {
		t.Fatalf("tail truncate: %v", err)
	}
	var newHead int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT max(id) FROM access_logs WHERE chain_name = $1`, chainName).Scan(&newHead); err != nil {
		t.Fatalf("read new head: %v", err)
	}
	if newHead >= checkpointHead {
		t.Fatalf("expected head to regress below checkpoint head %d, got %d", checkpointHead, newHead)
	}

	// Control: plain walk (no checkpoint guard) reports OK on the truncated tail.
	plain := audit.NewVerifier(database.Conn(), database)
	plainRes, err := plain.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("plain Verify: %v", err)
	}
	if !plainRes.OK {
		t.Fatalf("plain hash-walk should NOT catch tail truncation, but reported FAIL reason=%s — "+
			"this means the truncation became detectable without the checkpoint (test invalid)",
			plainRes.FirstMismatchReason)
	}

	// With the signed-checkpoint guard enabled, truncation IS detected.
	guarded := audit.NewVerifier(database.Conn(), database)
	guarded.SetCheckpointVerification(adapter, signer)
	res, err := guarded.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("guarded Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("expected ReasonChainTruncated, got OK (truncation guard did not fire)")
	}
	if res.FirstMismatchReason != audit.ReasonChainTruncated {
		t.Fatalf("expected reason=%s, got %s", audit.ReasonChainTruncated, res.FirstMismatchReason)
	}
	if res.FirstMismatchID != checkpointHead {
		t.Fatalf("expected truncation reported at checkpoint head id=%d, got id=%d",
			checkpointHead, res.FirstMismatchID)
	}
}

// TestAuditWritePath_MultiChainName_IndependentWalk proves each per-instance
// chain_name is verified as an independent single-writer chain (RD-1112 gap #3):
// two chains written through their OWN HashChain + sealer, interleaved by id in
// access_logs, must each verify with NO false gap/sequence/fork alarm. A naive
// global id-ordered walk would mis-chain the interleaved rows and falsely alarm.
func TestAuditWritePath_MultiChainName_IndependentWalk(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const chainA = "inst_a"
	const chainB = "inst_b"

	bufA, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer A: %v", err)
	}
	t.Cleanup(func() { _ = bufA.Close() })
	bufB, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer B: %v", err)
	}
	t.Cleanup(func() { _ = bufB.Close() })

	// Each instance owns its own buffer with an INDEPENDENT seq space, but they
	// share ONE access_logs table whose buffer_seq UNIQUE index is global (not
	// per chain_name — see migration 062). In production the per-instance buffer
	// seq spaces are disjoint; mirror that here by advancing buffer B's sequence
	// past buffer A's range so the two never collide on the shared index.
	// (Verified separately: making them OVERLAP trips a 23505 unique-constraint
	// error on the buffer_seq index — a real cross-instance constraint, reported
	// in the summary, not a bug in this test.)
	const seqOffsetB = 1000
	for i := 0; i < seqOffsetB; i++ {
		if _, err := bufB.Append([]byte("x")); err != nil {
			t.Fatalf("advance bufB seq: %v", err)
		}
	}
	if err := bufB.DeleteThrough(seqOffsetB); err != nil {
		t.Fatalf("clear bufB placeholders: %v", err)
	}

	// Each chain_name gets its OWN in-process HashChain (single writer per chain).
	chA := audit.NewHashChain("")
	chB := audit.NewHashChain("")
	sealA := sealer.New(bufA, makeSealFn(database, chA, chainA),
		func(ctx context.Context) (uint64, error) { return database.GetMaxAccessLogBufferSeq(ctx, chainA) },
		sealer.Config{Batch: 1})
	sealB := sealer.New(bufB, makeSealFn(database, chB, chainB),
		func(ctx context.Context) (uint64, error) { return database.GetMaxAccessLogBufferSeq(ctx, chainB) },
		sealer.Config{Batch: 1})

	// Append to both buffers, then drain ONE entry at a time alternating A/B so
	// the access_logs ids interleave across chain_names (id: A,B,A,B,...).
	const per = 5
	for i := 0; i < per; i++ {
		appendRec(t, bufA, db.AccessLogRecord{ExternalID: fmt.Sprintf("did:a:%d", i), Method: "eth_chainId", StatusCode: 200, IPAddress: "203.0.113.1"})
		appendRec(t, bufB, db.AccessLogRecord{ExternalID: fmt.Sprintf("did:b:%d", i), Method: "net_version", StatusCode: 200, IPAddress: "203.0.113.2"})
	}
	for i := 0; i < per; i++ {
		if sealed, err := sealA.Tick(ctx); err != nil || sealed != 1 {
			t.Fatalf("sealA tick %d: sealed=%d err=%v", i, sealed, err)
		}
		if sealed, err := sealB.Tick(ctx); err != nil || sealed != 1 {
			t.Fatalf("sealB tick %d: sealed=%d err=%v", i, sealed, err)
		}
	}

	// Confirm the rows really are interleaved by id (so this is a meaningful test).
	rows, err := database.Conn().QueryContext(ctx,
		`SELECT chain_name FROM access_logs WHERE chain_name IN ($1,$2) ORDER BY id ASC`, chainA, chainB)
	if err != nil {
		t.Fatalf("read interleave: %v", err)
	}
	defer rows.Close()
	var seq []string
	for rows.Next() {
		var cn string
		if err := rows.Scan(&cn); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seq = append(seq, cn)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate: %v", err)
	}
	if len(seq) != per*2 {
		t.Fatalf("expected %d interleaved rows, got %d", per*2, len(seq))
	}
	interleaved := false
	for i := 1; i < len(seq); i++ {
		if seq[i] != seq[i-1] {
			interleaved = true
			break
		}
	}
	if !interleaved {
		t.Fatalf("rows are not interleaved by id (%v) — test would not exercise per-chain isolation", seq)
	}

	// The verifier walks every chain_name independently and must report OK with
	// all rows scanned. A global id-ordered walk would mis-chain the interleave.
	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected both chains OK, got FAIL reason=%s id=%d", res.FirstMismatchReason, res.FirstMismatchID)
	}
	if res.ScannedRows != per*2 {
		t.Fatalf("expected %d scanned rows across both chains, got %d", per*2, res.ScannedRows)
	}
	if got := countChainRows(t, database, chainA); got != per {
		t.Fatalf("chain A: expected %d rows, got %d", per, got)
	}
	if got := countChainRows(t, database, chainB); got != per {
		t.Fatalf("chain B: expected %d rows, got %d", per, got)
	}
}

// TestAuditWritePath_BreakGlassReAnchor_Integration drives audit.BreakGlassReAnchor
// against the REAL DB adapter (RD-1112 gap #4 / security review #3):
//
//  1. Seal a run of rows, write a signed checkpoint, then introduce a chain
//     discontinuity by deleting a MIDDLE row (a hash-walk mismatch the verifier
//     flags) AND truncating the tail relative to the checkpoint.
//  2. Confirm the verifier (with checkpoint guard) ALARMS before re-anchor.
//  3. Call BreakGlassReAnchor(ctx, adapter, signer, chainName, actor, reason).
//  4. Assert: (a) a signed audit_chain_reanchor row exists and verifies;
//     (b) the audit_chain_anchor moved to the current head; (c) a fresh signed
//     checkpoint was written at the current head; (d) the verifier no longer
//     alarms and resumes clean from the recovery point.
func TestAuditWritePath_BreakGlassReAnchor_Integration(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const chainName = "access_logs"
	const n = 9

	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open buffer: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close() })

	chain := audit.NewHashChain("")
	for i := 0; i < n; i++ {
		appendRec(t, buf, db.AccessLogRecord{
			ExternalID: fmt.Sprintf("did:bg:%02d", i),
			Method:     "eth_blockNumber",
			StatusCode: 200,
			IPAddress:  "203.0.113.30",
		})
	}
	s := sealer.New(buf, makeSealFn(database, chain, chainName),
		func(ctx context.Context) (uint64, error) { return database.GetMaxAccessLogBufferSeq(ctx, chainName) },
		sealer.Config{Batch: 500})
	if sealed, err := s.Tick(ctx); err != nil || sealed != n {
		t.Fatalf("seal: sealed=%d err=%v (want %d)", sealed, err, n)
	}

	signer := audit.NewHMACSigner("bg-key", []byte("break-glass-hmac-secret-32bytes!"))
	adapter := dbCheckpointAdapter{db: database}

	// Pin a checkpoint at the full head before the incident.
	worker := audit.NewCheckpointWorker(adapter, signer, []audit.ChainName{audit.ChainName(chainName)}, 0)
	if err := worker.Checkpoint(ctx, audit.ChainName(chainName)); err != nil {
		t.Fatalf("initial checkpoint: %v", err)
	}

	// Collect the ids so we can delete a middle one + the tail (data-loss style
	// discontinuity).
	var ids []int64
	idRows, err := database.Conn().QueryContext(ctx,
		`SELECT id FROM access_logs WHERE chain_name = $1 ORDER BY id ASC`, chainName)
	if err != nil {
		t.Fatalf("read ids: %v", err)
	}
	for idRows.Next() {
		var id int64
		if err := idRows.Scan(&id); err != nil {
			idRows.Close()
			t.Fatalf("scan id: %v", err)
		}
		ids = append(ids, id)
	}
	idRows.Close()
	if len(ids) != n {
		t.Fatalf("expected %d ids, got %d", n, len(ids))
	}
	// Delete a middle row (breaks the hash chain — verifier hash-mismatches) and
	// the last two rows (tail truncation below the checkpoint).
	middle := ids[n/2]
	tail1, tail2 := ids[n-1], ids[n-2]
	if _, err := database.Conn().ExecContext(ctx,
		`DELETE FROM access_logs WHERE id IN ($1,$2,$3)`, middle, tail1, tail2); err != nil {
		t.Fatalf("introduce discontinuity: %v", err)
	}

	// Before re-anchor: the guarded verifier must ALARM (either the hash
	// mismatch from the middle deletion or the truncation guard from the tail).
	guarded := audit.NewVerifier(database.Conn(), database)
	guarded.SetCheckpointVerification(adapter, signer)
	pre, err := guarded.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("pre-reanchor Verify: %v", err)
	}
	if pre.OK {
		t.Fatalf("expected the discontinuity to alarm before re-anchor, got OK")
	}
	if pre.FirstMismatchReason != audit.ReasonHashMismatch &&
		pre.FirstMismatchReason != audit.ReasonChainTruncated {
		t.Fatalf("expected hash_mismatch or chain_truncated before re-anchor, got %s", pre.FirstMismatchReason)
	}

	// Current head AFTER the loss — the recovery point the re-anchor moves to.
	var recoveryHead int64
	var recoveryHash string
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT id, entry_hash FROM access_logs WHERE chain_name = $1 ORDER BY id DESC LIMIT 1`, chainName,
	).Scan(&recoveryHead, &recoveryHash); err != nil {
		t.Fatalf("read recovery head: %v", err)
	}

	// Break-glass re-anchor against the REAL DB adapter (the existing function —
	// no CLI involved).
	const actor = "did:operator:on-call"
	const reason = "RD-1112 break-glass: recover after partial audit data loss (incident-4242)"
	r, err := audit.BreakGlassReAnchor(ctx, adapter, signer, chainName, actor, reason)
	if err != nil {
		t.Fatalf("BreakGlassReAnchor: %v", err)
	}
	if r == nil {
		t.Fatal("BreakGlassReAnchor returned nil record")
	}

	// (a) A signed audit_chain_reanchor row exists, attributed, and verifies.
	var (
		gotChain, gotReason, gotActor, gotKeyID, gotSig, gotToHash string
		gotToHeadID                                                int64
		reanchorCount                                              int
	)
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT count(*) FROM audit_chain_reanchor WHERE chain_name = $1`, chainName).Scan(&reanchorCount); err != nil {
		t.Fatalf("count reanchor rows: %v", err)
	}
	if reanchorCount != 1 {
		t.Fatalf("expected exactly 1 audit_chain_reanchor row, got %d", reanchorCount)
	}
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT chain_name, reason, actor, to_head_id, to_hash, key_id, signature
		 FROM audit_chain_reanchor WHERE chain_name = $1 ORDER BY id DESC LIMIT 1`, chainName,
	).Scan(&gotChain, &gotReason, &gotActor, &gotToHeadID, &gotToHash, &gotKeyID, &gotSig); err != nil {
		t.Fatalf("read reanchor row: %v", err)
	}
	if gotActor != actor || gotReason != reason {
		t.Fatalf("reanchor row not attributed: actor=%q reason=%q", gotActor, gotReason)
	}
	if gotToHeadID != recoveryHead {
		t.Fatalf("reanchor to_head_id=%d, want recovery head %d", gotToHeadID, recoveryHead)
	}
	if gotSig == "" || gotKeyID == "" {
		t.Fatalf("reanchor row unsigned: key_id=%q sig=%q", gotKeyID, gotSig)
	}
	// Reconstruct and verify the signature against the persisted row.
	persisted := audit.ReAnchor{
		ChainName: gotChain, Reason: gotReason, Actor: gotActor,
		FromHeadID: r.FromHeadID, FromHash: r.FromHash,
		ToHeadID: gotToHeadID, ToHash: gotToHash,
		CreatedAt: r.CreatedAt, KeyID: gotKeyID, Signature: gotSig,
	}
	if err := audit.VerifyReAnchor(signer, persisted); err != nil {
		t.Fatalf("persisted reanchor signature does not verify: %v", err)
	}

	// (b) The chain anchor moved to the current (recovery) head.
	anchor, err := database.GetAuditChainAnchor(ctx, chainName)
	if err != nil {
		t.Fatalf("read anchor: %v", err)
	}
	if anchor == nil {
		t.Fatal("expected audit_chain_anchor row after re-anchor, got none")
	}
	if anchor.LastPrunedID != recoveryHead || anchor.LastPrunedEntryHash != recoveryHash {
		t.Fatalf("anchor not moved to recovery head: got id=%d hash=%s want id=%d hash=%s",
			anchor.LastPrunedID, anchor.LastPrunedEntryHash, recoveryHead, recoveryHash)
	}

	// (c) A fresh signed checkpoint was written at the recovery head.
	cp, err := adapter.LatestCheckpoint(ctx, chainName)
	if err != nil || cp == nil {
		t.Fatalf("expected fresh checkpoint after re-anchor, got cp=%v err=%v", cp, err)
	}
	if cp.HeadID != recoveryHead {
		t.Fatalf("fresh checkpoint head=%d, want recovery head %d", cp.HeadID, recoveryHead)
	}
	if err := audit.VerifyCheckpoint(signer, *cp); err != nil {
		t.Fatalf("fresh checkpoint does not verify: %v", err)
	}

	// (d) The verifier no longer alarms — it resumes clean from the recovery
	// point (anchor + checkpoint baseline now both at the current head).
	post, err := guarded.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("post-reanchor Verify: %v", err)
	}
	if !post.OK {
		t.Fatalf("expected clean verify after re-anchor, got FAIL reason=%s id=%d",
			post.FirstMismatchReason, post.FirstMismatchID)
	}
}
