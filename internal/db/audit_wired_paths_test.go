package db_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/db"
)

// This file adds PERMANENT CI coverage for the RD-1112 audit paths that the
// v0.12.0 acceptance review flagged as untested against a real database
// (RD-1159 Phase 2). The pre-existing audit tests either use fakes
// (internal/audit/sealer/sealer_test.go uses a mock chain recorder and never
// touches Postgres) or exercise only the hash-mismatch / null-hash reasons
// (internal/db/audit_integrity_test.go), leaving three wired paths uncovered:
//
//   1. RD-1112a — the buffer→sealer→access_logs chain wiring on a real DB.
//   2. RD-1112b — the signed-checkpoint TAIL-TRUNCATION guard (chain_truncated),
//      which the plain hash-walk structurally cannot see.
//   3. RD-1112c — per-chain_name independence (multi-instance scale-out).
//
// All tests use the same real-Postgres testcontainer harness as
// audit_integrity_test.go (setupIntegrityTestDB) and assert the DOCUMENTED
// behavior (verifier.go / checkpoint.go doc comments), not merely current
// output — see the truncation test's explicit red-then-green demonstration.

// checkpointAdapterForTest bridges *db.DB to the audit package's
// CheckpointReader / CheckpointStore interfaces. It is a byte-for-byte copy of
// the unexported server.checkpointAdapter (internal/server/server.go:113) —
// the audit package deliberately does not import db, so the wiring lives in a
// layer that imports both. Duplicated here (rather than exported) because these
// tests are in package db_test and must not reach into the server package.
type checkpointAdapterForTest struct{ database *db.DB }

func (a checkpointAdapterForTest) ChainStats(ctx context.Context, chainName string) (int64, int64, string, error) {
	return a.database.GetAccessLogChainStats(ctx, chainName)
}

func (a checkpointAdapterForTest) WriteCheckpoint(ctx context.Context, c audit.Checkpoint) error {
	return a.database.WriteAuditChainCheckpoint(ctx, db.AuditChainCheckpointRow{
		ChainName: c.ChainName, HeadID: c.HeadID, HeadHash: c.HeadHash,
		RowCount: c.RowCount, KeyID: c.KeyID, Signature: c.Signature, CreatedAt: c.CreatedAt,
	})
}

func (a checkpointAdapterForTest) LatestCheckpoint(ctx context.Context, chainName string) (*audit.Checkpoint, error) {
	row, err := a.database.GetLatestAuditChainCheckpoint(ctx, chainName)
	if err != nil || row == nil {
		return nil, err
	}
	return &audit.Checkpoint{
		ChainName: row.ChainName, HeadID: row.HeadID, HeadHash: row.HeadHash,
		RowCount: row.RowCount, KeyID: row.KeyID, Signature: row.Signature, CreatedAt: row.CreatedAt,
	}, nil
}

// TestAuditWiredBufferSealer_LandsInAccessLogChain (RD-1112a) exercises the
// REAL async audit path end-to-end against Postgres: the durable Pebble buffer
// (internal/audit/buffer) feeds the sealer (internal/audit/sealer), whose
// SealFunc is the production db.SealBufferedAccessLog + audit.HashChain — the
// exact wiring server.go builds at ~lines 655-705. It asserts the sealed rows
// land in the access_logs hash chain (entry_hash set, chain advances, verifier
// reports OK). No mock recorder — the prior sealer_test.go used a fake and never
// touched a DB, so this is the first test to prove the wired path persists a
// verifiable chain.
func TestAuditWiredBufferSealer_LandsInAccessLogChain(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const chainName = "access_logs" // the migration-063 default chain

	// 1. Real durable buffer (Pebble on a temp dir), as server.go opens for
	//    AUDIT_BUFFER_DIR.
	buf, err := buffer.Open(t.TempDir())
	if err != nil {
		t.Fatalf("buffer.Open: %v", err)
	}
	t.Cleanup(func() { _ = buf.Close() })

	// 2. The production hash chain + SealFunc + HighWaterFunc, wired exactly as
	//    server.go does (SealBufferedAccessLog is the one and only chain writer
	//    on the async path).
	chain := audit.NewHashChain("")
	sealFn := func(ctx context.Context, seq uint64, data []byte) error {
		var rec db.AccessLogRecord
		if uerr := json.Unmarshal(data, &rec); uerr != nil {
			// server.go logs+skips corrupt records; a decode error in this
			// test means the record we appended is malformed — fail loudly.
			t.Errorf("unexpected corrupt buffered record at seq %d: %v", seq, uerr)
			return nil
		}
		_, serr := database.SealBufferedAccessLog(ctx, chain, rec, seq, chainName)
		return serr
	}
	highWater := func(ctx context.Context) (uint64, error) {
		return database.GetMaxAccessLogBufferSeq(ctx, chainName)
	}
	seal := sealer.New(buf, sealFn, highWater, sealer.Config{Batch: 1000})

	// 3. Append audit entries to the buffer (the hot-path write: encode a
	//    db.AccessLogRecord and hand it to the buffer, exactly like
	//    jsonrpcProcessor does behind SetAuditBuffer).
	const n = 5
	respOK := 200
	for i := 0; i < n; i++ {
		rec := db.AccessLogRecord{
			ExternalID:     "did:test:async-auditor",
			Method:         "eth_blockNumber",
			StatusCode:     200,
			IPAddress:      "203.0.113.7",
			CorrelationID:  "corr-async",
			ResponseStatus: &respOK,
			OrgID:          "org-async",
		}
		payload, merr := json.Marshal(rec)
		if merr != nil {
			t.Fatalf("marshal rec #%d: %v", i, merr)
		}
		if _, aerr := buf.Append(payload); aerr != nil {
			t.Fatalf("buffer.Append #%d: %v", i, aerr)
		}
	}

	// Before sealing: nothing is in the chain yet (async — the hot path
	// returned after buffering).
	if got := countAccessLogRows(t, database, chainName); got != 0 {
		t.Fatalf("expected 0 sealed rows before Tick, got %d", got)
	}

	// 4. Run the sealer once (Tick drains the buffer and seals in order).
	sealedN, err := seal.Tick(ctx)
	if err != nil {
		t.Fatalf("sealer.Tick: %v", err)
	}
	if sealedN != n {
		t.Fatalf("sealer sealed %d entries, want %d", sealedN, n)
	}

	// 5. The rows must now be in access_logs, each with a non-NULL entry_hash
	//    and the sealed chain_name.
	if got := countAccessLogRows(t, database, chainName); got != n {
		t.Fatalf("expected %d sealed rows in chain %q, got %d", n, chainName, got)
	}
	var nullHashes int
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT count(*) FROM access_logs WHERE chain_name = $1 AND (entry_hash IS NULL OR entry_hash = '')`,
		chainName,
	).Scan(&nullHashes); err != nil {
		t.Fatalf("count null hashes: %v", err)
	}
	if nullHashes != 0 {
		t.Fatalf("expected 0 NULL entry_hash rows on the sealed chain, got %d", nullHashes)
	}

	// 6. The verifier must walk the sealed chain and report OK — proving the
	//    buffer→sealer→DB path produced a byte-for-byte valid hash chain.
	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected sealed chain OK, got FAIL reason=%s row_id=%d stored=%s expect=%s",
			res.FirstMismatchReason, res.FirstMismatchID, res.FirstMismatchHash, res.FirstMismatchExpect)
	}
	if res.ScannedRows != n {
		t.Fatalf("verifier scanned %d rows, want %d", res.ScannedRows, n)
	}
	if res.NullHashRows != 0 {
		t.Fatalf("verifier saw %d NULL-hash rows, want 0", res.NullHashRows)
	}

	// 7. The chain head advanced: the buffered high-water now equals n, so a
	//    second Tick is a no-op (crash-safe resume — no double-seal).
	hw, err := database.GetMaxAccessLogBufferSeq(ctx, chainName)
	if err != nil {
		t.Fatalf("GetMaxAccessLogBufferSeq: %v", err)
	}
	if hw != uint64(n) {
		t.Fatalf("buffer high-water = %d, want %d", hw, n)
	}
	sealedAgain, err := seal.Tick(ctx)
	if err != nil {
		t.Fatalf("second Tick: %v", err)
	}
	if sealedAgain != 0 {
		t.Fatalf("second Tick sealed %d, want 0 (idempotent resume)", sealedAgain)
	}
}

// TestAuditWiredCheckpoint_TruncationDetection (RD-1112b) is the KEY gap: the
// signed-checkpoint tail-truncation guard. Signing/verify is unit-tested with
// fakes and audit_integrity_test.go covers hash-mismatch/null-hash, but nothing
// exercises the wired Verifier.checkTruncation against a real DB. Tail
// truncation (deleting the most-recent rows) breaks NO downstream hash, so the
// hash-walk alone reports OK — only the checkpoint guard catches it.
//
// This test demonstrates the documented behavior with an explicit RED→GREEN:
//   - RED: a verifier WITHOUT SetCheckpointVerification (the default) reports OK
//     even after the tail is deleted — proving the guard is what does the work,
//     not the walk.
//   - GREEN: the same DB state, verified WITH SetCheckpointVerification, reports
//     chain_truncated.
//
// It also asserts a wrong-key (forged) checkpoint is rejected as a tamper
// signal (checkpoint_signature_invalid).
func TestAuditWiredCheckpoint_TruncationDetection(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	const (
		chainName = "access_logs"
		keyID     = "default"
	)
	realKey := []byte("audit-checkpoint-key-rd1112b-truncation")
	signer := audit.NewHMACSigner(keyID, realKey)
	adapter := checkpointAdapterForTest{database: database}

	// Seed a healthy chain of 6 rows through the production writer.
	chain := audit.NewHashChain("")
	seedAccessLogChain(t, database, chain, chainName, 6)

	// Sign a checkpoint over the FULL healthy chain (head id + row count). This
	// is what the CheckpointWorker.Checkpoint does in production; we drive it
	// through the same adapter path so the persisted row is identical.
	if err := signAndWriteCheckpoint(ctx, t, adapter, signer, chainName); err != nil {
		t.Fatalf("sign+write checkpoint: %v", err)
	}

	// Record the pre-truncation head, then TAIL-TRUNCATE: delete the two most
	// recent rows. The remaining rows still chain correctly among themselves —
	// the hash walk cannot see that the tail is gone.
	var headBefore, rowsBefore int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT COALESCE(max(id),0), count(*) FROM access_logs WHERE chain_name = $1`, chainName,
	).Scan(&headBefore, &rowsBefore); err != nil {
		t.Fatalf("read head/rows before truncation: %v", err)
	}
	if _, err := database.Conn().ExecContext(ctx,
		`DELETE FROM access_logs WHERE chain_name = $1 AND id IN (
			SELECT id FROM access_logs WHERE chain_name = $1 ORDER BY id DESC LIMIT 2
		)`, chainName,
	); err != nil {
		t.Fatalf("tail-truncate DELETE: %v", err)
	}
	var headAfter, rowsAfter int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT COALESCE(max(id),0), count(*) FROM access_logs WHERE chain_name = $1`, chainName,
	).Scan(&headAfter, &rowsAfter); err != nil {
		t.Fatalf("read head/rows after truncation: %v", err)
	}
	if !(headAfter < headBefore && rowsAfter == rowsBefore-2) {
		t.Fatalf("truncation setup wrong: head %d->%d, rows %d->%d", headBefore, headAfter, rowsBefore, rowsAfter)
	}

	// --- RED: without the checkpoint guard, truncation is INVISIBLE. ---
	// A verifier with NO SetCheckpointVerification call (the default) walks the
	// surviving rows, all of which chain correctly, and reports OK. This proves
	// the plain hash-walk structurally cannot detect tail truncation — the whole
	// reason the signed checkpoint exists.
	plainVerifier := audit.NewVerifier(database.Conn(), database)
	redRes, err := plainVerifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("RED Verify: %v", err)
	}
	if !redRes.OK {
		t.Fatalf("RED: expected plain (checkpoint-less) verify to report OK after tail truncation "+
			"(the hash-walk cannot see it) — got FAIL reason=%s. If this fires, the walk gained "+
			"truncation detection and this test's premise is stale.", redRes.FirstMismatchReason)
	}
	t.Logf("RED confirmed: without SetCheckpointVerification, verify reports OK=%v after tail truncation "+
		"(scanned %d rows) — the hash-walk alone is blind to it", redRes.OK, redRes.ScannedRows)

	// --- GREEN: with the checkpoint guard enabled, truncation is detected. ---
	guardedVerifier := audit.NewVerifier(database.Conn(), database)
	guardedVerifier.SetCheckpointVerification(adapter, signer)
	greenRes, err := guardedVerifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("GREEN Verify: %v", err)
	}
	if greenRes.OK {
		t.Fatalf("GREEN: expected chain_truncated FAIL with checkpoint verification enabled, got OK")
	}
	if greenRes.FirstMismatchReason != audit.ReasonChainTruncated {
		t.Fatalf("GREEN: expected reason=%s, got %s", audit.ReasonChainTruncated, greenRes.FirstMismatchReason)
	}
	// The guard reports the checkpointed head as the offending point.
	if greenRes.FirstMismatchID != headBefore {
		t.Fatalf("GREEN: expected FirstMismatchID=%d (checkpointed head), got %d", headBefore, greenRes.FirstMismatchID)
	}
	t.Logf("GREEN confirmed: with SetCheckpointVerification, verify reports reason=%s at head id=%d",
		greenRes.FirstMismatchReason, greenRes.FirstMismatchID)

	// --- Forged checkpoint: a checkpoint the verifier cannot trust is itself a
	//     tamper signal. Verify with the WRONG key and expect
	//     checkpoint_signature_invalid (not chain_truncated, not OK). ---
	wrongKeySigner := audit.NewHMACSigner(keyID, []byte("this-is-the-wrong-checkpoint-key"))
	forgedVerifier := audit.NewVerifier(database.Conn(), database)
	forgedVerifier.SetCheckpointVerification(adapter, wrongKeySigner)
	forgedRes, err := forgedVerifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("forged-key Verify: %v", err)
	}
	if forgedRes.OK {
		t.Fatalf("expected forged/wrong-key checkpoint to FAIL, got OK")
	}
	if forgedRes.FirstMismatchReason != audit.ReasonCheckpointForged {
		t.Fatalf("expected reason=%s for wrong-key checkpoint, got %s",
			audit.ReasonCheckpointForged, forgedRes.FirstMismatchReason)
	}
	t.Logf("forged-key confirmed: wrong signing key → reason=%s (untrustworthy checkpoint treated as tamper)",
		forgedRes.FirstMismatchReason)
}

// TestAuditWiredMultiChain_IndependentVerification (RD-1112c) covers the
// per-chain_name walk (verifier.go verifyOneAccessLogChain / accessLogChainNames).
// verifier.go:264-311 documents that each chain_name is an independent
// single-writer chain and a global id-ordered walk would mis-chain interleaved
// per-instance chains — but no test inserted rows under two chain_names sharing
// one DB. This seals two independent chains (distinct AUDIT_CHAIN_NAME values,
// each its own HashChain) into one Postgres and asserts each verifies with no
// false gap/fork alarm.
func TestAuditWiredMultiChain_IndependentVerification(t *testing.T) {
	database := setupIntegrityTestDB(t)
	ctx := context.Background()

	// Two instances, two chain_names, two independent hash chains — exactly what
	// two scaled-out sealers would produce (each seeds NewHashChain("") and tags
	// its own chain_name). Interleave the seals so the rows' global id order
	// alternates between chains; a naive global walk would mis-chain them.
	const chainA = "instance-a"
	const chainB = "instance-b"
	chA := audit.NewHashChain("")
	chB := audit.NewHashChain("")

	respOK := 200
	seal := func(chain *audit.HashChain, chainName, extID string, seq uint64) {
		rec := db.AccessLogRecord{
			ExternalID:     extID,
			Method:         "eth_chainId",
			StatusCode:     200,
			IPAddress:      "203.0.113.50",
			ResponseStatus: &respOK,
		}
		if _, err := database.SealBufferedAccessLog(ctx, chain, rec, seq, chainName); err != nil {
			t.Fatalf("seal into %s seq %d: %v", chainName, seq, err)
		}
	}
	// Interleaved writes: A,B,A,B,... buffer_seq is per-chain (unique index is
	// global, so use disjoint ranges).
	for i := uint64(1); i <= 4; i++ {
		seal(chA, chainA, "did:test:inst-a", i)
		seal(chB, chainB, "did:test:inst-b", 100+i)
	}

	// The verifier enumerates chain_names and verifies each independently.
	// audit.ChainAccessLogs aggregation walks every chain_name; if the per-chain
	// isolation were broken, the interleaved ids would produce a hash_mismatch.
	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify (aggregate): %v", err)
	}
	if !res.OK {
		t.Fatalf("expected both chains OK, got FAIL reason=%s id=%d stored=%s expect=%s",
			res.FirstMismatchReason, res.FirstMismatchID, res.FirstMismatchHash, res.FirstMismatchExpect)
	}
	if res.ScannedRows != 8 {
		t.Fatalf("expected 8 scanned rows across both chains, got %d", res.ScannedRows)
	}

	// Sanity: each chain independently has the expected row count and a valid
	// (non-NULL) head hash — i.e. they really are two separate chains in one DB.
	for _, cn := range []string{chainA, chainB} {
		rc, headID, headHash, serr := database.GetAccessLogChainStats(ctx, cn)
		if serr != nil {
			t.Fatalf("GetAccessLogChainStats(%s): %v", cn, serr)
		}
		if rc != 4 {
			t.Fatalf("chain %s: expected 4 rows, got %d", cn, rc)
		}
		if headID == 0 || headHash == "" {
			t.Fatalf("chain %s: expected non-zero head id and non-empty head hash, got id=%d hash=%q", cn, headID, headHash)
		}
	}

	// Cross-check: a tamper in chain A must NOT be attributed to chain B, and
	// chain B must still verify. Delete-tamper is caught by the aggregate; here
	// we corrupt one A row and confirm the failure names an A row.
	var aRowID int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT id FROM access_logs WHERE chain_name = $1 ORDER BY id ASC OFFSET 1 LIMIT 1`, chainA,
	).Scan(&aRowID); err != nil {
		t.Fatalf("pick chain-A row: %v", err)
	}
	if _, err := database.Conn().ExecContext(ctx,
		`UPDATE access_logs SET entry_hash = $1 WHERE id = $2`,
		"deadbeef"+"00000000000000000000000000000000000000000000000000000000", aRowID,
	); err != nil {
		t.Fatalf("tamper chain-A row: %v", err)
	}
	afterTamper, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify after tamper: %v", err)
	}
	if afterTamper.OK {
		t.Fatalf("expected FAIL after tampering a chain-A row, got OK")
	}
	if afterTamper.FirstMismatchReason != audit.ReasonHashMismatch {
		t.Fatalf("expected reason=%s, got %s", audit.ReasonHashMismatch, afterTamper.FirstMismatchReason)
	}
	if afterTamper.FirstMismatchID != aRowID {
		t.Fatalf("expected mismatch at chain-A id=%d, got id=%d", aRowID, afterTamper.FirstMismatchID)
	}
}

// --- helpers ---

// countAccessLogRows returns the number of access_logs rows on chainName.
func countAccessLogRows(t *testing.T, database *db.DB, chainName string) int {
	t.Helper()
	var n int
	if err := database.Conn().QueryRowContext(context.Background(),
		`SELECT count(*) FROM access_logs WHERE chain_name = $1`, chainName,
	).Scan(&n); err != nil {
		t.Fatalf("count access_logs for %q: %v", chainName, err)
	}
	return n
}

// seedAccessLogChain seals n rows into chainName through the production
// SealBufferedAccessLog writer using the provided chain, so the resulting rows
// form a valid hash chain the verifier accepts. buffer_seq starts at 1.
func seedAccessLogChain(t *testing.T, database *db.DB, chain *audit.HashChain, chainName string, n int) {
	t.Helper()
	ctx := context.Background()
	respOK := 200
	for i := 1; i <= n; i++ {
		rec := db.AccessLogRecord{
			ExternalID:     "did:test:seed",
			Method:         "eth_blockNumber",
			StatusCode:     200,
			IPAddress:      "203.0.113.7",
			ResponseStatus: &respOK,
		}
		if _, err := database.SealBufferedAccessLog(ctx, chain, rec, uint64(i), chainName); err != nil {
			t.Fatalf("seed seal #%d into %q: %v", i, chainName, err)
		}
	}
}

// signAndWriteCheckpoint reads the current head/row-count for chainName, signs a
// Checkpoint with signer, and persists it — mirroring
// audit.CheckpointWorker.Checkpoint (checkpoint_worker.go:69) exactly.
func signAndWriteCheckpoint(ctx context.Context, t *testing.T, store audit.CheckpointStore, signer audit.Signer, chainName string) error {
	t.Helper()
	rowCount, headID, headHash, err := store.ChainStats(ctx, chainName)
	if err != nil {
		return err
	}
	c := audit.Checkpoint{
		ChainName: chainName,
		HeadID:    headID,
		HeadHash:  headHash,
		RowCount:  rowCount,
		CreatedAt: time.Now().UTC(),
	}
	if err := audit.SignCheckpoint(signer, &c); err != nil {
		return err
	}
	return store.WriteCheckpoint(ctx, c)
}
