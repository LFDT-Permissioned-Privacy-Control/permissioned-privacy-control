package db_test

import (
	"context"
	"os"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

// setupIntegrityTestDB mirrors the package-internal setupTestDB helper
// but lives in the external _test package so we can also import the
// audit package (which would otherwise cause a cycle via
// audit/retention.go → db).
func setupIntegrityTestDB(t *testing.T) *db.DB {
	t.Helper()
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		var cleanup func()
		dbURL, cleanup = db.SetupTestContainer(t)
		t.Cleanup(cleanup)
	} else if err := db.EnsureTestDatabase(dbURL); err != nil {
		t.Fatalf("PostgreSQL not available: %v", err)
	}
	database, err := db.New(dbURL)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	// Match the package-internal setupTestDB pattern: clear data
	// tables so the test runs against a known-empty audit history.
	// Critical when CI shares a single Postgres instance across
	// every test in the package — without this, earlier tests'
	// access_logs / rbac_audit_log rows leak into the verifier's
	// walk and break id-based assertions.
	if err := db.ResetTestDatabase(database); err != nil {
		t.Fatalf("ResetTestDatabase: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})
	return database
}

// TestAuditIntegrity_WriterVerifierSymmetry_AccessLogs (RD-858) is the
// canonical end-to-end check that the access_logs writer and the
// audit.Verifier agree on the canonical hash-chain content format.
//
// If this test ever fails after a code change, the writer and verifier
// have drifted byte-for-byte — production chains will look tampered to
// the verifier even though no one tampered. The format is a hard
// schema; bumping it requires hash_format_version + a new builder, NOT
// an in-place change to v2.
func TestAuditIntegrity_WriterVerifierSymmetry_AccessLogs(t *testing.T) {
	database := setupIntegrityTestDB(t)

	ctx := context.Background()
	chain := audit.NewHashChain("")

	// Write three rows through the production path. A non-empty org_id is
	// passed deliberately (RD-1135): org_id is NOT part of the hash content,
	// so the verifier must still report OK — this row doubles as the
	// regression guard that the new column stays out of the chain.
	for i := 0; i < 3; i++ {
		_, _, _, err := database.LogAccessChained(
			ctx,
			chain,
			"did:test:auditor", "eth_blockNumber", 200,
			"203.0.113.42", "corr-xyz", nil, nil, "org-audit", "",
		)
		if err != nil {
			t.Fatalf("LogAccessChained #%d: %v", i, err)
		}
	}

	// Verifier walks the same rows and must report OK.
	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected chain OK, got FAIL reason=%s row_id=%d stored=%s expect=%s",
			res.FirstMismatchReason, res.FirstMismatchID,
			res.FirstMismatchHash, res.FirstMismatchExpect)
	}
	if res.ScannedRows != 3 {
		t.Fatalf("expected 3 scanned rows, got %d", res.ScannedRows)
	}
	if res.NullHashRows != 0 {
		t.Fatalf("expected 0 NULL-hash rows, got %d", res.NullHashRows)
	}
}

// TestAuditIntegrity_TamperedAccessLogRow_DetectedAsHashMismatch is
// the negative-path companion: after the writer + verifier agree on
// a clean chain, hand-edit one row's hash to simulate an attacker and
// confirm the verifier locates it.
func TestAuditIntegrity_TamperedAccessLogRow_DetectedAsHashMismatch(t *testing.T) {
	database := setupIntegrityTestDB(t)

	ctx := context.Background()
	chain := audit.NewHashChain("")

	// Seed enough rows that the tampered one isn't at the chain head
	// (so the mismatch propagates).
	for i := 0; i < 5; i++ {
		if _, _, _, err := database.LogAccessChained(
			ctx, chain,
			"did:test:auditor", "eth_chainId", 200,
			"203.0.113.42", "", nil, nil, "", "",
		); err != nil {
			t.Fatalf("seed write %d: %v", i, err)
		}
	}

	// Pick the third row by offset rather than hardcoded id —
	// ResetTestDatabase clears rows but does not reset the
	// access_logs_id_seq, so the writer may have started at any
	// value. The verifier walks in id order regardless.
	var targetID int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT id FROM access_logs ORDER BY id ASC OFFSET 2 LIMIT 1`,
	).Scan(&targetID); err != nil {
		t.Fatalf("pick target row: %v", err)
	}
	if _, err := database.Conn().ExecContext(ctx,
		`UPDATE access_logs SET entry_hash = $1 WHERE id = $2`,
		"deadbeef"+"00000000000000000000000000000000000000000000000000000000", targetID,
	); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("expected chain FAIL after tampering, got OK")
	}
	if res.FirstMismatchReason != audit.ReasonHashMismatch {
		t.Fatalf("expected reason=%s, got %s",
			audit.ReasonHashMismatch, res.FirstMismatchReason)
	}
	if res.FirstMismatchID != targetID {
		t.Fatalf("expected mismatch at id=%d, got id=%d", targetID, res.FirstMismatchID)
	}
}

// TestAuditIntegrity_WriterVerifierSymmetry_RBACAudit pins the rbac
// chain end-to-end. CreateAuditLog goes through HashChain.Append with
// the production content builder; the verifier recomputes via its own
// builder. The two MUST produce the same bytes.
func TestAuditIntegrity_WriterVerifierSymmetry_RBACAudit(t *testing.T) {
	database := setupIntegrityTestDB(t)

	ctx := context.Background()

	// Wire the rbac chain on the DB — production startup does this in
	// server.go; here we mirror the wiring so CreateAuditLog uses the
	// chain path (not the legacy fallback).
	chain := audit.NewHashChain("")
	database.SetRBACAuditChain(chain)

	resourceID := "11111111-1111-1111-1111-111111111111"
	orgID := "22222222-2222-2222-2222-222222222222"

	entries := []*rbac.AuditLogEntry{
		{
			ActorExternalID: "did:admin:alice",
			Action:          "create",
			ResourceType:    "group",
			ResourceID:      &resourceID,
			ResourceName:    "engineering",
			OrgID:           &orgID,
			IPAddress:       "203.0.113.1",
			NewValue:        map[string]any{"name": "engineering"},
		},
		{
			ActorExternalID: "did:admin:alice",
			Action:          "update",
			ResourceType:    "group",
			ResourceID:      &resourceID,
			ResourceName:    "engineering",
			OrgID:           &orgID,
			IPAddress:       "203.0.113.1",
			OldValue:        map[string]any{"name": "engineering"},
			NewValue:        map[string]any{"name": "platform"},
		},
		{
			ActorExternalID: "did:admin:bob",
			Action:          "delete",
			ResourceType:    "membership",
			ResourceID:      &resourceID,
			ResourceName:    "alice@engineering",
			OrgID:           &orgID,
			IPAddress:       "203.0.113.7",
			OldValue:        map[string]any{"user_id": "alice"},
		},
	}

	for i, e := range entries {
		if err := database.CreateAuditLog(ctx, e); err != nil {
			t.Fatalf("CreateAuditLog #%d: %v", i, err)
		}
		if e.ID == 0 {
			t.Fatalf("entry %d: ID not set", i)
		}
		if e.CreatedAt.IsZero() {
			t.Fatalf("entry %d: CreatedAt not set", i)
		}
	}

	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainRBACAuditLog)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK {
		t.Fatalf("expected chain OK, got FAIL reason=%s row_id=%d stored=%s expect=%s",
			res.FirstMismatchReason, res.FirstMismatchID,
			res.FirstMismatchHash, res.FirstMismatchExpect)
	}
	if res.ScannedRows < int64(len(entries)) {
		t.Fatalf("expected at least %d scanned rows, got %d", len(entries), res.ScannedRows)
	}
}

// TestAuditIntegrity_TamperedRBACAuditRow_Detected mirrors the
// access_logs negative-path test for the rbac chain. Tampering with
// new_value (any field that feeds the canonical content) must trip
// the verifier.
func TestAuditIntegrity_TamperedRBACAuditRow_Detected(t *testing.T) {
	database := setupIntegrityTestDB(t)

	ctx := context.Background()
	database.SetRBACAuditChain(audit.NewHashChain(""))

	resourceID := "11111111-1111-1111-1111-111111111111"
	orgID := "22222222-2222-2222-2222-222222222222"

	for i := 0; i < 4; i++ {
		entry := &rbac.AuditLogEntry{
			ActorExternalID: "did:admin:carol",
			Action:          "assign",
			ResourceType:    "membership",
			ResourceID:      &resourceID,
			ResourceName:    "row-" + time.Now().UTC().Format(time.RFC3339Nano),
			OrgID:           &orgID,
			IPAddress:       "203.0.113.9",
		}
		if err := database.CreateAuditLog(ctx, entry); err != nil {
			t.Fatalf("seed #%d: %v", i, err)
		}
	}

	// Tamper: rewrite new_value on a middle row. The hash will no
	// longer match the canonical content the verifier recomputes.
	var targetID int64
	if err := database.Conn().QueryRowContext(ctx,
		`SELECT id FROM rbac_audit_log ORDER BY id ASC OFFSET 1 LIMIT 1`,
	).Scan(&targetID); err != nil {
		t.Fatalf("pick target row: %v", err)
	}
	if _, err := database.Conn().ExecContext(ctx,
		`UPDATE rbac_audit_log SET new_value = $1::jsonb WHERE id = $2`,
		`{"tampered":"by-attacker"}`, targetID,
	); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainRBACAuditLog)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("expected chain FAIL after tampering, got OK")
	}
	if res.FirstMismatchReason != audit.ReasonHashMismatch {
		t.Fatalf("expected reason=%s, got %s",
			audit.ReasonHashMismatch, res.FirstMismatchReason)
	}
	if res.FirstMismatchID != targetID {
		t.Fatalf("expected mismatch at id=%d, got id=%d", targetID, res.FirstMismatchID)
	}
}

// TestAuditIntegrity_NullEntryHash_Flagged covers the "pre-RD-858
// legacy row" case: a row written via the chain-less code path leaves
// entry_hash NULL. The verifier must surface this as
// ReasonNullEntryHash (NOT silently OK), so operators can decide
// whether to treat the row as a tamper signal or accept it as a
// legacy fixed-point.
func TestAuditIntegrity_NullEntryHash_Flagged(t *testing.T) {
	database := setupIntegrityTestDB(t)

	ctx := context.Background()

	// Intentionally do NOT install a chain — CreateAuditLog falls back
	// to the legacy chain-less INSERT.
	resourceID := "11111111-1111-1111-1111-111111111111"
	orgID := "22222222-2222-2222-2222-222222222222"
	entry := &rbac.AuditLogEntry{
		ActorExternalID: "did:admin:legacy",
		Action:          "create",
		ResourceType:    "group",
		ResourceID:      &resourceID,
		ResourceName:    "legacy-row",
		OrgID:           &orgID,
		IPAddress:       "203.0.113.99",
	}
	if err := database.CreateAuditLog(ctx, entry); err != nil {
		t.Fatalf("CreateAuditLog legacy path: %v", err)
	}

	verifier := audit.NewVerifier(database.Conn(), database)
	res, err := verifier.Verify(ctx, audit.ChainRBACAuditLog)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.OK {
		t.Fatalf("expected NULL entry_hash to fail-closed, got OK")
	}
	if res.FirstMismatchReason != audit.ReasonNullEntryHash {
		t.Fatalf("expected reason=%s, got %s",
			audit.ReasonNullEntryHash, res.FirstMismatchReason)
	}
	if res.NullHashRows == 0 {
		t.Fatal("expected NullHashRows > 0")
	}
}
