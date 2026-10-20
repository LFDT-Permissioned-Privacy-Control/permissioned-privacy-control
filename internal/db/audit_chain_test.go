package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// queryAccessLogsPruneAuditRows reads every rbac_audit_log row whose
// action = "audit.access_logs.prune" and decodes its JSONB new_value payload.
// Used by audit-of-the-audit tests to assert the prune emitted a row with the
// expected metadata.
func queryAccessLogsPruneAuditRows(t *testing.T, ctx context.Context, d *DB) []map[string]any {
	t.Helper()
	rows, err := d.Conn().QueryContext(ctx, `
		SELECT new_value FROM rbac_audit_log
		WHERE action = $1 ORDER BY id ASC`, "audit.access_logs.prune")
	if err != nil {
		t.Fatalf("query audit-of-the-audit rows: %v", err)
	}
	defer rows.Close()

	out := make([]map[string]any, 0)
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan audit-of-the-audit row: %v", err)
		}
		details := map[string]any{}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &details); err != nil {
				t.Fatalf("unmarshal audit-of-the-audit details: %v", err)
			}
		}
		out = append(out, details)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit-of-the-audit rows: %v", err)
	}
	return out
}

// computeChainHash mirrors internal/audit.HashChain.ComputeNext but is duplicated
// here to keep the test free of cross-package coupling. The value MUST stay in
// lockstep with hashchain.go.
func computeChainHash(prev, content string) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// seedAccessLogs inserts n access_logs rows for a single user, computing and
// persisting the entry_hash chain forward. Returns the ids and hashes in
// insertion order.
func seedAccessLogs(t *testing.T, ctx context.Context, d *DB, n int, prev string) ([]int64, []string) {
	t.Helper()
	ids := make([]int64, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id, createdAt, err := d.LogAccessEnhanced(ctx, "did:test:user", "eth_call", 200, "127.0.0.1", "", nil, nil, "", "")
		if err != nil {
			t.Fatalf("seed insert %d: %v", i, err)
		}
		// Mirror jsonrpc_processor.go entry content layout.
		content := fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
			id, "did:test:user", "eth_call", "127.0.0.1", 200, 200,
			createdAt.Format(time.RFC3339Nano), "", "")
		hash := computeChainHash(prev, content)
		if err := d.UpdateAccessLogHash(ctx, id, hash); err != nil {
			t.Fatalf("update hash %d: %v", id, err)
		}
		prev = hash
		ids = append(ids, id)
		hashes = append(hashes, hash)
	}
	return ids, hashes
}

// TestFIFOTrim_AnchorFlow drives a real Postgres through the FIFO trim path
// and verifies (a) the row count drops to the cap, (b) the audit_chain_anchor
// table records the (id, hash) of the highest deleted row, (c) walking the
// surviving rows from the anchor as seed reproduces every row's entry_hash —
// i.e. the hash chain is verifiable across the cut.
func TestFIFOTrim_AnchorFlow(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	const totalRows = 12
	const maxRows = 5

	ids, hashes := seedAccessLogs(t, ctx, database, totalRows, "")

	// Trim down to maxRows; loop until 0 deleted. Capture aggregated
	// PruneResult metadata across batches so we can verify the new fields.
	var totalDeleted int64
	var minLowestID int64
	var maxHighestID int64
	var lastAnchorHash string
	for i := 0; i < 100; i++ {
		res, err := database.TrimAccessLogsFIFOBatch(ctx, maxRows, 1000)
		if err != nil {
			t.Fatalf("trim batch: %v", err)
		}
		if res.Deleted == 0 {
			break
		}
		totalDeleted += res.Deleted
		if minLowestID == 0 && res.LowestID > 0 {
			minLowestID = res.LowestID
		}
		if res.HighestID > maxHighestID {
			maxHighestID = res.HighestID
		}
		if res.AnchorHash != "" {
			lastAnchorHash = res.AnchorHash
		}
	}
	if totalDeleted != int64(totalRows-maxRows) {
		t.Fatalf("expected %d rows deleted, got %d", totalRows-maxRows, totalDeleted)
	}
	// PruneResult fields: lowest = first seeded id; highest = last deleted id
	// = anchor's last_pruned_id; anchor hash = last surviving deleted-row hash.
	if want := ids[0]; minLowestID != want {
		t.Fatalf("PruneResult.LowestID: want %d, got %d", want, minLowestID)
	}
	if want := ids[totalRows-maxRows-1]; maxHighestID != want {
		t.Fatalf("PruneResult.HighestID: want %d, got %d", want, maxHighestID)
	}
	if want := hashes[totalRows-maxRows-1]; lastAnchorHash != want {
		t.Fatalf("PruneResult.AnchorHash: want %s, got %s", want, lastAnchorHash)
	}

	// Surviving row count.
	count, err := database.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != int64(maxRows) {
		t.Fatalf("expected %d surviving rows, got %d", maxRows, count)
	}

	// The anchor row should pin the highest deleted id and its entry_hash.
	anchor, err := database.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		t.Fatalf("get anchor: %v", err)
	}
	if anchor == nil {
		t.Fatal("expected anchor row, got nil")
	}
	expectedAnchorID := ids[totalRows-maxRows-1]
	expectedAnchorHash := hashes[totalRows-maxRows-1]
	if anchor.LastPrunedID != expectedAnchorID {
		t.Fatalf("anchor id mismatch: want %d, got %d", expectedAnchorID, anchor.LastPrunedID)
	}
	if anchor.LastPrunedEntryHash != expectedAnchorHash {
		t.Fatalf("anchor hash mismatch: want %s, got %s", expectedAnchorHash, anchor.LastPrunedEntryHash)
	}

	// The seeder used for a fresh chain on startup must return the anchor
	// hash now that the originally-seeded rows are still in the DB. (Surviving
	// rows have entry_hash set so the function should still prefer the most
	// recent surviving hash. Verify this matches the last surviving entry.)
	seed, err := database.GetLatestAccessLogHash(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed != hashes[totalRows-1] {
		t.Fatalf("seed should reflect newest surviving row %s, got %s", hashes[totalRows-1], seed)
	}

	// Hash-chain forward walk: seed = anchor hash, then recompute entry_hash
	// for each surviving row and confirm it matches what the DB stored.
	rows, err := database.Conn().QueryContext(ctx, `
		SELECT id, external_id, method, status_code, response_status, ip_address,
		       correlation_id, request_params, entry_hash, hash_format_version, created_at
		FROM access_logs ORDER BY id ASC`)
	if err != nil {
		t.Fatalf("select surviving: %v", err)
	}
	defer rows.Close()

	prev := anchor.LastPrunedEntryHash
	walked := 0
	for rows.Next() {
		var l AccessLog
		var corrID sql.NullString
		var entryHash sql.NullString
		var respStatus *int
		var params []byte
		var createdAtStr string
		if err := rows.Scan(&l.ID, &l.ExternalID, &l.Method, &l.StatusCode, &respStatus, &l.IPAddress, &corrID, &params, &entryHash, &l.HashFormatVersion, &createdAtStr); err != nil {
			t.Fatalf("scan: %v", err)
		}
		// We seeded with no correlation id and no params, status 200/200 — the
		// content string the processor would have built is reproducible here.
		createdAt, perr := time.Parse(time.RFC3339Nano, createdAtStr)
		if perr != nil {
			// Fallback: the driver may return stripped-precision RFC3339.
			createdAt, perr = time.Parse(time.RFC3339, createdAtStr)
			if perr != nil {
				t.Fatalf("parse created_at %q: %v", createdAtStr, perr)
			}
		}
		content := fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
			l.ID, "did:test:user", "eth_call", "127.0.0.1", 200, 200,
			createdAt.Format(time.RFC3339Nano), "", "")
		got := computeChainHash(prev, content)
		if got != entryHash.String {
			t.Fatalf("hash mismatch on id=%d: want %s, got %s", l.ID, entryHash.String, got)
		}
		prev = got
		walked++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if walked != maxRows {
		t.Fatalf("walked %d rows, expected %d", walked, maxRows)
	}

	// Audit-of-the-audit: retention.go emits LogAuditAction after a successful
	// FIFO drain. Mirror the production payload here so we can assert the row
	// reaches rbac_audit_log and the JSONB metadata round-trips intact, plus
	// the deleted-range metadata sourced from PruneResult.
	pruneDetails := map[string]any{
		"reason":          "fifo",
		"deleted_count":   totalDeleted,
		"lowest_id":       minLowestID,
		"highest_id":      maxHighestID,
		"new_anchor_hash": lastAnchorHash,
		"max_rows":        int64(maxRows),
	}
	if err := database.LogAuditAction(ctx, "audit.access_logs.prune", pruneDetails); err != nil {
		t.Fatalf("LogAuditAction: %v", err)
	}
	rowsRead := queryAccessLogsPruneAuditRows(t, ctx, database)
	if len(rowsRead) != 1 {
		t.Fatalf("expected exactly 1 audit.access_logs.prune row in rbac_audit_log, got %d", len(rowsRead))
	}
	gotDetails := rowsRead[0]
	if gotDetails["reason"] != "fifo" {
		t.Fatalf("audit row reason: got %v, want \"fifo\"", gotDetails["reason"])
	}
	// JSONB → json.Unmarshal decodes numbers as float64.
	if got, want := gotDetails["deleted_count"], float64(totalDeleted); got != want {
		t.Fatalf("audit row deleted_count: got %v, want %v", got, want)
	}
	if got, want := gotDetails["max_rows"], float64(maxRows); got != want {
		t.Fatalf("audit row max_rows: got %v, want %v", got, want)
	}
	if got, want := gotDetails["lowest_id"], float64(minLowestID); got != want {
		t.Fatalf("audit row lowest_id: got %v, want %v", got, want)
	}
	if got, want := gotDetails["highest_id"], float64(maxHighestID); got != want {
		t.Fatalf("audit row highest_id: got %v, want %v", got, want)
	}
	if got, want := gotDetails["new_anchor_hash"], lastAnchorHash; got != want {
		t.Fatalf("audit row new_anchor_hash: got %v, want %v", got, want)
	}
}

// TestTimeBasedPrune_WritesAnchor verifies that the existing CleanupAccessLogs
// path also persists the anchor — Option A: TTL prune must keep the chain
// verifiable across the cut.
func TestTimeBasedPrune_WritesAnchor(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	ids, hashes := seedAccessLogs(t, ctx, database, 5, "")

	// Backdate the first 3 rows so they fall outside the retention window.
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	if _, err := database.Conn().ExecContext(ctx,
		`UPDATE access_logs SET created_at = $1 WHERE id <= $2`, cutoff.Add(-time.Minute), ids[2]); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	res, err := database.CleanupAccessLogs(ctx, cutoff)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if res.Deleted != 3 {
		t.Fatalf("expected 3 rows deleted, got %d", res.Deleted)
	}
	if res.LowestID != ids[0] {
		t.Fatalf("PruneResult.LowestID: want %d, got %d", ids[0], res.LowestID)
	}
	if res.HighestID != ids[2] {
		t.Fatalf("PruneResult.HighestID: want %d, got %d", ids[2], res.HighestID)
	}
	if res.AnchorHash != hashes[2] {
		t.Fatalf("PruneResult.AnchorHash: want %s, got %s", hashes[2], res.AnchorHash)
	}

	anchor, err := database.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		t.Fatalf("get anchor: %v", err)
	}
	if anchor == nil {
		t.Fatal("expected anchor after time-based prune, got nil")
	}
	if anchor.LastPrunedID != ids[2] {
		t.Fatalf("anchor id: want %d, got %d", ids[2], anchor.LastPrunedID)
	}
	if anchor.LastPrunedEntryHash != hashes[2] {
		t.Fatalf("anchor hash: want %s, got %s", hashes[2], anchor.LastPrunedEntryHash)
	}

	// Audit-of-the-audit: retention.go emits LogAuditAction after a successful
	// TTL prune. Mirror the production payload (now including the deleted-range
	// metadata sourced from PruneResult) to verify the JSONB round-trips intact.
	const ttl = 1 * time.Hour
	pruneDetails := map[string]any{
		"reason":          "ttl",
		"deleted_count":   res.Deleted,
		"lowest_id":       res.LowestID,
		"highest_id":      res.HighestID,
		"new_anchor_hash": res.AnchorHash,
		"retention":       ttl.String(),
		"cutoff":          cutoff.UTC().Format(time.RFC3339Nano),
	}
	if err := database.LogAuditAction(ctx, "audit.access_logs.prune", pruneDetails); err != nil {
		t.Fatalf("LogAuditAction: %v", err)
	}
	rowsRead := queryAccessLogsPruneAuditRows(t, ctx, database)
	if len(rowsRead) != 1 {
		t.Fatalf("expected exactly 1 audit.access_logs.prune row in rbac_audit_log, got %d", len(rowsRead))
	}
	gotDetails := rowsRead[0]
	if gotDetails["reason"] != "ttl" {
		t.Fatalf("audit row reason: got %v, want \"ttl\"", gotDetails["reason"])
	}
	if got, want := gotDetails["deleted_count"], float64(res.Deleted); got != want {
		t.Fatalf("audit row deleted_count: got %v, want %v", got, want)
	}
	if gotDetails["retention"] != ttl.String() {
		t.Fatalf("audit row retention: got %v, want %v", gotDetails["retention"], ttl.String())
	}
	if got, want := gotDetails["lowest_id"], float64(res.LowestID); got != want {
		t.Fatalf("audit row lowest_id: got %v, want %v", got, want)
	}
	if got, want := gotDetails["highest_id"], float64(res.HighestID); got != want {
		t.Fatalf("audit row highest_id: got %v, want %v", got, want)
	}
	if got, want := gotDetails["new_anchor_hash"], res.AnchorHash; got != want {
		t.Fatalf("audit row new_anchor_hash: got %v, want %v", got, want)
	}
}

// TestGetLatestAccessLogHash_FallsBackToAnchor confirms that the chain seeder
// reads from the anchor when no surviving access_logs row carries a hash.
func TestGetLatestAccessLogHash_FallsBackToAnchor(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	// Seed and trim everything: the surviving table is empty but the anchor
	// must still hold the last-known hash.
	_, hashes := seedAccessLogs(t, ctx, database, 4, "")
	for i := 0; i < 10; i++ {
		res, err := database.TrimAccessLogsFIFOBatch(ctx, 0, 1000)
		if err != nil {
			t.Fatalf("trim: %v", err)
		}
		if res.Deleted == 0 {
			break
		}
	}
	count, err := database.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected 0 surviving, got %d", count)
	}

	seed, err := database.GetLatestAccessLogHash(ctx)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if seed == "" {
		t.Fatal("seed should fall back to anchor, got empty string")
	}
	if seed != hashes[len(hashes)-1] {
		t.Fatalf("seed should equal last hash before prune: want %s, got %s", hashes[len(hashes)-1], seed)
	}
}

// filterSeedRow mirrors the columns we vary across the GetAccessLogs filter
// matrix tests. createdAtOffset is added to a base time to control the From/To
// filter boundaries deterministically.
type filterSeedRow struct {
	externalID      string
	method          string
	statusCode      int
	correlationID   string
	createdAtOffset time.Duration
}

// seedFilterRows inserts each row via LogAccessEnhanced and then back-dates
// created_at to the requested offset relative to baseTime. Returns the inserted
// ids in order.
func seedFilterRows(t *testing.T, ctx context.Context, d *DB, baseTime time.Time, rows []filterSeedRow) []int64 {
	t.Helper()
	ids := make([]int64, 0, len(rows))
	for i, r := range rows {
		id, _, err := d.LogAccessEnhanced(ctx, r.externalID, r.method, r.statusCode, "127.0.0.1", r.correlationID, nil, nil, "", "")
		if err != nil {
			t.Fatalf("seed row %d: %v", i, err)
		}
		// Back-date deterministically. Using the underlying sql.DB so we don't
		// depend on whatever default the timestamp column was assigned.
		ts := baseTime.Add(r.createdAtOffset)
		if _, err := d.Conn().ExecContext(ctx,
			`UPDATE access_logs SET created_at = $1 WHERE id = $2`, ts, id); err != nil {
			t.Fatalf("backdate row %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	return ids
}

// TestGetAccessLogs_FiltersNarrowResults exercises every dimension of
// AccessLogFilter against a real Postgres. Each sub-test asserts that GetAccessLogs
// returns only rows matching the supplied filter, and that limit/offset are
// respected.
func TestGetAccessLogs_FiltersNarrowResults(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Hour)

	// 10 rows spanning every filter dimension. Offsets are picked so From/To
	// boundary tests are deterministic.
	rows := []filterSeedRow{
		{"did:test:alice", "eth_call", 200, "corr-A", 0 * time.Hour},
		{"did:test:alice", "eth_blockNumber", 200, "corr-B", 1 * time.Hour},
		{"did:test:alice", "eth_call", 401, "corr-A", 2 * time.Hour},
		{"did:test:bob", "eth_call", 200, "corr-A", 3 * time.Hour},
		{"did:test:bob", "eth_call", 200, "corr-C", 4 * time.Hour},
		{"did:test:bob", "eth_blockNumber", 401, "corr-A", 5 * time.Hour},
		{"did:test:carol", "eth_getLogs", 500, "corr-D", 6 * time.Hour},
		{"did:test:carol", "eth_call", 200, "", 7 * time.Hour},
		{"did:test:dave", "eth_getLogs", 200, "corr-E", 8 * time.Hour},
		{"did:test:dave", "eth_call", 503, "corr-F", 9 * time.Hour},
	}
	seedFilterRows(t, ctx, database, base, rows)

	t.Run("external_id filter", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{ExternalID: "did:test:alice", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 rows for alice, got %d", len(got))
		}
		for _, r := range got {
			if r.ExternalID != "did:test:alice" {
				t.Fatalf("external_id leak: got %q", r.ExternalID)
			}
		}
	})

	t.Run("method filter", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{Method: "eth_getLogs", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for eth_getLogs, got %d", len(got))
		}
		for _, r := range got {
			if r.Method != "eth_getLogs" {
				t.Fatalf("method leak: got %q", r.Method)
			}
		}
	})

	t.Run("status_code filter", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusCode: 401, Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for status_code=401, got %d", len(got))
		}
		for _, r := range got {
			if r.StatusCode != 401 {
				t.Fatalf("status_code leak: got %d", r.StatusCode)
			}
		}
	})

	// RD-914 — StatusClass is a range filter (status_code BETWEEN N00 AND N99)
	// that drives the admin UI's outcome dropdown. The bug it replaces was a
	// hard-coded exact match on 403, which missed 401/404/etc.
	t.Run("status_class 2xx covers all success rows", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusClass: "2xx", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		// Seed has six 200 rows.
		if len(got) != 6 {
			t.Fatalf("expected 6 rows for 2xx, got %d", len(got))
		}
		for _, r := range got {
			if r.StatusCode < 200 || r.StatusCode > 299 {
				t.Fatalf("2xx range leak: got %d", r.StatusCode)
			}
		}
	})

	t.Run("status_class 4xx covers every 4xx code, not just one", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusClass: "4xx", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		// Seed has two 401 rows.
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for 4xx, got %d", len(got))
		}
		for _, r := range got {
			if r.StatusCode < 400 || r.StatusCode > 499 {
				t.Fatalf("4xx range leak: got %d", r.StatusCode)
			}
		}
	})

	t.Run("status_class 5xx covers every 5xx code", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusClass: "5xx", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		// Seed has 500 + 503.
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for 5xx, got %d", len(got))
		}
		seen := map[int]bool{}
		for _, r := range got {
			if r.StatusCode < 500 || r.StatusCode > 599 {
				t.Fatalf("5xx range leak: got %d", r.StatusCode)
			}
			seen[r.StatusCode] = true
		}
		if !seen[500] || !seen[503] {
			t.Fatalf("expected 500 and 503 both present, got %v", seen)
		}
	})

	t.Run("status_class unknown value is ignored (no constraint)", func(t *testing.T) {
		// An unknown class returns ok=false from statusClassRange, so
		// buildAccessLogWhere applies no clause. Handler-level validation
		// already rejects unknowns up front; this just guards the DB layer
		// against silent data leaks if the handler grew a new bug.
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusClass: "garbage", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != len(rows) {
			t.Fatalf("expected unknown class to be a no-op (returning all %d rows), got %d", len(rows), len(got))
		}
	})

	t.Run("status_code wins when both StatusCode and StatusClass set", func(t *testing.T) {
		// Belt-and-braces: handler enforces mutual exclusion, but if a
		// caller bypasses the handler, the DB layer falls back to the
		// exact match — never the union.
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{StatusCode: 401, StatusClass: "5xx", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected exact StatusCode=401 to win (2 rows), got %d", len(got))
		}
		for _, r := range got {
			if r.StatusCode != 401 {
				t.Fatalf("StatusCode precedence leak: got %d", r.StatusCode)
			}
		}
	})

	t.Run("correlation_id filter", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{CorrelationID: "corr-A", Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 4 {
			t.Fatalf("expected 4 rows for corr-A, got %d", len(got))
		}
		for _, r := range got {
			if r.CorrelationID == nil || *r.CorrelationID != "corr-A" {
				t.Fatalf("correlation_id leak: got %v", r.CorrelationID)
			}
		}
	})

	t.Run("from filter", func(t *testing.T) {
		// From = base + 5h: rows at offsets 5h..9h → 5 rows.
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{From: base.Add(5 * time.Hour), Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 5 {
			t.Fatalf("expected 5 rows >= base+5h, got %d", len(got))
		}
	})

	t.Run("to filter", func(t *testing.T) {
		// To = base + 4h: rows at offsets 0..4h → 5 rows.
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{To: base.Add(4 * time.Hour), Limit: 100})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 5 {
			t.Fatalf("expected 5 rows <= base+4h, got %d", len(got))
		}
	})

	t.Run("external_id + method intersection", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{
			ExternalID: "did:test:bob",
			Method:     "eth_call",
			Limit:      100,
		})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		// Two bob+eth_call rows (statuses 200, 200).
		if len(got) != 2 {
			t.Fatalf("expected 2 rows for bob+eth_call, got %d", len(got))
		}
		for _, r := range got {
			if r.ExternalID != "did:test:bob" || r.Method != "eth_call" {
				t.Fatalf("intersection leak: got %s/%s", r.ExternalID, r.Method)
			}
		}
	})

	t.Run("limit is honoured", func(t *testing.T) {
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{Limit: 3})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 rows with limit=3, got %d", len(got))
		}
	})

	t.Run("offset is honoured", func(t *testing.T) {
		// All 10 rows ordered by created_at DESC. Offset 7 → 3 oldest remain.
		got, err := database.GetAccessLogs(ctx, AccessLogFilter{Limit: 100, Offset: 7})
		if err != nil {
			t.Fatalf("GetAccessLogs: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected 3 rows with offset=7, got %d", len(got))
		}
	})
}

// TestCountAccessLogs_HonoursFilters mirrors the filter coverage for the
// COUNT(*) path so pagination totals stay aligned with the rows returned by
// GetAccessLogs (modulo limit/offset, which CountAccessLogs deliberately
// ignores).
func TestCountAccessLogs_HonoursFilters(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second).Add(-10 * time.Hour)

	rows := []filterSeedRow{
		{"did:test:alice", "eth_call", 200, "corr-A", 0 * time.Hour},
		{"did:test:alice", "eth_blockNumber", 200, "corr-B", 1 * time.Hour},
		{"did:test:alice", "eth_call", 401, "corr-A", 2 * time.Hour},
		{"did:test:bob", "eth_call", 200, "corr-A", 3 * time.Hour},
		{"did:test:bob", "eth_call", 200, "corr-C", 4 * time.Hour},
		{"did:test:bob", "eth_blockNumber", 401, "corr-A", 5 * time.Hour},
		{"did:test:carol", "eth_getLogs", 500, "corr-D", 6 * time.Hour},
		{"did:test:carol", "eth_call", 200, "", 7 * time.Hour},
		{"did:test:dave", "eth_getLogs", 200, "corr-E", 8 * time.Hour},
		{"did:test:dave", "eth_call", 503, "corr-F", 9 * time.Hour},
	}
	seedFilterRows(t, ctx, database, base, rows)

	cases := []struct {
		name   string
		filter AccessLogFilter
		want   int64
	}{
		{"external_id", AccessLogFilter{ExternalID: "did:test:alice"}, 3},
		{"method", AccessLogFilter{Method: "eth_getLogs"}, 2},
		{"status_code", AccessLogFilter{StatusCode: 401}, 2},
		{"correlation_id", AccessLogFilter{CorrelationID: "corr-A"}, 4},
		{"from", AccessLogFilter{From: base.Add(5 * time.Hour)}, 5},
		{"to", AccessLogFilter{To: base.Add(4 * time.Hour)}, 5},
		{"external_id+method", AccessLogFilter{ExternalID: "did:test:bob", Method: "eth_call"}, 2},
		{"no filters", AccessLogFilter{}, int64(len(rows))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			n, err := database.CountAccessLogs(ctx, tc.filter)
			if err != nil {
				t.Fatalf("CountAccessLogs: %v", err)
			}
			if n != tc.want {
				t.Fatalf("CountAccessLogs(%+v) = %d, want %d", tc.filter, n, tc.want)
			}

			// Also confirm len(GetAccessLogs(...)) under a generous limit
			// matches the count — the two paths must agree.
			f := tc.filter
			f.Limit = int(MaxAccessLogQueryLimit)
			rows, err := database.GetAccessLogs(ctx, f)
			if err != nil {
				t.Fatalf("GetAccessLogs: %v", err)
			}
			if int64(len(rows)) != n {
				t.Fatalf("GetAccessLogs returned %d rows, CountAccessLogs returned %d (filter=%+v)", len(rows), n, tc.filter)
			}
		})
	}
}
