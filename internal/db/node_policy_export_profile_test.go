package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/nodepolicy"
)

// TestNodePolicyExportTimingAtScale is a P0 profile (plan RD-1410 §5.6): the
// full fact export at realistic sizes — 1,000 users with linked addresses and
// memberships, 100 organisations with one group, one active policy and 100
// contracts each (10,000 contracts), 100 sanctions. Gated: OPS_P0_PROFILE=1.
func TestNodePolicyExportTimingAtScale(t *testing.T) {
	if os.Getenv("OPS_P0_PROFILE") != "1" {
		t.Skip("set OPS_P0_PROFILE=1 to run the full-export timing profile")
	}
	d := setupTestDB(t)
	ctx := context.Background()
	bytecode := make([]byte, 8192)
	for i := range bytecode {
		bytecode[i] = byte(i * 31)
	}
	digest := sha256.Sum256(bytecode)
	runtimeDigest := hex.EncodeToString(digest[:])
	policySum := sha256.Sum256([]byte("perf-policy"))
	policyDigest := hex.EncodeToString(policySum[:])
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, slug, name) SELECT gen_random_uuid(), 'perf-org-' || g, 'Perf org ' || g FROM generate_series(1, 100) g`, nil},
		{`INSERT INTO groups (id, org_id, slug, name, depth, path) SELECT gen_random_uuid(), o.id, 'g-' || o.slug, 'Group', 0, 'g-' || o.slug FROM organizations o WHERE o.slug LIKE 'perf-org-%'`, nil},
		{`INSERT INTO group_access (group_id, claims, allowed_methods) SELECT g.id, ARRAY['deploy'], ARRAY['*'] FROM groups g JOIN organizations o ON o.id = g.org_id WHERE o.slug LIKE 'perf-org-%'`, nil},
		{`INSERT INTO users (id, external_id, kyc) SELECT gen_random_uuid(), 'did:test:perf-' || g, true FROM generate_series(1, 1000) g`, nil},
		{`INSERT INTO user_memberships (user_id, group_id) SELECT u.id, g.id FROM users u JOIN LATERAL (SELECT g.id FROM groups g JOIN organizations o ON o.id = g.org_id WHERE o.slug = 'perf-org-' || (1 + (substring(u.external_id from 'perf-(\d+)')::int % 100))) g ON true WHERE u.external_id LIKE 'did:test:perf-%'`, nil},
		{`INSERT INTO eth_address_links (did, eth_address, link_type) SELECT u.external_id, '0x' || lpad(to_hex(substring(u.external_id from 'perf-(\d+)')::int), 40, '0'), 'system' FROM users u WHERE u.external_id LIKE 'did:test:perf-%'`, nil},
		{`INSERT INTO contracts (id, org_id, address, name) SELECT gen_random_uuid(), o.id, '0x' || lpad(to_hex(1000000 + row_number() OVER ()), 40, '0'), 'C' FROM organizations o CROSS JOIN generate_series(1, 100) WHERE o.slug LIKE 'perf-org-%'`, nil},
		{`INSERT INTO contract_grants (group_id, contract_id) SELECT g.id, c.id FROM contracts c JOIN groups g ON g.org_id = c.org_id WHERE c.name = 'C'`, nil},
		{`INSERT INTO sanctioned_addresses (org_id, address, reason) SELECT NULL, '0x' || lpad(to_hex(5000000 + g), 40, '0'), 'perf' FROM generate_series(1, 100) g`, nil},
		{`INSERT INTO execution_policy_revisions (org_id, revision, status, source, policy_digest, solidity_source, solidity_digest, runtime_bytecode, runtime_digest, compiler)
 SELECT o.id, 1, 'active', 'policy', $1, 'contract P {}', $1, $2, $3, '{"solc":"0.8.35"}'::jsonb FROM organizations o WHERE o.slug LIKE 'perf-org-%'`, []any{policyDigest, bytecode, runtimeDigest}},
	} {
		if _, err := d.conn.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("seed: %v\n%s", err, stmt.sql)
		}
	}
	if _, err := d.conn.ExecContext(ctx, `ANALYZE`); err != nil {
		t.Fatal(err)
	}
	// The seed must have produced what the profile claims.
	var memberships, links, grants, policies int
	if err := d.conn.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM user_memberships m JOIN users u ON u.id = m.user_id WHERE u.external_id LIKE 'did:test:perf-%'),
 (SELECT count(*) FROM eth_address_links WHERE did LIKE 'did:test:perf-%'), (SELECT count(*) FROM contract_grants g JOIN contracts c ON c.id = g.contract_id WHERE c.name = 'C'),
 (SELECT count(*) FROM execution_policy_revisions WHERE status = 'active')`).Scan(&memberships, &links, &grants, &policies); err != nil {
		t.Fatal(err)
	}
	if memberships != 1000 || links != 1000 || grants != 10000 || policies != 100 {
		t.Fatalf("seed produced memberships=%d links=%d grants=%d policies=%d", memberships, links, grants, policies)
	}
	network := nodepolicy.Network{ChainID: 31337, DeploymentID: "export-profile"}
	var durations []time.Duration
	var snapshot nodepolicy.Snapshot
	for i := 0; i < 7; i++ {
		start := time.Now()
		s, err := d.ExportNodePolicySnapshot(ctx, network, time.Now(), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if i > 0 { // the first run warms caches and plans
			durations = append(durations, time.Since(start))
		}
		snapshot = s
	}
	// The fact queries alone (what a change log would replace), without Pin.
	var queries []time.Duration
	for i := 0; i < 6; i++ {
		tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		var facts nodepolicy.Snapshot
		start := time.Now()
		if err := exportNodeFacts(ctx, tx, &facts); err != nil {
			t.Fatal(err)
		}
		queries = append(queries, time.Since(start))
		_ = tx.Rollback()
	}
	sort.Slice(queries, func(i, j int) bool { return queries[i] < queries[j] })
	pinStart := time.Now()
	if _, err := nodepolicy.Pin(snapshot); err != nil {
		t.Fatal(err)
	}
	pin := time.Since(pinStart)
	encoded, _ := json.Marshal(snapshot)
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	result := map[string]any{"principals": len(snapshot.Principals), "groups": len(snapshot.Groups), "contracts": len(snapshot.Contracts), "policies": len(snapshot.Policies), "sanctions": len(snapshot.Sanctions),
		"export_ms_p50": float64(durations[len(durations)/2].Microseconds()) / 1e3, "export_ms_max": float64(durations[len(durations)-1].Microseconds()) / 1e3,
		"pin_ms": float64(pin.Microseconds()) / 1e3, "fact_queries_only_ms_p50": float64(queries[len(queries)/2].Microseconds()) / 1e3,
		"note": "export_ms includes one Pin inside the transaction; artifact_set is NULL (org-wide policies), shared_infrastructure/preregistered_addresses empty", "snapshot_json_bytes": len(encoded), "threshold_ms": 25}
	// Incremental export (RD-1411 §5.6) of one typical change: one ban, one
	// new contract with its grant. Read, patch and the publisher's one Pin.
	var incremental []time.Duration
	base := snapshot
	for i := 0; i < 6; i++ {
		if _, err := d.conn.ExecContext(ctx, `UPDATE users SET banned=NOT banned WHERE external_id='did:test:perf-7'`); err != nil {
			t.Fatal(err)
		}
		if _, err := d.conn.ExecContext(ctx, `WITH c AS (INSERT INTO contracts (id, org_id, address, name) SELECT gen_random_uuid(), g.org_id, '0x' || lpad(to_hex(9000000 + $1::int), 40, '0'), 'N' FROM groups g JOIN organizations o ON o.id = g.org_id WHERE o.slug = 'perf-org-1' RETURNING id, org_id)
 INSERT INTO contract_grants (group_id, contract_id) SELECT g.id, c.id FROM c JOIN groups g ON g.org_id = c.org_id`, i); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		changes, err := d.ExportNodePolicyChanges(ctx, base)
		if err != nil || changes.Full {
			t.Fatalf("incremental export: %v full=%v", err, changes.Full)
		}
		next, _, err := nodepolicy.ApplyChanges(base, strings.Repeat("ab", 32), base.Header, changes)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := nodepolicy.Pin(next); err != nil {
			t.Fatal(err)
		}
		incremental = append(incremental, time.Since(start))
		base = next
	}
	sort.Slice(incremental, func(i, j int) bool { return incremental[i] < incremental[j] })
	result["incremental_ms_p50"] = float64(incremental[len(incremental)/2].Microseconds()) / 1e3
	result["incremental_ms_max"] = float64(incremental[len(incremental)-1].Microseconds()) / 1e3
	t.Logf("full export: %+v", result)
	if out := os.Getenv("OPS_P0_OUTPUT"); out != "" {
		data, _ := json.MarshalIndent(result, "", "  ")
		_ = os.MkdirAll(out, 0o700)
		_ = os.WriteFile(filepath.Join(out, "export-timing.json"), data, 0o600)
	}
}
