package db_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
	"privacy-proxy/internal/rbac"
)

// migrateAuditDB opens an EMPTY testcontainer database as the owner and applies
// the LEAN, standalone audit migration set (RD-1147): roles + access_logs +
// chain tables + append-only grants. It does NOT run the main migration FS, so
// the audit DB never gets users/contracts/groups/rbac_audit_log. Returns the
// admin/owner handle.
func migrateAuditDB(t *testing.T, auditURL string) *db.DB {
	t.Helper()
	admin, err := db.NewWithoutMigrate(auditURL)
	if err != nil {
		t.Fatalf("open audit admin DB: %v", err)
	}
	if err := admin.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		admin.Close()
		t.Fatalf("apply lean audit migrations: %v", err)
	}
	return admin
}

// tableExists reports whether a table exists in the public schema of database.
func tableExists(t *testing.T, database *db.DB, name string) bool {
	t.Helper()
	var reg *string
	if err := database.Conn().QueryRowContext(context.Background(),
		`SELECT to_regclass('public.' || $1)::text`, name).Scan(&reg); err != nil {
		t.Fatalf("to_regclass(%s): %v", name, err)
	}
	return reg != nil
}

// TestMainDB_HasNoAccessLogs_ButKeepsRBACChain is the RD-1147 main-DB assertion:
// after migrating a MAIN database, access_logs does NOT exist (migration 068
// dropped it), while rbac_audit_log + compliance_logs DO, the shared chain
// tables (audit_chain_anchor/checkpoint/reanchor) survive, AND the rbac_audit_log
// hash chain still verifies — proving the drop did not break the admin-audit
// chain (whose verifier reads audit_chain_anchor by chain_name).
func TestMainDB_HasNoAccessLogs_ButKeepsRBACChain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container integration test in -short mode")
	}
	ctx := context.Background()

	mainURL, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)
	mainDB, err := db.New(mainURL) // runs the full main migration set incl. 068
	if err != nil {
		t.Fatalf("open+migrate main DB: %v", err)
	}
	t.Cleanup(func() { mainDB.Close() })

	// access_logs must be GONE from main.
	if tableExists(t, mainDB, "access_logs") {
		t.Fatal("MAIN DB still has access_logs — migration 068 (drop) did not take effect")
	}
	// rbac_audit_log + compliance_logs must STAY in main (RD-1147 scope = access_logs only).
	if !tableExists(t, mainDB, "rbac_audit_log") {
		t.Fatal("MAIN DB is missing rbac_audit_log — it must stay in main")
	}
	if !tableExists(t, mainDB, "compliance_logs") {
		t.Fatal("MAIN DB is missing compliance_logs — it must stay in main")
	}
	// The chain_name-keyed chain tables must survive in main: the rbac_audit_log
	// verifier reads audit_chain_anchor by chain_name.
	for _, tbl := range []string{"audit_chain_anchor", "audit_chain_checkpoint", "audit_chain_reanchor"} {
		if !tableExists(t, mainDB, tbl) {
			t.Fatalf("MAIN DB is missing %s — it is shared with the rbac_audit_log chain and must stay", tbl)
		}
	}

	// Install the rbac chain (as server.go does), write a few chained
	// rbac_audit_log rows, then verify the chain still walks cleanly on main.
	// This is the "drop didn't break the admin chain" proof.
	seed, err := mainDB.GetLatestRBACAuditLogHash(ctx)
	if err != nil {
		t.Fatalf("seed rbac chain: %v", err)
	}
	mainDB.SetRBACAuditChain(audit.NewHashChain(seed))

	orgID := "22222222-2222-2222-2222-222222222222"
	for i := 0; i < 3; i++ {
		if err := mainDB.CreateAuditLog(ctx, &rbac.AuditLogEntry{
			ActorExternalID: "did:test:admin",
			Action:          "update",
			ResourceType:    "group",
			ResourceName:    "engineering",
			OrgID:           &orgID,
			IPAddress:       "127.0.0.1",
			NewValue:        map[string]any{"iteration": i},
		}); err != nil {
			t.Fatalf("CreateAuditLog #%d: %v", i, err)
		}
	}
	verifier := audit.NewVerifier(mainDB.Conn(), mainDB)
	res, err := verifier.Verify(ctx, audit.ChainRBACAuditLog)
	if err != nil {
		t.Fatalf("verify rbac_audit_log chain on main: %v", err)
	}
	if !res.OK {
		t.Fatalf("rbac_audit_log chain failed verification after access_logs drop: %+v", res)
	}
	if res.ScannedRows < 3 {
		t.Fatalf("expected >=3 rbac_audit_log rows scanned, got %d", res.ScannedRows)
	}
}

// TestAuditDB_LeanSchema is the RD-1147 audit-DB assertion: the lean migration
// set builds ONLY access_logs + the three chain tables (and the roles), and does
// NOT create users/contracts/groups/rbac_audit_log/compliance_logs.
func TestAuditDB_LeanSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container integration test in -short mode")
	}

	auditURL, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)
	auditAdminDB := migrateAuditDB(t, auditURL)
	t.Cleanup(func() { auditAdminDB.Close() })

	// Present: access_logs + the chain tables.
	for _, tbl := range []string{"access_logs", "audit_chain_anchor", "audit_chain_checkpoint", "audit_chain_reanchor"} {
		if !tableExists(t, auditAdminDB, tbl) {
			t.Fatalf("audit DB is missing expected lean table %s", tbl)
		}
	}
	// Absent: the entire main RBAC/operational schema.
	for _, tbl := range []string{"users", "contracts", "groups", "rbac_audit_log", "compliance_logs", "organizations", "disclosure_grants"} {
		if tableExists(t, auditAdminDB, tbl) {
			t.Fatalf("audit DB unexpectedly has main-schema table %s — the lean set must not create it", tbl)
		}
	}
}

// TestAccessLogsSeparateAuditDB is the RD-1147 end-to-end acceptance test: a
// SEPARATE audit Postgres migrated by the LEAN set, a restricted runtime role
// sealed to INSERT-only, and an owner/admin role. It proves:
//   - the restricted runtime role is DENIED UPDATE/DELETE on access_logs (SQLSTATE 42501);
//   - INSERT + SELECT are allowed for the runtime role;
//   - a chained access_logs write via the runtime role lands in the AUDIT DB;
//     reads (incl. org-scoping) come back from the audit DB;
//   - the verifier verifies the audit-DB chain;
//   - prune via the ADMIN pool works (the runtime role could not).
func TestAccessLogsSeparateAuditDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping container integration test in -short mode")
	}
	ctx := context.Background()

	// --- audit DB: admin pool runs the LEAN migrations against an empty DB -----
	auditURL, auditCleanup := db.SetupTestContainer(t)
	t.Cleanup(auditCleanup)
	auditAdminDB := migrateAuditDB(t, auditURL)
	t.Cleanup(func() { auditAdminDB.Close() })

	// --- provision a restricted LOGIN role in the audit DB --------------------
	// privacy_proxy_app is created NOLOGIN by the lean migration; grant it a
	// password + LOGIN here so we can connect AS the restricted role.
	const restrictedPassword = "app-restricted-pw"
	if _, err := auditAdminDB.Conn().ExecContext(ctx,
		fmt.Sprintf("ALTER ROLE privacy_proxy_app WITH LOGIN PASSWORD '%s'", restrictedPassword)); err != nil {
		t.Fatalf("grant LOGIN to privacy_proxy_app: %v", err)
	}
	runtimeURL := rewriteDSNCredential(t, auditURL, "privacy_proxy_app", restrictedPassword)
	auditRuntimeDB, err := db.NewWithoutMigrate(runtimeURL) // restricted role, no DDL
	if err != nil {
		t.Fatalf("open audit runtime DB (restricted role): %v", err)
	}
	t.Cleanup(func() { auditRuntimeDB.Close() })

	// --- SEAL PROOF: restricted role DENIED UPDATE/DELETE on access_logs ------
	seedChain := audit.NewHashChain("")
	if _, _, _, err := auditAdminDB.LogAccessChained(ctx, seedChain, "did:test:seed", "eth_chainId", 200, "127.0.0.1", "corr-seed", nil, nil, "org-seed", ""); err != nil {
		t.Fatalf("seed access_logs via admin: %v", err)
	}
	rc := auditRuntimeDB.Conn()
	if _, err := rc.ExecContext(ctx, `UPDATE access_logs SET status_code = 999`); err == nil {
		t.Fatal("SEAL BROKEN: restricted runtime role was allowed to UPDATE access_logs")
	} else if !isPermissionDenied(err) {
		t.Fatalf("expected permission-denied (42501) on UPDATE, got: %v", err)
	}
	if _, err := rc.ExecContext(ctx, `DELETE FROM access_logs`); err == nil {
		t.Fatal("SEAL BROKEN: restricted runtime role was allowed to DELETE from access_logs")
	} else if !isPermissionDenied(err) {
		t.Fatalf("expected permission-denied (42501) on DELETE, got: %v", err)
	}
	// The runtime role CAN SELECT.
	if _, err := rc.ExecContext(ctx, `SELECT count(*) FROM access_logs`); err != nil {
		t.Fatalf("restricted role should be able to SELECT access_logs: %v", err)
	}

	// --- chained write via runtime role (INSERT allowed) lands in AUDIT DB ----
	runtimeChainSeed, err := auditRuntimeDB.GetLatestAccessLogHashForChain(ctx, "access_logs")
	if err != nil {
		t.Fatalf("seed runtime chain: %v", err)
	}
	runtimeChain := audit.NewHashChain(runtimeChainSeed)
	if _, _, _, err := auditRuntimeDB.LogAccessChained(ctx, runtimeChain, "did:test:alice", "eth_getLogs", 200, "10.0.0.1", "corr-alice", nil, nil, "org-A", ""); err != nil {
		t.Fatalf("chained write via runtime role (INSERT should be allowed): %v", err)
	}

	// It appears in the audit DB, readable via the runtime role.
	auditLogs, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{ExternalID: "did:test:alice", Limit: 10})
	if err != nil {
		t.Fatalf("read audit access_logs: %v", err)
	}
	if len(auditLogs) != 1 || auditLogs[0].Method != "eth_getLogs" {
		t.Fatalf("expected 1 alice row in audit db, got %+v", auditLogs)
	}

	// --- org-scoping (org_id = ANY) still works on the audit DB ---------------
	scopedA, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{OrgIDs: []string{"org-A"}, Limit: 100})
	if err != nil {
		t.Fatalf("org-scoped read (org-A): %v", err)
	}
	if len(scopedA) != 1 {
		t.Fatalf("org-A scoped read: got %d rows, want 1", len(scopedA))
	}
	scopedOther, err := auditRuntimeDB.GetAccessLogs(ctx, db.AccessLogFilter{OrgIDs: []string{"org-does-not-exist"}, Limit: 100})
	if err != nil {
		t.Fatalf("org-scoped read (other): %v", err)
	}
	if len(scopedOther) != 0 {
		t.Fatalf("cross-org read leak: got %d rows for a foreign org, want 0", len(scopedOther))
	}

	// --- verifier verifies the audit-DB access_logs chain ---------------------
	verifier := audit.NewVerifier(auditAdminDB.Conn(), auditAdminDB)
	res, err := verifier.Verify(ctx, audit.ChainAccessLogs)
	if err != nil {
		t.Fatalf("verify audit chain: %v", err)
	}
	if !res.OK {
		t.Fatalf("audit chain failed verification: %+v", res)
	}

	// --- prune via the ADMIN pool works (runtime role could not) --------------
	cutoff := time.Now().UTC().Add(time.Hour)
	pr, err := auditAdminDB.CleanupAccessLogs(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune via admin pool: %v", err)
	}
	if pr.Deleted == 0 {
		t.Fatalf("expected admin prune to delete rows, deleted 0")
	}
	remaining, err := auditAdminDB.CountAccessLogsTotal(ctx)
	if err != nil {
		t.Fatalf("count after prune: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("expected 0 rows after prune, got %d", remaining)
	}
	if pr.AnchorHash == "" {
		t.Fatal("expected prune to record a chain anchor hash")
	}
}

// rewriteDSNCredential returns dsn with its user/password replaced, preserving
// host/port/db. Used to derive a restricted-role DSN from the owner DSN.
func rewriteDSNCredential(t *testing.T, dsn, user, password string) string {
	t.Helper()
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		user, password, cfg.Host, cfg.Port, cfg.Database)
}

// isPermissionDenied reports whether err is a Postgres "permission denied" error
// (SQLSTATE 42501) — the expected outcome when the sealed runtime role attempts
// UPDATE/DELETE on access_logs.
func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "permission denied") || strings.Contains(msg, "42501")
}
