package db_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/audit"
	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

// freshDatabaseURL returns an empty database: a new one on TEST_DATABASE_URL's
// server, or a new testcontainer.
func freshDatabaseURL(t *testing.T) string {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		u, cleanup := db.SetupTestContainer(t)
		t.Cleanup(cleanup)
		return u
	}
	parsed, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("audit_fresh_%d", time.Now().UnixNano())
	parsed.Path = "/" + name
	if err := db.EnsureTestDatabase(parsed.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		server, err := db.NewWithoutMigrate(base)
		if err != nil {
			return
		}
		defer server.Close()
		_, _ = server.Conn().ExecContext(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
	})
	return parsed.String()
}

// uniqueRole returns a role name unused by earlier runs, and drops the role
// when the test ends (before its database is dropped, so DROP OWNED reaches
// the role's privileges there).
func uniqueRole(t *testing.T, databaseURL, prefix string) string {
	t.Helper()
	role := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	t.Cleanup(func() {
		owner, err := db.NewWithoutMigrate(databaseURL)
		if err != nil {
			return
		}
		defer owner.Close()
		_, _ = owner.Conn().ExecContext(context.Background(), `DROP OWNED BY `+role)
		_, _ = owner.Conn().ExecContext(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	return role
}

type sealedRow struct {
	id   int64
	hash string
}

func accessLogRows(t *testing.T, d *db.DB) []sealedRow {
	t.Helper()
	rows, err := d.Conn().QueryContext(context.Background(), `SELECT id, entry_hash FROM access_logs ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []sealedRow
	for rows.Next() {
		var r sealedRow
		if err := rows.Scan(&r.id, &r.hash); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func verifyAccessLogChain(t *testing.T, d *db.DB, signer audit.Signer) *audit.Result {
	t.Helper()
	v := audit.NewVerifier(d.Conn(), d)
	v.SetCheckpointVerification(checkpointAdapterForTest{d}, signer)
	res, err := v.Verify(context.Background(), audit.ChainAccessLogs)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("access-log chain does not verify: %+v", res)
	}
	return res
}

func sealRecords(t *testing.T, d *db.DB, chain *audit.HashChain, firstSeq uint64, n int) error {
	t.Helper()
	ctx := context.Background()
	batch := make([]db.BufferedAccessLog, 0, n)
	for i := 0; i < n-1; i++ {
		batch = append(batch, db.BufferedAccessLog{Seq: firstSeq + uint64(i), Record: eventMix(i)})
	}
	if _, err := d.SealBufferedAccessLogs(ctx, chain, batch, "access_logs"); err != nil {
		return err
	}
	_, err := d.SealBufferedAccessLog(ctx, chain, eventMix(n), firstSeq+uint64(n-1), "access_logs")
	return err
}

// TestAccessLogIDBigintMigrationKeepsChainVerifiable: audit migration 003
// widens access_logs.id without touching a stored id or hash. A chain sealed
// (batch, single and synchronous paths) and checkpointed at version 2 still
// verifies after it, and records past 2^31 seal and verify on top of it; at
// version 2 the sequence cannot go past 2^31 - 1.
func TestAccessLogIDBigintMigrationKeepsChainVerifiable(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	ctx := context.Background()
	auditURL := freshDatabaseURL(t)
	admin, err := db.NewWithoutMigrate(auditURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { admin.Close() }()
	if err := db.MigrateAuditFSToForTest(ctx, admin, migrationsaudit.FS, 2); err != nil {
		t.Fatal(err)
	}
	columnType := func() (string, string, int64) {
		t.Helper()
		var column, seqType string
		var seqMax int64
		if err := admin.Conn().QueryRowContext(ctx, `SELECT (SELECT data_type FROM information_schema.columns WHERE table_name='access_logs' AND column_name='id'),
			data_type::text, max_value FROM pg_sequences WHERE sequencename='access_logs_id_seq'`).Scan(&column, &seqType, &seqMax); err != nil {
			t.Fatal(err)
		}
		return column, seqType, seqMax
	}
	if column, seqType, _ := columnType(); column != "integer" || seqType != "integer" {
		t.Fatalf("version 2 precondition: id %s, sequence %s", column, seqType)
	}
	signer := audit.NewHMACSigner("bigint-test", []byte("checkpoint-hmac-secret-32bytes!!"))
	checkpoints := audit.NewCheckpointWorker(checkpointAdapterForTest{admin}, signer, []audit.ChainName{audit.ChainAccessLogs}, time.Hour)
	chain := audit.NewHashChain("")
	if err := sealRecords(t, admin, chain, 1, 6); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := admin.LogAccessChained(ctx, chain, "did:test:sync", "eth_call", 200, "127.0.0.1", "corr-sync", nil, nil, "", ""); err != nil {
		t.Fatal(err)
	}
	if err := checkpoints.Checkpoint(ctx, audit.ChainAccessLogs); err != nil {
		t.Fatal(err)
	}
	verifyAccessLogChain(t, admin, signer)

	// Red at version 2: the integer sequence cannot pass 2^31 - 1.
	if _, err := admin.Conn().ExecContext(ctx, `SELECT setval('access_logs_id_seq', 2147483647)`); err != nil {
		t.Fatal(err)
	}
	if err := sealRecords(t, admin, chain, 100, 2); err == nil || !strings.Contains(err.Error(), "maximum value") {
		t.Fatalf("an integer id past 2^31 - 1 must fail at version 2, got %v", err)
	}
	before := accessLogRows(t, admin)
	tail := verifyAccessLogChain(t, admin, signer).TailHash

	if err := admin.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
		t.Fatal(err)
	}
	// Pooled sessions keep plans prepared for the integer column (Postgres
	// refuses them once: "cached plan must not change result type"), which is
	// why the migration runs with the instances stopped. Continue on new ones.
	admin.Close()
	if admin, err = db.NewWithoutMigrate(auditURL); err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	checkpoints = audit.NewCheckpointWorker(checkpointAdapterForTest{admin}, signer, []audit.ChainName{audit.ChainAccessLogs}, time.Hour)
	if column, seqType, seqMax := columnType(); column != "bigint" || seqType != "bigint" || seqMax != 9223372036854775807 {
		t.Fatalf("after 003: id %s, sequence %s max %d", column, seqType, seqMax)
	}
	var serial string
	var canInsert, canUpdate, canDelete, canUseSequence bool
	if err := admin.Conn().QueryRowContext(ctx, `SELECT pg_get_serial_sequence('access_logs','id'),
		has_table_privilege('privacy_proxy_app','access_logs','INSERT'), has_table_privilege('privacy_proxy_app','access_logs','UPDATE'),
		has_table_privilege('privacy_proxy_app','access_logs','DELETE'), has_sequence_privilege('privacy_proxy_app','access_logs_id_seq','USAGE')`).Scan(&serial, &canInsert, &canUpdate, &canDelete, &canUseSequence); err != nil {
		t.Fatal(err)
	}
	if serial != "public.access_logs_id_seq" || !canInsert || canUpdate || canDelete || !canUseSequence {
		t.Fatalf("ownership or the append-only seal changed: serial=%s insert=%v update=%v delete=%v sequence=%v", serial, canInsert, canUpdate, canDelete, canUseSequence)
	}
	after := accessLogRows(t, admin)
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("the migration changed stored ids or hashes:\nbefore %v\nafter  %v", before, after)
	}
	if got := verifyAccessLogChain(t, admin, signer).TailHash; got != tail {
		t.Fatalf("tail hash %s, want %s", got, tail)
	}

	// Past 2^31: batch, single and synchronous paths seal and verify.
	if err := sealRecords(t, admin, chain, 200, 4); err != nil {
		t.Fatal(err)
	}
	id, _, _, err := admin.LogAccessChained(ctx, chain, "did:test:sync", "eth_call", 200, "127.0.0.1", "corr-sync-2", nil, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if id <= 2147483647 {
		t.Fatalf("id %d not past 2^31 - 1", id)
	}
	if err := checkpoints.Checkpoint(ctx, audit.ChainAccessLogs); err != nil {
		t.Fatal(err)
	}
	verifyAccessLogChain(t, admin, signer)
	logs, err := admin.GetAccessLogs(ctx, db.AccessLogFilter{CorrelationID: "corr-sync-2"})
	if err != nil || len(logs) != 1 || int64(logs[0].ID) != id {
		t.Fatalf("reading an id past 2^31: %+v %v", logs, err)
	}
	if _, headID, _, err := admin.GetAccessLogChainStats(ctx, "access_logs"); err != nil || headID != id {
		t.Fatalf("chain stats head %d, want %d (%v)", headID, id, err)
	}
}

// A role that holds every privilege but does not own access_logs cannot widen
// it; the migration refuses up front with the remedy instead of a bare 42501.
func TestAuditMigration003RefusesNonOwnerWithTheFix(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	ctx := context.Background()
	auditURL := freshDatabaseURL(t)
	owner, err := db.NewWithoutMigrate(auditURL)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err := db.MigrateAuditFSToForTest(ctx, owner, migrationsaudit.FS, 2); err != nil {
		t.Fatal(err)
	}
	nonOwner := uniqueRole(t, auditURL, "audit_bigint_migrator")
	createLoginRole(t, owner, nonOwner, "migratorpass", false)
	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, nonOwner, "migratorpass"))
	if err != nil {
		t.Fatal(err)
	}
	defer migrator.Close()
	err = migrator.MigrateAuditOnly(ctx, migrationsaudit.FS)
	if err == nil {
		t.Fatal("a non-owner widened access_logs")
	}
	for _, want := range []string{"access_logs", nonOwner, "OWNER TO", "REASSIGN OWNED BY", "AUDIT_ADMIN_DATABASE_URL", "migrate -audit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "SQLSTATE") {
		t.Errorf("want an actionable error, got %v", err)
	}
	idType := func() string {
		t.Helper()
		var dataType string
		if err := owner.Conn().QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns WHERE table_name='access_logs' AND column_name='id'`).Scan(&dataType); err != nil {
			t.Fatal(err)
		}
		return dataType
	}
	if got := idType(); got != "integer" {
		t.Fatalf("the refused run changed access_logs.id to %s", got)
	}
	// A member of the owner may migrate.
	memberRole := uniqueRole(t, auditURL, "audit_bigint_member")
	createLoginRole(t, owner, memberRole, "memberpass", true)
	member, err := db.NewWithoutMigrate(asRole(t, auditURL, memberRole, "memberpass"))
	if err != nil {
		t.Fatal(err)
	}
	defer member.Close()
	if err := member.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
		t.Fatalf("a member of the owning role must migrate: %v", err)
	}
	if got := idType(); got != "bigint" {
		t.Fatalf("after the member's run access_logs.id is %s", got)
	}
}

// audit/004 on a database that already holds buffer sequences: the first
// range drawn starts above the highest one, whatever range it is in.
func TestBufferRangeSequenceStartsAboveStoredSequences(t *testing.T) {
	if testing.Short() {
		t.Skip("database test")
	}
	ctx := context.Background()
	admin, err := db.NewWithoutMigrate(freshDatabaseURL(t))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	if err := db.MigrateAuditFSToForTest(ctx, admin, migrationsaudit.FS, 3); err != nil {
		t.Fatal(err)
	}
	chain := audit.NewHashChain("")
	stored := uint64(1)<<db.BufferRangeShift + 3 // a row already in range 1
	if err := sealRecords(t, admin, chain, stored-1, 2); err != nil {
		t.Fatal(err)
	}
	if err := admin.MigrateAuditOnly(ctx, migrationsaudit.FS); err != nil {
		t.Fatal(err)
	}
	n, err := admin.ReserveAccessLogBufferRange(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n<<db.BufferRangeShift <= stored {
		t.Fatalf("first range %d starts at %d, at or below the stored sequence %d", n, n<<db.BufferRangeShift, stored)
	}
	if n != 2 {
		t.Fatalf("first range %d, want 2 (the one after the stored sequence's range)", n)
	}
}
