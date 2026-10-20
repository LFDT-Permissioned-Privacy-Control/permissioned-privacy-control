package db_test

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"privacy-proxy/internal/db"
	migrationsaudit "privacy-proxy/internal/db/migrations_audit"
)

// tern >= 2.4 retro-fits a PRIMARY KEY onto a version table created by an older
// tern, which needs ownership. The audit database's documented lifecycle leaves
// schema_version_audit owned by DATABASE_URL's role while
// AUDIT_ADMIN_DATABASE_URL migrates it, so that deployment starts failing with a
// bare "must be owner of table ... (SQLSTATE 42501)".

// asRole returns dsn rewritten to connect as the given role.
func asRole(t *testing.T, dsn, role, password string) string {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	parsed.User = url.UserPassword(role, password)
	return parsed.String()
}

// dropVersionTablePrimaryKey reproduces a version table created by tern < 2.4.
func dropVersionTablePrimaryKey(t *testing.T, database *db.DB) {
	t.Helper()
	var name string
	err := database.Conn().QueryRowContext(context.Background(),
		`SELECT conname FROM pg_constraint
		  WHERE conrelid = 'schema_version_audit'::regclass AND contype = 'p'`).Scan(&name)
	if err != nil {
		t.Fatalf("find version table primary key: %v", err)
	}
	if _, err := database.Conn().ExecContext(context.Background(),
		`ALTER TABLE schema_version_audit DROP CONSTRAINT `+name); err != nil {
		t.Fatalf("drop %s: %v", name, err)
	}
}

func versionTableHasPrimaryKey(t *testing.T, database *db.DB) bool {
	t.Helper()
	var ok bool
	if err := database.Conn().QueryRowContext(context.Background(),
		`SELECT EXISTS (SELECT 1 FROM pg_constraint
		                 WHERE conrelid = 'schema_version_audit'::regclass AND contype = 'p')`,
	).Scan(&ok); err != nil {
		t.Fatalf("check primary key: %v", err)
	}
	return ok
}

// createLoginRole creates a login role holding every privilege audit/001 grants
// privacy_proxy_admin — but no ownership. memberOfOwner additionally makes it a
// member of the owning role, which is what lets Postgres treat it as the owner.
func createLoginRole(t *testing.T, owner *db.DB, role, password string, memberOfOwner bool) {
	t.Helper()
	stmts := []string{
		`DROP ROLE IF EXISTS ` + role,
		`CREATE ROLE ` + role + ` LOGIN PASSWORD '` + password + `'`,
		`GRANT USAGE, CREATE ON SCHEMA public TO ` + role,
		`GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ` + role,
		`GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ` + role,
	}
	if memberOfOwner {
		var ownerRole string
		if err := owner.Conn().QueryRowContext(context.Background(), `SELECT current_user`).Scan(&ownerRole); err != nil {
			t.Fatalf("resolve owner role: %v", err)
		}
		stmts = append(stmts, `GRANT `+ownerRole+` TO `+role)
	}
	for _, stmt := range stmts {
		if _, err := owner.Conn().ExecContext(context.Background(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// setupAuditDB migrates a fresh audit database and returns the owner handle.
func setupAuditDB(t *testing.T) (auditURL string, owner *db.DB) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	auditURL, cleanup := db.SetupTestContainer(t)
	t.Cleanup(cleanup)

	owner = migrateAuditDB(t, auditURL)
	t.Cleanup(func() { owner.Close() })
	return auditURL, owner
}

func TestMigrateAuditOnly_NonOwnerWithoutPrimaryKey_ExplainsTheFix(t *testing.T) {
	auditURL, owner := setupAuditDB(t)
	dropVersionTablePrimaryKey(t, owner)
	createLoginRole(t, owner, "audit_migrator", "migratorpass", false)

	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, "audit_migrator", "migratorpass"))
	if err != nil {
		t.Fatalf("open audit DB as non-owner: %v", err)
	}
	defer migrator.Close()

	err = migrator.MigrateAuditOnly(context.Background(), migrationsaudit.FS)
	if err == nil {
		t.Fatal("expected the migration to fail for a non-owner, got nil")
	}

	got := err.Error()
	for _, want := range []string{
		"schema_version_audit",     // which table
		"audit_migrator",           // who is connected
		"OWNER TO",                 // the remediation
		"REVOKE",                   // the elevation must not outlive the transfer
		"REASSIGN OWNED BY",        // the remediation for a whole audit schema
		"AUDIT_ADMIN_DATABASE_URL", // where this configuration comes from
	} {
		if !strings.Contains(got, want) {
			t.Errorf("error should mention %q, got: %v", want, got)
		}
	}
	if strings.Contains(got, "SQLSTATE") {
		t.Errorf("expected an actionable error rather than a raw SQLSTATE, got: %v", got)
	}
}

// A primary key already in place means tern never issues the ALTER TABLE, so a
// non-owner must keep migrating. This is what keeps the check from breaking
// deployments that work today.
func TestMigrateAuditOnly_NonOwnerWithPrimaryKey_StillMigrates(t *testing.T) {
	auditURL, owner := setupAuditDB(t)
	createLoginRole(t, owner, "audit_migrator", "migratorpass", false)

	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, "audit_migrator", "migratorpass"))
	if err != nil {
		t.Fatalf("open audit DB as non-owner: %v", err)
	}
	defer migrator.Close()

	if err := migrator.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		t.Fatalf("migration should succeed when the version table already has its primary key: %v", err)
	}
}

// Membership in the owning role is enough for Postgres, so it must be enough
// here too — this is why the check asks pg_has_role rather than comparing names.
func TestMigrateAuditOnly_MemberOfOwner_Migrates(t *testing.T) {
	auditURL, owner := setupAuditDB(t)
	dropVersionTablePrimaryKey(t, owner)
	createLoginRole(t, owner, "audit_member", "memberpass", true)

	migrator, err := db.NewWithoutMigrate(asRole(t, auditURL, "audit_member", "memberpass"))
	if err != nil {
		t.Fatalf("open audit DB as a member of the owner: %v", err)
	}
	defer migrator.Close()

	if err := migrator.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		t.Fatalf("a member of the owning role must be able to migrate: %v", err)
	}
	if !versionTableHasPrimaryKey(t, owner) {
		t.Error("tern should have added the version table's primary key")
	}
}

func TestMigrateAuditOnly_Owner_AddsThePrimaryKey(t *testing.T) {
	_, owner := setupAuditDB(t)
	dropVersionTablePrimaryKey(t, owner)

	if err := owner.MigrateAuditOnly(context.Background(), migrationsaudit.FS); err != nil {
		t.Fatalf("owner migration failed: %v", err)
	}
	if !versionTableHasPrimaryKey(t, owner) {
		t.Error("tern should have added the version table's primary key when run as owner")
	}
}
