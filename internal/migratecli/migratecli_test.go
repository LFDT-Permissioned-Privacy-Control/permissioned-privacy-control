package migratecli

import (
	"context"
	"testing"

	"privacy-proxy/internal/db"
)

// The migration command is reachable from the shipped image (review finding
// 9): the server binary runs it as `privacy-proxy migrate [-audit|-exec]`,
// through this package, with the same guards as cmd/migrate.
func TestRefusesAuditAndExecTogether(t *testing.T) {
	hermetic(t)
	if code := Main([]string{"-audit", "-exec"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if code := Main([]string{"-unknown"}); code != 2 {
		t.Fatalf("unknown flag: exit %d, want 2", code)
	}
	if code := Main([]string{"audit"}); code != 2 {
		t.Fatalf("a positional argument must not migrate the main database: exit %d, want 2", code)
	}
	if code := Main([]string{"-h"}); code != 0 {
		t.Fatalf("-h: exit %d, want 0", code)
	}
}

// hermetic clears the settings a developer's environment may carry.
func hermetic(t *testing.T) {
	t.Helper()
	for _, k := range []string{"ENVIRONMENT", "CONFIG_FILE", "DATABASE_URL", "AUDIT_ADMIN_DATABASE_URL", "EXECUTION_ADMIN_DATABASE_URL"} {
		t.Setenv(k, "")
	}
}

// In production the owner DSN of the audit or the tracking database may not
// be DATABASE_URL; refused before any connection is opened.
func TestProductionRefusesTheMainDatabaseByName(t *testing.T) {
	hermetic(t)
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("DATABASE_URL", "postgres://u:p@127.0.0.1:1/main?sslmode=disable")
	t.Setenv("AUDIT_ADMIN_DATABASE_URL", "postgres://u:p@127.0.0.1:1/main?sslmode=disable")
	t.Setenv("EXECUTION_ADMIN_DATABASE_URL", "postgres://u:p@127.0.0.1:1/main?sslmode=disable")
	for _, args := range [][]string{{"-audit"}, {"-exec"}} {
		if code := Main(args); code != 1 {
			t.Fatalf("%v: exit %d, want 1", args, code)
		}
	}
}

// Run with only the audit owner's DSN (review of finding 9), the name
// comparison cannot tell it names the main database: the command refuses by
// content.
func TestRefusesAnAuditDSNThatHoldsTheMainSchema(t *testing.T) {
	hermetic(t)
	url, cleanup := db.SetupTestContainer(t)
	defer cleanup()
	conn, err := db.NewWithoutMigrate(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Conn().ExecContext(context.Background(), `CREATE TABLE users (id int)`); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUDIT_ADMIN_DATABASE_URL", url)
	if code := Main([]string{"-audit"}); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	var applied bool
	if err := conn.Conn().QueryRowContext(context.Background(), `SELECT to_regclass('schema_version_audit') IS NOT NULL`).Scan(&applied); err != nil || applied {
		t.Fatalf("audit migrations reached the main database: %v %v", applied, err)
	}
}

func TestMigratesTheAuditDatabase(t *testing.T) {
	hermetic(t)
	url, cleanup := db.SetupTestContainer(t)
	defer cleanup()
	t.Setenv("DATABASE_URL", url)
	t.Setenv("AUDIT_ADMIN_DATABASE_URL", url)
	if code := Main([]string{"-audit"}); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	conn, err := db.NewWithoutMigrate(url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var version int
	if err := conn.Conn().QueryRowContext(context.Background(), `SELECT version FROM schema_version_audit`).Scan(&version); err != nil || version < 3 {
		t.Fatalf("audit schema version %d %v", version, err)
	}
}
