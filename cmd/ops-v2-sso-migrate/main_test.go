package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/operational/ssosql"
)

func TestExplicitOfflineSSOArguments(t *testing.T) {
	t.Setenv("TEST_SSO_OWNER_DSN", "postgres://private-user:do-not-print@127.0.0.1:1/private")
	for _, args := range [][]string{
		nil, {"unknown"}, {"migrate"}, {"migrate", "--dsn-env", "bad-name"},
		{"migrate", "--dsn-env", "TEST_SSO_OWNER_DSN", "--app-role", "app", "--retention-role", "retention"},
		{"initialize", "--dsn-env", "TEST_SSO_OWNER_DSN", "--acknowledge-drained"},
		{"cleanup", "--dsn-env", "TEST_SSO_OWNER_DSN", "--origin", "https://OPS.test"},
	} {
		var out, stderr bytes.Buffer
		if code := run(args, &out, &stderr); code != 2 || out.Len() != 0 || strings.Contains(stderr.String(), "do-not-print") {
			t.Fatal("invalid offline arguments were not rejected safely", args, code)
		}
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"initialize", "--help"}, &out, &stderr); code != 0 || !strings.Contains(out.String(), "--dsn-env") {
		t.Fatal("help", code)
	}
}

// The caller supplies an empty owned PostgreSQL16 database. No external network
// or production credentials are needed to exercise the actual command lifecycle.
func TestOfflineSSOAdministrationLifecycle(t *testing.T) {
	dsn := os.Getenv("OPS_SSO_ADMIN_OWNER_DSN")
	if dsn == "" {
		t.Skip("OPS_SSO_ADMIN_OWNER_DSN must name an empty owned PostgreSQL16 fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("owned database connection failed")
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(ctx, `CREATE ROLE sso_cli_app LOGIN NOINHERIT PASSWORD 'public-local-sso-cli';CREATE ROLE sso_cli_retention LOGIN NOINHERIT PASSWORD 'public-local-sso-cli'`)
	if err != nil {
		t.Fatal("owned fixture roles", err)
	}
	t.Setenv("TEST_SSO_OWNER_DSN", dsn)
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("owned fixture DSN")
	}
	u.User = url.UserPassword("sso_cli_retention", "public-local-sso-cli")
	t.Setenv("TEST_SSO_RETENTION_DSN", u.String())
	const first = "11111111-1111-4111-8111-111111111111"
	const second = "22222222-2222-4222-8222-222222222222"
	binding := []string{"--environment", "test", "--deployment-id", "sso-cli", "--issuer", "https://issuer.test", "--origin", "https://ops.test", "--recovery-epoch", first, "--broker-recovery-epoch", first}
	roles := []string{"--app-role", "sso_cli_app", "--retention-role", "sso_cli_retention", "--acknowledge-drained"}
	execute := func(command string, arguments ...string) []byte {
		t.Helper()
		var out, stderr bytes.Buffer
		args := append([]string{command, "--dsn-env", "TEST_SSO_OWNER_DSN"}, arguments...)
		if code := run(args, &out, &stderr); code != 0 {
			t.Fatal(command, "failed", code, stderr.String())
		}
		return append([]byte{}, out.Bytes()...)
	}
	for i := 0; i < 2; i++ {
		execute("migrate", roles...)
		execute("initialize", append(append([]string{}, binding...), roles...)...)
	}
	var status ssosql.StatusResult
	if json.Unmarshal(execute("status", binding...), &status) != nil || !status.Ready || status.Metadata.Scope.Epoch != first {
		t.Fatal("initialized status")
	}
	recoverArgs := append(append([]string{}, binding...), roles...)
	recoverArgs = append(recoverArgs, "--new-recovery-epoch", second, "--new-broker-recovery-epoch", second)
	if json.Unmarshal(execute("begin-recovery", recoverArgs...), &status) != nil || status.Ready || status.Metadata.Scope.Epoch != second {
		t.Fatal("recovery must be unready")
	}
	selected := append([]string{}, binding...)
	for i := range selected {
		if selected[i] == first {
			selected[i] = second
		}
	}
	initialized := execute("initialize", append(append([]string{}, selected...), roles...)...)
	if bytes.Contains(initialized, []byte(`"ready"`)) || !bytes.Contains(initialized, []byte(`"initialized":true`)) {
		t.Fatal("initialize must not claim readiness for a recovery namespace")
	}
	if json.Unmarshal(execute("status", selected...), &status) != nil || status.Ready {
		t.Fatal("idempotent initialize must preserve unready recovery state")
	}
	execute("reconfigure", append(append([]string{}, selected...), "--acknowledge-drained")...)
	execute("finalize", append(append([]string{}, selected...), "--acknowledge-drained")...)
	if json.Unmarshal(execute("status", selected...), &status) != nil || !status.Ready {
		t.Fatal("finalized status")
	}
	var out, stderr bytes.Buffer
	if code := run(append([]string{"cleanup", "--dsn-env", "TEST_SSO_RETENTION_DSN"}, selected...), &out, &stderr); code != 0 {
		t.Fatal("restricted retention cleanup", code, stderr.String())
	}
}
