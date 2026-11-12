package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCleanupRejectsInvalidRetentionAndKeepsMigrationArguments(t *testing.T) {
	t.Setenv("TEST_DISCLOSURE_RETENTION_DSN", "postgres://public-test-only@127.0.0.1:1/none?sslmode=disable")
	t.Setenv("RETENTION_DISCLOSURE_CASES", "1h")
	var out, stderr bytes.Buffer
	if code := run([]string{"cleanup", "--dsn-env", "TEST_DISCLOSURE_RETENTION_DSN"}, &out, &stderr); code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "retention settings") || strings.Contains(stderr.String(), "postgres://") {
		t.Fatal("invalid cleanup settings must fail before database work", code)
	}
	for _, args := range [][]string{{"--dsn-env", "TEST_DISCLOSURE_RETENTION_DSN"}, {"migrate", "--dsn-env", "TEST_DISCLOSURE_RETENTION_DSN"}} {
		out.Reset()
		stderr.Reset()
		if code := run(args, &out, &stderr); code != 2 || out.Len() != 0 {
			t.Fatal("migration still requires explicit application and retention roles", code)
		}
	}
	for _, args := range [][]string{{"--help"}, {"cleanup", "--help"}} {
		out.Reset()
		stderr.Reset()
		if code := run(args, &out, &stderr); code != 0 || !strings.Contains(out.String(), "cleanup") {
			t.Fatal("help", code)
		}
	}
}
