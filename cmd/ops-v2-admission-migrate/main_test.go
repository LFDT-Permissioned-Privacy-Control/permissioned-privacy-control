package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestOfflineRecoveryCLIRejectsUnboundedOrMisplacedTimeout(t *testing.T) {
	// An unreachable public test DSN makes accidental DB work visible as exit1;
	// invalid operator flags must fail before trying any connection.
	t.Setenv("OPS_TEST_ADMISSION_DSN", "postgres://public-test-only@127.0.0.1:1/none?sslmode=disable")
	for _, args := range [][]string{
		{"finalize", "--recovery-timeout", "0"},
		{"finalize", "--recovery-timeout", "-1s"},
		{"finalize", "--recovery-timeout", "30m1ns"},
		{"migrate", "--recovery-timeout", "1m"},
	} {
		args = append(args, "--dsn-env", "OPS_TEST_ADMISSION_DSN")
		var out, err bytes.Buffer
		if code := run(args, &out, &err); code != 2 || out.Len() != 0 || !strings.Contains(err.String(), "recovery timeout") || strings.Contains(err.String(), "postgres://") {
			t.Fatal(args, code, out.String(), err.String())
		}
	}
}

func TestCleanupRequiresExactStateAndValidRetentionBeforeOpeningStore(t *testing.T) {
	t.Setenv("TEST_ADMISSION_RETENTION_DSN", "postgres://public-test-only@127.0.0.1:1/none?sslmode=disable")
	args := []string{"cleanup", "--dsn-env", "TEST_ADMISSION_RETENTION_DSN", "--environment", "test", "--chain-id", "1", "--genesis-hash", "0x" + strings.Repeat("1", 64), "--deployment-id", "cleanup", "--generation", "11111111-1111-4111-8111-111111111111", "--coverage-digest", "sha256:" + strings.Repeat("1", 64)}
	for _, test := range []struct {
		setting string
		args    []string
	}{{"1001", args}, {"1000", args[:len(args)-2]}} {
		t.Setenv("RETENTION_COMPLIANCE_CLEANUP_BATCH", test.setting)
		var out, stderr bytes.Buffer
		if code := run(test.args, &out, &stderr); code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "exact network/generation/coverage") || strings.Contains(stderr.String(), "postgres://") {
			t.Fatal("invalid cleanup must fail before database work", code)
		}
	}
}
