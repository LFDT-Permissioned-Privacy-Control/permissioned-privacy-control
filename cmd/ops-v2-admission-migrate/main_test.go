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
