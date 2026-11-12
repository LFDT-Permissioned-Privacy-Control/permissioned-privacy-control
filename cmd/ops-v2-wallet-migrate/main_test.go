package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestArgumentsAndSecretsStayOffline(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown", "--dsn-env", "OPS_WALLET_TEST_DSN"}, {"migrate"}, {"migrate", "--dsn-env", "bad-env"}, {"migrate", "--unknown", "do-not-echo-this"}} {
		t.Setenv("OPS_WALLET_TEST_DSN", "private DSN sentinel must never be echoed")
		var out, err bytes.Buffer
		if run(args, &out, &err) == 0 {
			t.Fatal("invalid arguments succeeded", args)
		}
		if strings.Contains(out.String()+err.String(), "sentinel") || strings.Contains(err.String(), "do-not-echo-this") {
			t.Fatal("sensitive argument echoed")
		}
	}
	var out, err bytes.Buffer
	if run([]string{"migrate", "--help"}, &out, &err) != 0 {
		t.Fatal("help failed")
	}
}

func TestCleanupRejectsInvalidRetentionBeforeOpeningStore(t *testing.T) {
	t.Setenv("TEST_WALLET_RETENTION_DSN", "postgres://public-test-only@127.0.0.1:1/none?sslmode=disable")
	t.Setenv("RETENTION_WALLET_CHALLENGES_CLEANUP_BATCH", "1001")
	var out, stderr bytes.Buffer
	if code := run([]string{"cleanup", "--dsn-env", "TEST_WALLET_RETENTION_DSN"}, &out, &stderr); code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "retention settings") || strings.Contains(stderr.String(), "postgres://") {
		t.Fatal("invalid cleanup settings must fail before database work", code)
	}
}
