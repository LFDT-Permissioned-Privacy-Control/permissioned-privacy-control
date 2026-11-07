package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestOwnerCLIRejectsMissingDrainAndAmbiguousInputsBeforeConnection(t *testing.T) {
	for _, args := range [][]string{{"migrate"}, {"unknown"}, {"status", "unexpected"}, {"status", "--source-id=not-a-uuid"}, {"migrate", "--drained", "--writer-role=x", "--reader-role=x", "--retention-role=z"}} {
		var out, stderr bytes.Buffer
		secret := "postgres://test-only:never-print-this@127.0.0.1:1/unused"
		err := run(context.Background(), args, &out, &stderr, func(string) string { return secret })
		if err == nil {
			t.Fatal("invalid invocation accepted", args)
		}
		if strings.Contains(err.Error(), secret) || strings.Contains(out.String(), secret) || strings.Contains(stderr.String(), secret) {
			t.Fatal("DSN exposed")
		}
	}
}
