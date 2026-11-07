package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestNamespaceCommandRejectsUnboundedOrUnusedInputBeforeIO(t *testing.T) {
	t.Setenv("NAMESPACE_OWNER_DSN", "must-not-be-used-or-printed")
	for name, args := range map[string][]string{
		"unknown":            {"bogus", "--dsn-env", "NAMESPACE_OWNER_DSN"},
		"unused secret":      {"migrate", "--dsn-env", "NAMESPACE_OWNER_DSN", "--reference-credential-env", "SECRET"},
		"missing drain":      {"migrate", "--dsn-env", "NAMESPACE_OWNER_DSN", "--reader-role", "namespace_reader"},
		"duration overflow":  {"finalize", "--dsn-env", "NAMESPACE_OWNER_DSN", "--acknowledge-drained", "--generation", "12345678-1234-4234-8234-123456789abc", "--revision", "1", "--recovery-timeout-seconds", "9223372036854775807"},
		"missing revision":   {"import", "--dsn-env", "NAMESPACE_OWNER_DSN", "--acknowledge-drained", "--generation", "12345678-1234-4234-8234-123456789abc"},
		"timeout wrong mode": {"status", "--dsn-env", "NAMESPACE_OWNER_DSN", "--recovery-timeout-seconds", "600"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, diagnostic bytes.Buffer
			if code := run(context.Background(), args, &out, &diagnostic); code != 2 || out.Len() != 0 || strings.Contains(diagnostic.String(), "must-not-be-used-or-printed") {
				t.Fatal("invalid input reached operational I/O or leaked a secret", code, out.String(), diagnostic.String())
			}
		})
	}
}
