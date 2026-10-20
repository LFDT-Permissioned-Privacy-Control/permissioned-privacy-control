package testfixtures

import (
	"strings"
	"testing"
)

// InternalLeakageTokens is the canonical deny-list of substrings that
// must never appear in a 4xx error response body returned to a client.
// Shared so tools/check-err-leak.sh and runtime test assertions can
// stay in lockstep (RD-964 acceptance: "single source of truth").
//
// Categories:
//
//   - Panic / runtime: any of these means a goroutine crashed and the
//     stack frame leaked.
//   - DB drivers: pgx, pq, jackc, database/sql — exposing these
//     confirms a DB error reached the response.
//   - Internal package paths: github.com/gateway-fm/ and internal/
//     reveal the source layout.
//   - File paths: .go:, /usr/, C:\ confirm a stack frame is in the body.
//
// Specific request-dependent substrings (the literal org slug, user
// DID, contract address, function selector) should be added by the
// caller when those are sensitive in context — they're caller-known
// rather than universally forbidden.
var InternalLeakageTokens = []string{
	"panic", "runtime.", "goroutine",
	"pgx", "pq:", "sql:", "jackc/", "database/sql",
	"github.com/gateway-fm/", "internal/",
	".go:",
}

// AssertNoInternalLeakage scans body for any of InternalLeakageTokens
// plus the caller-supplied extras and fails the test with a clear
// pointer to which token leaked. Comparison is case-insensitive
// because Go error messages may capitalize identifiers.
func AssertNoInternalLeakage(t *testing.T, body []byte, extra ...string) {
	t.Helper()
	bodyLower := strings.ToLower(string(body))
	for _, leak := range InternalLeakageTokens {
		if strings.Contains(bodyLower, strings.ToLower(leak)) {
			t.Errorf("response body leaks internal token %q: %s", leak, string(body))
		}
	}
	for _, leak := range extra {
		if leak == "" {
			continue
		}
		if strings.Contains(bodyLower, strings.ToLower(leak)) {
			t.Errorf("response body leaks request-sensitive token %q: %s", leak, string(body))
		}
	}
}
