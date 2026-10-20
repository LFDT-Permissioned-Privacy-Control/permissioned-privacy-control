//go:build mockauth

package e2e

import (
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the integration-level bypass cases from
// e2e/playwright/tests/security/03-blocked-methods.spec.ts.
//
// Coverage map (23 source tests → 1 Go test function):
//
//   BLOCKED-001 … BLOCKED-013 (13 tests) — globally-blocked methods
//   return 404. Already covered at unit level by
//   internal/rbac/access_test.go TestIsMethodBlocked. Not ported.
//
//   ALLOWED-001 … ALLOWED-005 (5 tests) — anonymous-allowed metadata
//   methods (eth_blockNumber, eth_chainId, etc.). Already covered by
//   e2e.TestProxyAuth_AnonymousAllowedMethods (PR A). Not ported.
//
//   BYPASS-001 … BYPASS-005 (5 tests) — case variation, unicode
//   homoglyphs, prefix/suffix tricks, URL encoding, null bytes.
//   Consolidated here as table-driven.

// TestBlockedMethodBypassAttempts verifies that obfuscation tricks
// (case variation, lookalike characters, whitespace, escape sequences)
// don't sneak a globally-blocked method through. Each attempt must
// return a 4xx, never 200 — the gate is opaque so any of 400/403/404
// is acceptable.
func TestBlockedMethodBypassAttempts(t *testing.T) {
	cases := []struct {
		name   string
		method string
	}{
		// BYPASS-001: case variation
		{"upper_debug", "DEBUG_traceTransaction"},
		{"title_debug", "Debug_TraceTransaction"},
		{"alternating_case", "dEbUg_tRaCeTraNsAcTiOn"},
		{"upper_admin", "ADMIN_PEERS"},
		{"title_admin", "Admin_Peers"},

		// BYPASS-002: unicode homoglyphs
		{"cyrillic_e_in_debug", "dеbug_traceTransaction"},
		{"cyrillic_a_in_admin", "аdmin_peers"},

		// BYPASS-003: prefix/suffix variations
		{"leading_underscore", "_debug_traceTransaction"},
		{"trailing_underscore", "debug_traceTransaction_"},
		{"double_underscore_wrap", "__debug_traceTransaction__"},
		{"leading_space", " debug_traceTransaction"},
		{"trailing_space", "debug_traceTransaction "},
		{"leading_tab", "\tdebug_traceTransaction"},
		{"leading_newline", "\ndebug_traceTransaction"},

		// BYPASS-004: URL-encoded underscore
		{"url_encoded_underscore", "debug%5ftraceTransaction"},

		// BYPASS-005: null-byte truncation attempt
		{"null_byte_truncation", "debug_traceTransaction\x00safe"},
	}

	// Single shared setup — every bypass attempt hits the proxy as
	// anonymous (no JWT). Globally-blocked methods are denied before
	// any RBAC evaluation, so authentication isn't needed for the
	// gate to fire.
	_, serverURL, cleanup := setupE2E(t)
	defer cleanup()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := testfixtures.JSONRPCPost(t, serverURL, tc.method, []any{}, nil)
			if res.Status >= 200 && res.Status < 300 {
				t.Errorf("bypass attempt succeeded (status %d): %s", res.Status, string(res.Body))
			}
		})
	}
}
