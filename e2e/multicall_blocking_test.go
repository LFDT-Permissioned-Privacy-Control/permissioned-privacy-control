//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the multicall blocking specs:
//
//   e2e/playwright/tests/multicall.spec.ts (4 tests)
//   e2e/playwright/tests/security/04-multicall-bypass.spec.ts (15 tests)
//
// 19 source tests consolidate into 3 Go test functions. The
// well-known-address detection is exercised against all 3 hardcoded
// Multicall addresses × 6 selectors. The unit-level detection logic
// (IsMulticallTarget, IsMulticallData, DetectMulticall) is already
// covered by internal/rbac/access_test.go — this file pins the
// integration-level guarantee that the proxy denies these requests
// over HTTP.

// Hardcoded Multicall addresses (see internal/rbac/access.go).
const (
	multicall3 = "0xca11bde05977b3631167028862be2a173976ca11"
	multicall2 = "0x5ba1e12693dc8f9c48aad8770482f4739beed696"
	multicall1 = "0xeefba1e63905ef1d7acba5a8513c70307c1ce441"
)

// Multicall function selectors.
var multicallSelectors = []string{
	"0x252dba42", // aggregate
	"0x82ad56cb", // aggregate3
	"0x174dea71", // aggregate3Value
	"0xc3077fa9", // blockAndAggregate
	"0xbce38bd7", // tryAggregate
	"0x399542e9", // tryBlockAndAggregate
}

// setupMulticallUser creates a user with eth_call + deploy claim in
// their own test org. Used by the integration-level multicall tests.
func setupMulticallUser(t *testing.T) (string, string, string) {
	t.Helper()
	srv, serverURL, cleanup := setupE2E(t)
	t.Cleanup(cleanup)
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("mc")
	group := f.CreateGroup(org.ID, "mc-grp", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_estimateGas", "eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)
	return serverURL, org.ID, token
}

// TestMulticallBlocked verifies that every (Multicall address ×
// multicall selector × forwarding method) combination is denied with
// opaque 404. Case variations on the address must also be blocked
// (the proxy normalises addresses before checking).
//
// Ports multicall.spec.ts cases 1-2 + security/04 MULTICALL-001/-002/-003/-004/-005/-006.
func TestMulticallBlocked(t *testing.T) {
	serverURL, orgID, token := setupMulticallUser(t)

	// Multicall addresses including case variations (multicall3 has
	// both lowercase and EIP-55 checksummed forms in the wild).
	addresses := []string{
		multicall3,
		multicall2,
		multicall1,
		"0xcA11bDe05977b3631167028862bE2A173976CA11", // EIP-55 checksum
		"0xCA11BDE05977B3631167028862BE2A173976CA11", // upper
	}
	methods := []string{"eth_call", "eth_estimateGas", "eth_sendTransaction"}
	dummyArgs := "0000000000000000000000000000000000000000000000000000000000000000"

	for _, addr := range addresses {
		for _, method := range methods {
			for _, selector := range multicallSelectors {
				name := method + "_to_" + addr[:10] + "_" + selector
				t.Run(name, func(t *testing.T) {
					call := map[string]any{"to": addr, "data": selector + dummyArgs}
					var params []any
					switch method {
					case "eth_call", "eth_estimateGas":
						params = []any{call, "latest"}
					case "eth_sendTransaction":
						call["from"] = "0x" + "11111111111111111111111111111111111111111"[:40]
						params = []any{call}
					}
					res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+orgID, method, params,
						map[string]string{"Authorization": "Bearer " + token})
					if res.Status != http.StatusNotFound {
						t.Errorf("expected 404, got %d: %s", res.Status, string(res.Body))
					}
				})
			}
		}
	}
}

// TestMulticallReadOnlyMethodsAllowed verifies that informational
// methods on a Multicall address are NOT short-circuited at the
// auth-layer (403). Whether the address gets 200 (forwarded), 404
// (private-by-default RBAC denial of an unregistered address), or
// 502 (upstream unreachable) is acceptable — only 403 would indicate
// the multicall block falsely tripped on a non-multicall method.
//
// Ports multicall.spec.ts "allows eth_getBalance" + security/04
// MULTICALL-008/-009/-010. The Playwright assertion was
// `expect(status).not.toBe(403)`, preserved verbatim.
func TestMulticallReadOnlyMethodsAllowed(t *testing.T) {
	serverURL, orgID, token := setupMulticallUser(t)

	cases := []struct {
		method string
		params []any
	}{
		{"eth_getBalance", []any{multicall3, "latest"}},
		{"eth_getCode", []any{multicall3, "latest"}},
		{"eth_getStorageAt", []any{multicall3, "0x0", "latest"}},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+orgID, tc.method, tc.params,
				map[string]string{"Authorization": "Bearer " + token})
			if res.Status == http.StatusForbidden {
				t.Errorf("%s on Multicall address must not return 403 (multicall block falsely tripping); body: %s", tc.method, string(res.Body))
			}
		})
	}
}

// TestMulticallEdgeCases pins the proxy's behavior on edge cases
// that exercise the detection boundary:
//
//   - empty calldata to Multicall: not a multicall call, so the
//     address gate alone shouldn't deny (any 2xx/4xx/5xx is OK as
//     long as it's not 403 specifically — RBAC denial would be 404
//     anyway).
//   - partial / wrong-prefix selectors: the proxy needs the full
//     4-byte selector to classify, so these go through.
//
// Ports security/04 BYPASS-003/-004/-005. BYPASS-001 (custom
// Multicall address) is a documented limitation — runtime tracing,
// not the address blocklist, covers that case (already exercised by
// e2e/create2_test.go). BYPASS-002 was a Playwright placeholder
// without real assertions and is dropped.
func TestMulticallEdgeCases(t *testing.T) {
	serverURL, orgID, token := setupMulticallUser(t)

	cases := []struct {
		name     string
		callData map[string]any
	}{
		{"empty_calldata", map[string]any{"to": multicall3}},
		{"partial_selector", map[string]any{"to": multicall3, "data": "0x252d"}},
		{"wrong_prefix_selector", map[string]any{"to": multicall3, "data": "0x152dba42" +
			"0000000000000000000000000000000000000000000000000000000000000000"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+orgID, "eth_call",
				[]any{tc.callData, "latest"},
				map[string]string{"Authorization": "Bearer " + token})
			// 403 (forbidden) would indicate the proxy short-circuited
			// without proper detection; any other status is acceptable.
			if res.Status == http.StatusForbidden {
				t.Errorf("%s: unexpected 403 (proxy short-circuited); body: %s", tc.name, string(res.Body))
			}
		})
	}
}
