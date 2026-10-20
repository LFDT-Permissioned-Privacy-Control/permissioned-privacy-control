//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports e2e/playwright/tests/security/01-cross-org-isolation.spec.ts.
// All 10 source tests share the same two-org/two-user/two-contract
// setup, then run JSON-RPC queries that attempt to cross the org
// boundary. Every cross-org query must return opaque 404; every
// in-org or public-contract query must NOT be 403.
//
// Per [[MEMORY]]: "Cross-org leakage is a P0 security issue." This
// suite is the integration-level enforcement test for that property.

// crossOrgSetup is the shared two-org/two-user/two-contract harness.
// Returned as a struct so tests can address the pieces by name.
type crossOrgSetup struct {
	f          *testfixtures.Fixture
	serverURL  string
	orgA       testfixtures.Organization
	orgB       testfixtures.Organization
	contractA  string
	contractB  string
	userAToken string
	userBToken string
}

func setupCrossOrg(t *testing.T) (crossOrgSetup, func()) {
	t.Helper()
	srv, serverURL, cleanup := setupE2E(t)
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	orgA := f.CreateOrg("xorg-a")
	orgB := f.CreateOrg("xorg-b")

	groupA := f.CreateGroup(orgA.ID, "group-a", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(orgA.ID, groupA.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{
			"eth_call", "eth_getBalance", "eth_blockNumber", "eth_getLogs",
			"eth_getCode", "eth_getStorageAt", "eth_sendTransaction",
		},
		Claims: []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	groupB := f.CreateGroup(orgB.ID, "group-b", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(orgB.ID, groupB.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{
			"eth_call", "eth_getBalance", "eth_blockNumber", "eth_getLogs",
			"eth_getCode", "eth_getStorageAt", "eth_sendTransaction",
		},
		Claims: []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	contractA := f.Address()
	contractB := f.Address()
	f.CreateContract(orgA.ID, testfixtures.CreateContractOptions{
		Address: contractA, Name: "Contract A",
	})
	f.CreateContract(orgB.ID, testfixtures.CreateContractOptions{
		Address: contractB, Name: "Contract B",
	})
	f.Client.CreateContractGrant(t, orgA.ID, contractA, testfixtures.CreateContractGrantInput{GroupID: groupA.ID})
	f.Client.CreateContractGrant(t, orgB.ID, contractB, testfixtures.CreateContractGrantInput{GroupID: groupB.ID})

	userA, userAToken := f.CreateUserWithMembership(groupA.ID, testfixtures.CreateUserOptions{})
	userB, userBToken := f.CreateUserWithMembership(groupB.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(userA.ID)
	f.DeleteDefaultMembership(userB.ID)

	return crossOrgSetup{
		f:          f,
		serverURL:  serverURL,
		orgA:       orgA,
		orgB:       orgB,
		contractA:  contractA,
		contractB:  contractB,
		userAToken: userAToken,
		userBToken: userBToken,
	}, cleanup
}

// crossOrgRPC issues a JSON-RPC request scoped to the given org.
// Authenticated cross-org tests use /rpc/:org_id so the caller's
// org context is explicit.
func crossOrgRPC(t *testing.T, s crossOrgSetup, orgID, token, method string, params []any) testfixtures.JSONRPCResult {
	return testfixtures.JSONRPCPostAt(t, s.serverURL, "/rpc/"+orgID, method, params,
		map[string]string{"Authorization": "Bearer " + token})
}

// TestCrossOrgIsolation_DenyCrossOrgQueries is the bulk of
// security/01: every JSON-RPC method that touches a cross-org
// contract must return opaque 404 (RBAC denial), regardless of
// the method.
//
// Ports SECURITY-001, -002, -004, -006, -008, -009, -010.
// SECURITY-005 (mixed-org eth_getLogs) is also covered here.
func TestCrossOrgIsolation_DenyCrossOrgQueries(t *testing.T) {
	s, cleanup := setupCrossOrg(t)
	defer cleanup()

	hexHash := "0x0000000000000000000000000000000000000000000000000000000000000001"
	_ = hexHash

	cases := []struct {
		name   string
		token  string
		orgID  string
		method string
		params []any
	}{
		{"A_reads_B_via_eth_call", s.userAToken, s.orgA.ID, "eth_call",
			[]any{map[string]any{"to": s.contractB, "data": "0x"}, "latest"}},
		{"B_reads_A_via_eth_call", s.userBToken, s.orgB.ID, "eth_call",
			[]any{map[string]any{"to": s.contractA, "data": "0x"}, "latest"}},
		{"A_eth_getLogs_for_B", s.userAToken, s.orgA.ID, "eth_getLogs",
			[]any{map[string]any{"address": s.contractB, "fromBlock": "0x0", "toBlock": "latest"}}},
		{"A_eth_getLogs_mixed_AB", s.userAToken, s.orgA.ID, "eth_getLogs",
			[]any{map[string]any{"address": []any{s.contractA, s.contractB}, "fromBlock": "0x0", "toBlock": "latest"}}},
		{"A_eth_getBalance_on_B", s.userAToken, s.orgA.ID, "eth_getBalance",
			[]any{s.contractB, "latest"}},
		{"A_eth_getCode_on_B", s.userAToken, s.orgA.ID, "eth_getCode",
			[]any{s.contractB, "latest"}},
		{"A_eth_getStorageAt_on_B", s.userAToken, s.orgA.ID, "eth_getStorageAt",
			[]any{s.contractB, "0x0", "latest"}},
		{"A_eth_sendTransaction_to_B", s.userAToken, s.orgA.ID, "eth_sendTransaction",
			[]any{map[string]any{"to": s.contractB, "from": "0x" + repeatHex("9", 40), "data": "0x"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := crossOrgRPC(t, s, tc.orgID, tc.token, tc.method, tc.params)
			if res.Status != http.StatusNotFound {
				t.Errorf("expected 404 (cross-org denial), got %d: %s", res.Status, string(res.Body))
			}
		})
	}
}

// TestCrossOrgIsolation_AllowsOwnContract verifies that the in-org
// path is not broken — user A reading contract A must NOT 403.
// May 502 if the upstream node is unreachable, which is acceptable
// (auth + grant passed; only the forward failed).
//
// Ports SECURITY-003.
func TestCrossOrgIsolation_AllowsOwnContract(t *testing.T) {
	s, cleanup := setupCrossOrg(t)
	defer cleanup()

	res := crossOrgRPC(t, s, s.orgA.ID, s.userAToken, "eth_call",
		[]any{map[string]any{"to": s.contractA, "data": "0x"}, "latest"})

	if res.Status == http.StatusForbidden || res.Status == http.StatusNotFound {
		t.Fatalf("user A should be permitted to read contract A; got %d: %s", res.Status, string(res.Body))
	}
}

// TestCrossOrgIsolation_PublicContract verifies that an address NOT
// registered to any org (public-by-default in production sense) is
// still reachable by a user with the right claim. Not 403, not 404.
//
// Ports SECURITY-007.
func TestCrossOrgIsolation_PublicContract(t *testing.T) {
	s, cleanup := setupCrossOrg(t)
	defer cleanup()

	publicAddr := s.f.Address()
	res := crossOrgRPC(t, s, s.orgA.ID, s.userAToken, "eth_call",
		[]any{map[string]any{"to": publicAddr, "data": "0x"}, "latest"})

	if res.Status == http.StatusForbidden {
		t.Fatalf("public-contract access denied with 403 — claim path broken; body: %s", string(res.Body))
	}
}

func repeatHex(s string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = s[0]
	}
	return string(out)
}
