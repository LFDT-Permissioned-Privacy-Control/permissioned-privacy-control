//go:build mockauth

package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// RD-964: the proxy must not let a user in org A distinguish between
// "this address exists in org B" and "this address doesn't exist at
// all". Confirming existence is itself a cross-org leak.
//
// We exercise the property by querying two addresses from the same
// caller:
//
//  1. An address registered as a contract in org B (caller has no
//     access to org B).
//  2. A random, never-registered address.
//
// Both queries must return responses that are byte-equivalent
// (modulo the id/jsonrpc envelope which never differs). Any
// observable difference is a leak.
func TestErrorOpaqueness_CrossOrgExistenceDisclosure(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)

	// Org B owns the secret contract.
	orgB := f.CreateOrg("opaque-b")
	groupB := f.CreateGroup(orgB.ID, "b-grp", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(orgB.ID, groupB.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	secretContract := f.CreateContract(orgB.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: groupB.ID,
	})
	f.Client.CreateContractGrant(t, orgB.ID, secretContract.Address, testfixtures.CreateContractGrantInput{
		GroupID: groupB.ID,
	})

	// Org A is the prober. User has eth_call but no grant to org-B
	// contracts.
	orgA := f.CreateOrg("opaque-a")
	groupA := f.CreateGroup(orgA.ID, "a-grp", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(orgA.ID, groupA.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	userA, tokenA := f.CreateUserWithMembership(groupA.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(userA.ID)

	// Untrackable random address — guaranteed not registered to any org.
	unregistered := f.Address()

	// Probe both addresses from the same caller, with the same method
	// and the same calldata shape. Anything that varies between the
	// two responses (other than the id round-trip) is a leak.
	authHdr := map[string]string{"Authorization": "Bearer " + tokenA}
	probeBOrg := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+orgA.ID, "eth_call",
		[]any{map[string]any{"to": secretContract.Address, "data": "0x"}, "latest"}, authHdr)
	probeNoOrg := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+orgA.ID, "eth_call",
		[]any{map[string]any{"to": unregistered, "data": "0x"}, "latest"}, authHdr)

	if probeBOrg.Status != probeNoOrg.Status {
		t.Errorf("status leak: cross-org probe=%d, not-found probe=%d — caller can distinguish via status code",
			probeBOrg.Status, probeNoOrg.Status)
	}

	// Compare bodies after stripping the JSON-RPC id (which echoes
	// the request and is allowed to vary) and any internal address
	// we deliberately put in the request (caller already knows it).
	normalized := func(body []byte, knownAddr string) []byte {
		// Parse + re-marshal to drop any whitespace / ordering
		// differences and strip the id field which is request-local.
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return body // not JSON; compare raw
		}
		delete(parsed, "id")
		// The caller knows the address they sent; redact it from the
		// comparison so any echoed address doesn't dominate the diff.
		normalized, _ := json.Marshal(parsed)
		return bytes.ReplaceAll(normalized, []byte(knownAddr), []byte("0xCALLER_KNOWN"))
	}

	bodyB := normalized(probeBOrg.Body, secretContract.Address)
	bodyN := normalized(probeNoOrg.Body, unregistered)

	if !bytes.Equal(bodyB, bodyN) {
		t.Errorf("body leak: cross-org probe vs not-found probe differ — caller can infer org-B contract exists\n  cross-org: %s\n  not-found: %s", string(bodyB), string(bodyN))
	}

	// Both responses must also be free of internal leakage.
	testfixtures.AssertNoInternalLeakage(t, probeBOrg.Body)
	testfixtures.AssertNoInternalLeakage(t, probeNoOrg.Body)
}

// TestErrorOpaqueness_NegativeCasesLeakNothing is a coarse sweep over
// the existing negative-auth response bodies, applying the canonical
// internal-leakage deny-list to each. Catches regressions where one
// of the handlers starts echoing pgx or stack frames in its 4xx body.
func TestErrorOpaqueness_NegativeCasesLeakNothing(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	cases := []struct {
		name   string
		method string
		params []any
		auth   string
		path   string
	}{
		{"unauth_eth_getBalance", "eth_getBalance",
			[]any{"0x0000000000000000000000000000000000000001", "latest"}, "", "/"},
		{"invalid_jwt", "eth_blockNumber", []any{},
			"Bearer not.a.valid.jwt", "/"},
		{"bearer_only_no_token", "eth_blockNumber", []any{}, "Bearer ", "/"},
		{"malformed_alg_none", "eth_blockNumber", []any{},
			"Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.", "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.auth != "" {
				headers["Authorization"] = tc.auth
			}
			var res testfixtures.JSONRPCResult
			if tc.path == "/" {
				res = testfixtures.JSONRPCPost(t, serverURL, tc.method, tc.params, headers)
			} else {
				res = testfixtures.JSONRPCPostAt(t, serverURL, tc.path, tc.method, tc.params, headers)
			}
			if res.Status >= 200 && res.Status < 300 {
				t.Fatalf("%s: unexpectedly succeeded (status %d) — test premise broken", tc.name, res.Status)
			}
			if res.Status == http.StatusInternalServerError {
				t.Errorf("%s: 500 from a denial path — handler should return 4xx, not 500", tc.name)
			}
			testfixtures.AssertNoInternalLeakage(t, res.Body)
		})
	}
}
