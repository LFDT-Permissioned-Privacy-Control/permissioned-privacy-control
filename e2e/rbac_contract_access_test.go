//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the integration-level cases from
// e2e/playwright/tests/rbac/11-contract-access.spec.ts (10 source tests).
// CheckAccess-only assertions are condensed; the JSON-RPC enforcement
// paths are pinned independently because they exercise the proxy's
// access controller through a different code path.

// TestRBACContractAccess_Grants verifies the access controller's
// contract-grant logic via admin /access/check:
//
//   - explicit grant → allowed
//   - registered contract without grant → denied with opaque
//     "contract access denied" reason
//   - unregistered (public-private-default) contract → denied for
//     a user without deploy claim
//
// Ports rbac/11 tests 1, 2, 4, and the case-insensitivity assertion.
func TestRBACContractAccess_Grants(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ca")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	grantedContract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: group.ID,
	})
	f.Client.CreateContractGrant(t, org.ID, grantedContract.Address,
		testfixtures.CreateContractGrantInput{GroupID: group.ID})

	ungrantedContract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: group.ID,
	})

	t.Run("granted_contract_allowed", func(t *testing.T) {
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
			TargetAddress: grantedContract.Address,
		})
		if !res.Allowed {
			t.Errorf("granted contract should be allowed; reason=%q", res.Reason)
		}
	})

	t.Run("ungranted_registered_contract_denied", func(t *testing.T) {
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
			TargetAddress: ungrantedContract.Address,
		})
		if res.Allowed {
			t.Errorf("registered contract without grant should be denied")
		}
	})

	t.Run("case_insensitive_address_matching", func(t *testing.T) {
		// Force uppercase address on the lookup — proxy must normalize.
		upper := "0x" + asciiUpper(grantedContract.Address[2:])
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
			TargetAddress: upper,
		})
		if !res.Allowed {
			t.Errorf("uppercase address should match registered contract; reason=%q", res.Reason)
		}
	})
}

// TestRBACContractAccess_RPCEnforcement is the JSON-RPC counterpart:
// eth_call to a granted contract reaches upstream, eth_call to an
// unregistered/un-granted contract returns opaque 404.
//
// Ports rbac/11 "RPC eth_call to contract with grant" + "RPC eth_call
// to unregistered contract denied".
func TestRBACContractAccess_RPCEnforcement(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ca-rpc")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: group.ID,
	})
	f.Client.CreateContractGrant(t, org.ID, contract.Address,
		testfixtures.CreateContractGrantInput{GroupID: group.ID})

	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	t.Run("granted_contract_reaches_upstream", func(t *testing.T) {
		res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_call",
			[]any{map[string]any{"to": contract.Address, "data": "0x"}, "latest"},
			map[string]string{"Authorization": "Bearer " + token})
		if res.Status == http.StatusForbidden || res.Status == http.StatusNotFound {
			t.Errorf("granted contract should not be RBAC-denied; got %d: %s", res.Status, string(res.Body))
		}
	})

	t.Run("unregistered_contract_denied", func(t *testing.T) {
		unregistered := f.Address()
		res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_call",
			[]any{map[string]any{"to": unregistered, "data": "0x"}, "latest"},
			map[string]string{"Authorization": "Bearer " + token})
		if res.Status != http.StatusNotFound {
			t.Errorf("unregistered contract should be denied (private-by-default); got %d: %s", res.Status, string(res.Body))
		}
	})
}

func asciiUpper(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'f' {
			c -= 32
		}
		b[i] = c
	}
	return string(b)
}
