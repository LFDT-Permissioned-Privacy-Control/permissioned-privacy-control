//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the still-uncovered tests from
// e2e/playwright/tests/rbac/10-method-access.spec.ts (6 tests + 1
// skipped flake) and e2e/playwright/tests/rbac/16-function-selectors.spec.ts (5
// tests). Together they exercise the admin /access/check endpoint
// and the JSON-RPC path with per-group method allowlists and
// per-contract-grant function-selector rules.
//
// Claim-model translation per [[feedback_no_read_write_users]]: the
// source specs use `read`/`write` claims that were removed by RD-853.
// Ports use the current model (admin/upgrade/deploy + allowed_methods).

// === rbac/10-method-access ===

// TestMethodAccess_CheckAccessAllowsWhitelisted verifies the admin
// /access/check endpoint allows methods in the user's group
// allowed_methods.
//
// Ports rbac/10 "allows method in allowlist".
func TestMethodAccess_CheckAccessAllowsWhitelisted(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ma-allow")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []testfixtures.Claim{},
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID,
		OrgSlug:        org.Slug,
		Method:         "eth_call",
	})
	if !res.Allowed {
		t.Errorf("eth_call should be allowed; reason=%q", res.Reason)
	}
}

// TestMethodAccess_CheckAccessDeniesNonWhitelisted is the negative
// counterpart: methods absent from allowed_methods get Allowed=false
// with a reason mentioning "method".
//
// Ports rbac/10 "denies method NOT in allowlist".
func TestMethodAccess_CheckAccessDeniesNonWhitelisted(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ma-deny")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_blockNumber"},
		Claims:         []testfixtures.Claim{},
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID,
		OrgSlug:        org.Slug,
		Method:         "eth_sendTransaction",
	})
	if res.Allowed {
		t.Errorf("eth_sendTransaction should be denied; got Allowed=true")
	}
}

// TestMethodAccess_RPCRequestAllowedForWhitelistedMethod sanity-checks
// that the JSON-RPC path agrees with the admin checkAccess endpoint:
// a method in the group's allowed_methods reaches the upstream node
// (200 or 502 if Anvil unreachable; not 4xx).
//
// Ports rbac/10 "RPC request allowed for method in allowlist".
// The flaky "RPC request denied" case (test.skip in source) is
// left unported — Go integration tests don't share the test
// runner's cache-propagation race.
func TestMethodAccess_RPCRequestAllowedForWhitelistedMethod(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ma-rpc")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_getBalance"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_getBalance",
		[]any{"0x0000000000000000000000000000000000000000", "latest"},
		map[string]string{"Authorization": "Bearer " + token})
	if res.Status != http.StatusOK && res.Status != http.StatusBadGateway {
		t.Errorf("expected 200 or 502 (whitelist allowed), got %d: %s", res.Status, string(res.Body))
	}
}

// TestMethodAccess_MultipleMethodsInAllowlist iterates several
// allowed methods and asserts each passes checkAccess.
//
// Ports rbac/10 "allows multiple methods in allowlist".
func TestMethodAccess_MultipleMethodsInAllowlist(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ma-multi")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	methods := []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId"}
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: methods,
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
				UserExternalID: user.ExternalID,
				OrgSlug:        org.Slug,
				Method:         m,
			})
			if !res.Allowed {
				t.Errorf("%s should be allowed; reason=%q", m, res.Reason)
			}
		})
	}
}

// TestMethodAccess_EmptyAllowlistDeniesEverything verifies that an
// explicit empty allowed_methods slice denies all methods (the
// closed-by-default semantic).
//
// Ports rbac/10 "denies when allowlist is empty".
func TestMethodAccess_EmptyAllowlistDeniesEverything(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("ma-empty")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{}, // explicit empty
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	// Use an auth-required method (eth_getBalance, not in the
	// anonymous allowlist). eth_blockNumber falls through to the
	// anonymous-group allowance migration 044 added, so it would
	// pass even with an empty org-scoped allowlist.
	res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID,
		OrgSlug:        org.Slug,
		Method:         "eth_getBalance",
	})
	if res.Allowed {
		t.Errorf("empty allowlist should deny eth_getBalance; got Allowed=true")
	}
}

// === rbac/16-function-selectors ===

// Common ERC20 function selectors (mirrors rbac/16 constants).
const (
	transferSelector  = "0xa9059cbb" // transfer(address,uint256)
	approveSelector   = "0x095ea7b3" // approve(address,uint256)
	balanceOfSelector = "0x70a08231" // balanceOf(address)
)

// TestFunctionSelector_AllowedAndDenied tests the contract-grant
// `functions` restriction: when the grant lists explicit selectors,
// only matching selectors pass the gate. Other selectors are denied,
// and an empty `functions` list (no restriction) allows every
// selector.
//
// Consolidates rbac/16 "allows function selector in allowlist",
// "denies function selector NOT in allowlist", and "allows all
// functions when no functions restriction exists" (3 tests).
func TestFunctionSelector_AllowedAndDenied(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("fs")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	t.Run("restricted_grant_allows_matching", func(t *testing.T) {
		contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
			OwnerGroupID: group.ID,
		})
		f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{
			GroupID:   group.ID,
			Functions: testfixtures.Fns(transferSelector, balanceOfSelector),
		})
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID:   user.ExternalID,
			OrgSlug:          org.Slug,
			Method:           "eth_call",
			TargetAddress:    contract.Address,
			FunctionSelector: transferSelector,
		})
		if !res.Allowed {
			t.Errorf("transfer selector should be allowed; reason=%q", res.Reason)
		}
	})

	t.Run("restricted_grant_denies_non_matching", func(t *testing.T) {
		contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
			OwnerGroupID: group.ID,
		})
		f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{
			GroupID:   group.ID,
			Functions: testfixtures.Fns(balanceOfSelector),
		})
		// balanceOf passes
		ok := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID:   user.ExternalID,
			OrgSlug:          org.Slug,
			Method:           "eth_call",
			TargetAddress:    contract.Address,
			FunctionSelector: balanceOfSelector,
		})
		if !ok.Allowed {
			t.Errorf("balanceOf selector should be allowed; reason=%q", ok.Reason)
		}
		// approve denied
		deny := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID:   user.ExternalID,
			OrgSlug:          org.Slug,
			Method:           "eth_call",
			TargetAddress:    contract.Address,
			FunctionSelector: approveSelector,
		})
		if deny.Allowed {
			t.Errorf("approve selector should be denied; got Allowed=true")
		}
	})

	t.Run("unrestricted_grant_allows_any_selector", func(t *testing.T) {
		contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
			OwnerGroupID: group.ID,
		})
		f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{
			GroupID: group.ID,
			// No Functions — wildcard.
		})
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID,
			OrgSlug:        org.Slug,
			Method:         "eth_call",
			TargetAddress:  contract.Address,
		})
		if !res.Allowed {
			t.Errorf("unrestricted grant should allow any function; reason=%q", res.Reason)
		}
	})
}

// TestFunctionSelector_RPCEnforcement covers the JSON-RPC path:
// eth_call with a permitted selector reaches the upstream; with a
// disallowed selector returns opaque 404.
//
// Ports rbac/16 "RPC request allowed for function selector in
// allowlist" + "RPC request denied for function selector NOT in
// allowlist".
func TestFunctionSelector_RPCEnforcement(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("fs-rpc")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: group.ID,
	})
	f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{
		GroupID:   group.ID,
		Functions: testfixtures.Fns(balanceOfSelector),
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	abiPadding := "0000000000000000000000000000000000000000000000000000000000000001"

	t.Run("allowed_selector_passes", func(t *testing.T) {
		res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_call",
			[]any{map[string]any{"to": contract.Address, "data": balanceOfSelector + abiPadding}, "latest"},
			map[string]string{"Authorization": "Bearer " + token})
		if res.Status == http.StatusForbidden || res.Status == http.StatusNotFound {
			t.Errorf("balanceOf should be permitted; got %d: %s", res.Status, string(res.Body))
		}
	})

	t.Run("disallowed_selector_denied", func(t *testing.T) {
		res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_call",
			[]any{map[string]any{"to": contract.Address, "data": approveSelector + abiPadding}, "latest"},
			map[string]string{"Authorization": "Bearer " + token})
		if res.Status != http.StatusNotFound {
			t.Errorf("approve should be denied with 404; got %d: %s", res.Status, string(res.Body))
		}
	})
}
