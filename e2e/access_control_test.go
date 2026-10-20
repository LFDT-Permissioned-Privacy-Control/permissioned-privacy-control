//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the still-uncovered tests from
// e2e/playwright/tests/access-control.spec.ts. The "banned user",
// "no KYC", and global-method-block cases are already covered by
// TestE2E_BannedUser, TestE2E_NoKYC, and TestE2E_ForbiddenRequest_DisallowedMethod
// in proxy_test.go.
//
// What this file adds: positive per-group whitelist coverage (allow),
// negative per-group whitelist coverage (deny on a method that exists
// but isn't whitelisted for the user's group), and the
// "user exists but has no membership" case.

// TestAccessControl_AllowsMethodInWhitelist verifies the proxy
// permits a method when the user's group has it in allowed_methods.
//
// Distinct from TestE2E_Proxy_JSONRPCWithAuth (which exercises the
// default group's broad allowlist) — here we narrow the group to a
// single method and assert it goes through.
func TestAccessControl_AllowsMethodInWhitelist(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("allowmethod-org")
	group := f.CreateGroup(org.ID, "allowmethod-group", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_getBalance"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	// Authenticated JSON-RPC must hit /rpc/:org_id (RD-877 removed the
	// implicit getUserDefaultOrganization fallback).
	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_getBalance",
		[]any{"0x0000000000000000000000000000000000000000", "latest"},
		map[string]string{"Authorization": "Bearer " + token})

	// 200 if Anvil is reachable, 502 if not — both mean the auth gate
	// let us through; only 404 indicates RBAC denial.
	if res.Status != http.StatusOK && res.Status != http.StatusBadGateway {
		t.Fatalf("expected 200 or 502 (auth + whitelist allowed), got %d: %s", res.Status, string(res.Body))
	}
}

// TestAccessControl_DeniesMethodNotInWhitelist verifies that a method
// absent from the user's group allowed_methods is rejected with an
// opaque 404.
//
// Distinct from TestE2E_ForbiddenRequest_DisallowedMethod, which
// exercises the global method blocklist (debug_storageRangeAt).
// Here the method is not globally blocked — just not in the user's
// per-group whitelist.
func TestAccessControl_DeniesMethodNotInWhitelist(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("denymethod-org")
	group := f.CreateGroup(org.ID, "denymethod-group", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_blockNumber"},
		Claims:         []testfixtures.Claim{},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_sendTransaction",
		[]any{map[string]any{}},
		map[string]string{"Authorization": "Bearer " + token})

	if res.Status != http.StatusNotFound {
		t.Fatalf("expected 404 (opaque RBAC denial), got %d: %s", res.Status, string(res.Body))
	}
	assertOpaqueErrorBody(t, res.Body)
}

// TestAccessControl_DeniesUserWithoutMembership verifies that a user
// who exists in the DB but has zero memberships is denied at the
// RBAC layer with an opaque 404. This pins behavior for the brief
// window between user provisioning (EnsureUserExists) and an admin
// granting the first membership.
func TestAccessControl_DeniesUserWithoutMembership(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)

	// Mint a JWT via the mock-login flow — this auto-creates a user
	// with KYC=false and a default-group membership.
	did := f.DID()
	token := f.GetJWTToken(did)

	user := f.Client.FindUserByExternalID(t, did)
	if user == nil {
		t.Fatalf("expected user %s to exist after JWT mint", did)
	}

	// Flip KYC=true so we test the no-membership path, not the
	// no-KYC path (TestE2E_NoKYC already covers KYC denial).
	f.Client.UpdateUser(t, user.ID, testfixtures.UpdateUserInput{
		KYC: testfixtures.Ptr(true),
	})

	// Strip every membership so the user has zero group affiliation.
	for _, m := range f.Client.ListUserMemberships(t, user.ID) {
		f.Client.DeleteMembership(t, user.ID, m.Membership.ID)
	}

	// Use an auth-required method (eth_getBalance, not in the anonymous
	// allowlist) — that's the only way to differentiate "no membership"
	// from "anonymous" at the proxy boundary. eth_blockNumber would
	// fall through to the anonymous allowlist and succeed.
	res := testfixtures.JSONRPCPost(t, serverURL, "eth_getBalance",
		[]any{"0x0000000000000000000000000000000000000001", "latest"},
		map[string]string{"Authorization": "Bearer " + token})

	if res.Status != http.StatusNotFound {
		t.Fatalf("expected 404 (no membership → opaque denial), got %d: %s", res.Status, string(res.Body))
	}
	assertOpaqueErrorBody(t, res.Body)
}
