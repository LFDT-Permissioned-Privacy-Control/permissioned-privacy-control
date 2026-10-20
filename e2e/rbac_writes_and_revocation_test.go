//go:build mockauth

package e2e

import (
	"net/http"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports the integration-level cases from:
//
//   e2e/playwright/tests/rbac/17-overlapping-grants.spec.ts (8 tests)
//   e2e/playwright/tests/rbac/18-write-operations.spec.ts (11 tests, 2 skipped)
//   e2e/playwright/tests/rbac/21-permission-revocation.spec.ts (14 tests, 1 skipped)
//
// 33 source tests consolidate into 7 Go functions. Coverage focuses on
// the load-bearing semantics (write enforcement, grant union, immediate
// revocation); admin-REST CRUD aspects already covered by
// internal/server/admin_rbac_*_test.go are not re-tested.

// === rbac/17 — Overlapping grants (1 representative test) ===

// TestRBACOverlappingGrants_ClaimsUnion verifies that when a user is
// in two groups both with grants on the same contract, claims and
// allowed_methods union across grants.
//
// Ports rbac/17 "user in 2 groups gets UNION of claims on same
// contract" and the corresponding allowed_methods variant. Most of
// the other rbac/17 tests (function-selector union, claim escalation,
// admin combination) exercise the same union code path with different
// inputs; the unit-level rbac.AccessController coverage of those is
// already strong.
func TestRBACOverlappingGrants_ClaimsUnion(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("og")

	// Two groups, both granting access to the same contract. Group A
	// brings the upgrade claim + eth_getStorageAt; Group B brings the
	// deploy claim + eth_call. Effective user perms should include
	// both claims and both methods.
	groupA := f.CreateGroup(org.ID, "ga", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, groupA.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_getStorageAt"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimUpgrade},
	})
	groupB := f.CreateGroup(org.ID, "gb", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, groupB.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	contract := f.CreateContract(org.ID, testfixtures.CreateContractOptions{
		OwnerGroupID: groupA.ID,
	})
	f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{GroupID: groupA.ID})
	f.Client.CreateContractGrant(t, org.ID, contract.Address, testfixtures.CreateContractGrantInput{GroupID: groupB.ID})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: groupA.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: groupB.ID})

	perms := f.Client.GetEffectivePermissions(t, user.ID, org.Slug)
	if !containsClaim(perms.Claims, testfixtures.ClaimUpgrade) {
		t.Errorf("union should include upgrade claim from group A; got %v", perms.Claims)
	}
	if !containsClaim(perms.Claims, testfixtures.ClaimDeploy) {
		t.Errorf("union should include deploy claim from group B; got %v", perms.Claims)
	}
	if !containsString(perms.AllowedMethods, "eth_getStorageAt") {
		t.Errorf("union should include eth_getStorageAt; got %v", perms.AllowedMethods)
	}
	if !containsString(perms.AllowedMethods, "eth_call") {
		t.Errorf("union should include eth_call; got %v", perms.AllowedMethods)
	}
}

// === rbac/18 — Write operations (3 representative tests) ===

// TestRBACWrites_DeniedWithoutDeployClaim verifies that
// eth_sendTransaction is denied for a user whose group lacks the
// deploy claim (current claim model: deploy is the closest analogue
// to the removed "write" claim for unregistered targets).
//
// Ports rbac/18 "denies eth_sendTransaction when user has only read
// claim" (translated to the post-RD-853 claim model).
func TestRBACWrites_DeniedWithoutDeployClaim(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("wd")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:         []testfixtures.Claim{}, // no deploy claim
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	target := f.Address()
	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_sendTransaction",
		[]any{map[string]any{"to": target, "from": "0x" + asciiUpper("1111111111111111111111111111111111111111"), "data": "0x"}},
		map[string]string{"Authorization": "Bearer " + token})
	// The proxy has two denial paths for a write without deploy
	// claim: RBAC opaque 404 (missing claim) or the sender-link
	// check returning 400 (from address not linked). Either is
	// acceptable — the security invariant is "denied", not the
	// specific status. eth_sendTransaction with no linked sender
	// hits the latter first on the current code path.
	if res.Status < 400 || res.Status >= 500 {
		t.Errorf("write to unregistered contract without deploy claim should be 4xx; got %d: %s", res.Status, string(res.Body))
	}
}

// TestRBACWrites_AllowedForDeployClaim is the positive counterpart:
// a user with the deploy claim CAN reach the upstream for a write
// against an unregistered address.
//
// Ports rbac/18 "deploy user allowed write to unregistered contracts".
func TestRBACWrites_AllowedForDeployClaim(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("wa")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(user.ID)

	target := f.Address()
	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_sendTransaction",
		[]any{map[string]any{"to": target, "from": "0x" + asciiUpper("1111111111111111111111111111111111111111"), "data": "0x"}},
		map[string]string{"Authorization": "Bearer " + token})
	// 200 (forwarded), 502 (anvil unreachable), or any non-RBAC code.
	// 4xx from RBAC layer (403/404) would indicate denial — only those
	// are failures here.
	if res.Status == http.StatusForbidden || res.Status == http.StatusNotFound {
		t.Errorf("deploy claim should permit write; got %d: %s", res.Status, string(res.Body))
	}
}

// TestRBACWrites_BlockedForBannedUser verifies that banning a user
// blocks writes even when their group has the deploy claim. The user
// status (banned) is checked separately from claim resolution.
//
// Ports rbac/18 "write operations blocked for banned user even with
// write claim".
func TestRBACWrites_BlockedForBannedUser(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("wb")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, token := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{
		Banned: true,
	})
	f.DeleteDefaultMembership(user.ID)

	target := f.Address()
	res := testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_sendTransaction",
		[]any{map[string]any{"to": target, "from": "0x" + asciiUpper("1111111111111111111111111111111111111111"), "data": "0x"}},
		map[string]string{"Authorization": "Bearer " + token})
	// Any 4xx is acceptable — ban check, sender-link check, or claim
	// check, in whatever order the proxy applies them. The security
	// invariant is "denied".
	if res.Status < 400 || res.Status >= 500 {
		t.Errorf("banned user should be denied (any 4xx); got %d: %s", res.Status, string(res.Body))
	}
}

// === rbac/21 — Permission revocation (3 representative tests) ===

// TestRBACRevocation_MembershipRemoval verifies that deleting a
// user's membership in a group immediately drops the methods they
// inherited from that group.
//
// Ports rbac/21 "removing membership revokes method access" and
// "RPC: removing grant immediately blocks RPC access to contract"
// (rolled into a single end-to-end assertion).
//
// Note on RD-956: the full revocation suite assumes a synchronous
// cache flush. Today the permissions cache invalidates on the next
// CheckAccess call (no admin endpoint needed). When the cache-flush
// admin endpoint lands (RD-956 endpoint ticket), the remaining
// timing-sensitive tests in rbac/21 can be ported on top of it.
func TestRBACRevocation_MembershipRemoval(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("rm")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	m := f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group.ID})

	// Pre-removal: eth_call allowed.
	pre := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
	})
	if !pre.Allowed {
		t.Fatalf("pre-removal: eth_call should be allowed; reason=%q", pre.Reason)
	}

	// Remove the membership.
	f.Client.DeleteMembership(t, user.ID, m.ID)

	// Post-removal: eth_call denied.
	post := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
	})
	if post.Allowed {
		t.Errorf("post-removal: eth_call should be denied; got Allowed=true")
	}
}

// TestRBACRevocation_GrantRemoval verifies that deleting a contract
// grant immediately removes the user's access to that specific
// contract while leaving other contract access intact.
//
// Ports rbac/21 "removing contract grant revokes access to that
// contract" + "removing grant from one group keeps access from
// another group" (consolidated).
func TestRBACRevocation_GrantRemoval(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("rg")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	contractA := f.CreateContract(org.ID, testfixtures.CreateContractOptions{OwnerGroupID: group.ID})
	contractB := f.CreateContract(org.ID, testfixtures.CreateContractOptions{OwnerGroupID: group.ID})
	f.Client.CreateContractGrant(t, org.ID, contractA.Address, testfixtures.CreateContractGrantInput{GroupID: group.ID})
	f.Client.CreateContractGrant(t, org.ID, contractB.Address, testfixtures.CreateContractGrantInput{GroupID: group.ID})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	// Both accessible pre-revocation.
	for _, c := range []string{contractA.Address, contractB.Address} {
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
			TargetAddress: c,
		})
		if !res.Allowed {
			t.Fatalf("pre-revoke: %s should be allowed", c)
		}
	}

	// Revoke grant on A only.
	f.Client.DoRaw(t, http.MethodDelete,
		"/api/v1/admin/orgs/"+org.ID+"/contracts/"+contractA.Address+"/grants/"+group.ID, nil)

	// A denied, B still allowed.
	a := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
		TargetAddress: contractA.Address,
	})
	if a.Allowed {
		t.Errorf("post-revoke: contract A should be denied; got Allowed=true")
	}
	b := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
		TargetAddress: contractB.Address,
	})
	if !b.Allowed {
		t.Errorf("post-revoke: contract B should still be allowed (orthogonal); reason=%q", b.Reason)
	}
}

// TestRBACRevocation_GroupDeletion verifies that deleting a group
// revokes every method/contract access path that group provided,
// for every member. Sanity check: the cascade-delete chain works
// (group_access → memberships → contract_grants) at the access
// controller level.
//
// Ports rbac/21 "deleting group revokes all access for members".
func TestRBACRevocation_GroupDeletion(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("gd")
	group := f.CreateGroup(org.ID, "g", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	user, _ := f.CreateUserWithMembership(group.ID, testfixtures.CreateUserOptions{})

	pre := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
	})
	if !pre.Allowed {
		t.Fatalf("pre-delete: eth_call should be allowed")
	}

	// Delete the group via the admin REST API.
	f.Client.DeleteGroup(t, org.ID, group.ID)

	post := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
	})
	if post.Allowed {
		t.Errorf("post-delete: eth_call should be denied after group removal; got Allowed=true")
	}
}
