//go:build mockauth

package e2e

import (
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// This file ports e2e/playwright/tests/rbac/23-multi-org-users.spec.ts —
// admin REST API behaviors around cross-org memberships, per-org
// effective permissions, and the access-check endpoint.
//
// Claim model translation: the Playwright spec used the removed
// `read` / `write` claims (RD-853, migration 048). For Go ports the
// semantic intent is preserved using only the current claims
// (admin, upgrade, deploy) plus allowed_methods. See [[feedback_no_read_write_users]].

// TestMultiOrgUsers_MemberOfMultipleOrgs verifies a user can hold
// memberships across multiple organizations and the admin listing
// surfaces all of them.
func TestMultiOrgUsers_MemberOfMultipleOrgs(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("multiorg1")
	org2 := f.CreateOrg("multiorg2")
	group1 := f.CreateGroup(org1.ID, "group1", testfixtures.CreateGroupOptions{})
	group2 := f.CreateGroup(org2.ID, "group2", testfixtures.CreateGroupOptions{})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	m1 := f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	m2 := f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	if m1.GroupID != group1.ID {
		t.Errorf("membership1 GroupID = %q, want %q", m1.GroupID, group1.ID)
	}
	if m2.GroupID != group2.ID {
		t.Errorf("membership2 GroupID = %q, want %q", m2.GroupID, group2.ID)
	}

	memberships := f.Client.ListUserMemberships(t, user.ID)
	groupIDs := map[string]bool{}
	for _, m := range memberships {
		groupIDs[m.Membership.GroupID] = true
	}
	if !groupIDs[group1.ID] {
		t.Errorf("memberships missing group1 (%s); got %v", group1.ID, groupIDs)
	}
	if !groupIDs[group2.ID] {
		t.Errorf("memberships missing group2 (%s); got %v", group2.ID, groupIDs)
	}
}

// TestMultiOrgUsers_MembershipsCarryOrgID verifies the
// listUserMemberships response embeds the group's org_id so the
// admin frontend can group memberships by org without an extra lookup.
func TestMultiOrgUsers_MembershipsCarryOrgID(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("orgid1")
	org2 := f.CreateOrg("orgid2")
	group1 := f.CreateGroup(org1.ID, "group1", testfixtures.CreateGroupOptions{})
	group2 := f.CreateGroup(org2.ID, "group2", testfixtures.CreateGroupOptions{})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	memberships := f.Client.ListUserMemberships(t, user.ID)
	orgIDs := map[string]bool{}
	for _, m := range memberships {
		if m.Membership.GroupID == group1.ID || m.Membership.GroupID == group2.ID {
			orgIDs[m.Group.OrgID] = true
		}
	}
	if !orgIDs[org1.ID] {
		t.Errorf("expected org1 ID %s in memberships, got %v", org1.ID, orgIDs)
	}
	if !orgIDs[org2.ID] {
		t.Errorf("expected org2 ID %s in memberships, got %v", org2.ID, orgIDs)
	}
}

// TestMultiOrgUsers_EffectivePermissionsAreOrgScoped verifies that
// /effective-permissions returns only the permissions from the
// queried org's groups, not the union across orgs.
func TestMultiOrgUsers_EffectivePermissionsAreOrgScoped(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("effperm1")
	org2 := f.CreateOrg("effperm2")

	// org1: admin claim + write-capable allowed_methods.
	group1 := f.CreateGroup(org1.ID, "admins", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org1.ID, group1.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimAdmin},
	})

	// org2: no claim, read-only methods.
	group2 := f.CreateGroup(org2.ID, "readers", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org2.ID, group2.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	perms1 := f.Client.GetEffectivePermissions(t, user.ID, org1.Slug)
	if perms1.OrgID != org1.ID {
		t.Errorf("org1 perms OrgID = %q, want %q", perms1.OrgID, org1.ID)
	}
	if !containsClaim(perms1.Claims, testfixtures.ClaimAdmin) {
		t.Errorf("org1 perms missing admin claim; got %v", perms1.Claims)
	}
	if !containsString(perms1.AllowedMethods, "eth_sendTransaction") {
		t.Errorf("org1 perms missing eth_sendTransaction; got %v", perms1.AllowedMethods)
	}

	perms2 := f.Client.GetEffectivePermissions(t, user.ID, org2.Slug)
	if perms2.OrgID != org2.ID {
		t.Errorf("org2 perms OrgID = %q, want %q", perms2.OrgID, org2.ID)
	}
	if containsClaim(perms2.Claims, testfixtures.ClaimAdmin) {
		t.Errorf("org2 perms should NOT contain admin (org-scoped); got %v", perms2.Claims)
	}
	if containsString(perms2.AllowedMethods, "eth_sendTransaction") {
		t.Errorf("org2 perms should NOT contain eth_sendTransaction (org-scoped); got %v", perms2.AllowedMethods)
	}
}

// TestMultiOrgUsers_NoMembershipInOrgYieldsEmptyPerms verifies that
// effective permissions for an org the user is NOT a member of
// return an empty (not nil) claims+methods set, not the union from
// other orgs.
func TestMultiOrgUsers_NoMembershipInOrgYieldsEmptyPerms(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("iso1")
	org2 := f.CreateOrg("iso2")

	group1 := f.CreateGroup(org1.ID, "privileged", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org1.ID, group1.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimAdmin},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})

	perms1 := f.Client.GetEffectivePermissions(t, user.ID, org1.Slug)
	if !containsClaim(perms1.Claims, testfixtures.ClaimAdmin) {
		t.Errorf("org1 perms should contain admin; got %v", perms1.Claims)
	}

	perms2 := f.Client.GetEffectivePermissions(t, user.ID, org2.Slug)
	if len(perms2.Claims) != 0 {
		t.Errorf("org2 perms should be empty (no membership); got claims %v", perms2.Claims)
	}
	if len(perms2.AllowedMethods) != 0 {
		t.Errorf("org2 perms should have no methods (no membership); got %v", perms2.AllowedMethods)
	}
}

// TestMultiOrgUsers_MultipleMembershipsInSameOrgCombine verifies
// that two memberships in the same org union their claims +
// allowed_methods.
func TestMultiOrgUsers_MultipleMembershipsInSameOrgCombine(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("combined")

	readers := f.CreateGroup(org.ID, "readers", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, readers.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{},
	})
	deployers := f.CreateGroup(org.ID, "deployers", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, deployers.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: readers.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: deployers.ID})

	perms := f.Client.GetEffectivePermissions(t, user.ID, org.Slug)
	if !containsClaim(perms.Claims, testfixtures.ClaimDeploy) {
		t.Errorf("combined perms missing deploy claim; got %v", perms.Claims)
	}
	if !containsString(perms.AllowedMethods, "eth_call") {
		t.Errorf("combined perms missing eth_call; got %v", perms.AllowedMethods)
	}
	if !containsString(perms.AllowedMethods, "eth_sendTransaction") {
		t.Errorf("combined perms missing eth_sendTransaction; got %v", perms.AllowedMethods)
	}
}

// TestMultiOrgUsers_AccessCheckRespectsOrgContext verifies the
// admin /access/check endpoint resolves permissions per the
// requested org_slug — a user with disjoint methods in org1 vs
// org2 sees different verdicts depending on which org is asked.
func TestMultiOrgUsers_AccessCheckRespectsOrgContext(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("accessctx1")
	org2 := f.CreateOrg("accessctx2")

	group1 := f.CreateGroup(org1.ID, "txsenders", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org1.ID, group1.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_sendTransaction"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})
	group2 := f.CreateGroup(org2.ID, "callers", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org2.ID, group2.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	cases := []struct {
		name    string
		orgSlug string
		method  string
		want    bool
	}{
		{"org1_sendTx_allowed", org1.Slug, "eth_sendTransaction", true},
		{"org1_call_denied", org1.Slug, "eth_call", false},
		{"org2_call_allowed", org2.Slug, "eth_call", true},
		{"org2_sendTx_denied", org2.Slug, "eth_sendTransaction", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
				UserExternalID: user.ExternalID,
				OrgSlug:        tc.orgSlug,
				Method:         tc.method,
			})
			if res.Allowed != tc.want {
				t.Errorf("%s: Allowed = %v, want %v (reason: %s)", tc.name, res.Allowed, tc.want, res.Reason)
			}
		})
	}
}

// TestMultiOrgUsers_RemovingMembershipPreservesOtherOrgs verifies
// that deleting a user's membership in org1 doesn't affect their
// permissions in org2.
func TestMultiOrgUsers_RemovingMembershipPreservesOtherOrgs(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("remove1")
	org2 := f.CreateOrg("remove2")

	group1 := f.CreateGroup(org1.ID, "g1", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org1.ID, group1.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{},
	})
	group2 := f.CreateGroup(org2.ID, "g2", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org2.ID, group2.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	m1 := f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	// Remove org1 membership.
	f.Client.DeleteMembership(t, user.ID, m1.ID)

	// org1 perms must drop.
	perms1 := f.Client.GetEffectivePermissions(t, user.ID, org1.Slug)
	if containsString(perms1.AllowedMethods, "eth_call") {
		t.Errorf("org1 perms still grant eth_call after membership removal; got %v", perms1.AllowedMethods)
	}

	// org2 perms must be intact.
	perms2 := f.Client.GetEffectivePermissions(t, user.ID, org2.Slug)
	if !containsString(perms2.AllowedMethods, "eth_call") {
		t.Errorf("org2 perms missing eth_call after org1 removal (cross-org leak); got %v", perms2.AllowedMethods)
	}
	if !containsClaim(perms2.Claims, testfixtures.ClaimDeploy) {
		t.Errorf("org2 perms missing deploy claim after org1 removal; got %v", perms2.Claims)
	}
}

// TestMultiOrgUsers_BannedAffectsAllOrgs verifies that banning a
// user is global — not per-org — and the access-check endpoint
// reflects this across all org contexts.
func TestMultiOrgUsers_BannedAffectsAllOrgs(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org1 := f.CreateOrg("ban1")
	org2 := f.CreateOrg("ban2")

	group1 := f.CreateGroup(org1.ID, "g1", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org1.ID, group1.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})
	group2 := f.CreateGroup(org2.ID, "g2", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org2.ID, group2.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_call"},
	})

	user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group1.ID})
	f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group2.ID})

	// Sanity: both orgs allow eth_call pre-ban.
	pre1 := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
		UserExternalID: user.ExternalID, OrgSlug: org1.Slug, Method: "eth_call",
	})
	if !pre1.Allowed {
		t.Fatalf("pre-ban: org1 should allow eth_call; got reason=%s", pre1.Reason)
	}

	// Ban the user globally.
	f.Client.UpdateUser(t, user.ID, testfixtures.UpdateUserInput{
		Banned: testfixtures.Ptr(true),
	})

	// Both orgs must deny.
	for _, org := range []testfixtures.Organization{org1, org2} {
		res := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID, OrgSlug: org.Slug, Method: "eth_call",
		})
		if res.Allowed {
			t.Errorf("post-ban: org %s should deny eth_call; got Allowed=true", org.Slug)
		}
	}
}

// === Helpers ===

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func containsClaim(haystack []testfixtures.Claim, needle testfixtures.Claim) bool {
	for _, c := range haystack {
		if c == needle {
			return true
		}
	}
	return false
}
