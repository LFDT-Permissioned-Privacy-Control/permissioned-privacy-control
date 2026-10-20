package db

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// fakeAddr produces a deterministic-shape 40-hex eth address from a uuid
// for fixture use. Real ETH validation is not in scope for these tests.
func fakeAddr() string {
	hex := strings.ReplaceAll(uuid.New().String(), "-", "")
	if len(hex) < 40 {
		hex = hex + strings.Repeat("0", 40-len(hex))
	}
	return "0x" + hex[:40]
}

// userListFixture seeds a small graph used by TestListUsersFilteredPaginated_*.
// It is intentionally larger than strictly needed so subtests can pivot on
// different filter combinations without re-seeding.
type userListFixture struct {
	orgA, orgB string

	// orgA groups
	groupAdminA  string // is_org_admin=true (tier-2)
	groupTier3A  string // has contract_grant with 'admin' claim (tier-3)
	groupMemberA string // plain group, no admin

	// orgB group
	groupAdminB string // is_org_admin=true in orgB

	// users
	userOrgAdminA   string // member of groupAdminA
	userTier3AdminA string // member of groupTier3A
	userMemberA     string // member of groupMemberA
	userOrgAdminB   string // member of groupAdminB only (cross-org test)
	userMulti       string // member of groupMemberA AND groupAdminB
	userOrphan      string // exists, no memberships
}

func seedUserListFixture(t *testing.T, d *DB) userListFixture {
	t.Helper()
	ctx := context.Background()
	f := userListFixture{
		orgA:            uuid.New().String(),
		orgB:            uuid.New().String(),
		groupAdminA:     uuid.New().String(),
		groupTier3A:     uuid.New().String(),
		groupMemberA:    uuid.New().String(),
		groupAdminB:     uuid.New().String(),
		userOrgAdminA:   uuid.New().String(),
		userTier3AdminA: uuid.New().String(),
		userMemberA:     uuid.New().String(),
		userOrgAdminB:   uuid.New().String(),
		userMulti:       uuid.New().String(),
		userOrphan:      uuid.New().String(),
	}

	mustCreateOrg(t, d, ctx, f.orgA, "org-a")
	mustCreateOrg(t, d, ctx, f.orgB, "org-b")

	mustCreateGroup(t, d, ctx, f.groupAdminA, f.orgA, "admins-a", true)
	mustCreateGroup(t, d, ctx, f.groupTier3A, f.orgA, "deployers-a", false)
	mustCreateGroup(t, d, ctx, f.groupMemberA, f.orgA, "members-a", false)
	mustCreateGroup(t, d, ctx, f.groupAdminB, f.orgB, "admins-b", true)

	// Tier-3 admin: a contract grant carrying the 'admin' claim, owned by
	// groupTier3A. This is the marker the role filter looks for.
	contractID := uuid.New().String()
	if err := d.CreateContract(ctx, &rbac.Contract{
		ID:       contractID,
		OrgID:    f.orgA,
		Address:  fakeAddr(),
		Name:     "contract-a",
		Metadata: map[string]any{},
	}); err != nil {
		t.Fatalf("CreateContract: %v", err)
	}
	if err := d.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    f.groupTier3A,
	}); err != nil {
		t.Fatalf("CreateContractGrant: %v", err)
	}
	// claims is owned by a separate column added in migration 029; set it
	// directly so we don't depend on grant-claims handler internals.
	if _, err := d.conn.ExecContext(ctx,
		`UPDATE contract_grants SET claims = ARRAY['admin'] WHERE group_id = $1`, f.groupTier3A); err != nil {
		t.Fatalf("set admin claim: %v", err)
	}

	mustCreateUser(t, d, ctx, f.userOrgAdminA, "did:test:org-admin-a")
	mustCreateUser(t, d, ctx, f.userTier3AdminA, "did:test:tier3-a")
	mustCreateUser(t, d, ctx, f.userMemberA, "did:test:member-a")
	mustCreateUser(t, d, ctx, f.userOrgAdminB, "did:test:admin-b")
	mustCreateUser(t, d, ctx, f.userMulti, "did:test:multi")
	mustCreateUser(t, d, ctx, f.userOrphan, "did:test:orphan")

	mustCreateMembership(t, d, ctx, f.userOrgAdminA, f.groupAdminA)
	mustCreateMembership(t, d, ctx, f.userTier3AdminA, f.groupTier3A)
	mustCreateMembership(t, d, ctx, f.userMemberA, f.groupMemberA)
	mustCreateMembership(t, d, ctx, f.userOrgAdminB, f.groupAdminB)
	mustCreateMembership(t, d, ctx, f.userMulti, f.groupMemberA)
	mustCreateMembership(t, d, ctx, f.userMulti, f.groupAdminB)

	return f
}

func mustCreateOrg(t *testing.T, d *DB, ctx context.Context, id, slug string) {
	t.Helper()
	if err := d.CreateOrganization(ctx, &rbac.Organization{
		ID:       id,
		Slug:     slug,
		Name:     slug,
		Settings: map[string]interface{}{},
	}); err != nil {
		t.Fatalf("CreateOrganization(%s): %v", slug, err)
	}
}

func mustCreateGroup(t *testing.T, d *DB, ctx context.Context, id, orgID, slug string, isOrgAdmin bool) {
	t.Helper()
	if err := d.CreateGroup(ctx, &rbac.Group{
		ID:         id,
		OrgID:      orgID,
		Slug:       slug,
		Name:       slug,
		Path:       slug,
		IsOrgAdmin: isOrgAdmin,
	}); err != nil {
		t.Fatalf("CreateGroup(%s): %v", slug, err)
	}
}

func mustCreateUser(t *testing.T, d *DB, ctx context.Context, id, did string) {
	t.Helper()
	if err := d.CreateUser(ctx, &rbac.User{
		ID:         id,
		ExternalID: did,
		Metadata:   map[string]any{},
	}); err != nil {
		t.Fatalf("CreateUser(%s): %v", did, err)
	}
}

func mustCreateMembership(t *testing.T, d *DB, ctx context.Context, userID, groupID string) {
	t.Helper()
	if err := d.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userID,
		GroupID: groupID,
		Source:  rbac.MembershipSourceAdmin,
	}); err != nil {
		t.Fatalf("CreateMembership: %v", err)
	}
}

// listUserIDs is a small helper that runs ListUsersFilteredPaginated and
// returns just the user IDs as a set so tests can assert membership without
// caring about row order.
func listUserIDs(t *testing.T, d *DB, filter UserFilter) map[string]struct{} {
	t.Helper()
	users, _, err := d.ListUsersFilteredPaginated(context.Background(), filter, 100, 0)
	if err != nil {
		t.Fatalf("ListUsersFilteredPaginated: %v", err)
	}
	out := make(map[string]struct{}, len(users))
	for _, u := range users {
		out[u.ID] = struct{}{}
	}
	return out
}

func TestListUsersFilteredPaginated_RoleFilter(t *testing.T) {
	d := setupRBACTestDB(t)
	defer cleanupTestDB(t, d)
	f := seedUserListFixture(t, d)

	cases := []struct {
		name string
		role string
		want []string // user IDs that must be present
		not  []string // user IDs that must NOT be present
	}{
		{
			name: "org_admin includes tier-2 (orgs A and B)",
			role: UserRoleOrgAdmin,
			want: []string{f.userOrgAdminA, f.userOrgAdminB, f.userMulti},
			not:  []string{f.userTier3AdminA, f.userMemberA, f.userOrphan},
		},
		{
			name: "admin includes tier-3 only",
			role: UserRoleAdmin,
			want: []string{f.userTier3AdminA},
			not:  []string{f.userOrgAdminA, f.userMemberA, f.userOrphan, f.userOrgAdminB},
		},
		{
			name: "member excludes both admin tiers and orphans",
			role: UserRoleMember,
			want: []string{f.userMemberA},
			not:  []string{f.userOrgAdminA, f.userTier3AdminA, f.userOrphan, f.userOrgAdminB, f.userMulti},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := listUserIDs(t, d, UserFilter{Role: tc.role})
			for _, id := range tc.want {
				if _, ok := got[id]; !ok {
					t.Errorf("want user %s in result, missing", id)
				}
			}
			for _, id := range tc.not {
				if _, ok := got[id]; ok {
					t.Errorf("user %s should not be in result", id)
				}
			}
		})
	}
}

func TestListUsersFilteredPaginated_GroupIDsFilter(t *testing.T) {
	d := setupRBACTestDB(t)
	defer cleanupTestDB(t, d)
	f := seedUserListFixture(t, d)

	t.Run("single group", func(t *testing.T) {
		got := listUserIDs(t, d, UserFilter{GroupIDs: []string{f.groupMemberA}})
		want := map[string]struct{}{f.userMemberA: {}, f.userMulti: {}}
		assertEqualIDSet(t, got, want)
	})

	t.Run("multiple groups OR", func(t *testing.T) {
		got := listUserIDs(t, d, UserFilter{GroupIDs: []string{f.groupAdminA, f.groupTier3A}})
		want := map[string]struct{}{f.userOrgAdminA: {}, f.userTier3AdminA: {}}
		assertEqualIDSet(t, got, want)
	})
}

func TestListUsersFilteredPaginated_ScopedOrgIDs(t *testing.T) {
	d := setupRBACTestDB(t)
	defer cleanupTestDB(t, d)
	f := seedUserListFixture(t, d)

	t.Run("scope to orgA only", func(t *testing.T) {
		got := listUserIDs(t, d, UserFilter{ScopedOrgIDs: []string{f.orgA}})
		// userOrgAdminB has no orgA membership and must be filtered out.
		// userMulti has orgA + orgB membership and must remain.
		// userOrphan has no memberships in any org and must be excluded.
		want := map[string]struct{}{
			f.userOrgAdminA:   {},
			f.userTier3AdminA: {},
			f.userMemberA:     {},
			f.userMulti:       {},
		}
		assertEqualIDSet(t, got, want)
	})

	t.Run("role admin scoped to orgB returns nothing", func(t *testing.T) {
		// Tier-3 admin marker only exists in orgA. With scope=orgB the
		// admin role must produce no matches.
		got := listUserIDs(t, d, UserFilter{Role: UserRoleAdmin, ScopedOrgIDs: []string{f.orgB}})
		if len(got) != 0 {
			t.Errorf("want empty result, got %d users", len(got))
		}
	})

	t.Run("empty scope -> empty result", func(t *testing.T) {
		got := listUserIDs(t, d, UserFilter{ScopedOrgIDs: []string{}})
		if len(got) != 0 {
			t.Errorf("want 0 users for empty scope, got %d", len(got))
		}
	})
}

func TestListGroupMembershipsForUsers_Scoping(t *testing.T) {
	d := setupRBACTestDB(t)
	defer cleanupTestDB(t, d)
	f := seedUserListFixture(t, d)

	t.Run("super-admin sees all orgs", func(t *testing.T) {
		got, err := d.ListGroupMembershipsForUsers(context.Background(),
			[]string{f.userMulti}, nil)
		if err != nil {
			t.Fatalf("ListGroupMembershipsForUsers: %v", err)
		}
		if n := len(got[f.userMulti]); n != 2 {
			t.Errorf("userMulti memberships = %d, want 2", n)
		}
	})

	t.Run("orgA scope hides orgB memberships", func(t *testing.T) {
		got, err := d.ListGroupMembershipsForUsers(context.Background(),
			[]string{f.userMulti}, []string{f.orgA})
		if err != nil {
			t.Fatalf("ListGroupMembershipsForUsers: %v", err)
		}
		if n := len(got[f.userMulti]); n != 1 {
			t.Errorf("userMulti memberships under orgA scope = %d, want 1", n)
		}
		if got[f.userMulti][0].OrgID != f.orgA {
			t.Errorf("returned membership not in orgA: %+v", got[f.userMulti][0])
		}
	})

	t.Run("empty userIDs returns empty map", func(t *testing.T) {
		got, err := d.ListGroupMembershipsForUsers(context.Background(), nil, nil)
		if err != nil {
			t.Fatalf("ListGroupMembershipsForUsers: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("want empty map, got %d entries", len(got))
		}
	})
}

func assertEqualIDSet(t *testing.T, got, want map[string]struct{}) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("set size: got=%d want=%d (got=%v want=%v)", len(got), len(want), got, want)
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			t.Errorf("missing expected id %s", id)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("unexpected id %s in result", id)
		}
	}
}
