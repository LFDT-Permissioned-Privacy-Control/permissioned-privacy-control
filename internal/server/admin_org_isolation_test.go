package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the cross-org admin authority gates (RD-917 §1 + RD-916).
// The agreed model: tier-1 super-admin (X-Admin-Token) creates and deletes
// orgs, tier-2 (JWT is_org_admin) can read/edit own orgs only and never
// sees other tenants. These tests lock in that invariant.

func TestCreateOrganization_RejectsJWTAdmin(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	// Tier-2 admin of some org tries to POST /admin/orgs.
	userDID, _, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"slug": "newtenant", "name": "New Tenant"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "tier-2 admin must NOT be able to create orgs")
	var body2 map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body2))
	assert.Contains(t, body2["error"], "super admin")
}

func TestCreateOrganization_AcceptsAdminToken(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	_ = srv

	body, _ := json.Marshal(map[string]any{"slug": "platformcreated", "name": "Platform Created"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "secret")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code, "super-admin must be able to create orgs")
}

func TestDeleteOrganization_RejectsJWTAdminEvenOnOwnOrg(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	// User is is_org_admin on this org. Per the agreed model, deletion is
	// platform-level and locked even on the user's own org.
	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+orgID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code, "tier-2 admin cannot delete even their own org")

	// Sanity-check the org still exists.
	got, err := srv.db.GetOrganization(t.Context(), orgID)
	require.NoError(t, err)
	require.NotNil(t, got, "org must not be deleted by jwt-admin attempt")
}

func TestDeleteOrganization_AcceptsAdminToken(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	// Seed an org via admin token (since createOrganization is now restricted).
	org := &rbac.Organization{
		ID:   uuid.New().String(),
		Slug: "deletable-" + uuid.New().String()[:8],
		Name: "Deletable",
	}
	require.NoError(t, srv.db.CreateOrganization(t.Context(), org))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/orgs/"+org.ID, nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "super-admin must be able to delete orgs")

	// Confirm deletion landed in the DB.
	got, err := srv.db.GetOrganization(t.Context(), org.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "org should be deleted")
}

func TestListOrganizations_JWTAdminScopedByMembership(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Alice is org admin of orgA only.
	aliceDID, orgAID, _ := createOrgAndAdminUser(t, srv)

	// Seed orgB and orgC where Alice has zero membership. Pre-RD-916 the
	// list endpoint would return all three to Alice; post-fix it returns
	// just orgA.
	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "orgb-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgC := &rbac.Organization{ID: uuid.New().String(), Slug: "orgc-" + uuid.New().String()[:8], Name: "Org C"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgC))

	token, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Data, 1, "tier-2 admin must see only orgs they're admin of")
	assert.Equal(t, orgAID, resp.Data[0]["id"])
	assert.Equal(t, 1, resp.Total)

	// Negative — orgB / orgC must NOT leak.
	for _, row := range resp.Data {
		assert.NotEqual(t, orgB.ID, row["id"], "orgB must not leak to non-member tier-2 admin")
		assert.NotEqual(t, orgC.ID, row["id"], "orgC must not leak to non-member tier-2 admin")
	}
}

func TestListOrganizations_AdminTokenSeesAllOrgs(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Create three orgs; super-admin should see all of them.
	_, orgAID, _ := createOrgAndAdminUser(t, srv)
	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "orgb-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgC := &rbac.Organization{ID: uuid.New().String(), Slug: "orgc-" + uuid.New().String()[:8], Name: "Org C"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgC))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs", nil)
	req.Header.Set("X-Admin-Token", "secret")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	seen := make(map[string]bool)
	for _, row := range resp.Data {
		seen[row["id"].(string)] = true
	}
	assert.True(t, seen[orgAID], "super-admin must see orgA")
	assert.True(t, seen[orgB.ID], "super-admin must see orgB")
	assert.True(t, seen[orgC.ID], "super-admin must see orgC")
}

func TestListOrganizations_JWTAdminWithReadonlyAdminAlsoIncluded(t *testing.T) {
	// A user who is is_org_readonly_admin (tier-2 read-only) of an org
	// should still see that org in the list — that's their dashboard scope.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	// Set up a user who is full admin in orgA AND readonly admin in orgB.
	aliceDID, orgAID, aliceUserID := createOrgAndAdminUser(t, srv)

	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "orgb-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))

	roGroup := &rbac.Group{
		ID:                 uuid.New().String(),
		OrgID:              orgB.ID,
		Slug:               "readonly-admins-" + uuid.New().String()[:8],
		Name:               "Readonly Admins",
		Path:               "readonly-admins",
		IsOrgReadonlyAdmin: true,
	}
	require.NoError(t, srv.db.CreateGroup(ctx, roGroup))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  aliceUserID,
		GroupID: roGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	token, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/orgs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Data []map[string]any `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	seen := make(map[string]bool)
	for _, row := range resp.Data {
		seen[row["id"].(string)] = true
	}
	assert.True(t, seen[orgAID], "full admin org must be visible")
	assert.True(t, seen[orgB.ID], "readonly admin org must also be visible")
	assert.Len(t, resp.Data, 2, "no other orgs should leak")
}
