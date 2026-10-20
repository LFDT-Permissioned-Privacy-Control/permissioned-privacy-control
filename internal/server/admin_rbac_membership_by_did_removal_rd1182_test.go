package server

import (
	"net/http"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwtAdminRouterForOrg builds a router that injects a jwt_admin context scoped
// to a single org (full admin of orgID) and mounts the RBAC routes, so the
// tier-2 escalation gate can be exercised without a real JWT / orgScoping
// round-trip. No admin-auth middleware runs, so requests carry no token.
func jwtAdminRouterForOrg(srv *Server, orgID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_method", "jwt_admin")
		c.Set("admin_org_ids", []string{orgID})
		c.Next()
	})
	srv.registerRBACRoutes(r.Group("/api/v1/admin"))
	return r
}

// RD-1182: DELETE /api/v1/admin/orgs/{org_id}/memberships/by-did — the symmetric
// counterpart of onboard-by-did, so the operator token can complete the
// org-admin lifecycle (mint AND remove) without a tenant-confidential read.

// Operator IS allowed to remove from an admin-tier group (mint then remove),
// and a second remove returns the opaque not-found 403 (membership is gone).
func TestRemoveByDID_OperatorAdminTierGroup_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, gid := createOrgWithOrgAdminGroup(t, srv)
	did := "did:test:" + uuid.New().String()[:8]

	// Operator mints the DID into the org-admin group.
	w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusCreated, w.Code, "operator mint into admin-tier group: %s", w.Body.String())

	// Operator removes it → 200.
	w = operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusOK, w.Code, "operator remove from admin-tier group: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "membership deleted")

	// Removing again → opaque 403 (no membership) — proves it's gone, no oracle.
	w = operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	assert.Equal(t, http.StatusForbidden, w.Code, "second remove must be opaque 403 (membership gone)")
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)
}

// Operator is REJECTED removing from a regular (non-admin-tier) group — that's
// the org admin's job (mirrors the onboard deny).
func TestRemoveByDID_OperatorRegularGroup_403_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, gid := createOrgWithNormalGroup(t, srv)

	w := operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errOperatorNoTenantMgmt)
}

// A tier-2 JWT org admin is REJECTED removing from an is_org_admin group
// (demoting an org admin is super-admin-only), even in their own org.
func TestRemoveByDID_Tier2JWTOnOrgAdminGroup_403_RD1182(t *testing.T) {
	srv, _ := setupTieredAdminTestServer(t, "secret")
	orgID, gid := createOrgWithOrgAdminGroup(t, srv)

	// A jwt_admin who is a full admin of orgID still cannot remove from an
	// is_org_admin group — demoting an org admin is super-admin-only.
	router := jwtAdminRouterForOrg(srv, orgID)
	w := tokenReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did", "",
		map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
	require.Equal(t, http.StatusForbidden, w.Code, "tier-2 jwt_admin must not touch org-admin group: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), errModifyOrgAdminGroupSuperOnly)
}

// Happy path with the full admin token: mint then remove; opaque 403 for an
// unknown DID.
func TestRemoveByDID_AdminHappyPathAndUnknownDID_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, gid := createOrgWithNormalGroup(t, srv)
	did := "did:test:" + uuid.New().String()[:8]

	w := adminReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusCreated, w.Code, "admin mint: %s", w.Body.String())

	w = adminReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusOK, w.Code, "admin remove: %s", w.Body.String())

	// Unknown DID → opaque 403 (same as no-membership / foreign-org).
	w = adminReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)
}

// Cross-org: removing via org B's path with a group_id that lives in org A must
// be rejected (opaque foreign-org) — the group.OrgID==path-org check is the sole
// cross-org binding for the operator.
func TestRemoveByDID_CrossOrgGroupSubstitution_403_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgA, gidA := createOrgWithOrgAdminGroup(t, srv)
	orgB, _ := createOrgWithOrgAdminGroup(t, srv)

	// Mint into org A's admin group (via admin so the row exists).
	did := "did:test:" + uuid.New().String()[:8]
	w := adminReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgA+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gidA})
	require.Equal(t, http.StatusCreated, w.Code)

	// Operator tries to remove it via org B's path (group_id from org A).
	w = operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgB+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gidA})
	assert.Equal(t, http.StatusForbidden, w.Code, "group from another org must be opaque 403")
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)
}

// A malformed (non-UUID) group_id is client input, not an internal fault, so it
// must return 400 — not a 500 from the uuid-column driver error. (Copilot #403.)
func TestRemoveByDID_MalformedGroupID_400_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, _ := createOrgWithOrgAdminGroup(t, srv)

	w := operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": "did:test:x", "group_id": "not-a-uuid"})
	assert.Equal(t, http.StatusBadRequest, w.Code, "malformed group_id must be 400 not 500: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "invalid group_id")
}

// The operator token is a distinct principal from the super-admin token, so its
// revoke must be attributed to "__operator__" in the audit trail — never
// misreported as "__super_admin__" (change-management fidelity). (Copilot #403.)
func TestRemoveByDID_OperatorAuditActor_RD1182(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()
	orgID, gid := createOrgWithOrgAdminGroup(t, srv)
	did := "did:test:" + uuid.New().String()[:8]

	w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusCreated, w.Code, "operator mint: %s", w.Body.String())
	w = operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
		map[string]any{"did": did, "group_id": gid})
	require.Equal(t, http.StatusOK, w.Code, "operator remove: %s", w.Body.String())

	entries, err := srv.db.ListAuditLogs(ctx, rbac.ResourceTypeMembership, nil, 50, 0)
	require.NoError(t, err)
	var revoke *rbac.AuditLogEntry
	for _, e := range entries {
		if e.Action == rbac.AuditActionRevoke {
			revoke = e
			break
		}
	}
	require.NotNil(t, revoke, "expected a revoke audit entry for the operator removal")
	assert.Equal(t, "__operator__", revoke.ActorExternalID, "operator revoke must not be misattributed to super-admin")
}
