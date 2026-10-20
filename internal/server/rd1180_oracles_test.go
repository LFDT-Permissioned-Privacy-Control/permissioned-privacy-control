package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/rbac"
)

// disclosureRouterScopedTo builds a router that registers the disclosure admin
// routes behind a jwt_admin context scoped to the given org IDs — so the
// RD-1180 check-access scope clamp is actually exercised (setupTestServerForRBAC
// runs dev-mode, which would bypass the clamp).
func disclosureRouterScopedTo(srv *Server, authMethod string, orgIDs ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("auth_method", authMethod)
		if len(orgIDs) > 0 {
			c.Set("admin_org_ids", orgIDs)
		}
		c.Next()
	})
	srv.registerDisclosureRoutes(r.Group("/api"))
	return r
}

// RD-1180: checkDisclosureAccess must not let a jwt_admin probe whether a
// disclosure grant exists over another org's user. Out-of-scope callers get the
// SAME opaque has_access:false body as the not-found case.
func TestCheckDisclosureAccess_CrossOrgScopeClamp_RD1180(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	ctx := context.Background()

	orgA := createCrossOrgTestOrg(t, srv, "disc-orgA")
	orgB := createCrossOrgTestOrg(t, srv, "disc-orgB")

	// Target user lives in org B; seed an active grant for a requester DID.
	requesterDID := "did:test:auditor-" + uuid.New().String()[:8]
	targetDID := "did:test:target-" + uuid.New().String()[:8]
	targetUser := &rbac.User{ID: uuid.New().String(), ExternalID: targetDID}
	require.NoError(t, srv.db.CreateUser(ctx, targetUser))

	req := &disclosure.Request{
		ID:           uuid.New().String(),
		RequesterDID: requesterDID,
		TargetUserID: targetUser.ID,
		OrgID:        orgB,
		Scope:        disclosure.Scope{DisclosureLevel: disclosure.DisclosureFull},
		Reason:       "audit",
		Status:       disclosure.StatusApproved,
		RequestedAt:  time.Now(),
	}
	require.NoError(t, srv.db.CreateDisclosureRequest(ctx, req))
	grant := &disclosure.Grant{
		ID:             uuid.New().String(),
		RequestID:      req.ID,
		GrantTokenHash: "test-hash-" + uuid.New().String()[:8],
		Scope:          req.Scope,
		GrantedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(24 * time.Hour),
	}
	require.NoError(t, srv.db.CreateDisclosureGrant(ctx, grant))

	url := "/api/disclosure/check-access?requester_did=" + requesterDID + "&target_user_did=" + targetDID

	call := func(router *gin.Engine) map[string]any {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
		var body map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		return body
	}

	t.Run("jwt_admin scoped to a DIFFERENT org sees opaque no-grant", func(t *testing.T) {
		body := call(disclosureRouterScopedTo(srv.Server, "jwt_admin", orgA))
		assert.Equal(t, false, body["has_access"], "out-of-scope admin must not see the grant")
		assert.Nil(t, body["grant_id"], "must not leak grant_id")
		assert.Nil(t, body["scope"], "must not leak scope")
		assert.Equal(t, "No active disclosure grant found", body["message"], "must be the exact opaque body")
	})

	t.Run("jwt_admin scoped to the grant's org sees it", func(t *testing.T) {
		body := call(disclosureRouterScopedTo(srv.Server, "jwt_admin", orgB))
		assert.Equal(t, true, body["has_access"], "in-scope admin must see the grant")
		assert.NotEmpty(t, body["grant_id"])
	})

	t.Run("super-admin (admin_token) sees it for any org", func(t *testing.T) {
		body := call(disclosureRouterScopedTo(srv.Server, "admin_token"))
		assert.Equal(t, true, body["has_access"], "super-admin bypasses the scope clamp")
		assert.NotEmpty(t, body["grant_id"])
	})
}

// RD-1180: deleteUserMembership must bind the path :user_id to the membership's
// real owner, so the audit row and cache invalidation can't be misattributed.
func TestDeleteUserMembership_IDBinding_RD1180(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	ctx := context.Background()

	orgID := createCrossOrgTestOrg(t, srv, "mbind-org")
	groupID := createCrossOrgTestGroup(t, srv, orgID, "mbind-g", "G")

	userX := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:x-" + uuid.New().String()[:8]}
	userY := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:y-" + uuid.New().String()[:8]}
	require.NoError(t, srv.db.CreateUser(ctx, userX))
	require.NoError(t, srv.db.CreateUser(ctx, userY))

	membership := &rbac.UserMembership{ID: uuid.New().String(), UserID: userX.ID, GroupID: groupID}
	require.NoError(t, srv.db.CreateMembership(ctx, membership))

	del := func(userID string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		srv.router.ServeHTTP(w, httptest.NewRequest(http.MethodDelete,
			"/api/users/"+userID+"/memberships/"+membership.ID, nil))
		return w
	}

	// Mismatched user_id (userY) must be rejected and NOT delete userX's membership.
	w := del(userY.ID)
	require.Equal(t, http.StatusForbidden, w.Code, "mismatched user_id must be 403: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)
	got, err := srv.db.GetMembership(ctx, membership.ID)
	require.NoError(t, err)
	assert.NotNil(t, got, "membership must still exist after a mismatched-user delete")

	// Correct user_id (userX) succeeds.
	w = del(userX.ID)
	require.Equal(t, http.StatusOK, w.Code, "correct user_id must succeed: %s", w.Body.String())
	got, err = srv.db.GetMembership(ctx, membership.ID)
	require.NoError(t, err)
	assert.Nil(t, got, "membership must be deleted with the correct user_id")
}
