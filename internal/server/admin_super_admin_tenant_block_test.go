package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1107 + RD-1132 — the OPERATOR token model.
//
// The admin API accepts two X-Admin-Token values: the full ADMIN_API_TOKEN
// ("secret" in tests → auth_method=="admin_token", unrestricted — trusted ops /
// MCP) and the restricted OPERATOR_API_TOKEN (testOperatorToken →
// auth_method=="operator_token"). The operator is platform/bootstrap only: it
// may create/manage orgs and mint org admins, but must NOT mutate (RD-1107) or
// read (RD-1132) per-org tenant data. These tests pin all three facets on the
// RBAC routes registered by registerRBACRoutes. (Per-org compliance is gated by
// the same helpers and exercised against the live stack; those routes are not
// wired into setupTieredAdminTestServer.)

// testOperatorToken is the restricted operator credential configured by
// setupTieredAdminTestServer (sent via the X-Admin-Token header).
const testOperatorToken = "operator-secret"

// operatorReq issues a request with the restricted operator token.
func operatorReq(t *testing.T, router http.Handler, method, url string, body map[string]any) *httptest.ResponseRecorder {
	return tokenReq(t, router, method, url, testOperatorToken, body)
}

// adminReq issues a request with the full admin token ("secret").
func adminReq(t *testing.T, router http.Handler, method, url string, body map[string]any) *httptest.ResponseRecorder {
	return tokenReq(t, router, method, url, "secret", body)
}

func tokenReq(t *testing.T, router http.Handler, method, url, token string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, url, r)
	req.Header.Set("X-Admin-Token", token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestRD1107_OperatorBlockedFromRegularInOrgMutations(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	user := &rbac.User{ID: uuid.New().String(), ExternalID: "did:test:" + uuid.New().String()[:8], KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, user))

	const wantMsg = errOperatorNoTenantMgmt

	t.Run("create regular group", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups",
			map[string]any{"slug": "team-x", "name": "Team X"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("set access on regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid+"/access",
			map[string]any{"allowed_methods": []string{"eth_call"}, "claims": []string{}})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("delete regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid, nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("batch-delete including a regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups/batch-delete",
			map[string]any{"group_ids": []string{gid}})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("create contract", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/contracts",
			map[string]any{"address": "0x1111111111111111111111111111111111111111", "name": "Tok"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("create grant", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost,
			"/api/v1/admin/orgs/"+orgID+"/contracts/0x1111111111111111111111111111111111111111/grants",
			map[string]any{"group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("onboard-by-did into regular group", func(t *testing.T) {
		orgID, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
			map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	t.Run("add membership by uuid into regular group", func(t *testing.T) {
		_, gid := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/users/"+user.ID+"/memberships",
			map[string]any{"group_id": gid})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})
}

// RD-1132: the operator token is blocked from tenant-confidential READS, while
// it keeps the org list + org metadata; the full admin token reads everything.
func TestRD1132_OperatorBlockedFromTenantReads(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, gid := createOrgWithOrgAdminGroup(t, srv)
	const wantMsg = errOperatorNoTenantRead

	blocked := []struct{ name, url string }{
		{"list groups", "/api/v1/admin/orgs/" + orgID + "/groups"},
		{"get group", "/api/v1/admin/orgs/" + orgID + "/groups/" + gid},
		{"get group access", "/api/v1/admin/orgs/" + orgID + "/groups/" + gid + "/access"},
		{"list contracts", "/api/v1/admin/orgs/" + orgID + "/contracts"},
		{"list users", "/api/v1/admin/users"},
		{"get user", "/api/v1/admin/users/" + uuid.New().String()},
		{"list user memberships", "/api/v1/admin/users/" + uuid.New().String() + "/memberships"},
		{"effective permissions", "/api/v1/admin/users/" + uuid.New().String() + "/effective-permissions"},
		{"audit logs", "/api/v1/admin/audit-logs"},
		{"sessions", "/api/v1/admin/sessions"},
		{"lookup contract by address", "/api/v1/admin/contracts/by-address/0x1111111111111111111111111111111111111111"},
	}
	for _, tc := range blocked {
		t.Run("operator 403: "+tc.name, func(t *testing.T) {
			w := operatorReq(t, router, http.MethodGet, tc.url, nil)
			assert.Equal(t, http.StatusForbidden, w.Code)
			assert.Contains(t, w.Body.String(), wantMsg)
		})
	}

	// access/check is a POST "simulate" read — also blocked.
	t.Run("operator 403: access/check", func(t *testing.T) {
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/access/check",
			map[string]any{"user_external_id": "did:test:x", "org_id": orgID, "method": "eth_call"})
		assert.Equal(t, http.StatusForbidden, w.Code)
		assert.Contains(t, w.Body.String(), wantMsg)
	})

	// Kept readable for the operator: org list + org metadata.
	t.Run("operator 200: list orgs", func(t *testing.T) {
		w := operatorReq(t, router, http.MethodGet, "/api/v1/admin/orgs", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
	t.Run("operator 200: get org metadata", func(t *testing.T) {
		w := operatorReq(t, router, http.MethodGet, "/api/v1/admin/orgs/"+orgID, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	// The full admin token still reads tenant data (unrestricted).
	t.Run("admin token 200: list groups", func(t *testing.T) {
		w := adminReq(t, router, http.MethodGet, "/api/v1/admin/orgs/"+orgID+"/groups", nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// The operator keeps platform / bootstrap powers: org lifecycle + minting org
// admins (is_org_admin group ops). This is what lets a fresh org get its first
// tier-2 admin from a platform-only operator.
func TestRD1107_OperatorKeepsPlatformAndAdminTierOps(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")

	t.Run("create org", func(t *testing.T) {
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs",
			map[string]any{"slug": "plat-" + uuid.New().String()[:8], "name": "Platform Org"})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("create is_org_admin group (mint org admin)", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups",
			map[string]any{"slug": "admins", "name": "Admins", "is_org_admin": true})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("set access on is_org_admin group", func(t *testing.T) {
		orgID, gid := createOrgWithOrgAdminGroup(t, srv)
		w := operatorReq(t, router, http.MethodPut, "/api/v1/admin/orgs/"+orgID+"/groups/"+gid+"/access",
			map[string]any{"allowed_methods": []string{"eth_call"}, "claims": []string{}})
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("onboard-by-did into is_org_admin group", func(t *testing.T) {
		orgID, gid := createOrgWithOrgAdminGroup(t, srv)
		w := operatorReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did",
			map[string]any{"did": "did:test:" + uuid.New().String()[:8], "group_id": gid})
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("delete org", func(t *testing.T) {
		orgID, _ := createOrgWithNormalGroup(t, srv)
		w := operatorReq(t, router, http.MethodDelete, "/api/v1/admin/orgs/"+orgID, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// The full admin token (trusted ops / MCP) is unrestricted — it can do the
// per-org mutations the operator cannot. Pins that RD-1132 did not restrict it.
func TestRD1132_AdminTokenStillFull(t *testing.T) {
	srv, router := setupTieredAdminTestServer(t, "secret")
	orgID, _ := createOrgWithNormalGroup(t, srv)

	w := adminReq(t, router, http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups",
		map[string]any{"slug": "team-admin-full", "name": "Team"})
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestRD1107_Tier2OrgAdminStillManagesRegularGroups(t *testing.T) {
	// Sanity: the change must not break the tier-2 path it hands the work to.
	srv, router := setupTieredAdminTestServer(t, "secret")
	userDID, orgID, _ := createOrgAndAdminUser(t, srv)
	token, err := srv.jwtService.IssueAccessToken(userDID, true)
	require.NoError(t, err)

	body, _ := json.Marshal(map[string]any{"slug": "team-y", "name": "Team Y"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/groups", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
}
