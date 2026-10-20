// RD-944 — pin the admin-org fallback on the disclosure list endpoints.
//
// Pre-fix `listDisclosureRequests` defaulted to the system default org
// (`00000000-...001`) when no `org_id` query param was supplied. For any
// tier-2 admin of a real org the system default org isn't in
// admin_org_ids, so requireTargetInScope always 403'd — breaking the
// dashboard Disclosure tab for every prod tier-2 admin.
//
// `listDisclosureGrants` already had the right behaviour (default to
// caller's first full-admin org); the fix mirrored that in
// listDisclosureRequests so the two parallel requests fired by the
// frontend now succeed symmetrically.
//
// This test exercises the four acceptance criteria from the RD-944
// issue body against a real testcontainer Postgres, simulating
// jwt_admin context via a small middleware that sets the same gin keys
// adminAuthMiddleware would in production.

package server

import (
	"bytes"
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

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/disclosure"
)

// fakeAdminAuth sets the same gin context keys adminAuthMiddleware
// would after a real JWT-admin token validation. Used to drive the
// scoping branches in disclosure list handlers without standing up the
// full JWT+claims plumbing.
func fakeAdminAuth(authMethod string, fullAdminOrgIDs, readonlyAdminOrgIDs []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authMethod != "" {
			c.Set("auth_method", authMethod)
		}
		if fullAdminOrgIDs != nil {
			c.Set("admin_org_ids", fullAdminOrgIDs)
		}
		if readonlyAdminOrgIDs != nil {
			c.Set("admin_readonly_org_ids", readonlyAdminOrgIDs)
		}
		c.Next()
	}
}

func setupDisclosureRouterWithAuth(srv *Server, auth gin.HandlerFunc) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	api := router.Group("/api")
	if auth != nil {
		api.Use(auth)
	}
	srv.registerDisclosureRoutes(api)
	return router
}

func seedRequest(t *testing.T, database *db.DB, orgID string) string {
	t.Helper()
	targetUserID := uuid.New().String()
	ctx := context.Background()
	_, err := database.Conn().ExecContext(ctx,
		"INSERT INTO users (id, external_id, kyc, banned, metadata) VALUES ($1, $2, false, false, '{}')",
		targetUserID, "did:test:rd944-"+uuid.New().String()[:8])
	require.NoError(t, err)
	req := &disclosure.Request{
		ID:           uuid.New().String(),
		TargetUserID: targetUserID,
		OrgID:        orgID,
		Scope:        disclosure.Scope{},
		Reason:       "rd-944 seed",
		Status:       disclosure.StatusPending,
		RequestedAt:  time.Now(),
	}
	require.NoError(t, database.CreateRequest(ctx, req))
	return req.ID
}

// AC #1 — single-org tier-2 admin opens disclosure tab without org_id → list loads (no 403).
func TestRD944_ListRequests_JWTAdmin_NoOrgID_PicksOwnOrg(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-orgA")
	_ = seedRequest(t, database, orgA) // seed one request so we can confirm the right org was picked

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "tier-2 admin of orgA must see disclosure list scoped to orgA; got body=%s", w.Body.String())
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Requests, 1, "should see the seeded request in caller's own org")
}

// AC #2 — multi-org tier-2 admin without org_id MUST be rejected with
// an explicit 400, not silently scoped to one of their orgs. This is
// the corrected behaviour after the user pushback on the first cut of
// this PR: implicit fall-back is only acceptable when there is exactly
// one valid choice; 2+ choices means the caller must pick explicitly.
func TestRD944_ListRequests_JWTAdmin_MultiOrg_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-multiA")
	orgB := createTestOrgForHandler(t, database, "rd944-multiB")
	_ = seedRequest(t, database, orgA)
	_ = seedRequest(t, database, orgB)

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusBadRequest, w.Code,
		"multi-org admin without org_id must get 400 — silently scoping to first admin org was the bug we just removed. body=%s",
		w.Body.String())
}

// AC #2 continued — explicit org_id allows multi-org admin to choose their other org.
func TestRD944_ListRequests_JWTAdmin_MultiOrg_ExplicitOrgID_Works(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-explicit-A")
	orgB := createTestOrgForHandler(t, database, "rd944-explicit-B")
	_ = seedRequest(t, database, orgA)
	_ = seedRequest(t, database, orgB)

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgB, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Requests, 1, "explicit org_id should scope to that org")
}

// AC #3 — Audit C3 preserved: cross-org probe still 403s.
// Alice admins orgA, tries to query disclosure requests for orgB she
// has no admin role in. Must 403, regardless of whether orgB exists.
func TestRD944_ListRequests_CrossOrgProbe_StillBlocked(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-c3-A")
	orgB := createTestOrgForHandler(t, database, "rd944-c3-B")

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/requests?org_id="+orgB, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusForbidden, w.Code, "Audit C3 must still fire: tier-2 admin of orgA cannot query orgB's disclosure list. body=%s", w.Body.String())
}

// AC #4 — super-admin (no auth_method set, mirrors X-Admin-Token in
// real adminAuthMiddleware path) without org_id falls back to system
// default org. Pre-fix behaviour preserved for admin scripts.
func TestRD944_ListRequests_SuperAdmin_NoOrgID_UsesSystemDefault(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	// No fakeAdminAuth installed — auth_method stays empty, matching
	// the dev/super-admin bypass path in requireTargetInScope.
	router := setupDisclosureRouterWithAuth(srv, nil)

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code, "super-admin / dev caller without org_id must still succeed (falls back to system default). body=%s", w.Body.String())
}

// AC #5 — single-RO-admin without org_id: single valid choice → fall
// back. RO-admin in EXACTLY one org is the same shape as full-admin in
// exactly one org from the resolver's perspective. Cross-org gate
// downstream still re-verifies via requireTargetInScope.
func TestRD944_ListRequests_SingleROAdmin_NoOrgID_PicksTheROOrg(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-ro-single")
	_ = seedRequest(t, database, orgA)

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{}, []string{orgA}))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code,
		"single-RO-admin (exactly one scoped org) without org_id falls back to that org. body=%s", w.Body.String())
	var resp disclosure.DisclosureListResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Requests, 1)
}

// AC #6 — mixed scope (full admin in orgA + RO admin in orgB): TWO
// distinct orgs in scope. Caller must specify which one.
func TestRD944_ListRequests_FullPlusROAdmin_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-mixed-full")
	orgB := createTestOrgForHandler(t, database, "rd944-mixed-ro")

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, []string{orgB}))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusBadRequest, w.Code,
		"full+RO admin (2 distinct orgs in scope) without org_id must get 400, same as multi-full-admin. body=%s",
		w.Body.String())
}

// AC #7 — RO-only with no orgs at all (shouldn't happen given the
// middleware established jwt_admin, but defensive): 400 not a panic.
func TestRD944_ListRequests_NoAdminScope_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{}, []string{}))

	req := httptest.NewRequest("GET", "/api/disclosure/requests", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code,
		"jwt_admin with no admin scope at all (defensive) must 400 without panicking")
}

// AC #8 — listDisclosureGrants applies the same explicit-over-implicit
// rule. Pre-fix it silently picked admin_org_ids[0] for multi-org admins;
// post-fix multi-org admins without `org_id` get 400 here too, so the
// dashboard's two parallel requests behave symmetrically.
func TestRD944_ListGrants_JWTAdmin_MultiOrg_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-grants-multiA")
	orgB := createTestOrgForHandler(t, database, "rd944-grants-multiB")
	_ = orgA
	_ = orgB

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/grants", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusBadRequest, w.Code,
		"multi-org admin without org_id on /grants must get 400 — symmetric with /requests. body=%s",
		w.Body.String())
}

// AC #9 — listDisclosureGrants single-org admin without org_id: fall
// back to caller's only org (the legitimate use of the implicit pick).
func TestRD944_ListGrants_JWTAdmin_SingleOrg_NoOrgID_OK(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-grants-singleA")

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	req := httptest.NewRequest("GET", "/api/disclosure/grants", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equalf(t, http.StatusOK, w.Code,
		"single-org admin without org_id on /grants falls back to caller's only org. body=%s", w.Body.String())
}

// ---------------------------------------------------------------------------
// JWT-admin coverage for the CREATE endpoint.
//
// RD-944 added jwt_admin coverage for ListRequests / ListGrants but left
// createDisclosureRequest untested under jwt_admin. The FE bug that prompted
// PR #278 (frontend omitting org_id, backend defaulting to system default,
// caller of a non-default org getting 403) was structurally invisible to
// `TestCreateDisclosureRequest` because that test runs without an
// auth_method (i.e. dev-mode bypass — requireFullAdminInScope returns true
// without checking org_ids). These tests close that gap by exercising the
// same set of caller scopes RD-944 exercises for the list endpoints.
//
// RD-1011 then extended the RD-944 explicit-over-implicit rule from the
// list endpoints to createDisclosureRequest itself, so the no-org_id path
// resolves to the caller's single admin org (or 400 for multi-org admins)
// instead of silently defaulting to the system default org. The AC #11
// family of cases below pins that behaviour.
// ---------------------------------------------------------------------------

// seedTargetUserInOrg inserts a user plus a minimal group + membership
// rooted at orgID, so the requireUserInCallerScope gate inside
// createDisclosureRequest sees the user as belonging to orgID.
func seedTargetUserInOrg(t *testing.T, database *db.DB, orgID string) string {
	t.Helper()
	ctx := context.Background()
	userID := uuid.New().String()
	groupID := uuid.New().String()
	membershipID := uuid.New().String()

	_, err := database.Conn().ExecContext(ctx,
		`INSERT INTO users (id, external_id, kyc, banned, metadata)
		 VALUES ($1, $2, true, false, '{}')`,
		userID, "did:test:create-jwt-"+uuid.New().String()[:8])
	require.NoError(t, err)

	slug := "create-jwt-" + uuid.New().String()[:8]
	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO groups (id, org_id, slug, name, path, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, NOW(), NOW())`,
		groupID, orgID, slug, "Create JWT Test Group", slug)
	require.NoError(t, err)

	_, err = database.Conn().ExecContext(ctx,
		`INSERT INTO user_memberships (id, user_id, group_id, source)
		 VALUES ($1, $2, $3, 'admin')`,
		membershipID, userID, groupID)
	require.NoError(t, err)

	return userID
}

func postCreateRequest(t *testing.T, router *gin.Engine, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/api/disclosure/requests", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// AC #10 — single-org full admin, body carries the matching org_id, target
// user belongs to that org → 201. This is the post-FE-fix happy path.
func TestRD944_CreateRequest_JWTAdmin_MatchingOrgID_201(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-create-okA")
	targetUserID := seedTargetUserInOrg(t, database, orgA)
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"org_id":         orgA,
		"reason":         "rd-944 create happy path",
	})

	require.Equalf(t, http.StatusCreated, w.Code,
		"full admin of orgA creating in orgA must succeed. body=%s", w.Body.String())
	var resp disclosure.Request
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, orgA, resp.OrgID, "request must be scoped to the body's org_id, not the system default")
}

// AC #11 (RD-1011) — single-org full admin omits org_id. Pre-RD-1011
// the backend silently defaulted to the system default org and the
// caller (admin of orgA, not of the default org) got a 403 from
// requireFullAdminInScope; PR #278 worked around it by always sending
// org_id from the FE. The defensive backend fix mirrors the RD-944
// LIST behaviour: exactly one org in scope → pick it, so a future FE
// regression "create with empty org_id" succeeds with the caller's
// only org instead of failing opaquely against the system default.
func TestRD944_CreateRequest_JWTAdmin_SingleOrg_NoOrgID_PicksOwnOrg(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd1011-create-singleA")
	targetUserID := seedTargetUserInOrg(t, database, orgA)
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"reason":         "rd-1011 single-org no org_id",
		// org_id intentionally omitted — single-org admin should fall back to orgA
	})

	require.Equalf(t, http.StatusCreated, w.Code,
		"single-org JWT admin without org_id must fall back to their only admin org, not the system default. body=%s",
		w.Body.String())
	var resp disclosure.Request
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, orgA, resp.OrgID, "request must be scoped to the caller's only admin org, not the system default")
}

// AC #11b (RD-1011) — multi-org full admin omits org_id. Pre-RD-1011
// the backend defaulted to the system default org; if the admin
// happened to have rights there it would silently scope to it (wrong
// org), otherwise 403 (opaque). Post-fix it MUST be a 400 with an
// explicit "org_id is required" — symmetric with the LIST endpoints,
// so multi-org admins are forced to pick a target explicitly.
func TestRD944_CreateRequest_JWTAdmin_MultiOrg_NoOrgID_400(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd1011-create-multiA")
	orgB := createTestOrgForHandler(t, database, "rd1011-create-multiB")
	targetUserID := seedTargetUserInOrg(t, database, orgA)
	_ = orgB

	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA, orgB}, nil))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"reason":         "rd-1011 multi-org no org_id",
		// org_id intentionally omitted
	})

	require.Equalf(t, http.StatusBadRequest, w.Code,
		"multi-org JWT admin without org_id must get 400 — silently scoping to one of several admin orgs is the bug we are fixing. body=%s",
		w.Body.String())
}

// AC #11c (RD-1011) — super-admin / dev mode without org_id falls
// back to the system default org. Preserved for backward compatibility
// with admin scripts that target the system defaults, matching the
// RD-944 super-admin behaviour on the LIST endpoints.
func TestRD944_CreateRequest_SuperAdmin_NoOrgID_DefaultOrg(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	// Seed the system default org row (ResetTestDatabase truncates
	// everything, and the foreign-key chain target_user → group →
	// org requires the org row to exist before seedTargetUserInOrg
	// can insert the group).
	defaultOrgID := "00000000-0000-0000-0000-000000000001"
	_, err := database.Conn().ExecContext(context.Background(),
		`INSERT INTO organizations (id, slug, name, settings)
		 VALUES ($1, $2, $3, '{}')
		 ON CONFLICT (id) DO NOTHING`,
		defaultOrgID, "default", "Default Organization")
	require.NoError(t, err)

	// Target user must live in the system default org so the
	// requireUserInCallerScope gate downstream doesn't 403 the
	// super-admin path before the org-resolution behaviour we want to
	// pin gets exercised.
	targetUserID := seedTargetUserInOrg(t, database, defaultOrgID)

	// No fakeAdminAuth installed — auth_method stays empty, matching
	// the dev / super-admin bypass path (requireFullAdminInScope
	// returns true unconditionally for non-jwt_admin callers).
	router := setupDisclosureRouterWithAuth(srv, nil)

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"reason":         "rd-1011 super-admin default-org fallback",
		// org_id intentionally omitted
	})

	require.Equalf(t, http.StatusCreated, w.Code,
		"super-admin / dev mode without org_id must keep falling back to the system default org. body=%s",
		w.Body.String())
	var resp disclosure.Request
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, defaultOrgID, resp.OrgID,
		"super-admin fallback must resolve to the system default org")
}

// AC #12 — full admin of orgA, body carries orgB → 403. Cross-org probe
// gate, mirrors TestRD944_ListRequests_CrossOrgProbe_StillBlocked.
func TestRD944_CreateRequest_JWTAdmin_ForeignOrgID_403(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-create-foreignA")
	orgB := createTestOrgForHandler(t, database, "rd944-create-foreignB")
	targetUserID := seedTargetUserInOrg(t, database, orgB)
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"org_id":         orgB,
		"reason":         "rd-944 create cross-org probe",
	})

	require.Equalf(t, http.StatusForbidden, w.Code,
		"admin of orgA cannot create disclosures scoped to orgB. body=%s", w.Body.String())
}

// AC #13 — read-only admin of orgA, body carries matching orgA → 403.
// Mutating endpoint must reject RO admins regardless of org match.
func TestRD944_CreateRequest_JWTReadOnlyAdmin_MatchingOrgID_403(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-create-roA")
	targetUserID := seedTargetUserInOrg(t, database, orgA)
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", nil, []string{orgA}))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"org_id":         orgA,
		"reason":         "rd-944 create read-only attempt",
	})

	require.Equalf(t, http.StatusForbidden, w.Code,
		"read-only admin cannot create disclosures even within their own org. body=%s",
		w.Body.String())
}

// AC #14 — full admin of orgA, body carries orgA (matching), but target
// user lives only in orgB → 403 from requireUserInCallerScope. The body's
// org_id passes the first gate; the target-user-scope check catches the
// cross-org probe attempt that orgID alone wouldn't.
func TestRD944_CreateRequest_JWTAdmin_TargetUserCrossOrg_403(t *testing.T) {
	srv, _, database := setupTestServerForDisclosure(t)
	defer database.Close()

	orgA := createTestOrgForHandler(t, database, "rd944-create-userxA")
	orgB := createTestOrgForHandler(t, database, "rd944-create-userxB")
	// Target user lives in orgB only.
	targetUserID := seedTargetUserInOrg(t, database, orgB)
	router := setupDisclosureRouterWithAuth(srv, fakeAdminAuth("jwt_admin", []string{orgA}, nil))

	w := postCreateRequest(t, router, map[string]any{
		"target_user_id": targetUserID,
		"org_id":         orgA,
		"reason":         "rd-944 target-user cross-org probe",
	})

	require.Equalf(t, http.StatusForbidden, w.Code,
		"admin of orgA cannot disclose a user who lives in orgB. body=%s", w.Body.String())
}
