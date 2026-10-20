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

// Tests for POST /api/v1/admin/orgs/:org_id/memberships/by-did (RD-945).
// The endpoint lets a tier-2 admin pull a known DID into their own org
// without a super-admin handoff. EnsureUserExists provisions the user row
// on first onboarding so a previously-unseen DID works too.

// onboardBody is the request body shape for the by-did endpoint.
type onboardBody struct {
	DID     string `json:"did"`
	GroupID string `json:"group_id"`
}

func postOnboardByDID(t *testing.T, router http.Handler, orgID, token string, body onboardBody) *httptest.ResponseRecorder {
	t.Helper()
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func TestOnboardByDID_HappyPath_KnownDID(t *testing.T) {
	// Alice is tier-2 admin of orgA. Bob already exists somewhere in the
	// system (a DID who self-authenticated previously and landed in default).
	// Alice pulls Bob into orgA's normal group — expect 201 + a new
	// membership row.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-rd945", Name: "Team", Path: "team-rd945"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	bobDID := "did:test:bob-known-" + uuid.New().String()[:8]
	bob := &rbac.User{ID: uuid.New().String(), ExternalID: bobDID, KYC: true}
	require.NoError(t, srv.db.CreateUser(ctx, bob))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: bobDID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	var resp struct {
		UserID     string                `json:"user_id"`
		Membership *rbac.UserMembership `json:"membership"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, bob.ID, resp.UserID)
	require.NotNil(t, resp.Membership)
	assert.Equal(t, bob.ID, resp.Membership.UserID)
	assert.Equal(t, normalGroup.ID, resp.Membership.GroupID)

	// Verify the row landed in DB.
	memberships, err := srv.db.ListUserMemberships(ctx, bob.ID)
	require.NoError(t, err)
	var found bool
	for _, m := range memberships {
		if m.GroupID == normalGroup.ID {
			found = true
		}
	}
	assert.True(t, found, "membership row must exist for bob in normalGroup")
}

func TestOnboardByDID_NewDID_AutoProvisioned(t *testing.T) {
	// A DID that does not yet exist in the system should still be onboardable.
	// EnsureUserExists creates the row; the user lands in caller's group only
	// (no default-group membership since skipDefaultGroup=true).
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-new-rd945", Name: "Team", Path: "team-new-rd945"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	newDID := "did:test:new-" + uuid.New().String()[:8]

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: newDID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	// The row now exists in users.
	createdUser, err := srv.db.GetUserByExternalID(ctx, newDID)
	require.NoError(t, err)
	require.NotNil(t, createdUser, "EnsureUserExists must have created the row")

	// Exactly one membership — the caller's group. No default-group membership.
	memberships, err := srv.db.ListUserMemberships(ctx, createdUser.ID)
	require.NoError(t, err)
	require.Len(t, memberships, 1, "skipDefaultGroup=true: user should land in caller's group only")
	assert.Equal(t, normalGroup.ID, memberships[0].GroupID)
}

func TestOnboardByDID_GroupInForeignOrg_403(t *testing.T) {
	// Tier-2 admin of orgA tries to use orgA's path param but points to a
	// group_id that lives in orgB. Must be rejected with the opaque
	// errMembershipForeignOrg string — never reveal that the group exists.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgAID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))

	w := postOnboardByDID(t, router, orgAID, aliceToken, onboardBody{
		DID:     "did:test:carol-" + uuid.New().String()[:8],
		GroupID: orgBGroup.ID,
	})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), errMembershipForeignOrg)
}

func TestOnboardByDID_ForeignOrgPath_403(t *testing.T) {
	// Tier-2 admin of orgA hits the endpoint under orgB's :org_id. The
	// orgScopingMiddleware should reject before the handler ever runs.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, _, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	orgB := &rbac.Organization{ID: uuid.New().String(), Slug: "org-b-" + uuid.New().String()[:8], Name: "Org B"}
	require.NoError(t, srv.db.CreateOrganization(ctx, orgB))
	orgBGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgB.ID, Slug: "b-grp", Name: "B Grp", Path: "b-grp"}
	require.NoError(t, srv.db.CreateGroup(ctx, orgBGroup))

	w := postOnboardByDID(t, router, orgB.ID, aliceToken, onboardBody{
		DID:     "did:test:dave-" + uuid.New().String()[:8],
		GroupID: orgBGroup.ID,
	})
	assert.Equal(t, http.StatusForbidden, w.Code, "orgScopingMiddleware should reject foreign-org path")
}

func TestOnboardByDID_Repeat_409(t *testing.T) {
	// Idempotent repeat — the same DID + group combination returns 409 the
	// second time with the same opaque message used by createUserMembership.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-rep", Name: "Team", Path: "team-rep"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	eveDID := "did:test:eve-rep-" + uuid.New().String()[:8]
	body := onboardBody{DID: eveDID, GroupID: normalGroup.ID}

	w1 := postOnboardByDID(t, router, orgID, aliceToken, body)
	require.Equal(t, http.StatusCreated, w1.Code, "first call must succeed; body: %s", w1.Body.String())

	w2 := postOnboardByDID(t, router, orgID, aliceToken, body)
	assert.Equal(t, http.StatusConflict, w2.Code)
	assert.Contains(t, w2.Body.String(), "already a member")
}

func TestOnboardByDID_BannedUser_NoStatusLeak(t *testing.T) {
	// A banned user must NOT be distinguishable from a non-banned user via
	// this endpoint — ban is global state an org admin shouldn't enumerate
	// by probing. We accept the membership row; the auth-time ban gate
	// (auth.go's Banned check) keeps the banned user from actually using
	// it. Response shape and body must match an unbanned 201 byte-for-byte
	// except for the unique IDs.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-ban", Name: "Team", Path: "team-ban"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	bannedDID := "did:test:banned-" + uuid.New().String()[:8]
	bannedUser := &rbac.User{ID: uuid.New().String(), ExternalID: bannedDID, KYC: true, Banned: true}
	require.NoError(t, srv.db.CreateUser(ctx, bannedUser))

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: bannedDID, GroupID: normalGroup.ID})

	// 201 — banned status is invisible to the caller. No "banned" string
	// must appear in the body either.
	require.Equal(t, http.StatusCreated, w.Code, "ban status must not produce a distinguishable response; body: %s", w.Body.String())
	assert.NotContains(t, w.Body.String(), "banned")

	// The membership row was created — ban gate fires at auth-time, not
	// here. Verify the row exists.
	memberships, err := srv.db.ListUserMemberships(ctx, bannedUser.ID)
	require.NoError(t, err)
	var found bool
	for _, m := range memberships {
		if m.GroupID == normalGroup.ID {
			found = true
		}
	}
	assert.True(t, found, "membership must be created even for banned user (ban gate is at auth-time)")
}

func TestOnboardByDID_BadBody_400(t *testing.T) {
	// Missing required fields should produce 400, not 500.
	srv, router := setupTieredAdminTestServer(t, "secret")

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	cases := []struct {
		name string
		body string
	}{
		{"empty", `{}`},
		{"missing_did", `{"group_id": "some-group"}`},
		{"missing_group_id", `{"did": "did:test:x"}`},
		{"malformed_json", `{not-json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/orgs/"+orgID+"/memberships/by-did", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Authorization", "Bearer "+aliceToken)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, "body: %s", w.Body.String())
		})
	}
}

func TestOnboardByDID_AuditLogWritten(t *testing.T) {
	// Successful onboarding must produce an rbac_audit_log entry for the
	// AuditActionAssign action on the membership resource (parity with
	// createUserMembership). Compliance / Vanta consume these.
	srv, router := setupTieredAdminTestServer(t, "secret")
	ctx := t.Context()

	aliceDID, orgID, _ := createOrgAndAdminUser(t, srv)
	aliceToken, err := srv.jwtService.IssueAccessToken(aliceDID, true)
	require.NoError(t, err)

	normalGroup := &rbac.Group{ID: uuid.New().String(), OrgID: orgID, Slug: "team-audit", Name: "Team", Path: "team-audit"}
	require.NoError(t, srv.db.CreateGroup(ctx, normalGroup))

	frankDID := "did:test:frank-" + uuid.New().String()[:8]

	w := postOnboardByDID(t, router, orgID, aliceToken, onboardBody{DID: frankDID, GroupID: normalGroup.ID})
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	var resp struct {
		Membership *rbac.UserMembership `json:"membership"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	entries, err := srv.db.ListAuditLogs(ctx, rbac.ResourceTypeMembership, &resp.Membership.ID, 10, 0)
	require.NoError(t, err)
	require.NotEmpty(t, entries, "audit log entry expected for the by-did onboard")
	entry := entries[0]
	assert.Equal(t, rbac.AuditActionAssign, entry.Action)
	assert.Equal(t, aliceDID, entry.ActorExternalID)
	require.NotNil(t, entry.NewValue)
	assert.Equal(t, frankDID, entry.NewValue["did"])
	assert.Equal(t, "by-did", entry.NewValue["onboarded_via"])
}
