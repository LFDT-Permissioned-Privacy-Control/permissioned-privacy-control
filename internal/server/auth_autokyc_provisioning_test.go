package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/db"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file adds the RD-1131 auto-KYC-on-provisioning coverage that the
// v0.12.0 acceptance review found missing for the Azure interactive-SSO and
// Privado identity classes (RD-1159 Phase 2). Before this, only the
// service-principal class had a KYC-on-provisioning assertion
// (auth_azure_service_principal_test.go:166). The three login classes share the
// SAME safe-by-construction contract:
//
//   - a NEW user is created KYC-verified iff its class opted in via the
//     per-class AUTO_KYC_* flag (AutoKYCPrivado / AutoKYCAzureUser /
//     AutoKYCAzureServicePrincipal), and
//   - an EXISTING user's admin-managed KYC is NEVER changed at login —
//     rbac.EnsureUserExists sets kyc only on row creation.
//
// The Azure interactive path is exercised through completeAzureLogin (the exact
// shared helper handleAzureCallback funnels through at auth_azure.go:195,
// passing s.config.AutoKYCAzureUser). The Privado + generic contract is pinned
// directly at the rbac.EnsureUserExists level — the single primitive all three
// Privado call sites (auth.go:551, oauth.go:356, oauth.go:719) depend on for the
// AutoKYCPrivado knob — so the invariant is proven without faking JWZ transport.

// azureIdentityFor builds a synthetic verified Azure identity for a fresh OID in
// the given tenant — the post-code-exchange object completeAzureLogin consumes.
func azureIdentityFor(oid, tenantID string) *auth.AzureIdentity {
	return &auth.AzureIdentity{
		OID:               oid,
		TenantID:          tenantID,
		Email:             oid + "@example.test",
		Name:              "Interactive User " + oid,
		PreferredUsername: oid,
	}
}

// runCompleteAzureLogin drives the shared post-identity provisioning helper the
// way handleAzureCallback does, asserting the response inline (it returns nothing).
// autoKYCNewUser mirrors the s.config.AutoKYCAzureUser argument the real
// interactive callback passes.
func runCompleteAzureLogin(t *testing.T, ts *testServerAzureTenants, identity *auth.AzureIdentity, autoKYCNewUser bool) {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// completeAzureLogin only reads c.Request.Context(); a bare POST is enough.
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/azure/callback", strings.NewReader("{}"))
	ts.completeAzureLogin(c, identity, "azure_ad", autoKYCNewUser)
	require.Equalf(t, http.StatusOK, w.Code, "completeAzureLogin did not succeed: %s", w.Body.String())
}

// TestAutoKYC_AzureInteractiveUser_Provisioning (RD-1131) mirrors the SP class's
// KYC-on-provisioning assertion for the Azure interactive-SSO class. It drives
// completeAzureLogin — the real shared provisioning path (tenant allowlist →
// EnsureUserExists → KYC read-back → token issue) — with the same
// autoKYCNewUser argument handleAzureCallback passes (s.config.AutoKYCAzureUser).
func TestAutoKYC_AzureInteractiveUser_Provisioning(t *testing.T) {
	ts := setupTestServerForAzureTenants(t)
	ctx := context.Background()

	// One auto-provisioning tenant shared by the subtests; distinct OIDs keep
	// each provision brand-new.
	const tenantID = "abcd1234-5678-90ab-cdef-1234567890ab"
	_, err := ts.db.CreateAllowedAzureTenant(ctx, &db.AllowedAzureTenant{
		ID:            uuid.New().String(),
		TenantID:      tenantID,
		Label:         "Interactive Auto-KYC Tenant",
		AutoProvision: true,
	})
	require.NoError(t, err)

	t.Run("auto-KYC OFF (default): new interactive user is NOT KYC-verified", func(t *testing.T) {
		require.False(t, ts.config.AutoKYCAzureUser, "default must be off")
		oid := "azure-user-default-" + uuid.NewString()

		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), ts.config.AutoKYCAzureUser)

		user, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, user, "interactive user should be auto-provisioned")
		assert.False(t, user.KYC, "new interactive user must NOT be KYC'd when AUTO_KYC_AZURE_USER is off")
	})

	t.Run("auto-KYC ON: new interactive user IS KYC-verified (RD-1131)", func(t *testing.T) {
		ts.config.AutoKYCAzureUser = true
		defer func() { ts.config.AutoKYCAzureUser = false }()

		oid := "azure-user-autokyc-" + uuid.NewString()
		// Pass the flag exactly as handleAzureCallback does.
		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), ts.config.AutoKYCAzureUser)

		user, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.KYC, "new interactive user should be auto-KYC'd when AUTO_KYC_AZURE_USER is enabled")
	})

	t.Run("auto-KYC ON does NOT re-flip an existing user's admin-set KYC", func(t *testing.T) {
		// Pre-existing user provisioned with KYC OFF (as an admin left it).
		oid := "azure-user-existing-" + uuid.NewString()
		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), false /* auto-KYC off at first login */)
		existing, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, existing)
		require.False(t, existing.KYC, "precondition: existing user starts un-KYC'd")

		// Operator later enables auto-KYC. The SAME user logs in again.
		ts.config.AutoKYCAzureUser = true
		defer func() { ts.config.AutoKYCAzureUser = false }()
		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), ts.config.AutoKYCAzureUser)

		after, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.False(t, after.KYC,
			"existing user's admin-managed KYC must NOT be changed by a later auto-KYC login (safe-by-construction)")
		assert.Equal(t, existing.ID, after.ID, "must be the same user row, not a new one")
	})

	t.Run("existing KYC'd user is NOT downgraded when auto-KYC is off", func(t *testing.T) {
		// The symmetric direction: admin set KYC=true; a later login with
		// auto-KYC OFF must keep it true (EnsureUserExists never touches
		// existing rows in EITHER direction).
		oid := "azure-user-kycd-" + uuid.NewString()
		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), false)
		u, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, u)
		u.KYC = true // admin promotes them
		require.NoError(t, ts.db.UpdateUser(ctx, u))

		require.False(t, ts.config.AutoKYCAzureUser)
		runCompleteAzureLogin(t, ts, azureIdentityFor(oid, tenantID), ts.config.AutoKYCAzureUser)

		after, err := ts.db.GetUserByExternalID(ctx, auth.AzureSubject(oid))
		require.NoError(t, err)
		require.NotNil(t, after)
		assert.True(t, after.KYC, "admin-set KYC=true must survive a later auto-KYC-off login")
	})
}

// TestAutoKYC_EnsureUserExists_Contract (RD-1131) pins the safe-by-construction
// KYC behavior of rbac.EnsureUserExists directly. This is the ONE primitive that
// carries the AutoKYCPrivado knob at all three Privado login sites (auth.go:551,
// oauth.go:356, oauth.go:719) — each does `kyc := s.config.AutoKYCPrivado;
// EnsureUserExists(ctx, did, kyc, false)`. Because faking JWZ verification for
// each Privado surface would test the transport, not the KYC decision, we assert
// the decision at its source: the `kyc` argument sets KYC on a NEW row and is
// ignored for an EXISTING row. That is exactly the property the Privado (and
// Azure-user, and SP) provisioning relies on.
func TestAutoKYC_EnsureUserExists_Contract(t *testing.T) {
	ts := setupTestServerForAzureTenants(t)
	ctx := context.Background()

	t.Run("Privado-style: new user with autoKYC=true is created KYC-verified", func(t *testing.T) {
		// Simulates the Privado call site with AUTO_KYC_PRIVADO=true.
		did := "did:privado:autokyc-new-" + uuid.NewString()
		u, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, true /* AutoKYCPrivado */, false)
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.True(t, u.KYC, "new Privado user must be KYC'd when AUTO_KYC_PRIVADO is enabled")
	})

	t.Run("new user with autoKYC=false is created un-verified (default)", func(t *testing.T) {
		did := "did:privado:autokyc-off-" + uuid.NewString()
		u, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, false, false)
		require.NoError(t, err)
		require.NotNil(t, u)
		assert.False(t, u.KYC, "new user must be un-KYC'd when the class auto-KYC flag is off")
	})

	t.Run("existing user's admin-set KYC is never changed by a later autoKYC=true login", func(t *testing.T) {
		did := "did:privado:existing-" + uuid.NewString()
		// First login, auto-KYC off → created un-verified.
		first, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, false, false)
		require.NoError(t, err)
		require.NotNil(t, first)
		require.False(t, first.KYC)

		// Later login with AUTO_KYC_PRIVADO=true must return the existing row
		// unchanged — KYC is admin-managed once the user exists.
		second, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, true, false)
		require.NoError(t, err)
		require.NotNil(t, second)
		assert.False(t, second.KYC,
			"existing user's KYC must NOT flip to true on a later auto-KYC login (safe-by-construction)")
		assert.Equal(t, first.ID, second.ID, "must be the same user row")

		// And the persisted row agrees (not just the returned struct).
		persisted, err := ts.db.GetUserByExternalID(ctx, did)
		require.NoError(t, err)
		require.NotNil(t, persisted)
		assert.False(t, persisted.KYC, "persisted KYC must remain false")
	})

	t.Run("existing KYC'd user is not downgraded by a later autoKYC=false login", func(t *testing.T) {
		did := "did:privado:kycd-" + uuid.NewString()
		u, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, true, false)
		require.NoError(t, err)
		require.NotNil(t, u)
		require.True(t, u.KYC)

		again, err := ts.rbacAccessCtrl.EnsureUserExists(ctx, did, false, false)
		require.NoError(t, err)
		require.NotNil(t, again)
		assert.True(t, again.KYC, "existing KYC=true must survive a later auto-KYC-off login")
	})
}
