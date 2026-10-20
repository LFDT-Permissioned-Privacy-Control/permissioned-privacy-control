package db

import (
	"context"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// TestSessionTimezoneIsUTC verifies the connection pins the Postgres session
// timezone to UTC (RD-1005). Plain TIMESTAMP comparisons rely on it.
func TestSessionTimezoneIsUTC(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	var tz string
	if err := database.Conn().QueryRowContext(context.Background(), "SHOW timezone").Scan(&tz); err != nil {
		t.Fatalf("SHOW timezone: %v", err)
	}
	if tz != "UTC" {
		t.Fatalf("session timezone = %q, want UTC", tz)
	}
}

// TestMembershipExpiry_NonUTCProcessTimezone guards the fail-open RBAC bug from
// RD-1005: a membership whose ExpiresAt is a non-UTC time.Time (as time.Now()
// produces on a host with a local TZ) must still be evaluated by its true
// instant. Before the fix, pgx stored the wall-clock components of the non-UTC
// value into the plain TIMESTAMP column, so an expired membership could read as
// active under the `expires_at > NOW()` admin check.
func TestMembershipExpiry_NonUTCProcessTimezone(t *testing.T) {
	database := setupRBACTestDB(t)
	defer cleanupTestDB(t, database)
	ctx := context.Background()

	org := &rbac.Organization{ID: uuid.New().String(), Slug: "tz-org", Name: "TZ Org", Settings: map[string]interface{}{}}
	if err := database.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	group := &rbac.Group{ID: uuid.New().String(), OrgID: org.ID, Slug: "tz-group", Name: "TZ Group", Depth: 0, Path: "tz-group"}
	if err := database.CreateGroup(ctx, group); err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	// The group grants the admin claim, so HasAdminClaim depends purely on
	// whether the membership is still active.
	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{},
		Claims:         []rbac.Claim{rbac.Claim("admin")},
	}
	if err := database.SetGroupAccess(ctx, access); err != nil {
		t.Fatalf("SetGroupAccess: %v", err)
	}

	// A deliberately non-UTC location, simulating time.Now() on a host whose
	// process TZ is not UTC.
	tokyo := time.FixedZone("UTC+9", 9*3600)

	newUser := func(did string) *rbac.User {
		u := &rbac.User{ID: uuid.New().String(), ExternalID: did, KYC: true, Metadata: map[string]interface{}{}}
		if err := database.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		return u
	}
	addMembership := func(userID string, expires time.Time) {
		e := expires
		m := &rbac.UserMembership{
			ID:        uuid.New().String(),
			UserID:    userID,
			GroupID:   group.ID,
			Source:    rbac.MembershipSourceAdmin,
			ExpiresAt: &e,
		}
		if err := database.CreateMembership(ctx, m); err != nil {
			t.Fatalf("CreateMembership: %v", err)
		}
	}

	// Expired one hour ago, expressed in a non-UTC zone.
	expiredUser := newUser("did:tz:expired")
	addMembership(expiredUser.ID, time.Now().Add(-1*time.Hour).In(tokyo))

	// Valid for another hour, also non-UTC — positive control.
	activeUser := newUser("did:tz:active")
	addMembership(activeUser.ID, time.Now().Add(1*time.Hour).In(tokyo))

	expiredAdmin, err := database.HasAdminClaim(ctx, expiredUser.ID)
	if err != nil {
		t.Fatalf("HasAdminClaim(expired): %v", err)
	}
	if expiredAdmin {
		t.Fatal("fail-open: expired membership granted admin (timezone skew not fixed)")
	}

	activeAdmin, err := database.HasAdminClaim(ctx, activeUser.ID)
	if err != nil {
		t.Fatalf("HasAdminClaim(active): %v", err)
	}
	if !activeAdmin {
		t.Fatal("active membership should grant admin")
	}
}
