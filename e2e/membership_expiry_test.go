//go:build mockauth

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"privacy-proxy/e2e/testfixtures"
	"privacy-proxy/internal/rbac"
)

// RD-1145: a time-boxed membership window must actually revoke access.
//
// `user_memberships.expires_at` has existed since migration 001 and is persisted
// on create, but until RD-1145 the resolver's ListUserMembershipsInOrg did not
// filter expired rows — so an expired membership kept granting RPC access
// forever (fail-open). These tests drive the REAL wired path (/rpc/{org} plus
// the admin access/check endpoint), not a unit test of the query, and prove:
//
//   - a future window allows access, no window = permanent (regression guards);
//   - an expired window is DENIED on both the RPC path and the access check;
//   - the create API rejects a non-future / malformed window;
//   - a window that lapses mid-session auto-revokes WITHIN the window — the
//     resolver caps the permission cache by the soonest expiry, so revocation
//     is not delayed by the (5-minute) cache TTL.
//
// A denied RPC returns an opaque 404 (jsonrpc_processor.go); an allowed call
// reaches the upstream node (200) or 502 if the node is unreachable in CI —
// either way the proxy *permitted* it. eth_getBalance is used because it is not
// in the anonymous allowlist (migration 044), so denial is observable.
func TestMembershipExpiry(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("expiry")
	// A read-only observer group: it can read balances but holds no admin/
	// upgrade rights. Mirrors the regulator profile shape.
	group := f.CreateGroup(org.ID, "observer", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, group.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_getBalance"},
		Claims:         []testfixtures.Claim{testfixtures.ClaimDeploy},
	})

	getBalance := func(tok string) testfixtures.JSONRPCResult {
		return testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_getBalance",
			[]any{"0x0000000000000000000000000000000000000000", "latest"},
			map[string]string{"Authorization": "Bearer " + tok})
	}
	// reachedUpstream reports whether the proxy permitted the call (200 node
	// answer, or 502 node-unreachable). A pre-upstream access denial is 404.
	reachedUpstream := func(res testfixtures.JSONRPCResult) bool {
		return res.Status == http.StatusOK || res.Status == http.StatusBadGateway
	}

	t.Run("future window allows access", func(t *testing.T) {
		user, tok := f.CreateUser(testfixtures.CreateUserOptions{})
		f.DeleteDefaultMembership(user.ID) // isolate: the observer group is the only access
		exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{
			GroupID:   group.ID,
			ExpiresAt: &exp,
		})
		if res := getBalance(tok); !reachedUpstream(res) {
			t.Errorf("future-window membership should permit eth_getBalance; got %d: %s", res.Status, res.Body)
		}
	})

	t.Run("no window is permanent", func(t *testing.T) {
		user, tok := f.CreateUser(testfixtures.CreateUserOptions{})
		f.DeleteDefaultMembership(user.ID)
		f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{GroupID: group.ID})
		if res := getBalance(tok); !reachedUpstream(res) {
			t.Errorf("permanent (no-expiry) membership should permit eth_getBalance; got %d: %s", res.Status, res.Body)
		}
	})

	t.Run("expired window denies on RPC and access-check", func(t *testing.T) {
		user, tok := f.CreateUser(testfixtures.CreateUserOptions{})
		f.DeleteDefaultMembership(user.ID)
		// The create API rejects a past window (asserted below), so seed the
		// already-expired row straight through the DB layer — exactly the
		// state the enforcement filter must catch.
		past := time.Now().Add(-time.Hour).UTC()
		if err := srv.DB().CreateMembership(context.Background(), &rbac.UserMembership{
			ID:        uuid.NewString(),
			UserID:    user.ID,
			GroupID:   group.ID,
			Source:    rbac.MembershipSourceAdmin,
			ExpiresAt: &past,
		}); err != nil {
			t.Fatalf("seed expired membership: %v", err)
		}

		if res := getBalance(tok); reachedUpstream(res) {
			t.Errorf("expired membership must NOT reach upstream; got %d (permitted): %s", res.Status, res.Body)
		}
		// The admin access-check resolves through the same path and must agree.
		chk := f.Client.CheckAccess(t, testfixtures.CheckAccessInput{
			UserExternalID: user.ExternalID,
			OrgSlug:        org.Slug,
			Method:         "eth_getBalance",
		})
		if chk.Allowed {
			t.Errorf("access-check should deny an expired membership; got Allowed=true")
		}
	})

	t.Run("create API rejects non-future window", func(t *testing.T) {
		user, _ := f.CreateUser(testfixtures.CreateUserOptions{})
		path := "/api/v1/admin/users/" + user.ID + "/memberships"

		past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
		if status, body := f.Client.DoRaw(t, http.MethodPost, path,
			testfixtures.CreateMembershipInput{GroupID: group.ID, ExpiresAt: &past}); status != http.StatusBadRequest {
			t.Errorf("past expires_at should be rejected with 400; got %d: %s", status, body)
		}

		bad := "not-a-timestamp"
		if status, body := f.Client.DoRaw(t, http.MethodPost, path,
			testfixtures.CreateMembershipInput{GroupID: group.ID, ExpiresAt: &bad}); status != http.StatusBadRequest {
			t.Errorf("malformed expires_at should be rejected with 400; got %d: %s", status, body)
		}
	})

	t.Run("window lapsing mid-session auto-revokes within the window", func(t *testing.T) {
		user, tok := f.CreateUser(testfixtures.CreateUserOptions{})
		f.DeleteDefaultMembership(user.ID)
		// Short window. The first call resolves + caches while still valid;
		// the cache lifetime is capped at this expiry, so after it lapses the
		// next call re-resolves and the expired row is filtered out — proving
		// revocation is bounded by the window, not the 5-minute cache TTL.
		win := time.Now().Add(3 * time.Second).UTC().Format(time.RFC3339)
		f.Client.CreateMembership(t, user.ID, testfixtures.CreateMembershipInput{
			GroupID:   group.ID,
			ExpiresAt: &win,
		})

		if res := getBalance(tok); !reachedUpstream(res) {
			t.Fatalf("should be permitted during the window; got %d: %s", res.Status, res.Body)
		}
		time.Sleep(5 * time.Second) // let the window lapse (and the capped cache expire)
		if res := getBalance(tok); reachedUpstream(res) {
			t.Errorf("access should be auto-revoked after the window, but the call reached upstream: %d", res.Status)
		}
	})
}
