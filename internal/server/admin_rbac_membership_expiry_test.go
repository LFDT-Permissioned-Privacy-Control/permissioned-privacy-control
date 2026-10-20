package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/rbac"
)

// TestWithExpiryStatus covers the server-authoritative `expired` flag the
// memberships list returns so the admin UI can distinguish a live time-boxed
// grant from a lapsed one (RD-1157). Expiry is judged against the same clock
// the resolver's `expires_at > NOW()` access filter uses, so the badge matches
// enforcement.
func TestWithExpiryStatus(t *testing.T) {
	now := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	mk := func(id string, exp *time.Time) *rbac.MembershipWithDetails {
		return &rbac.MembershipWithDetails{
			Membership: &rbac.UserMembership{ID: id, ExpiresAt: exp},
			Group:      &rbac.Group{ID: "g-" + id},
		}
	}

	items := withExpiryStatus([]*rbac.MembershipWithDetails{
		mk("past", &past),
		mk("boundary", &now), // expires_at == now: resolver admits only expires_at > NOW(), so this is already expired
		mk("future", &future),
		mk("permanent", nil),
		nil, // defensive: nil entries are skipped
	}, now)

	if len(items) != 4 {
		t.Fatalf("want 4 items (nil skipped), got %d", len(items))
	}
	if !items[0].Expired {
		t.Error("membership with a past expires_at must be flagged expired")
	}
	if !items[1].Expired {
		t.Error("membership with expires_at == now must be flagged expired (resolver uses expires_at > NOW())")
	}
	if items[2].Expired {
		t.Error("membership with a future expires_at must NOT be flagged expired")
	}
	if items[3].Expired {
		t.Error("permanent membership (nil expires_at) must NOT be flagged expired")
	}

	// The wire shape the endpoint returns must carry `expired` alongside the
	// embedded membership/group.
	b, err := json.Marshal(items[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"expired":true`, `"membership"`, `"group"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("membership list item JSON missing %s; got: %s", want, b)
		}
	}
}
