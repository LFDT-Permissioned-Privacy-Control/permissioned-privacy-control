package server

import (
	"slices"
	"testing"
)

// TestNarrowMembershipScope pins the group-summary scoping for the users list:
// always bounded by the caller's administered orgs, and — when the list is
// filtered to one org — narrowed to that org so the Groups column never shows a
// user's memberships in orgs other than the one in view.
func TestNarrowMembershipScope(t *testing.T) {
	tests := []struct {
		name    string
		scoped  []string // caller's administered orgs (nil = super-admin, unrestricted)
		orgID   string   // org_id query param ("" = not filtered)
		want    []string
		wantNil bool // want a nil result (DB layer treats nil as "no org filter")
	}{
		{
			name:    "super-admin, no org filter → unrestricted",
			scoped:  nil,
			orgID:   "",
			wantNil: true,
		},
		{
			name:   "super-admin, org filter → just that org",
			scoped: nil,
			orgID:  "orgA",
			want:   []string{"orgA"},
		},
		{
			name:   "multi-org admin, no filter → all administered orgs (unchanged)",
			scoped: []string{"orgA", "orgB"},
			orgID:  "",
			want:   []string{"orgA", "orgB"},
		},
		{
			name:   "multi-org admin, filter to one administered org → just that org",
			scoped: []string{"orgA", "orgB"},
			orgID:  "orgA",
			want:   []string{"orgA"},
		},
		{
			name:   "single-org admin, filter to own org → that org",
			scoped: []string{"orgA"},
			orgID:  "orgA",
			want:   []string{"orgA"},
		},
		{
			name:   "scoped admin, filter to an org outside scope → empty (no groups), never widened",
			scoped: []string{"orgA"},
			orgID:  "orgB",
			want:   []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := narrowMembershipScope(tc.scoped, tc.orgID)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("want nil (unrestricted), got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want %v, got nil (would drop the org filter at the DB layer)", tc.want)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, got)
			}
		})
	}
}
