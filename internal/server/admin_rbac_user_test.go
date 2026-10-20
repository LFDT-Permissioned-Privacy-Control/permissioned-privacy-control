package server

import (
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
)

// Tests for resolveListUsersScope (RD-973).
//
// Pre-fix the helper:
//   - dropped read-only-admin orgs (RO admin who was added to a tier-2 group
//     in addition to their RO role would see only their FULL-admin orgs in
//     the user list), and
//   - fell through to "no scope" (== super-admin) when admin_org_ids was
//     missing from the gin context, leaking every user in the cluster.
//
// Post-fix the helper:
//   - merges admin_org_ids + admin_readonly_org_ids (deduped) for jwt_admin,
//   - returns an error when neither key is present (fail closed; that's a
//     middleware wiring bug, not a legitimate state),
//   - keeps the (nil, nil) pass-through for super-admin and dev mode.

// newGinCtxForScope builds a minimal gin.Context for exercising scope helpers
// in isolation. The context's keys mirror what adminAuthMiddleware sets at
// runtime; we never hit the middleware here.
func newGinCtxForScope(t *testing.T, authMethod string, setFull, setRO bool, full, ro []string) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	if authMethod != "" {
		c.Set("auth_method", authMethod)
	}
	if setFull {
		c.Set("admin_org_ids", full)
	}
	if setRO {
		c.Set("admin_readonly_org_ids", ro)
	}
	return c
}

// assertScopeIDSet compares two slices as sets, ignoring order.
func assertScopeIDSet(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("scope length mismatch: got %v, want %v", got, want)
	}
	gotSorted := append([]string(nil), got...)
	wantSorted := append([]string(nil), want...)
	sort.Strings(gotSorted)
	sort.Strings(wantSorted)
	for i := range gotSorted {
		if gotSorted[i] != wantSorted[i] {
			t.Fatalf("scope element mismatch at %d: got %v, want %v", i, gotSorted, wantSorted)
		}
	}
}

func TestResolveListUsersScope_FailClosedWhenJWTAdminMissingKeys(t *testing.T) {
	// jwt_admin caller but neither admin_org_ids nor admin_readonly_org_ids
	// is present. Middleware always sets both; this is a wiring bug and
	// must NOT degrade to "no scope" (== super-admin) — that would leak
	// every user in the cluster to a tier-2 admin.
	c := newGinCtxForScope(t, "jwt_admin", false, false, nil, nil)
	got, err := resolveListUsersScope(c)
	if err == nil {
		t.Fatalf("want error for jwt_admin with no admin org IDs, got nil (scope=%v)", got)
	}
	if got != nil {
		t.Fatalf("want nil scope on error, got %v", got)
	}
}

func TestResolveListUsersScope_ReadOnlyOnly(t *testing.T) {
	// jwt_admin with admin_org_ids=[] and admin_readonly_org_ids=[orgX].
	// Pre-fix this returned [] — the RO admin couldn't see any users at
	// all in their RO org. Now it returns [orgX] so list-users includes
	// the RO-scoped org.
	orgX := "11111111-1111-1111-1111-111111111111"
	c := newGinCtxForScope(t, "jwt_admin", true, true, []string{}, []string{orgX})
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertScopeIDSet(t, got, []string{orgX})
}

func TestResolveListUsersScope_MergeAndDedup(t *testing.T) {
	// jwt_admin with overlap between full and RO admin slices. Expect
	// the union, deduped: orgB appears in both inputs but only once
	// in the output.
	orgA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	orgB := "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	orgC := "cccccccc-cccc-cccc-cccc-cccccccccccc"
	c := newGinCtxForScope(t, "jwt_admin", true, true,
		[]string{orgA, orgB},
		[]string{orgB, orgC},
	)
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertScopeIDSet(t, got, []string{orgA, orgB, orgC})
}

func TestResolveListUsersScope_SuperAdminPassThrough(t *testing.T) {
	// X-Admin-Token: no scope, no error. nil signals "unrestricted" to
	// the DB filter.
	c := newGinCtxForScope(t, "admin_token", false, false, nil, nil)
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil scope for super-admin, got %v", got)
	}
}

func TestResolveListUsersScope_SuperAdminIgnoresOrgIDs(t *testing.T) {
	// Even if admin_org_ids happens to be set (it shouldn't be for
	// admin_token, but defence-in-depth), super-admin still bypasses
	// scoping. The DB filter receives nil and returns the full set.
	c := newGinCtxForScope(t, "admin_token", true, false,
		[]string{"should-be-ignored"}, nil)
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil scope for super-admin, got %v", got)
	}
}

func TestResolveListUsersScope_DevModePassThrough(t *testing.T) {
	// Dev mode: no admin auth configured, no auth_method set, no scope
	// context. Same pass-through as super-admin — matches the rest of
	// the codebase's dev-bypass (jwtAdminFullAdminOrgIDs, inScope).
	c := newGinCtxForScope(t, "", false, false, nil, nil)
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil scope for dev mode, got %v", got)
	}
}

func TestResolveListUsersScope_UnknownAuthMethodFailsClosed(t *testing.T) {
	// Anything other than admin_token / jwt_admin / "" is a contract
	// violation. Deny rather than guess.
	c := newGinCtxForScope(t, "some_other_auth", false, false, nil, nil)
	got, err := resolveListUsersScope(c)
	if err == nil {
		t.Fatalf("want error for unknown auth_method, got nil (scope=%v)", got)
	}
	if got != nil {
		t.Fatalf("want nil scope on error, got %v", got)
	}
}

func TestResolveListUsersScope_JWTAdminEmptyMergedSlice(t *testing.T) {
	// jwt_admin with both keys set to []. Legitimate state (admin has
	// no orgs assigned yet); helper returns ([], nil) and the SQL
	// filter produces zero rows — correct behaviour.
	c := newGinCtxForScope(t, "jwt_admin", true, true, []string{}, []string{})
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("want non-nil empty slice for jwt_admin with empty orgs, got nil")
	}
	if len(got) != 0 {
		t.Fatalf("want empty scope, got %v", got)
	}
}

func TestResolveListUsersScope_JWTAdminOnlyFullKey(t *testing.T) {
	// jwt_admin with only admin_org_ids set (no RO key). Per the
	// contract, the middleware always sets both — but if a legitimate
	// future path sets only the full key, the helper should still
	// succeed and return what it found. Tested defensively: as long as
	// at least one of the two keys is present, do not fail closed.
	orgA := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	c := newGinCtxForScope(t, "jwt_admin", true, false, []string{orgA}, nil)
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertScopeIDSet(t, got, []string{orgA})
}

func TestResolveListUsersScope_JWTAdminOnlyReadOnlyKey(t *testing.T) {
	// Symmetric to the above: only admin_readonly_org_ids set.
	orgX := "11111111-1111-1111-1111-111111111111"
	c := newGinCtxForScope(t, "jwt_admin", false, true, nil, []string{orgX})
	got, err := resolveListUsersScope(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertScopeIDSet(t, got, []string{orgX})
}
