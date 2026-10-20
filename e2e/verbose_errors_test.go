//go:build mockauth

package e2e

import (
	"encoding/json"
	"testing"

	"privacy-proxy/e2e/testfixtures"
)

// RD-1137 Part A: verbose errors are opt-in per group. By default the denial
// wire body stays opaque (just {"error": ...}); a group flagged
// verbose_errors additionally gets a curated, machine-readable `reason` code.
//
// The wireReason oracle-collapse mapping itself (cross_org etc. -> access_denied,
// unknown -> access_denied) is exhaustively unit-tested in
// TestWireReason_ClosedAllowlist. This test asserts the END-TO-END wiring the
// unit test can't reach: group flag -> GroupVerboseErrorsForUserOrg lookup ->
// the `reason` sibling key actually appears (or not) on the HTTP response. It
// also pins that the flag is per-group (same org, same denial, two outcomes).
func TestVerboseErrors_OptInWireReason(t *testing.T) {
	srv, serverURL, cleanup := setupE2E(t)
	defer cleanup()
	testfixtures.SeedRBACDefaults(t, srv.DB())

	f := testfixtures.New(t, serverURL)
	org := f.CreateOrg("verbose-org")

	// Two groups in the same org. Both allow ONLY eth_blockNumber, so any
	// other method is denied with method_not_allowed — a pass-through reason.
	// They differ only in the verbose_errors flag.
	quietGroup := f.CreateGroup(org.ID, "quiet", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, quietGroup.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_blockNumber"},
		VerboseErrors:  false,
	})
	verboseGroup := f.CreateGroup(org.ID, "verbose", testfixtures.CreateGroupOptions{})
	f.SetGroupAccess(org.ID, verboseGroup.ID, testfixtures.GroupAccessInput{
		AllowedMethods: []string{"eth_blockNumber"},
		VerboseErrors:  true,
	})

	quietUser, quietTok := f.CreateUserWithMembership(quietGroup.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(quietUser.ID) // ensure the group above is the only access
	verboseUser, verboseTok := f.CreateUserWithMembership(verboseGroup.ID, testfixtures.CreateUserOptions{})
	f.DeleteDefaultMembership(verboseUser.ID)

	// eth_getBalance is in neither group's allowlist -> method_not_allowed.
	deniedCall := func(tok string) testfixtures.JSONRPCResult {
		return testfixtures.JSONRPCPostAt(t, serverURL, "/rpc/"+org.ID, "eth_getBalance",
			[]any{f.Address(), "latest"}, map[string]string{"Authorization": "Bearer " + tok})
	}

	// reasonOf returns the `reason` field and whether it was present.
	reasonOf := func(body []byte) (string, bool) {
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("non-JSON denial body: %s", body)
		}
		r, ok := parsed["reason"]
		if !ok {
			return "", false
		}
		s, _ := r.(string)
		return s, true
	}

	t.Run("verbose off -> opaque, no reason key", func(t *testing.T) {
		res := deniedCall(quietTok)
		if reason, has := reasonOf(res.Body); has {
			t.Errorf("opaque-by-default broken: denial leaked reason=%q, body=%s", reason, res.Body)
		}
		// Internal-leakage deny-list still applies.
		testfixtures.AssertNoInternalLeakage(t, res.Body)
	})

	t.Run("verbose on -> curated reason on the wire", func(t *testing.T) {
		res := deniedCall(verboseTok)
		reason, has := reasonOf(res.Body)
		if !has {
			t.Fatalf("verbose group got no reason on the wire: %s", res.Body)
		}
		if reason != "method_not_allowed" {
			t.Errorf("expected reason=method_not_allowed, got %q (body: %s)", reason, res.Body)
		}
		// The opaque message must be unchanged — verbose only ADDS the code.
		testfixtures.AssertNoInternalLeakage(t, res.Body)
	})
}
