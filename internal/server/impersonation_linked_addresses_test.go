package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-928 — under impersonation, linked-address resolution must use the
// TARGET'S DID, never the admin's.
//
// The impersonation override flows through s.getViewerDIDFromRequest, which
// every viewer-aware handler funnels through. Downstream, anything that
// reads "the viewer's linked addresses" — `viewable-addresses`'s own_addresses
// list, the explorer redactor's participant-override check
// (RedactionEngine.RedactLogs → r.db.GetLinkedAddresses(ctx, viewerDID)),
// the `must_be=self` event-rule constraint — must see the TARGET's set,
// not the admin's.
//
// We pin this with the cleanest available probe: link DIFFERENT eth
// addresses to BOTH the admin and the target, then assert the impersonation
// path returns ONLY the target's. If the override leaks (or is replaced
// somewhere by the admin's subject) the admin's address shows up in the
// response and the test catches it.
//
// /viewable-addresses is the chosen surface because:
//
//   - It reads the viewer's linked addresses directly via
//     s.db.GetEthAddressesByDID(ctx, viewerDID), which is the same DB call
//     pattern the redactor uses. The chain target → linked-addresses → DB
//     is the codepath this test is locking in.
//   - It needs no explorerStore / no anvil — the test fixture is the same
//     setupImpersonationFixture() the rest of the impersonation suite uses.
//
// This is the "smaller test" variant called out in the RD-928 task: rather
// than spinning a full eth_getLogs fixture, we assert the override-aware
// codepath is exercised — that the address set used downstream is the
// target's, not the admin's.

// TestImpersonation_LinkedAddressesUseTargetDID asserts the override-aware
// codepath: admin and target both have linked addresses; under impersonation
// the response must contain ONLY the target's linked address, never the
// admin's.
//
// Failure modes this catches:
//
//   - If getViewerDIDFromRequest is changed to read `subject` before the
//     override, the response contains the admin's address.
//   - If viewable-addresses (or any downstream handler) is changed to read
//     GetEthAddressesByDID(ctx, adminSubject) instead of the viewer DID,
//     the response contains the admin's address.
//   - If the override is silently dropped between middleware and handler,
//     viewerDID falls back to admin's `subject` and the response contains
//     the admin's address.
//
// All three regressions surface as "admin address appears in the response
// body", which the assert.NotContains below catches.
func TestImpersonation_LinkedAddressesUseTargetDID(t *testing.T) {
	srv, f := setupImpersonationParity(t)
	ctx := context.Background()

	const targetAddr = "0xaaaa000000000000000000000000000000000001"
	const adminAddr = "0xbbbb000000000000000000000000000000000002"

	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.userDID, targetAddr))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.adminDID, adminAddr))

	// Sanity check the fixture: each DID has its own address.
	targetLinks, err := srv.db.GetEthAddressesByDID(ctx, f.userDID)
	require.NoError(t, err)
	require.Len(t, targetLinks, 1)
	require.Equal(t, targetAddr, targetLinks[0].EthAddress)

	adminLinks, err := srv.db.GetEthAddressesByDID(ctx, f.adminDID)
	require.NoError(t, err)
	require.Len(t, adminLinks, 1)
	require.Equal(t, adminAddr, adminLinks[0].EthAddress)

	// Impersonation call: admin browses as target. Response must reflect
	// the TARGET's linked addresses, not the admin's.
	impReq := httptest.NewRequest(http.MethodGet,
		impersonatePath(f.userDID, f.orgID, "/api/v1/explorer/viewable-addresses"), nil)
	impReq.Header.Set("X-Test-Auth-Method", "jwt_admin")
	impReq.Header.Set("X-Test-Admin-Subject", f.adminDID)
	impReq.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
	impW := httptest.NewRecorder()
	srv.router.ServeHTTP(impW, impReq)
	require.Equal(t, http.StatusOK, impW.Code, "impersonation path: %s", impW.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(impW.Body.Bytes(), &body))

	// viewer_did must be the TARGET's.
	assert.Equal(t, f.userDID, body["viewer_did"],
		"viewer_did under impersonation must be the target's DID, not the admin's")

	// own_addresses must contain ONLY the target's linked address.
	ownAddrsRaw, _ := body["own_addresses"].([]any)
	require.Len(t, ownAddrsRaw, 1, "expected exactly one linked address (the target's); got body=%s", impW.Body.String())

	addresses := make([]string, 0, len(ownAddrsRaw))
	for _, item := range ownAddrsRaw {
		m, _ := item.(map[string]any)
		if s, ok := m["address"].(string); ok {
			addresses = append(addresses, s)
		}
	}
	sort.Strings(addresses)
	assert.Contains(t, addresses, targetAddr, "own_addresses must contain the target's linked address")
	assert.NotContains(t, addresses, adminAddr,
		"own_addresses must NOT contain the admin's linked address — "+
			"override leaked or downstream resolved linked addresses against admin subject")
}

// TestImpersonation_LinkedAddresses_GetViewerDIDPrioritizesOverride is the
// unit-level companion: it directly asserts the contract that
// getViewerDIDFromRequest returns the impersonation override even when the
// admin's `subject` is ALSO set in the context. This is the chokepoint
// every viewer-aware handler reads through; if the priority ever flips,
// every linked-address read downstream points at the wrong DID.
func TestImpersonation_LinkedAddresses_GetViewerDIDPrioritizesOverride(t *testing.T) {
	srv, f := setupImpersonationParity(t)

	const targetAddr = "0xaaaa000000000000000000000000000000000001"
	const adminAddr = "0xbbbb000000000000000000000000000000000002"
	ctx := context.Background()
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.userDID, targetAddr))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, f.adminDID, adminAddr))

	// Hit the impersonation surface with BOTH `subject` (which would
	// normally be set by the JWT middleware for the calling admin) AND
	// the override (set by the impersonation gate). The override MUST
	// win — otherwise the admin's subject leaks into linked-address
	// resolution.
	impReq := httptest.NewRequest(http.MethodGet,
		impersonatePath(f.userDID, f.orgID, "/api/v1/explorer/viewable-addresses"), nil)
	impReq.Header.Set("X-Test-Auth-Method", "jwt_admin")
	impReq.Header.Set("X-Test-Admin-Subject", f.adminDID)
	impReq.Header.Set("X-Test-Admin-Org-IDs", f.orgID)
	// Belt + braces: also set X-Test-Subject so the parity test
	// middleware sets `subject` directly. The override must still take
	// priority over `subject` per getViewerDIDFromRequest's documented
	// invariant.
	impReq.Header.Set("X-Test-Subject", f.adminDID)
	impW := httptest.NewRecorder()
	srv.router.ServeHTTP(impW, impReq)
	require.Equal(t, http.StatusOK, impW.Code, "impersonation path: %s", impW.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(impW.Body.Bytes(), &body))

	assert.Equal(t, f.userDID, body["viewer_did"],
		"override must take priority over `subject` in getViewerDIDFromRequest")

	// Address-set assertion: target's, not admin's.
	ownAddrsRaw, _ := body["own_addresses"].([]any)
	require.Len(t, ownAddrsRaw, 1)
	first, _ := ownAddrsRaw[0].(map[string]any)
	assert.Equal(t, targetAddr, first["address"],
		"linked address under impersonation must be target's; admin subject must NOT win over the override")
}
