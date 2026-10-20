package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Cross-org param rule boundary enforcement tests
//
// These tests verify that custom hex addresses in event param rules are
// validated against organization boundaries:
//
// - Same-org contract address: allowed
// - Different-org contract address: rejected (403)
// - EOA linked to user in same org: allowed
// - EOA linked to user only in different org: rejected (403)
// - Unregistered address (not in any org): rejected (fail-closed)
// - "self" constraint: always allowed (no cross-org check)
// - Non-address param type (uint256): no cross-org check
// ---------------------------------------------------------------------------

// crossOrgFixture holds shared state for cross-org param rule tests.
type crossOrgFixture struct {
	server *testServerRBAC
	// Org A: the org creating the grants
	orgA            string
	groupA          string
	contractAddrA   string
	// Org B: a different org for cross-org testing
	orgB            string
	contractAddrB   string
	// EOA addresses
	eoaSameOrg       string // linked to user in orgA
	eoaDiffOrg       string // linked to user in orgB only
	eoaMultiOrg      string // linked to user in both orgA and orgB
	unregisteredAddr string // not linked to anyone
}

func setupCrossOrgFixture(t *testing.T) *crossOrgFixture {
	t.Helper()

	srv := setupTestServerForRBAC(t)
	ctx := context.Background()

	// Create two orgs via API
	orgAID := createCrossOrgTestOrg(t, srv, "cross-org-a")
	orgBID := createCrossOrgTestOrg(t, srv, "cross-org-b")

	// Create groups via API
	groupAID := createCrossOrgTestGroup(t, srv, orgAID, "group-a", "Group A")
	groupBID := createCrossOrgTestGroup(t, srv, orgBID, "group-b", "Group B")

	// Create contracts: one in each org
	contractAddrA := "0xaaaa000000000000000000000000000000000001"
	contractAddrB := "0xbbbb000000000000000000000000000000000001"
	createCrossOrgTestContract(t, srv, orgAID, contractAddrA, "TokenA")
	createCrossOrgTestContract(t, srv, orgBID, contractAddrB, "TokenB")

	// Upload ERC20 ABI to contract A (needed for param type resolution)
	uploadCrossOrgTestABI(t, srv, orgAID, contractAddrA, erc20ABI)

	// Create users and link addresses directly via DB (no user creation API)
	eoaSameOrg := "0x1111111111111111111111111111111111111111"
	eoaDiffOrg := "0x2222222222222222222222222222222222222222"
	eoaMultiOrg := "0x3333333333333333333333333333333333333333"
	unregisteredAddr := "0x9999999999999999999999999999999999999999"

	// User A: in orgA only
	didA := "did:test:user-a-" + uuid.New().String()[:8]
	userA := &rbac.User{ID: uuid.New().String(), ExternalID: didA}
	require.NoError(t, srv.db.CreateUser(ctx, userA))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userA.ID, GroupID: groupAID,
	}))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, didA, eoaSameOrg))

	// User B: in orgB only
	didB := "did:test:user-b-" + uuid.New().String()[:8]
	userB := &rbac.User{ID: uuid.New().String(), ExternalID: didB}
	require.NoError(t, srv.db.CreateUser(ctx, userB))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userB.ID, GroupID: groupBID,
	}))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, didB, eoaDiffOrg))

	// User Multi: in both orgA and orgB
	didMulti := "did:test:user-multi-" + uuid.New().String()[:8]
	userMulti := &rbac.User{ID: uuid.New().String(), ExternalID: didMulti}
	require.NoError(t, srv.db.CreateUser(ctx, userMulti))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userMulti.ID, GroupID: groupAID,
	}))
	require.NoError(t, srv.db.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userMulti.ID, GroupID: groupBID,
	}))
	require.NoError(t, srv.db.SystemLinkEthAddress(ctx, didMulti, eoaMultiOrg))

	return &crossOrgFixture{
		server:           srv,
		orgA:             orgAID,
		groupA:           groupAID,
		contractAddrA:    contractAddrA,
		orgB:             orgBID,
		contractAddrB:    contractAddrB,
		eoaSameOrg:       eoaSameOrg,
		eoaDiffOrg:       eoaDiffOrg,
		eoaMultiOrg:      eoaMultiOrg,
		unregisteredAddr: unregisteredAddr,
	}
}

// ---------------------------------------------------------------------------
// Helpers: create entities via admin API
// ---------------------------------------------------------------------------

func createCrossOrgTestOrg(t *testing.T, srv *testServerRBAC, slug string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"slug": slug, "name": slug})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create org: %s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp["id"].(string)
}

func createCrossOrgTestGroup(t *testing.T, srv *testServerRBAC, orgID, slug, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"slug": slug, "name": name})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/groups", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create group: %s", w.Body.String())
	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp["id"].(string)
}

func createCrossOrgTestContract(t *testing.T, srv *testServerRBAC, orgID, address, name string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"address": address, "name": name})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create contract: %s", w.Body.String())
}

func uploadCrossOrgTestABI(t *testing.T, srv *testServerRBAC, orgID, address, abiJSON string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"abi": abiJSON})
	url := "/api/orgs/" + orgID + "/contracts/" + address + "/abi"
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "upload ABI: %s", w.Body.String())
}

func postCrossOrgGrant(t *testing.T, srv *testServerRBAC, orgID, contractAddr, groupID string, eventRules any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"group_id":    groupID,
		"event_rules": eventRules,
	})
	url := "/api/orgs/" + orgID + "/contracts/" + contractAddr + "/grants"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

func putCrossOrgGrant(t *testing.T, srv *testServerRBAC, orgID, contractAddr, groupID string, eventRules any) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"event_rules": eventRules,
	})
	url := "/api/orgs/" + orgID + "/contracts/" + contractAddr + "/grants/" + groupID
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	return w
}

// ---------------------------------------------------------------------------
// Tests: Create grant
// ---------------------------------------------------------------------------

func TestCrossOrgParamRules_CreateGrant(t *testing.T) {
	f := setupCrossOrgFixture(t)

	t.Run("self_constraint_always_allowed", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, f.groupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": "self"},
				},
			},
		})
		assert.Equal(t, http.StatusCreated, w.Code, "self constraint should always be allowed: %s", w.Body.String())
	})

	// Create fresh groups for each subtest (grants are per group)
	secondGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a2", "Group A2")

	t.Run("same_org_contract_address_allowed", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, secondGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.contractAddrA}, // orgA's own contract
				},
			},
		})
		assert.Equal(t, http.StatusCreated, w.Code, "same-org contract address should be allowed: %s", w.Body.String())
	})

	thirdGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a3", "Group A3")

	t.Run("different_org_contract_address_rejected", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, thirdGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.contractAddrB}, // orgB's contract
				},
			},
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "cross-org contract address should be rejected")
		assert.Contains(t, w.Body.String(), "different organization")
	})

	fourthGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a4", "Group A4")

	t.Run("same_org_eoa_allowed", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, fourthGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.eoaSameOrg}, // EOA linked to user in orgA
				},
			},
		})
		assert.Equal(t, http.StatusCreated, w.Code, "same-org EOA should be allowed: %s", w.Body.String())
	})

	fifthGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a5", "Group A5")

	t.Run("different_org_eoa_rejected", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, fifthGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.eoaDiffOrg}, // EOA linked to user in orgB only
				},
			},
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "cross-org EOA should be rejected")
		assert.Contains(t, w.Body.String(), "different organization")
	})

	sixthGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a6", "Group A6")

	t.Run("multi_org_eoa_allowed_when_shared", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, sixthGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.eoaMultiOrg}, // user in both orgA and orgB
				},
			},
		})
		assert.Equal(t, http.StatusCreated, w.Code, "multi-org EOA in same org should be allowed: %s", w.Body.String())
	})

	seventhGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a7", "Group A7")

	t.Run("unregistered_address_rejected_fail_closed", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, seventhGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.unregisteredAddr}, // not in any org
				},
			},
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "unregistered address should be rejected (fail-closed)")
		assert.Contains(t, w.Body.String(), "unregistered address")
	})

	eighthGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a8", "Group A8")

	t.Run("non_address_param_type_skips_cross_org_check", func(t *testing.T) {
		// uint256 param (index 2 = "value" in Transfer event) — no cross-org check
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, eighthGroupA, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					// index 2 is "value" (uint256), not address
					{"index": 2, "must_be": "0x0000000000000000000000000000000000000000000000000000000000000064"},
				},
			},
		})
		assert.Equal(t, http.StatusCreated, w.Code, "non-address param should skip cross-org check: %s", w.Body.String())
	})

	ninthGroupA := createCrossOrgTestGroup(t, f.server, f.orgA, "group-a9", "Group A9")

	t.Run("wildcard_event_rules_skip_cross_org_check", func(t *testing.T) {
		w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, ninthGroupA, "*")
		assert.Equal(t, http.StatusCreated, w.Code, "wildcard event rules should be allowed: %s", w.Body.String())
	})
}

// ---------------------------------------------------------------------------
// Tests: Update grant
// ---------------------------------------------------------------------------

func TestCrossOrgParamRules_UpdateGrant(t *testing.T) {
	f := setupCrossOrgFixture(t)

	// Create a grant with self constraint, then test updates
	groupID := createCrossOrgTestGroup(t, f.server, f.orgA, "update-group", "Update Group")
	w := postCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, groupID, []map[string]any{
		{
			"topic0":      transferTopic0,
			"name":        "Transfer",
			"param_rules": []map[string]any{{"index": 0, "must_be": "self"}},
		},
	})
	require.Equal(t, http.StatusCreated, w.Code, "setup grant: %s", w.Body.String())

	t.Run("update_to_cross_org_address_rejected", func(t *testing.T) {
		w := putCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, groupID, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.contractAddrB}, // orgB's contract
				},
			},
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "update with cross-org address should be rejected")
		assert.Contains(t, w.Body.String(), "different organization")
	})

	t.Run("update_to_same_org_address_allowed", func(t *testing.T) {
		w := putCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, groupID, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.eoaSameOrg},
				},
			},
		})
		assert.Equal(t, http.StatusOK, w.Code, "update with same-org EOA should be allowed: %s", w.Body.String())
	})

	t.Run("update_to_unregistered_address_rejected", func(t *testing.T) {
		w := putCrossOrgGrant(t, f.server, f.orgA, f.contractAddrA, groupID, []map[string]any{
			{
				"topic0": transferTopic0,
				"name":   "Transfer",
				"param_rules": []map[string]any{
					{"index": 0, "must_be": f.unregisteredAddr},
				},
			},
		})
		assert.Equal(t, http.StatusForbidden, w.Code, "update with unregistered address should be rejected (fail-closed)")
		assert.Contains(t, w.Body.String(), "unregistered address")
	})
}
