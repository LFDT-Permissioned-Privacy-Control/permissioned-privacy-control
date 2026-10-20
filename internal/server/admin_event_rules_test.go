package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Well-known topic0 hashes for test assertions.
const (
	transferTopic0 = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	approvalTopic0 = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
)

// Standard ERC20 ABI used across the event-rule tests.
const erc20ABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "owner", "type": "address"},
			{"indexed": true, "name": "spender", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Approval",
		"type": "event"
	}
]`

// eventRulesFixture holds shared state created once per top-level test run.
type eventRulesFixture struct {
	server          *testServerRBAC
	orgID           string
	groupID         string
	secondGroupID   string
	contractAddress string
}

// setupEventRulesFixture creates an org, two groups, and a contract for event-rule tests.
func setupEventRulesFixture(t *testing.T) *eventRulesFixture {
	t.Helper()

	srv := setupTestServerForRBAC(t)

	// Create org
	orgID := createEventRulesOrg(t, srv)
	// Create two groups inside the org
	groupID := createEventRulesGroup(t, srv, orgID, "group-alpha", "Group Alpha")
	secondGroupID := createEventRulesGroup(t, srv, orgID, "group-beta", "Group Beta")
	// Create a contract
	contractAddr := "0x5555555555555555555555555555555555555555"
	createEventRulesContract(t, srv, orgID, contractAddr, "TestToken")

	return &eventRulesFixture{
		server:          srv,
		orgID:           orgID,
		groupID:         groupID,
		secondGroupID:   secondGroupID,
		contractAddress: contractAddr,
	}
}

// ---------------------------------------------------------------------------
// Helper: create org, group, contract via the admin API
// ---------------------------------------------------------------------------

func createEventRulesOrg(t *testing.T, srv *testServerRBAC) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"slug": "event-rules-org",
		"name": "Event Rules Org",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create org: %s", w.Body.String())

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	return resp["id"].(string)
}

func createEventRulesGroup(t *testing.T, srv *testServerRBAC, orgID, slug, name string) string {
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

// createEventRulesContract creates a contract that resolves to the built-in
// ERC-20 ABI via metadata.token_type. After RD-875, event_rules can only be
// saved against a contract whose ABI is resolvable (custom upload or
// metadata.token_type matching the built-in registry); the historical
// fixture defaulted to no ABI which used to be a permissive code path.
// Tests that need to exercise the no-ABI fail-closed gate explicitly use
// createEventRulesContractNoABI.
func createEventRulesContract(t *testing.T, srv *testServerRBAC, orgID, address, name string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"address":  address,
		"name":     name,
		"metadata": map[string]any{"token_type": "ERC20"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create contract: %s", w.Body.String())
}

// createEventRulesContractNoABI creates a contract with no resolvable ABI
// (no custom upload, no token_type metadata). After RD-875, attempting to
// save non-deny event_rules on such a contract returns 400.
func createEventRulesContractNoABI(t *testing.T, srv *testServerRBAC, orgID, address, name string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"address": address, "name": name})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create contract: %s", w.Body.String())
}

// ---------------------------------------------------------------------------
// I01-I08: Admin API CRUD for event_rules
// ---------------------------------------------------------------------------

func TestAdminEventRulesCRUD(t *testing.T) {
	f := setupEventRulesFixture(t)

	// I01: POST grant with event_rules -> 201, rules persisted
	t.Run("I01_CreateGrant_WithEventRules", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.groupID,
			"event_rules": []map[string]any{
				{"topic0": transferTopic0, "name": "Transfer"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

		var grant rbac.ContractGrant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grant))
		require.NotNil(t, grant.EventRules, "event_rules should not be nil")
		rules := grant.EventRules.GetRules()
		require.Len(t, rules, 1, "event_rules should have 1 rule")
		assert.Equal(t, transferTopic0, rules[0].Topic0)
		assert.Equal(t, "Transfer", rules[0].Name)
	})

	// I02: POST grant with invalid topic0 -> 400
	t.Run("I02_CreateGrant_InvalidTopic0", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.secondGroupID,
			"event_rules": []map[string]any{
				{"topic0": "0xZZZZ", "name": "Bad"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Contains(t, w.Body.String(), "invalid topic0")
	})

	// I03: PUT grant adding event_rules -> 200, rules present
	t.Run("I03_UpdateGrant_AddEventRules", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"event_rules": []map[string]any{
				{"topic0": transferTopic0, "name": "Transfer"},
				{"topic0": approvalTopic0, "name": "Approval"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants/" + f.groupID
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var grant rbac.ContractGrant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grant))
		require.NotNil(t, grant.EventRules)
		rules := grant.EventRules.GetRules()
		require.Len(t, rules, 2)
		assert.Equal(t, transferTopic0, rules[0].Topic0)
		assert.Equal(t, approvalTopic0, rules[1].Topic0)
	})

	// I04: PUT with event_rules: null -> 200, response has event_rules key present with null value.
	// This verifies the omitempty bug fix: the JSON key must be present, not omitted.
	t.Run("I04_UpdateGrant_ClearRules_Null", func(t *testing.T) {
		// Send {"event_rules": null}
		body := []byte(`{"event_rules": null}`)
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants/" + f.groupID
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// Parse the raw JSON to verify the event_rules key is present
		var rawResp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rawResp))

		eventRulesRaw, keyExists := rawResp["event_rules"]
		assert.True(t, keyExists, "event_rules key must be present in response JSON (omitempty bug)")
		assert.Equal(t, "null", string(eventRulesRaw), "event_rules value must be null, not omitted")
	})

	// I05: PUT with event_rules: [] -> 200, response has event_rules as null.
	// Both [] and null mean deny-all; the DB normalizes to null.
	t.Run("I05_UpdateGrant_EmptyRules_DenyAll", func(t *testing.T) {
		body := []byte(`{"event_rules": []}`)
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants/" + f.groupID
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// Parse raw JSON to verify event_rules is present as null (normalized deny-all)
		var rawResp map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rawResp))

		eventRulesRaw, keyExists := rawResp["event_rules"]
		assert.True(t, keyExists, "event_rules key must be present in response JSON")
		assert.Equal(t, "null", string(eventRulesRaw), "event_rules value must be null ([] normalized to null)")
	})

	// I06: PUT with param_rules -> 200, param_rules persisted
	t.Run("I06_UpdateGrant_WithParamRules", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 0, "must_be": "self"},
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants/" + f.groupID
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var grant rbac.ContractGrant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grant))
		require.NotNil(t, grant.EventRules)
		rules := grant.EventRules.GetRules()
		require.Len(t, rules, 1)
		require.Len(t, rules[0].ParamRules, 1, "param_rules should be persisted")
		assert.Equal(t, 0, rules[0].ParamRules[0].Index)
		assert.Equal(t, "self", rules[0].ParamRules[0].MustBe)
	})

	// Create a second grant for I07 verification
	t.Run("setup_second_grant", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.secondGroupID,
			"event_rules": []map[string]any{
				{"topic0": approvalTopic0, "name": "Approval"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	})

	// I07: GET grants -> both grants show correct event_rules
	t.Run("I07_ListGrants_IncludesRules", func(t *testing.T) {
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var grants []rbac.ContractGrant
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grants))
		require.Len(t, grants, 2, "should have 2 grants")

		// Find each grant by group ID and verify its event_rules
		grantByGroup := make(map[string]*rbac.ContractGrant)
		for i := range grants {
			grantByGroup[grants[i].GroupID] = &grants[i]
		}

		// First grant (group-alpha): has Transfer with param_rules from I06
		g1 := grantByGroup[f.groupID]
		require.NotNil(t, g1, "grant for group-alpha should exist")
		require.NotNil(t, g1.EventRules)
		g1Rules := g1.EventRules.GetRules()
		require.Len(t, g1Rules, 1)
		assert.Equal(t, transferTopic0, g1Rules[0].Topic0)
		require.Len(t, g1Rules[0].ParamRules, 1)

		// Second grant (group-beta): has Approval
		g2 := grantByGroup[f.secondGroupID]
		require.NotNil(t, g2, "grant for group-beta should exist")
		require.NotNil(t, g2.EventRules)
		g2Rules := g2.EventRules.GetRules()
		require.Len(t, g2Rules, 1)
		assert.Equal(t, approvalTopic0, g2Rules[0].Topic0)
	})

	// I08: GET contract by-address -> includes grants with event_rules
	t.Run("I08_LookupContract_IncludesRules", func(t *testing.T) {
		url := "/api/contracts/by-address/" + f.contractAddress
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Contract *rbac.Contract `json:"contract"`
			Grants   []struct {
				Grant *rbac.ContractGrant `json:"grant"`
			} `json:"grants"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.NotNil(t, resp.Contract)
		assert.Equal(t, f.contractAddress, resp.Contract.Address)
		require.Len(t, resp.Grants, 2, "lookup should include both grants")

		// Verify at least one grant has event_rules populated
		var foundRules bool
		for _, gi := range resp.Grants {
			if gi.Grant != nil && gi.Grant.EventRules != nil && !gi.Grant.EventRules.IsDeny() {
				foundRules = true
				break
			}
		}
		assert.True(t, foundRules, "at least one grant should have event_rules populated")
	})
}

// ---------------------------------------------------------------------------
// I09-I13: ABI Event Endpoint
// ---------------------------------------------------------------------------

func TestAdminEventRulesABIEndpoint(t *testing.T) {
	f := setupEventRulesFixture(t)

	// Upload ERC20 ABI to the contract
	uploadContractABI := func(t *testing.T, orgID, addr, abiJSON string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"abi": abiJSON})
		url := "/api/orgs/" + orgID + "/contracts/" + addr + "/abi"
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "upload ABI: %s", w.Body.String())
	}

	// I09: GET events with ERC20 ABI -> returns Transfer + Approval with correct topic0
	t.Run("I09_ParsesABI_ERC20", func(t *testing.T) {
		uploadContractABI(t, f.orgID, f.contractAddress, erc20ABI)

		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/events"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Events []rbac.EventSignature `json:"events"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Len(t, resp.Events, 2, "ERC20 ABI should yield 2 events")

		// Build a map of name -> topic0 for flexible assertion order
		eventMap := make(map[string]string)
		for _, ev := range resp.Events {
			eventMap[ev.Name] = ev.Topic0
		}

		assert.Equal(t, transferTopic0, eventMap["Transfer"], "Transfer topic0 mismatch")
		assert.Equal(t, approvalTopic0, eventMap["Approval"], "Approval topic0 mismatch")

		// Verify inputs for Transfer
		for _, ev := range resp.Events {
			if ev.Name == "Transfer" {
				require.Len(t, ev.Inputs, 3)
				assert.Equal(t, "from", ev.Inputs[0].Name)
				assert.True(t, ev.Inputs[0].Indexed)
				assert.Equal(t, "to", ev.Inputs[1].Name)
				assert.True(t, ev.Inputs[1].Indexed)
				assert.Equal(t, "value", ev.Inputs[2].Name)
				assert.False(t, ev.Inputs[2].Indexed)
			}
		}
	})

	// I09b: GET events -> default_param_rules populated for address-typed inputs
	t.Run("I09b_DefaultParamRules_AddressInputs", func(t *testing.T) {
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/events"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Events []rbac.EventSignature `json:"events"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

		// Find Transfer event — has 2 address inputs (from, to) and 1 uint256 (value).
		var transfer *rbac.EventSignature
		for i := range resp.Events {
			if resp.Events[i].Name == "Transfer" {
				transfer = &resp.Events[i]
				break
			}
		}
		require.NotNil(t, transfer, "Transfer event should be present")
		require.Len(t, transfer.DefaultParamRules, 2,
			"Transfer has 2 address inputs -> 2 default_param_rules")
		assert.Equal(t, 0, transfer.DefaultParamRules[0].Index)
		assert.Equal(t, "self", transfer.DefaultParamRules[0].MustBe)
		assert.Equal(t, 1, transfer.DefaultParamRules[1].Index)
		assert.Equal(t, "self", transfer.DefaultParamRules[1].MustBe)

		// Find Approval event — also has 2 address inputs (owner, spender).
		var approval *rbac.EventSignature
		for i := range resp.Events {
			if resp.Events[i].Name == "Approval" {
				approval = &resp.Events[i]
				break
			}
		}
		require.NotNil(t, approval, "Approval event should be present")
		require.Len(t, approval.DefaultParamRules, 2,
			"Approval has 2 address inputs -> 2 default_param_rules")
		assert.Equal(t, 0, approval.DefaultParamRules[0].Index)
		assert.Equal(t, "self", approval.DefaultParamRules[0].MustBe)
		assert.Equal(t, 1, approval.DefaultParamRules[1].Index)
		assert.Equal(t, "self", approval.DefaultParamRules[1].MustBe)
	})

	// I10: GET events, no ABI stored -> empty array
	t.Run("I10_NoABI_EmptyArray", func(t *testing.T) {
		// Create a second contract without an ABI (no token_type either, so
		// the built-in registry can't resolve one).
		noABIAddr := "0x6666666666666666666666666666666666666666"
		createEventRulesContractNoABI(t, f.server, f.orgID, noABIAddr, "NoABI")

		url := "/api/orgs/" + f.orgID + "/contracts/" + noABIAddr + "/events"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Events  []rbac.EventSignature `json:"events"`
			Message string                `json:"message"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Empty(t, resp.Events, "no ABI should return empty events array")
		assert.Contains(t, resp.Message, "no ABI", "should include helpful message")
	})

	// I12: GET events for nonexistent address -> 404
	t.Run("I12_ContractNotFound_404", func(t *testing.T) {
		fakeAddr := "0x0000000000000000000000000000000000099999"
		url := "/api/orgs/" + f.orgID + "/contracts/" + fakeAddr + "/events"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "not found")
	})
}

// ---------------------------------------------------------------------------
// ABI Validation Tests (RD-792)
// ---------------------------------------------------------------------------

func TestAdminEventRulesABIValidation(t *testing.T) {
	f := setupEventRulesFixture(t)

	// Upload ERC20 ABI to the contract
	uploadABI := func(t *testing.T, addr, abiJSON string) {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"abi": abiJSON})
		url := "/api/orgs/" + f.orgID + "/contracts/" + addr + "/abi"
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "upload ABI: %s", w.Body.String())
	}

	uploadABI(t, f.contractAddress, erc20ABI)

	// V01: param index out of bounds -> 400
	t.Run("V01_ParamIndex_OutOfBounds", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.groupID,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 5, "must_be": "self"}, // Transfer only has 3 inputs (0,1,2)
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "out of bounds")
	})

	// V02: "self" on non-address param -> 400
	t.Run("V02_Self_OnNonAddressParam", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.groupID,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 2, "must_be": "self"}, // index 2 is "value" (uint256), not address
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "not address")
	})

	// V03: valid "self" on address param -> 201
	t.Run("V03_Self_OnAddressParam_OK", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.groupID,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 0, "must_be": "self"}, // index 0 is "from" (address) — valid
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	})

	// V04: hex value wrong length for address -> 400
	t.Run("V04_HexValue_WrongLengthForAddress", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.secondGroupID,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						// index 0 is "from" (address) — expects 20 bytes, but giving 32 bytes
						{"index": 0, "must_be": "0x0000000000000000000000000000000000000000000000000000000000000001"},
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "bytes")
	})

	// V05/V05b/V05c: post-RD-875 fail-closed behaviour. Saving any non-deny
	// event_rules on a contract without a resolvable ABI (custom upload or
	// metadata.token_type matching the built-in registry) is rejected at
	// the grant-save handler with a clear 400. The previous "no ABI = skip
	// validation / accept self constraints" path is gone — see
	// REDACTION_SPEC.md §4 G5 and decisions.md §2 G5.

	t.Run("V05_NoABI_RejectsTopic0Only", func(t *testing.T) {
		// Even a bare topic0 rule (no param_rules) is rejected — without an
		// ABI the runtime gate denies all logs from this contract anyway,
		// so the rules would silently never fire. Reject up front.
		noABIAddr := "0x7777777777777777777777777777777777777777"
		createEventRulesContractNoABI(t, f.server, f.orgID, noABIAddr, "NoABIToken")
		thirdGroupID := createEventRulesGroup(t, f.server, f.orgID, "group-gamma", "Group Gamma")

		body, _ := json.Marshal(map[string]any{
			"group_id": thirdGroupID,
			"event_rules": []map[string]any{
				{"topic0": transferTopic0, "name": "Transfer"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + noABIAddr + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "contract has no ABI registered")
	})

	t.Run("V05b_NoABI_RejectsCustomHexParam", func(t *testing.T) {
		noABIAddr2 := "0x7777777777777777777777777777777777777778"
		createEventRulesContractNoABI(t, f.server, f.orgID, noABIAddr2, "NoABIToken2")
		groupForHex := createEventRulesGroup(t, f.server, f.orgID, "group-hex-noabi", "Group Hex NoABI")

		body, _ := json.Marshal(map[string]any{
			"group_id": groupForHex,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 0, "must_be": "0x000000000000000000000000deadbeefdeadbeef"},
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + noABIAddr2 + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "contract has no ABI registered")
	})

	t.Run("V05c_NoABI_RejectsSelfConstraint", func(t *testing.T) {
		// Previously "self" was allowed without an ABI on the rationale
		// that addresses can be matched topic-by-topic without decoding.
		// RD-875 closes the gap by denying the runtime path entirely
		// when no ABI is resolvable, so saving the rule is also rejected
		// now — no daylight between "saved" and "fired".
		noABIAddr3 := "0x7777777777777777777777777777777777777779"
		createEventRulesContractNoABI(t, f.server, f.orgID, noABIAddr3, "NoABIToken3")
		groupForSelf := createEventRulesGroup(t, f.server, f.orgID, "group-self-noabi", "Group Self NoABI")

		body, _ := json.Marshal(map[string]any{
			"group_id": groupForSelf,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 0, "must_be": "self"},
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + noABIAddr3 + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "contract has no ABI registered")
	})

	// V06: update grant with invalid param rules -> 400
	t.Run("V06_UpdateGrant_InvalidParamRules", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 2, "must_be": "self"}, // uint256, not address
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants/" + f.groupID
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "not address")
	})

	// V07: topic0 not declared by the contract's ABI -> 400. Demo seeds and
	// admin typos used to silently persist as orphan rules; this gate makes
	// each rule prove the event exists in the ABI before save.
	t.Run("V07_TopicNotInABI_Rejected", func(t *testing.T) {
		// All-zero topic0 is the canonical "definitely not in any real ABI"
		// hex — guaranteed not to match Transfer or Approval on the ERC-20
		// fixture above.
		const orphanTopic0 = "0x0000000000000000000000000000000000000000000000000000000000000000"
		body, _ := json.Marshal(map[string]any{
			"group_id": f.secondGroupID,
			"event_rules": []map[string]any{
				{
					"topic0": orphanTopic0,
					"name":   "GhostEvent",
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		body200 := w.Body.String()
		assert.Contains(t, body200, "topic0")
		assert.Contains(t, body200, "does not match any event")
		// Error should list the contract's actual events so admins can
		// copy-paste the right value.
		assert.Contains(t, body200, "Transfer")
		assert.Contains(t, body200, "Approval")
	})

	// V07b: param-less rule with bad topic0 also rejected (proves the gate
	// fires whether or not param_rules are present — the prior permissive
	// behaviour only checked when param_rules were set).
	t.Run("V07b_TopicNotInABI_NoParamRules_Rejected", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{
			"group_id": f.secondGroupID,
			"event_rules": []map[string]any{
				// Wrong-length hex would fail at the JSON layer; use a
				// well-formed but non-matching keccak256 hash.
				{"topic0": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", "name": "BogusEvent"},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "does not match any event")
	})
}

// ---------------------------------------------------------------------------
// Built-in ABI Registry Tests (RD-793)
// ---------------------------------------------------------------------------

func TestContractEventsBuiltInABI(t *testing.T) {
	f := setupEventRulesFixture(t)

	// Create a contract with token_type metadata but no custom ABI
	erc20Addr := "0x8888888888888888888888888888888888888888"
	createEventRulesContractWithMetadata(t, f.server, f.orgID, erc20Addr, "ERC20Token", map[string]any{
		"token_type": "ERC20",
	})

	t.Run("EventList_FallsBackToBuiltInABI", func(t *testing.T) {
		url := "/api/orgs/" + f.orgID + "/contracts/" + erc20Addr + "/events"
		req := httptest.NewRequest(http.MethodGet, url, nil)
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Events []rbac.EventSignature `json:"events"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Equal(t, 2, len(resp.Events), "built-in ERC20 ABI should yield 2 events")

		eventMap := make(map[string]string)
		for _, ev := range resp.Events {
			eventMap[ev.Name] = ev.Topic0
		}
		assert.Equal(t, transferTopic0, eventMap["Transfer"])
		assert.Equal(t, approvalTopic0, eventMap["Approval"])
	})

	t.Run("ParamValidation_UsesBuiltInABI", func(t *testing.T) {
		groupID := createEventRulesGroup(t, f.server, f.orgID, "group-delta", "Group Delta")

		// "self" on uint256 should fail even with built-in ABI
		body, _ := json.Marshal(map[string]any{
			"group_id": groupID,
			"event_rules": []map[string]any{
				{
					"topic0": transferTopic0,
					"name":   "Transfer",
					"param_rules": []map[string]any{
						{"index": 2, "must_be": "self"}, // value is uint256
					},
				},
			},
		})
		url := "/api/orgs/" + f.orgID + "/contracts/" + erc20Addr + "/grants"
		req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), "not address")
	})

	t.Run("CustomABI_TakesPrecedence", func(t *testing.T) {
		// Upload a custom ABI that only has a single custom event
		customABI := `[{
			"anonymous": false,
			"inputs": [
				{"indexed": true, "name": "amount", "type": "uint256"}
			],
			"name": "CustomEvent",
			"type": "event"
		}]`
		body, _ := json.Marshal(map[string]any{"abi": customABI})
		url := "/api/orgs/" + f.orgID + "/contracts/" + erc20Addr + "/abi"
		req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		// Now events should show only the custom event, not the built-in ERC20 events
		url = "/api/orgs/" + f.orgID + "/contracts/" + erc20Addr + "/events"
		req = httptest.NewRequest(http.MethodGet, url, nil)
		w = httptest.NewRecorder()
		f.server.router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())

		var resp struct {
			Events []rbac.EventSignature `json:"events"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		require.Len(t, resp.Events, 1, "custom ABI should take precedence over built-in")
		assert.Equal(t, "CustomEvent", resp.Events[0].Name)

		// CustomEvent has only uint256 inputs — no address params — so
		// default_param_rules should be empty (nil serializes as null).
		assert.Empty(t, resp.Events[0].DefaultParamRules,
			"event with no address inputs should have empty default_param_rules")
	})
}

// createEventRulesContractWithMetadata creates a contract with metadata via the
// admin API, then directly updates metadata in the DB since the create endpoint
// doesn't support metadata.
func createEventRulesContractWithMetadata(t *testing.T, srv *testServerRBAC, orgID, address, name string, metadata map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"address":  address,
		"name":     name,
		"metadata": metadata,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create contract: %s", w.Body.String())

	// Update the contract metadata via PUT (the create endpoint stores metadata)
	var created rbac.Contract
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

	body, _ = json.Marshal(map[string]any{
		"metadata": metadata,
	})
	req = httptest.NewRequest(http.MethodPut, "/api/orgs/"+orgID+"/contracts/"+address, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "update contract metadata: %s", w.Body.String())
}
