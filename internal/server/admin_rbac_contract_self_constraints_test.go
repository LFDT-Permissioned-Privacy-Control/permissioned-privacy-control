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

// Minimal ERC20-like ABI with Transfer(address,address,uint256) event.
const testABIWithTransfer = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "from", "type": "address"},
			{"indexed": true, "name": "to", "type": "address"},
			{"indexed": false, "name": "value", "type": "uint256"}
		],
		"name": "Transfer",
		"type": "event"
	}
]`

// ---------------------------------------------------------------------------
// Unit tests for autoAddSelfConstraints (function still exists for potential
// future use, so we keep the unit tests).
// ---------------------------------------------------------------------------

func TestAutoAddSelfConstraints_AddressParams(t *testing.T) {
	// Extract Transfer topic0 from the test ABI.
	sigs, err := rbac.ExtractEventSignatures(testABIWithTransfer)
	if err != nil {
		t.Fatalf("failed to parse test ABI: %v", err)
	}
	if len(sigs) != 1 {
		t.Fatalf("expected 1 event, got %d", len(sigs))
	}
	transferTopic0 := sigs[0].Topic0

	rules := []rbac.EventRule{
		{Topic0: transferTopic0, Name: "Transfer"},
	}

	result := autoAddSelfConstraints(rules, testABIWithTransfer)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}

	// Transfer has 2 address params (index 0 and 1) and 1 uint256 (index 2).
	// Both address params should get a "self" constraint. uint256 should not.
	if len(result[0].ParamRules) != 2 {
		t.Fatalf("expected 2 param rules (self for from + to), got %d", len(result[0].ParamRules))
	}

	foundIdx0, foundIdx1 := false, false
	for _, pr := range result[0].ParamRules {
		if pr.MustBe != "self" {
			t.Errorf("expected must_be=self, got %q", pr.MustBe)
		}
		switch pr.Index {
		case 0:
			foundIdx0 = true
		case 1:
			foundIdx1 = true
		default:
			t.Errorf("unexpected param rule index %d", pr.Index)
		}
	}
	if !foundIdx0 || !foundIdx1 {
		t.Errorf("expected self constraints at index 0 and 1, got idx0=%v idx1=%v", foundIdx0, foundIdx1)
	}
}

func TestAutoAddSelfConstraints_ExistingRulePreserved(t *testing.T) {
	sigs, err := rbac.ExtractEventSignatures(testABIWithTransfer)
	if err != nil {
		t.Fatalf("failed to parse test ABI: %v", err)
	}
	transferTopic0 := sigs[0].Topic0

	// Pre-existing constraint on index 0 (from) — should not be overwritten.
	rules := []rbac.EventRule{
		{
			Topic0: transferTopic0,
			Name:   "Transfer",
			ParamRules: []rbac.ParamRule{
				{Index: 0, MustBe: "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			},
		},
	}

	result := autoAddSelfConstraints(rules, testABIWithTransfer)
	if len(result) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(result))
	}

	// Index 0 has an existing constraint, so only index 1 (to) should get "self".
	if len(result[0].ParamRules) != 2 {
		t.Fatalf("expected 2 param rules (existing + new self), got %d", len(result[0].ParamRules))
	}

	// Verify the existing rule at index 0 is unchanged.
	for _, pr := range result[0].ParamRules {
		if pr.Index == 0 {
			if pr.MustBe == "self" {
				t.Errorf("existing constraint at index 0 should NOT be overwritten with self")
			}
		}
		if pr.Index == 1 {
			if pr.MustBe != "self" {
				t.Errorf("expected self at index 1, got %q", pr.MustBe)
			}
		}
	}
}

func TestAutoAddSelfConstraints_NoABI(t *testing.T) {
	rules := []rbac.EventRule{
		{Topic0: "0xabc123", Name: "SomeEvent"},
	}

	result := autoAddSelfConstraints(rules, "")
	if len(result) != 1 {
		t.Fatalf("expected 1 rule unchanged, got %d", len(result))
	}
	if len(result[0].ParamRules) != 0 {
		t.Errorf("expected no param rules added when ABI is empty, got %d", len(result[0].ParamRules))
	}
}

func TestAutoAddSelfConstraints_NilRules(t *testing.T) {
	result := autoAddSelfConstraints(nil, testABIWithTransfer)
	if result != nil {
		t.Errorf("expected nil returned for nil rules, got %v", result)
	}
}

// ---------------------------------------------------------------------------
// Integration test: createContractGrant no longer auto-adds self constraints.
// The admin's explicit choices are authoritative; defaults are provided by
// default_param_rules on the events endpoint for the frontend to pre-populate.
// ---------------------------------------------------------------------------

func TestCreateGrant_NoAutoSelfConstraints(t *testing.T) {
	f := setupEventRulesFixture(t)

	// Upload ABI so the server has address-type information available.
	body, _ := json.Marshal(map[string]any{"abi": testABIWithTransfer})
	url := "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/abi"
	req := httptest.NewRequest(http.MethodPut, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.server.router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "upload ABI: %s", w.Body.String())

	// Extract topic0 for Transfer.
	sigs, err := rbac.ExtractEventSignatures(testABIWithTransfer)
	require.NoError(t, err)
	require.Len(t, sigs, 1)
	topic0 := sigs[0].Topic0

	// Create a grant with a Transfer event rule but NO param_rules.
	// Previously autoAddSelfConstraints would inject "self" for both address
	// params. After the change, the grant should be stored as-is (no param_rules).
	body, _ = json.Marshal(map[string]any{
		"group_id": f.groupID,
		"event_rules": []map[string]any{
			{"topic0": topic0, "name": "Transfer"},
		},
	})
	url = "/api/orgs/" + f.orgID + "/contracts/" + f.contractAddress + "/grants"
	req = httptest.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	f.server.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

	var grant rbac.ContractGrant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &grant))
	require.NotNil(t, grant.EventRules)
	rules := grant.EventRules.GetRules()
	require.Len(t, rules, 1)
	assert.Empty(t, rules[0].ParamRules,
		"createContractGrant must NOT auto-add self constraints; admin's explicit choices are authoritative")
}
