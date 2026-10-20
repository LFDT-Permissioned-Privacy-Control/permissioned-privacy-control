package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1179: sync-delete must cap contract_ids — each ID does a DB read + an
// upstream eth_getCode, so an uncapped list fans out into unbounded load.
func TestSyncDeleteContractsCap_RD1179(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	orgID := createCrossOrgTestOrg(t, srv, "dos-syncdel")

	ids := make([]string, 201)
	for i := range ids {
		ids[i] = fmt.Sprintf("00000000-0000-0000-0000-%012d", i)
	}
	body, _ := json.Marshal(map[string]any{"contract_ids": ids})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts/sync-delete", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "201 ids must be rejected: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "too many contract_ids")

	// Exactly 200 must NOT trip the cap (may 200 with skipped entries since the
	// IDs don't exist — the point is it's not the cap 400).
	body200, _ := json.Marshal(map[string]any{"contract_ids": ids[:200]})
	req = httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts/sync-delete", bytes.NewReader(body200))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	assert.NotContains(t, w.Body.String(), "too many contract_ids", "200 ids must pass the cap")
}

// RD-1179: a contract grant may not carry an unbounded number of custom-hex
// address param rules (each drives up to 2 cross-org DB lookups).
func TestGrantParamRulesCap_RD1179(t *testing.T) {
	srv := setupTestServerForRBAC(t)
	orgID := createCrossOrgTestOrg(t, srv, "dos-grant")
	groupID := createCrossOrgTestGroup(t, srv, orgID, "g", "G")
	addr := "0xcccc000000000000000000000000000000000001"
	createCrossOrgTestContract(t, srv, orgID, addr, "Tok")
	uploadCrossOrgTestABI(t, srv, orgID, addr, erc20ABI)

	// One event rule with 101 custom-hex address param rules → over the cap.
	paramRules := make([]map[string]any, maxCustomAddressParamRules+1)
	for i := range paramRules {
		paramRules[i] = map[string]any{"index": 0, "must_be": "0x1111111111111111111111111111111111111111"}
	}
	eventRules := []map[string]any{{
		// Transfer(address,address,uint256)
		"topic0":      "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
		"name":        "Transfer",
		"param_rules": paramRules,
	}}
	body, _ := json.Marshal(map[string]any{"group_id": groupID, "event_rules": eventRules})
	req := httptest.NewRequest(http.MethodPost, "/api/orgs/"+orgID+"/contracts/"+addr+"/grants", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code, "over-cap param rules must be 400: %s", w.Body.String())
	assert.Contains(t, w.Body.String(), "too many custom-address param rules")
}

// RD-1179: parsePaginationParams clamps limit to maxPaginationLimit and rejects
// negative/zero/non-numeric values back to defaults.
func TestParsePaginationParamsClamp_RD1179(t *testing.T) {
	gin.SetMode(gin.TestMode)
	mk := func(q string) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodGet, "/x?"+q, nil)
		return c
	}
	cases := []struct {
		q          string
		wantLimit  int
		wantOffset int
	}{
		{"", 50, 0},
		{"limit=100000", maxPaginationLimit, 0},
		{"limit=" + fmt.Sprint(maxPaginationLimit+1), maxPaginationLimit, 0},
		{"limit=" + fmt.Sprint(maxPaginationLimit), maxPaginationLimit, 0},
		{"limit=-5", 50, 0},  // negative → default
		{"limit=abc", 50, 0}, // non-numeric → default
		{"limit=25&offset=10", 25, 10},
		{"offset=-3", 50, 0}, // negative offset → default 0
	}
	for _, tc := range cases {
		t.Run(url.QueryEscape(tc.q), func(t *testing.T) {
			limit, offset := parsePaginationParams(mk(tc.q), 50)
			assert.Equal(t, tc.wantLimit, limit, "limit for %q", tc.q)
			assert.Equal(t, tc.wantOffset, offset, "offset for %q", tc.q)
		})
	}
}

// RD-1179: explorer limit/offset clamps bound the SQL query args and reject the
// sign abuse (negative LIMIT = Postgres LIMIT ALL = dump-all; negative OFFSET = 500).
func TestClampExplorerLimitOffset_RD1179(t *testing.T) {
	assert.Equal(t, 25, clampExplorerLimit(0, 25), "zero → default")
	assert.Equal(t, 25, clampExplorerLimit(-1, 25), "negative → default (not LIMIT -1 / ALL)")
	assert.Equal(t, 50, clampExplorerLimit(50, 25), "in-range unchanged")
	assert.Equal(t, maxExplorerPageLimit, clampExplorerLimit(100000, 25), "over-max → clamped")
	assert.Equal(t, maxExplorerPageLimit, clampExplorerLimit(maxExplorerPageLimit, 25), "at-max unchanged")

	assert.Equal(t, 0, clampExplorerOffset(-1), "negative offset → 0 (avoids Postgres error)")
	assert.Equal(t, 0, clampExplorerOffset(0), "zero unchanged")
	assert.Equal(t, 500, clampExplorerOffset(500), "positive unchanged")
}
