package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Minimal ERC20 ABI containing balanceOf(address) and totalSupply().
// balanceOf selector: 0x70a08231
// totalSupply selector: 0x18160ddd
const erc20ABI = `[
	{
		"constant": true,
		"inputs": [{"name": "account", "type": "address"}],
		"name": "balanceOf",
		"outputs": [{"name": "", "type": "uint256"}],
		"type": "function"
	},
	{
		"constant": true,
		"inputs": [],
		"name": "totalSupply",
		"outputs": [{"name": "", "type": "uint256"}],
		"type": "function"
	}
]`

const (
	// balanceOf(address) selector
	selectorBalanceOf = "0x70a08231"
	// totalSupply() selector
	selectorTotalSupply = "0x18160ddd"
)

// paramConstraintTestSetup holds IDs created during test setup.
type paramConstraintTestSetup struct {
	orgID         string
	groupID       string
	userID        string
	userDID       string
	contractAddr  string
	linkedAddress string
}

// setupParamConstraintTest creates the full RBAC hierarchy needed for parameter constraint testing:
// org -> group (with read+write claims) -> user membership -> contract -> ABI -> grant with param rules -> ETH address link.
func setupParamConstraintTest(t *testing.T, database *db.DB) *paramConstraintTestSetup {
	t.Helper()
	ctx := context.Background()

	setup := &paramConstraintTestSetup{
		orgID:         uuid.New().String(),
		groupID:       uuid.New().String(),
		userDID:       "did:privado:param_constraint_user",
		contractAddr:  "0x5555555555555555555555555555555555555555",
		linkedAddress: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}

	// 1. Create organization
	org := &rbac.Organization{
		ID:       setup.orgID,
		Slug:     "param-test-org",
		Name:     "Param Constraint Test Org",
		Settings: map[string]any{},
	}
	require.NoError(t, database.CreateOrganization(ctx, org))

	// 2. Create group
	group := &rbac.Group{
		ID:    setup.groupID,
		OrgID: setup.orgID,
		Slug:  "param-test-group",
		Name:  "Param Constraint Test Group",
		Depth: 0,
		Path:  "param-test-group",
	}
	require.NoError(t, database.CreateGroup(ctx, group))

	// 3. Set group access with read+write claims and eth_call method
	groupAccess := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        setup.groupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId"},
		Claims:         []rbac.Claim{},
	}
	require.NoError(t, database.CreateGroupAccess(ctx, groupAccess))

	// 4. Create user
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: setup.userDID,
		KYC:        true,
		Banned:     false,
		Metadata:   map[string]any{},
	}
	require.NoError(t, database.CreateUser(ctx, user))
	setup.userID = user.ID

	// 5. Add user to group
	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: setup.groupID,
		Source:  rbac.MembershipSourceAdmin,
	}
	require.NoError(t, database.CreateMembership(ctx, membership))

	// 6. Register contract in the org
	contractID := uuid.New().String()
	contract := &rbac.Contract{
		ID:       contractID,
		OrgID:    setup.orgID,
		Address:  strings.ToLower(setup.contractAddr),
		Name:     "Test ERC20",
		Metadata: map[string]any{},
	}
	require.NoError(t, database.CreateContract(ctx, contract))

	// 7. Set contract ABI (required for parameter constraint validation)
	require.NoError(t, database.UpdateContractABI(ctx, contractID, erc20ABI))

	// 8. Create contract grant with param constraints on balanceOf
	//    balanceOf(address) selector: 0x70a08231
	//    ParamRule: index 0 must be "self" (caller's linked ETH address)
	grant := &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    setup.groupID,
		Functions: []rbac.FunctionRule{
			{
				Selector: selectorBalanceOf,
				ParamRules: []rbac.ParamRule{
					{Index: 0, MustBe: "self"},
				},
			},
			{
				Selector: selectorTotalSupply,
				// No param rules - totalSupply() has no parameters
			},
		},
	}
	require.NoError(t, database.CreateContractGrant(ctx, grant))

	// 9. Link an ETH address to the user
	require.NoError(t, database.LinkEthAddress(ctx, setup.userDID, strings.ToLower(setup.linkedAddress), "test-sig", "test-hash-param"))

	return setup
}

// buildEthCallBody builds a JSON-RPC eth_call request body targeting a contract with the given calldata.
func buildEthCallBody(contractAddr, calldata string) []byte {
	reqBody := map[string]any{
		"jsonrpc": "2.0",
		"method":  "eth_call",
		"params": []any{
			map[string]any{
				"to":   contractAddr,
				"data": calldata,
			},
			"latest",
		},
		"id": 1,
	}
	body, _ := json.Marshal(reqBody)
	return body
}

// encodeBalanceOfCalldata encodes a balanceOf(address) call.
// Selector: 0x70a08231, then the address left-padded to 32 bytes.
func encodeBalanceOfCalldata(address string) string {
	// Remove 0x prefix from address, left-pad with zeros to 64 hex chars (32 bytes)
	addr := strings.TrimPrefix(strings.ToLower(address), "0x")
	padded := strings.Repeat("0", 64-len(addr)) + addr
	return selectorBalanceOf + padded
}

// encodeTotalSupplyCalldata encodes a totalSupply() call.
// Selector: 0x18160ddd, no parameters.
func encodeTotalSupplyCalldata() string {
	return selectorTotalSupply
}

// doRPCRequest sends a JSON-RPC request to the proxy with the given JWT token.
func doRPCRequest(t *testing.T, serverURL, token string, body []byte) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", serverURL+"/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err)

	respBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)

	return resp, respBody
}

// TestE2E_ParamConstraints_BalanceOfSelf tests that a user can call balanceOf
// with their own linked ETH address (param constraint "self" passes).
func TestE2E_ParamConstraints_BalanceOfSelf(t *testing.T) {
	userDID := "did:privado:param_constraint_user"
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	setup := setupParamConstraintTest(t, srv.DB())

	// Get JWT token for the user
	accessToken := getJWTToken(t, serverURL, setup.userDID)

	// Build eth_call with balanceOf(ownLinkedAddress)
	calldata := encodeBalanceOfCalldata(setup.linkedAddress)
	body := buildEthCallBody(setup.contractAddr, calldata)

	resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

	// The RBAC check should pass (param constraint satisfied).
	// The actual eth_call may fail with 502 if no node is running, or return
	// a JSON-RPC error from the node. Either way, it should NOT be 404 (opaque denial).
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
		"balanceOf(ownAddress) should not be denied; got response: %s", string(respBody))

	// Accept 200 (node responded) or 502 (node not running) as success
	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
		"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
}

// TestE2E_ParamConstraints_BalanceOfOther tests that a user cannot call balanceOf
// with an address that is NOT their linked ETH address (param constraint "self" fails).
func TestE2E_ParamConstraints_BalanceOfOther(t *testing.T) {
	userDID := "did:privado:param_constraint_user"
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	setup := setupParamConstraintTest(t, srv.DB())

	// Get JWT token for the user
	accessToken := getJWTToken(t, serverURL, setup.userDID)

	// Build eth_call with balanceOf(someOtherAddress) - NOT the linked address
	otherAddress := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	calldata := encodeBalanceOfCalldata(otherAddress)
	body := buildEthCallBody(setup.contractAddr, calldata)

	resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

	// The RBAC check should deny this because the address does not match the user's linked address.
	// Opaque 404 — no access control info leaked to caller.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"balanceOf(otherAddress) should return opaque 404; got response: %s", string(respBody))
	assertOpaqueErrorBody(t, respBody, "parameter constraint")
}

// TestE2E_ParamConstraints_TotalSupplyAllowed tests that a user can call totalSupply()
// which has no parameter constraints and is explicitly in the grant's function list.
func TestE2E_ParamConstraints_TotalSupplyAllowed(t *testing.T) {
	userDID := "did:privado:param_constraint_user"
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	setup := setupParamConstraintTest(t, srv.DB())

	// Get JWT token for the user
	accessToken := getJWTToken(t, serverURL, setup.userDID)

	// Build eth_call with totalSupply() - no parameters, no constraints
	calldata := encodeTotalSupplyCalldata()
	body := buildEthCallBody(setup.contractAddr, calldata)

	resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

	// totalSupply() is in the grant's function list with no param constraints, so it should pass RBAC.
	// It may fail with 502 if no node is running.
	assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
		"totalSupply() should not be denied; got response: %s", string(respBody))

	assert.True(t, resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadGateway,
		"expected 200 or 502, got %d: %s", resp.StatusCode, string(respBody))
}

// TestE2E_ParamConstraints_UnlistedFunctionDenied tests that a function NOT in the
// grant's function list is denied, even if it has no parameter constraints.
func TestE2E_ParamConstraints_UnlistedFunctionDenied(t *testing.T) {
	userDID := "did:privado:param_constraint_user"
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	setup := setupParamConstraintTest(t, srv.DB())

	// Get JWT token for the user
	accessToken := getJWTToken(t, serverURL, setup.userDID)

	// Build eth_call with transfer(address,uint256) selector: 0xa9059cbb
	// This function is NOT in the grant's allowed functions list
	transferSelector := "0xa9059cbb"
	// Encode: transfer(0xbbbb..., 100)
	toAddr := strings.TrimPrefix("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "0x")
	amount := fmt.Sprintf("%064x", 100)
	calldata := transferSelector + fmt.Sprintf("%064s", toAddr) + amount
	body := buildEthCallBody(setup.contractAddr, calldata)

	resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

	// The function selector is not in the grant's allowed list, so RBAC should deny.
	// Opaque 404 — no access control info leaked to caller.
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"transfer() should return opaque 404; got response: %s", string(respBody))
	assertOpaqueErrorBody(t, respBody, "function", "transfer", transferSelector)
}

// TestE2E_ParamConstraints_MultipleLinkedAddresses tests that param constraints work
// when the user has multiple linked ETH addresses. A call with any of the linked
// addresses should be allowed.
func TestE2E_ParamConstraints_MultipleLinkedAddresses(t *testing.T) {
	userDID := "did:privado:param_multi_addr_user"
	mockVerifier := &mockPrivadoVerifier{userDID: userDID}
	srv, serverURL, cleanup := setupE2EWithVerifier(t, mockVerifier)
	defer cleanup()

	ctx := context.Background()
	database := srv.DB()

	// Create full setup manually (different DID from the shared helper)
	orgID := uuid.New().String()
	groupID := uuid.New().String()
	contractAddr := "0x6666666666666666666666666666666666666666"
	linkedAddr1 := "0xcccccccccccccccccccccccccccccccccccccccc"
	linkedAddr2 := "0xdddddddddddddddddddddddddddddddddddddddd"

	// Org
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "param-multi-org", Name: "Multi Addr Org", Settings: map[string]any{},
	}))
	// Group
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: groupID, OrgID: orgID, Slug: "param-multi-group", Name: "Multi Addr Group", Depth: 0, Path: "param-multi-group",
	}))
	// Group Access
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: groupID,
		AllowedMethods: []string{"eth_call", "eth_getBalance", "eth_blockNumber", "eth_chainId"},
		Claims:         []rbac.Claim{},
	}))
	// User
	userID := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: userID, ExternalID: userDID, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	// Membership
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: userID, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	// Contract
	contractID := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: contractID, OrgID: orgID, Address: strings.ToLower(contractAddr),
		Name: "Multi Addr ERC20", Metadata: map[string]any{},
	}))
	require.NoError(t, database.UpdateContractABI(ctx, contractID, erc20ABI))
	// Grant with param constraints
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID,
		Functions: []rbac.FunctionRule{
			{Selector: selectorBalanceOf, ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}}},
		},
	}))
	// Link two ETH addresses
	require.NoError(t, database.LinkEthAddress(ctx, userDID, strings.ToLower(linkedAddr1), "sig1", "hash-multi-1"))
	require.NoError(t, database.LinkEthAddress(ctx, userDID, strings.ToLower(linkedAddr2), "sig2", "hash-multi-2"))

	// Get JWT token
	accessToken := getJWTToken(t, serverURL, userDID)

	t.Run("first linked address allowed", func(t *testing.T) {
		calldata := encodeBalanceOfCalldata(linkedAddr1)
		body := buildEthCallBody(contractAddr, calldata)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
			"balanceOf(linkedAddr1) should not be denied; got: %s", string(respBody))
	})

	t.Run("second linked address allowed", func(t *testing.T) {
		calldata := encodeBalanceOfCalldata(linkedAddr2)
		body := buildEthCallBody(contractAddr, calldata)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.NotEqual(t, http.StatusNotFound, resp.StatusCode,
			"balanceOf(linkedAddr2) should not be denied; got: %s", string(respBody))
	})

	t.Run("unlinked address denied", func(t *testing.T) {
		otherAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		calldata := encodeBalanceOfCalldata(otherAddr)
		body := buildEthCallBody(contractAddr, calldata)
		resp, respBody := doRPCRequest(t, serverURL, accessToken, body)

		assert.Equal(t, http.StatusNotFound, resp.StatusCode,
			"balanceOf(unlinkedAddr) should return opaque 404; got: %s", string(respBody))
		assertOpaqueErrorBody(t, respBody, "parameter constraint")
	})
}

// assertOpaqueErrorBody verifies the response contains the generic "method not found"
// error and does not leak any of the provided forbidden substrings.
func assertOpaqueErrorBody(t *testing.T, body []byte, forbiddenSubstrings ...string) {
	t.Helper()
	bodyStr := strings.ToLower(string(body))
	assert.Contains(t, bodyStr, "method not found",
		"response body should contain generic 'method not found' message")
	assert.NotContains(t, bodyStr, "access denied",
		"response body must not leak access denial details")
	assert.NotContains(t, bodyStr, "forbidden",
		"response body must not leak forbidden status")
	for _, s := range forbiddenSubstrings {
		assert.NotContains(t, bodyStr, strings.ToLower(s),
			"response body must not leak: %s", s)
	}
}
