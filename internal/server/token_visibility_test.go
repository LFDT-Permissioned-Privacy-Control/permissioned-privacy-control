package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tokenSchema creates the explorer tables needed for token tests.
const tokenSchema = `
CREATE TABLE IF NOT EXISTS tokens (
    address TEXT PRIMARY KEY,
    symbol TEXT NOT NULL,
    name TEXT,
    decimals INT NOT NULL DEFAULT 18,
    token_type TEXT NOT NULL DEFAULT 'ERC-20',
    total_supply TEXT,
    holder_count INT NOT NULL DEFAULT 0,
    transfer_count INT NOT NULL DEFAULT 0,
    usd_price DOUBLE PRECISION,
    icon_url TEXT,
    l1_address TEXT,
    block_number BIGINT NOT NULL DEFAULT 0,
    creation_tx TEXT,
    off_chain_updated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS token_balances (
    address TEXT NOT NULL,
    token_address TEXT NOT NULL,
    block_number BIGINT NOT NULL DEFAULT 0,
    balance NUMERIC(78, 0) NOT NULL DEFAULT 0,
    PRIMARY KEY (address, token_address)
);

CREATE TABLE IF NOT EXISTS token_transfers (
    id BIGSERIAL PRIMARY KEY,
    tx_hash TEXT NOT NULL,
    log_index INT NOT NULL,
    token_address TEXT NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    value NUMERIC(78, 0) NOT NULL DEFAULT 0,
    block_number BIGINT NOT NULL DEFAULT 0,
    timestamp BIGINT,
    transfer_type TEXT NOT NULL DEFAULT 'transfer',
    token_type TEXT NOT NULL DEFAULT 'ERC-20',
    token_id TEXT,
    is_internal BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS address_stats (
    address TEXT PRIMARY KEY,
    tx_count INT NOT NULL DEFAULT 0,
    internal_tx_count INT NOT NULL DEFAULT 0,
    token_transfer_count INT NOT NULL DEFAULT 0,
    first_seen BIGINT,
    last_seen BIGINT,
    is_contract BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMP DEFAULT NOW()
);
`

// setupTokenTestServer creates a test server with explorer store for token tests.
func setupTokenTestServer(t *testing.T) (*Server, *sql.DB) {
	t.Helper()
	srv, database, conn := setupTestServerForExplorerTransactions(t)

	// Create token-specific explorer tables.
	_, err := conn.ExecContext(context.Background(), tokenSchema)
	require.NoError(t, err, "failed to create token schema")

	// Truncate for isolation.
	_, err = conn.ExecContext(context.Background(),
		"TRUNCATE tokens, token_balances, token_transfers, address_stats CASCADE")
	require.NoError(t, err)

	_ = database // keep reference alive; cleanup registered in setupTestServerForExplorerTransactions
	return srv, conn
}

// setupTokenRouter creates a gin router with token endpoints.
func setupTokenRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/tokens", srv.getExplorerTokens)
	explorerGroup.GET("/tokens/:address", srv.getExplorerToken)
	explorerGroup.GET("/tokens/:address/holders", srv.getExplorerTokenHolders)
	explorerGroup.GET("/tokens/:address/transfers", srv.getExplorerTokenTransfers)
	return router
}

// seedToken inserts a token into the explorer tokens table.
func seedToken(t *testing.T, conn *sql.DB, address, symbol, name, tokenType string) {
	t.Helper()
	_, err := conn.ExecContext(context.Background(),
		`INSERT INTO tokens (address, symbol, name, decimals, token_type, total_supply, holder_count, transfer_count, block_number)
		 VALUES ($1, $2, $3, 18, $4, '1000000', 10, 50, 1)`,
		address, symbol, name, tokenType)
	require.NoError(t, err)
}

// parseTokenListResponse unmarshals a paginated token list response.
func parseTokenListResponse(t *testing.T, body []byte) (int, []explorer.Token) {
	t.Helper()
	var resp struct {
		Data  []explorer.Token `json:"data"`
		Total int              `json:"total"`
	}
	require.NoError(t, json.Unmarshal(body, &resp))
	return resp.Total, resp.Data
}

// TestTokenList_AnonymousViewer_OrgTokenRedacted verifies that an anonymous viewer
// sees org-owned tokens with redacted fields (address=[PRIVATE], name/symbol stripped).
func TestTokenList_AnonymousViewer_OrgTokenRedacted(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	// Create an org contract in the RBAC DB for this address.
	privateAddr := "0xaaaa000000000000000000000000000000000099"
	registerOrgContract(t, srv.db, privateAddr)

	// Also insert the token in the explorer DB.
	seedToken(t, conn, privateAddr, "PRV", "Private Token", "ERC-20")

	// Insert a public token too.
	publicAddr := "0xbbbb000000000000000000000000000000000099"
	seedToken(t, conn, publicAddr, "PUB", "Public Token", "ERC-20")

	// Anonymous request (no JWT).
	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	total, tokens := parseTokenListResponse(t, w.Body.Bytes())

	// With all-private-by-default: unregistered token is Hidden (dropped),
	// org token is Redacted (visible but redacted). Only 1 token should appear.
	require.Len(t, tokens, 1, "only org token should appear (redacted); unregistered token is dropped")
	assert.Equal(t, 1, total, "total must reflect filtered count")

	// The one remaining token should be the redacted org token.
	tok := tokens[0]
	assert.Equal(t, "[PRIVATE]", tok.Address, "org token should be redacted")
	assert.Empty(t, tok.Symbol, "symbol should be empty for redacted token")
	assert.Nil(t, tok.Name, "name should be nil for redacted token")
	assert.Nil(t, tok.CreationTx, "creationTx should be nil for redacted token")
	assert.Nil(t, tok.L1Address, "l1Address should be nil for redacted token")
	assert.Nil(t, tok.TotalSupply, "totalSupply should be nil for redacted token")
	assert.Equal(t, 0, tok.HolderCount, "holderCount should be 0 for redacted token")
	assert.Equal(t, 0, tok.TransferCount, "transferCount should be 0 for redacted token")
}

// TestTokenList_AdminViewer_SeesFullTokenDetails verifies that an admin of the
// org sees the token with all fields intact.
func TestTokenList_AdminViewer_SeesFullTokenDetails(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)
	ctx := context.Background()

	// Register org contract.
	privateAddr := "0xaaaa000000000000000000000000000000000088"
	groupID := registerOrgContract(t, srv.db, privateAddr)

	// Create admin user and make them org admin.
	adminDID := "did:test:tokenadmin"
	adminUserID := createTestUserForExplorer(t, srv.db, adminDID)
	adminGroupID := uuid.New().String()
	_, err := srv.db.Conn().ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'token-admins', 'Token Admins', 0, 'token-admins', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, srv.db, adminUserID, adminGroupID)

	// Seed the token in explorer DB.
	seedToken(t, conn, privateAddr, "PRV", "Private Token", "ERC-20")

	// Authenticated request with admin JWT.
	jwt := issueTestJWT(t, srv, adminDID)
	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	total, tokens := parseTokenListResponse(t, w.Body.Bytes())

	require.Len(t, tokens, 1)
	assert.Equal(t, 1, total)
	assert.Equal(t, privateAddr, tokens[0].Address, "admin should see real address")
	assert.Equal(t, "PRV", tokens[0].Symbol, "admin should see full symbol")
	assert.NotNil(t, tokens[0].Name, "admin should see token name")
}

// TestTokenList_HiddenTokenExcluded verifies that tokens whose address resolves
// to VisibilityHidden are completely excluded from the list.
func TestTokenList_HiddenTokenExcluded(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	// Create a user and link an EOA — user EOAs are Hidden to everyone except the owner.
	hiddenAddr := "0xeeee000000000000000000000000000000000001"
	createTestUserForExplorer(t, srv.db, "did:test:eoa-owner")
	linkEthAddressToUser(t, srv.db, "did:test:eoa-owner", hiddenAddr)

	// Seed a token at that address in the explorer DB.
	seedToken(t, conn, hiddenAddr, "HID", "Hidden Token", "ERC-20")

	// Also seed a public token.
	publicAddr := "0xffff000000000000000000000000000000000001"
	seedToken(t, conn, publicAddr, "PUB", "Public Token", "ERC-20")

	// Anonymous request.
	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	total, tokens := parseTokenListResponse(t, w.Body.Bytes())

	// With all-private-by-default, both the EOA-linked token (Hidden) and the
	// unregistered "public" token (Hidden) are dropped.
	assert.Equal(t, 0, total, "both tokens should be hidden (all private by default)")
	require.Len(t, tokens, 0)
}

// TestTokenSingle_HiddenReturns404 verifies that GET /tokens/:address returns
// 404 for a token whose address is VisibilityHidden.
func TestTokenSingle_HiddenReturns404(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	// Create a user and link an EOA.
	hiddenAddr := "0xeeee000000000000000000000000000000000002"
	createTestUserForExplorer(t, srv.db, "did:test:eoa-hidden-single")
	linkEthAddressToUser(t, srv.db, "did:test:eoa-hidden-single", hiddenAddr)

	seedToken(t, conn, hiddenAddr, "HID", "Hidden Token", "ERC-20")

	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+hiddenAddr, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "hidden token should return 404")
}

// TestTokenSingle_RedactedReturns404 pins the M12 fix: pre-fix this
// endpoint returned 200-with-masked-fields when the token's
// visibility was Redacted, creating an enumeration oracle (200 →
// "registered to some org", 404 → "not registered"). The same shape
// G16 closed for /check-address. Now Hidden AND Redacted both return
// 404 so an attacker cannot distinguish the two.
func TestTokenSingle_RedactedReturns404(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	// Register an org contract (Redacted for anonymous viewers).
	privateAddr := "0xaaaa000000000000000000000000000000000077"
	registerOrgContract(t, srv.db, privateAddr)

	seedToken(t, conn, privateAddr, "PRV", "Private Token", "ERC-20")

	// Anonymous request — visibility resolves to Redacted.
	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+privateAddr, nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code,
		"Redacted token must return 404 (same shape as Hidden) to avoid the enumeration oracle")
}

// TestTokenHolders_HiddenTokenReturns404 verifies that the holders endpoint
// returns 404 when the token address is VisibilityHidden.
func TestTokenHolders_HiddenTokenReturns404(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	hiddenAddr := "0xeeee000000000000000000000000000000000003"
	createTestUserForExplorer(t, srv.db, "did:test:eoa-holder-hidden")
	linkEthAddressToUser(t, srv.db, "did:test:eoa-holder-hidden", hiddenAddr)

	seedToken(t, conn, hiddenAddr, "HID", "Hidden Token", "ERC-20")

	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+hiddenAddr+"/holders", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "hidden token holders should return 404")
}

// TestTokenHolders_RedactedTokenReturns404 verifies that the holders endpoint
// returns 404 when the token address is VisibilityRedacted (org contract, anonymous viewer).
func TestTokenHolders_RedactedTokenReturns404(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	privateAddr := "0xaaaa000000000000000000000000000000000066"
	registerOrgContract(t, srv.db, privateAddr)
	seedToken(t, conn, privateAddr, "PRV", "Private Token", "ERC-20")

	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+privateAddr+"/holders", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "redacted token holders should return 404")
}

// TestTokenTransfers_HiddenTokenReturns404 verifies that the transfers endpoint
// returns 404 when the token address is VisibilityHidden.
func TestTokenTransfers_HiddenTokenReturns404(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	hiddenAddr := "0xeeee000000000000000000000000000000000004"
	createTestUserForExplorer(t, srv.db, "did:test:eoa-transfer-hidden")
	linkEthAddressToUser(t, srv.db, "did:test:eoa-transfer-hidden", hiddenAddr)

	seedToken(t, conn, hiddenAddr, "HID", "Hidden Token", "ERC-20")

	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+hiddenAddr+"/transfers", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code, "hidden token transfers should return 404")
}

// TestTokenList_TotalReflectsFilteredCount verifies that the "total" field in the
// token list response reflects the filtered count, never the raw DB count.
func TestTokenList_TotalReflectsFilteredCount(t *testing.T) {
	srv, conn := setupTokenTestServer(t)
	router := setupTokenRouter(srv)

	// Seed 3 tokens: 1 public, 1 org-owned (redacted), 1 user-EOA (hidden).
	publicAddr := "0xbbbb000000000000000000000000000000000055"
	seedToken(t, conn, publicAddr, "PUB", "Public Token", "ERC-20")

	orgAddr := "0xaaaa000000000000000000000000000000000055"
	registerOrgContract(t, srv.db, orgAddr)
	seedToken(t, conn, orgAddr, "ORG", "Org Token", "ERC-20")

	hiddenAddr := "0xeeee000000000000000000000000000000000055"
	createTestUserForExplorer(t, srv.db, "did:test:eoa-count")
	linkEthAddressToUser(t, srv.db, "did:test:eoa-count", hiddenAddr)
	seedToken(t, conn, hiddenAddr, "HID", "Hidden Token", "ERC-20")

	// Anonymous request.
	req := httptest.NewRequest("GET", "/api/v1/explorer/tokens", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	total, tokens := parseTokenListResponse(t, w.Body.Bytes())

	// With all-private-by-default: unregistered is Hidden (dropped),
	// org token is Redacted (visible), EOA-linked is Hidden (dropped).
	// Only the redacted org token remains.
	assert.Equal(t, 1, total, "total must be 1 (only redacted org token), not 3 (raw DB count)")
	assert.Len(t, tokens, 1, "should have 1 token in data")

	// Verify the hidden token addresses don't appear.
	for _, tok := range tokens {
		assert.NotEqual(t, hiddenAddr, tok.Address, "hidden token address must not leak")
		assert.NotEqual(t, publicAddr, tok.Address, "unregistered token address must not leak")
	}
}
