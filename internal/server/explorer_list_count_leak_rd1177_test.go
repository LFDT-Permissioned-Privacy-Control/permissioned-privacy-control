package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1177 F1 & F3 — the list endpoints (/accounts, /tokens) must report the
// same per-viewer, visibility-aware activity counts as their already-correct
// single-item siblings (/addresses/:address/stats, /tokens/:address), never the
// raw DB aggregate. Same class as RD-1154, which hardened the single-item
// endpoints but missed the list siblings.

func setupRD1177AccountsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/accounts", srv.getExplorerAccounts)
	g.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	return r
}

func setupRD1177TokensRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v1/explorer")
	g.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	g.GET("/tokens", srv.getExplorerTokens)
	g.GET("/tokens/:address", srv.getExplorerToken)
	return r
}

// TestExplorerAccounts_CountsMatchSingleAddressSibling_RD1177 pins F1: the
// per-address counts in the /accounts list must equal the counts the
// /addresses/:address/stats endpoint reports for the same viewer, and must
// never be the raw address_stats aggregate.
//
// MUTATION CHECK: revert the Full-row recompute in getExplorerAccounts (return
// AddressStats as-is) and the list counts fall back to the raw 99, breaking
// both the parity and the "!= 99" assertions.
func TestExplorerAccounts_CountsMatchSingleAddressSibling_RD1177(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, explorerCoherenceExtraSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS logs; DROP TABLE IF EXISTS internal_transactions; DROP TABLE IF EXISTS token_transfers")
	})
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	subject := "0xc0ffee0000000000000000000000000000000a11"
	groupID := registerOrgContract(t, database, subject)

	aliceDID := "did:test:alice_acctcnt"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-acctcnt', 'Admins', 0, 'admins-acctcnt', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)
	addUserToGroup(t, database, aliceUserID, groupID)

	eveDID := "did:test:eve_acctcnt"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID)

	hiddenA := "0xdead000000000000000000000000000000000b01"
	hiddenB := "0xdead000000000000000000000000000000000b02"
	hiddenToken := "0xdead000000000000000000000000000000000b03"
	blockNum := seedExplorerBlock(t, conn)

	txHashes := []string{"0xacct_tx_0", "0xacct_tx_1", "0xacct_tx_2"}
	for i, h := range txHashes {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
			 VALUES ($1, $2, $3, $4, $5, 0, 21000, 1000, 1, '0x')`, h, blockNum, i, subject, hiddenA)
		require.NoError(t, err)
	}
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, txHashes[0], hiddenToken, subject, hiddenA, blockNum)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ($1, 0, $2, $3, $4, 2000, $5)`, txHashes[1], hiddenToken, subject, hiddenB, blockNum)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO internal_transactions (tx_hash, block_number, trace_address, from_address, to_address, value, call_type)
		 VALUES ($1, $2, '0', $3, $4, 5, 'CALL')`, txHashes[0], blockNum, subject, hiddenA)
	require.NoError(t, err)

	const rawAggregate = 99
	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract)
		 VALUES ($1, $2, $2, $2, 1, 1, true)`, subject, rawAggregate)
	require.NoError(t, err)

	router := setupRD1177AccountsRouter(srv)

	statsOf := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+subject+"/stats", nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var s explorer.AddressStats
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &s))
		return s
	}
	accountRowOf := func(t *testing.T, did string) explorer.AddressStats {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/accounts", nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var env struct {
			Data []explorer.AddressStats `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		for _, a := range env.Data {
			if strings.EqualFold(a.Address, subject) {
				return a
			}
		}
		t.Fatalf("subject %s not found in /accounts for %s: %s", subject, did, w.Body.String())
		return explorer.AddressStats{}
	}

	for _, did := range []string{aliceDID, eveDID} {
		did := did
		t.Run(did, func(t *testing.T) {
			stats := statsOf(t, did)
			row := accountRowOf(t, did)
			assert.Equal(t, stats.TxCount, row.TxCount, "accounts TxCount must match the single-address stats sibling")
			assert.Equal(t, stats.TokenTransferCount, row.TokenTransferCount, "accounts TokenTransferCount must match sibling")
			assert.Equal(t, stats.InternalTxCount, row.InternalTxCount, "accounts InternalTxCount must match sibling")
			assert.NotEqual(t, rawAggregate, row.TxCount, "accounts TxCount must not be the raw aggregate")
			assert.NotEqual(t, rawAggregate, row.TokenTransferCount, "accounts TokenTransferCount must not be the raw aggregate")
			assert.NotEqual(t, rawAggregate, row.InternalTxCount, "accounts InternalTxCount must not be the raw aggregate")
		})
	}
}

// TestExplorerTokensList_CountsMatchSingleTokenSibling_RD1177 pins F3: the
// holder/transfer counts in the /tokens list must equal the counts the
// /tokens/:address endpoint reports for the same viewer, never the raw
// tokens.transfer_count / holder_count aggregate.
//
// MUTATION CHECK: revert the Full-token recompute in getExplorerTokens (the new
// default branch) and the list counts fall back to the raw 50/10, breaking both
// the parity and the "!= raw" assertions.
func TestExplorerTokensList_CountsMatchSingleTokenSibling_RD1177(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, tokenSchema)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(),
			"DROP TABLE IF EXISTS token_transfers; DROP TABLE IF EXISTS token_balances; DROP TABLE IF EXISTS tokens")
	})
	_, err = conn.ExecContext(ctx, "TRUNCATE tokens, token_balances, token_transfers CASCADE")
	require.NoError(t, err)

	token := "0xc0ffee0000000000000000000000000000000abd"
	groupID := registerOrgContract(t, database, token)

	aliceDID := "did:test:alice_toklist"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-toklist', 'Admins', 0, 'admins-toklist', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)
	addUserToGroup(t, database, aliceUserID, groupID)

	eveDID := "did:test:eve_toklist"
	eveUserID := createTestUserForExplorer(t, database, eveDID)
	addUserToGroup(t, database, eveUserID, groupID)

	hiddenA := "0xdead000000000000000000000000000000000c01"
	hiddenB := "0xdead000000000000000000000000000000000c02"
	blockNum := seedExplorerBlock(t, conn)

	seedToken(t, conn, token, "TKN", "Test Token", "ERC-20")
	const rawTransfers, rawHolders = 50, 10

	txHashes := []string{"0xtoklist_0", "0xtoklist_1", "0xtoklist_2"}
	parties := [][2]string{{hiddenA, hiddenB}, {hiddenB, hiddenA}, {hiddenA, hiddenB}}
	for i, h := range txHashes {
		seedExplorerTransaction(t, conn, blockNum, h, parties[i][0], parties[i][1])
		_, err = conn.ExecContext(ctx,
			`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
			 VALUES ($1, 0, $2, $3, $4, 1000, $5)`, h, token, parties[i][0], parties[i][1], blockNum)
		require.NoError(t, err)
	}
	for _, holder := range []string{hiddenA, hiddenB} {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO token_balances (address, token_address, block_number, balance) VALUES ($1, $2, $3, 1000)`,
			holder, token, blockNum)
		require.NoError(t, err)
	}

	router := setupRD1177TokensRouter(srv)

	singleTokenOf := func(t *testing.T, did string) explorer.Token {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/tokens/"+token, nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var tok explorer.Token
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tok))
		return tok
	}
	listTokenRowOf := func(t *testing.T, did string) explorer.Token {
		t.Helper()
		req := httptest.NewRequest("GET", "/api/v1/explorer/tokens", nil)
		addBearerToken(t, req, srv, did)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
		var env struct {
			Data []explorer.Token `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env))
		for _, tk := range env.Data {
			if strings.EqualFold(tk.Address, token) {
				return tk
			}
		}
		t.Fatalf("token %s not found in /tokens for %s: %s", token, did, w.Body.String())
		return explorer.Token{}
	}

	for _, did := range []string{aliceDID, eveDID} {
		did := did
		t.Run(did, func(t *testing.T) {
			single := singleTokenOf(t, did)
			row := listTokenRowOf(t, did)
			assert.Equal(t, single.TransferCount, row.TransferCount, "tokens list TransferCount must match the single-token sibling")
			assert.Equal(t, single.HolderCount, row.HolderCount, "tokens list HolderCount must match the single-token sibling")
			assert.NotEqual(t, rawTransfers, row.TransferCount, "tokens list TransferCount must not be the raw aggregate")
			assert.NotEqual(t, rawHolders, row.HolderCount, "tokens list HolderCount must not be the raw aggregate")
		})
	}
}
