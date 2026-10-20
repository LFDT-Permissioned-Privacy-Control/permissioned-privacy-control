package server

import (
	"context"
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

// setupAddressStatsRouter creates a gin router with the address stats endpoint.
func setupAddressStatsRouter(srv *Server) *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	explorerGroup := router.Group("/api/v1/explorer")
	explorerGroup.Use(auth.OptionalJWTAuthMiddleware(srv.jwtService, srv.db))
	explorerGroup.GET("/addresses/:address/stats", srv.getExplorerAddressStats)
	return router
}

// addressStatsSchema extends the base explorer schema with the address_stats table.
const addressStatsSchema = `
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

// TestExplorerAddressStats_TxCountVisibilityFiltered verifies that the
// transaction count in the address stats response is the live filtered count
// from the transactions table, not the pre-computed address_stats.tx_count.
// Regression test for G22.
func TestExplorerAddressStats_TxCountVisibilityFiltered(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	// --- RBAC: register a private org contract ---
	privateContract := "0xaaaa000000000000000000000000000000000099"
	groupID := registerOrgContract(t, database, privateContract)

	aliceDID := "did:test:alice_stats"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)

	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-stats', 'Admins', 0, 'admins-stats', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)

	bobDID := "did:test:bob_stats"
	_ = createTestUserForExplorer(t, database, bobDID)

	// --- Explorer data ---
	publicAddr := "0xbbbb000000000000000000000000000000000099"
	publicCounterparty := "0xcccc000000000000000000000000000000000099"

	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (50, '0xblock50_stats', '0x0', 5000, 21000, 30000000, 3, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// 3 transactions involving publicAddr (all public-to-public).
	for i := 0; i < 3; i++ {
		_, err = conn.ExecContext(ctx,
			`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
			 VALUES ($1, 50, $2, $3, $4, 0, 21000, 1000, 1, '0x')`,
			"0xtx_stats_pub_"+string(rune('a'+i)), i, publicAddr, publicCounterparty)
		require.NoError(t, err)
	}

	// address_stats with inflated tx_count=12 (simulates raw/stale count).
	// Before the fix, the handler returned this raw value directly.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract)
		 VALUES ($1, 12, 5, 8, 5000, 5000, false)`, publicAddr)
	require.NoError(t, err)

	router := setupAddressStatsRouter(srv)

	t.Run("anonymous viewer gets 404 for unregistered address (private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+publicAddr+"/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"unregistered address should return 404 (private by default)")
	})

	t.Run("authenticated admin gets 404 for unregistered address (private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+publicAddr+"/stats", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"unregistered address should return 404 even for admin (private by default)")
	})

	t.Run("outsider gets 404 for unregistered address (private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+publicAddr+"/stats", nil)
		addBearerToken(t, req, srv, bobDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"unregistered address should return 404 for outsider (private by default)")
	})
}

// TestExplorerAddressStats_TxCountDiffersWithHiddenDeployer verifies that
// contract creation txs from a hidden deployer are excluded from the tx count
// for an anonymous viewer but included for an org admin.
func TestExplorerAddressStats_TxCountDiffersWithHiddenDeployer(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	_, err := conn.ExecContext(ctx, addressStatsSchema)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx, "TRUNCATE address_stats CASCADE")
	require.NoError(t, err)

	// Register a private deployer.
	hiddenDeployer := "0xaaaa000000000000000000000000000000000088"
	groupID := registerOrgContract(t, database, hiddenDeployer)

	// Alice is admin of the deployer's org.
	aliceDID := "did:test:alice_deploy"
	aliceUserID := createTestUserForExplorer(t, database, aliceDID)

	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-deploy', 'Admins', 0, 'admins-deploy', true)",
		adminGroupID, groupID)
	require.NoError(t, err)
	addUserToGroup(t, database, aliceUserID, adminGroupID)

	// We query stats for hiddenDeployer. Anonymous viewers get 404 (pre-auth).
	// Alice can see it because GetBatchVisibilityDetailed also checks contract_grants,
	// but the admin group doesn't have one. So we need to add alice to a group
	// that has a contract_grant on hiddenDeployer.
	addUserToGroup(t, database, aliceUserID, groupID)

	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (70, '0xblock70_deploy', '0x0', 7000, 21000, 30000000, 4, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	publicAddr := "0xeeee000000000000000000000000000000000088"

	// tx1-tx2: hiddenDeployer deploys contracts (to=NULL).
	// SQL filter: for anonymous, deployer is hidden => DROPPED.
	// For alice (admin), deployer is NOT hidden => kept.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_deploy1', 70, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, hiddenDeployer)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_deploy2', 70, 1, $1, NULL, 0, 21000, 1000, 1, '0x')`, hiddenDeployer)
	require.NoError(t, err)

	// tx3-tx4: hiddenDeployer <-> publicAddr.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_deploy3', 70, 2, $1, $2, 0, 21000, 1000, 1, '0x')`, hiddenDeployer, publicAddr)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_deploy4', 70, 3, $1, $2, 0, 21000, 1000, 1, '0x')`, publicAddr, hiddenDeployer)
	require.NoError(t, err)

	// address_stats with inflated count.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO address_stats (address, tx_count, first_seen, last_seen, is_contract)
		 VALUES ($1, 20, 7000, 7000, true)`, hiddenDeployer)
	require.NoError(t, err)

	router := setupAddressStatsRouter(srv)

	t.Run("admin sees live filtered count of 4", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+hiddenDeployer+"/stats", nil)
		addBearerToken(t, req, srv, aliceDID)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)

		var stats explorer.AddressStats
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stats))

		assert.Equal(t, 4, stats.TxCount,
			"admin should see all 4 txs (live count), not raw address_stats total (20)")
	})

	t.Run("anonymous gets 404 for hidden address", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/addresses/"+hiddenDeployer+"/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
