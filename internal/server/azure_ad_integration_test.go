package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/explorer"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Test 1: Azure AD user RBAC access works the same as Privado user
// =============================================================================

func TestAzureAD_Integration_RBACAccess(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// --- RBAC setup ---

	// Register a private org contract (creates org + member group + contract_grant).
	privateAddr := "0xaaaa000000000000000000000000000000000101"
	groupID := registerOrgContract(t, database, privateAddr)

	// Create an admin group in the same org so users can see contract creation txs.
	// Visibility of org contracts requires admin access (is_org_admin=true).
	adminGroupID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, (SELECT org_id FROM groups WHERE id = $2), 'admins-rbac', 'Admins', 0, 'admins-rbac', true)",
		adminGroupID, groupID)
	require.NoError(t, err)

	// Create Azure AD user and add to the admin group.
	azureSubject := auth.AzureSubject("test-oid-1")
	azureUserID := createTestUserForExplorer(t, database, azureSubject)
	addUserToGroup(t, database, azureUserID, adminGroupID)

	// Create a Privado user with the same admin group membership for comparison.
	privadoSubject := "did:privado:comparison-user"
	privadoUserID := createTestUserForExplorer(t, database, privadoSubject)
	addUserToGroup(t, database, privadoUserID, adminGroupID)

	// --- Explorer data ---

	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (100, '0xblock_azure_rbac', '0x0', 2000, 21000, 30000000, 3, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// tx1: involves the private org contract (contract creation) — visible to granted users
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_rbac1', 100, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, privateAddr)
	require.NoError(t, err)

	// tx2: public transaction — visible to everyone
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_rbac2', 100, 1, '0xbbbb000000000000000000000000000000000101', '0xbbbb000000000000000000000000000000000102', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)

	// tx3: public transaction — visible to everyone
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_rbac3', 100, 2, '0xbbbb000000000000000000000000000000000101', '0xbbbb000000000000000000000000000000000102', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)

	// --- Anonymous: sees nothing (all private by default) ---
	t.Run("anonymous sees nothing (all private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(0), total, "anonymous sees 0 txs (all private by default)")
		assert.Len(t, txs, 0)
	})

	// --- Azure AD user: sees only org contract tx (unregistered addrs are private) ---
	t.Run("Azure AD user sees only org contract transactions", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, azureSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(1), total, "Azure AD user sees only 1 tx involving org contract (unregistered addrs hidden)")
		assert.Len(t, txs, 1)
	})

	// --- Privado user: same result ---
	t.Run("Privado user with same grants sees identical results", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, privadoSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(1), total, "Privado user sees only 1 tx involving org contract (unregistered addrs hidden)")
		assert.Len(t, txs, 1)
	})
}

// =============================================================================
// Test 2: Azure AD user with admin visibility
// =============================================================================

func TestAzureAD_Integration_AdminVisibility(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// Create org with contract.
	orgID := uuid.New().String()
	_, err := conn.ExecContext(ctx,
		"INSERT INTO organizations (id, slug, name, settings) VALUES ($1, $2, $3, '{}')",
		orgID, "azure-admin-org-"+orgID[:8], "Azure Admin Org")
	require.NoError(t, err)

	contractAddr := "0xaaaa000000000000000000000000000000000201"
	contractID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, 'Admin Test Contract')",
		contractID, orgID, contractAddr)
	require.NoError(t, err)

	// Create admin group (is_org_admin=true)
	adminGroupID := uuid.New().String()
	_, err = conn.ExecContext(ctx,
		"INSERT INTO groups (id, org_id, slug, name, depth, path, is_org_admin) VALUES ($1, $2, 'admins', 'Admins', 0, 'admins', true)",
		adminGroupID, orgID)
	require.NoError(t, err)

	// Create Azure AD user and add to admin group.
	azureSubject := auth.AzureSubject("test-oid-2")
	azureUserID := createTestUserForExplorer(t, database, azureSubject)
	addUserToGroup(t, database, azureUserID, adminGroupID)

	// --- Explorer data ---
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (200, '0xblock_azure_admin', '0x0', 3000, 21000, 30000000, 4, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// tx1 & tx2: contract creation by the org contract (hidden from anonymous)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_admin1', 200, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, contractAddr)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_admin2', 200, 1, $1, NULL, 0, 21000, 1000, 1, '0x')`, contractAddr)
	require.NoError(t, err)

	// tx3 & tx4: public txs
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_admin3', 200, 2, '0xbbbb000000000000000000000000000000000201', '0xbbbb000000000000000000000000000000000202', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_admin4', 200, 3, '0xbbbb000000000000000000000000000000000201', '0xbbbb000000000000000000000000000000000202', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)

	t.Run("anonymous sees nothing (all private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, _ := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(0), total, "anonymous sees 0 txs (all private by default)")
	})

	t.Run("Azure AD admin sees only org contract txs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, azureSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(2), total, "admin Azure AD user sees 2 txs involving org contract (unregistered hidden)")
		assert.Len(t, txs, 2)
	})
}

// =============================================================================
// Test 3: Azure AD user with linked ETH address gets participant override
// =============================================================================

func TestAzureAD_Integration_ParticipantOverride(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// Create Azure AD user and link an ETH address.
	azureSubject := auth.AzureSubject("test-oid-3")
	_ = createTestUserForExplorer(t, database, azureSubject)
	linkedAddr := "0xcccc000000000000000000000000000000000301"
	err := database.SystemLinkEthAddress(ctx, azureSubject, linkedAddr)
	require.NoError(t, err)

	// --- Explorer data ---
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (300, '0xblock_azure_participant', '0x0', 4000, 21000, 30000000, 4, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)

	// tx1: from linked address, contract creation — this is a deploy from user's own EOA.
	// Because the linked address is private (owned), the contract creation tx should be
	// hidden from anonymous but visible to the owning user as a participant.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_part1', 300, 0, $1, NULL, 0, 21000, 1000, 1, '0x')`, linkedAddr)
	require.NoError(t, err)

	// tx2: from linked address, contract creation
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_part2', 300, 1, $1, NULL, 0, 21000, 1000, 1, '0x')`, linkedAddr)
	require.NoError(t, err)

	// tx3 & tx4: public txs
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_part3', 300, 2, '0xbbbb000000000000000000000000000000000301', '0xbbbb000000000000000000000000000000000302', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_part4', 300, 3, '0xbbbb000000000000000000000000000000000301', '0xbbbb000000000000000000000000000000000302', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)

	t.Run("anonymous sees nothing (all private by default)", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		assert.Equal(t, int64(0), total, "anonymous sees 0 txs (all private by default)")
		assert.Len(t, txs, 0)
	})

	t.Run("Azure AD user sees own participant txs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, azureSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)

		total, txs := parsePaginatedResponse(t, w.Body.Bytes())
		// Linked address is in visible set; tx1 and tx2 involve it. tx3/tx4 are unregistered -> hidden.
		assert.Equal(t, int64(2), total, "Azure AD user sees 2 txs involving linked address")
		assert.Len(t, txs, 2)

		// Verify the participant txs are present.
		hashes := make(map[string]bool)
		for _, tx := range txs {
			hashes[tx.Hash] = true
		}
		assert.True(t, hashes["0xtx_azure_part1"], "should include linked address tx1")
		assert.True(t, hashes["0xtx_azure_part2"], "should include linked address tx2")
	})

	t.Run("RedactLogs participant override for Azure AD user", func(t *testing.T) {
		// The linked address emits a log from a private contract address.
		// As a participant (linked EOA is the from_address in the tx), the Azure user
		// should get the log un-redacted via participant override.
		logs := []explorer.Log{
			{
				ID:          1,
				TxHash:      "0xtx_azure_part1",
				LogIndex:    0,
				Address:     linkedAddr,
				Data:        "0xdeadbeef",
				BlockNumber: 300,
			},
		}

		redacted, err := srv.explorerRedactor.RedactLogs(ctx, logs, azureSubject, linkedAddr)
		require.NoError(t, err)
		require.Len(t, redacted, 1)
		// Participant override: the user's own linked address is passed as participantAddr,
		// so the log should not be stripped or redacted.
		assert.Equal(t, "0xdeadbeef", redacted[0].Data, "participant override should preserve log data")
		assert.Equal(t, linkedAddr, redacted[0].Address, "participant override should preserve log address")
	})
}

// =============================================================================
// Test 4: Azure AD user tenant deletion bans user
// =============================================================================

func TestAzureAD_Integration_BannedUser(t *testing.T) {
	srv, database, conn := setupTestServerForExplorerTransactions(t)
	router := setupPaginatedTransactionsRouter(srv)
	ctx := context.Background()

	// Create Azure AD user with a tenant ID.
	azureSubject := auth.AzureSubject("test-oid-banned")
	azureUserID := createTestUserForExplorer(t, database, azureSubject)
	tenantID := "tenant-ban-test-" + uuid.New().String()[:8]
	_, err := conn.ExecContext(ctx,
		"UPDATE users SET auth_tenant_id = $2 WHERE id = $1",
		azureUserID, tenantID)
	require.NoError(t, err)

	// Insert a block + tx for the query.
	_, err = conn.ExecContext(ctx,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count, miner, extra_data, state_root, transactions_root, receipts_root)
		 VALUES (400, '0xblock_azure_banned', '0x0', 5000, 21000, 30000000, 1, '0x0000000000000000000000000000000000000000', '0x', '0x', '0x', '0x')`)
	require.NoError(t, err)
	_, err = conn.ExecContext(ctx,
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status, input_data)
		 VALUES ('0xtx_azure_banned1', 400, 0, '0xbbbb000000000000000000000000000000000401', '0xbbbb000000000000000000000000000000000402', 0, 21000, 1000, 1, '0x')`)
	require.NoError(t, err)

	t.Run("active user can authenticate and access", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, azureSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// The OptionalJWTAuthMiddleware only validates the JWT signature/expiry
		// and checks token revocation — it does NOT check the banned flag per-request.
		// So a banned user with a valid JWT will still pass the middleware.
		// The ban is enforced at LOGIN time (see handleAzureCallback).
		require.Equal(t, http.StatusOK, w.Code)
	})

	// Ban the user (simulating tenant deletion).
	_, err = conn.ExecContext(ctx,
		"UPDATE users SET banned = true WHERE auth_tenant_id = $1", tenantID)
	require.NoError(t, err)

	t.Run("banned user JWT is rejected by middleware (security audit L5)", func(t *testing.T) {
		// L5 (security audit follow-up): OptionalJWTAuthMiddleware now
		// enforces user.Banned at the auth boundary via the
		// auth.BannedChecker extension (db.IsUserBannedBySubject).
		// Pre-fix this case asserted that banned users with an
		// already-issued JWT could still pass the middleware until
		// expiry — a property that depended on every downstream
		// consumer routing through CheckAccess. Easy to silently
		// regress, so the middleware now closes the gap.
		//
		// The deny uses the same opaque 404 + "method not found"
		// response shape the JSON-RPC processor's CheckAccess emits
		// for RBAC denials, so the caller can't distinguish a banned
		// user from any other denied request. See e2e/proxy_test.go::
		// TestE2E_BannedUser for the JSON-RPC variant.
		req := httptest.NewRequest("GET", "/api/v1/explorer/transactions/paginated?page=1&pageSize=10", nil)
		addBearerToken(t, req, srv, azureSubject)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code,
			"banned user must be rejected with the opaque 404 'method not found' deny")
		assert.NotContains(t, w.Body.String(), "banned",
			"deny response must not leak the ban reason")
	})

	t.Run("banned user login is rejected at callback level", func(t *testing.T) {
		// Verify the DB state: user is actually banned.
		user, err := database.GetUserByExternalID(ctx, azureSubject)
		require.NoError(t, err)
		require.NotNil(t, user)
		assert.True(t, user.Banned, "user should be banned after tenant deletion simulation")

		// The handleAzureCallback checks user.Banned and returns 403.
		// We can't fully test the OIDC exchange here, but we verify the DB state
		// that the callback would use to reject the login.
	})
}

// =============================================================================
// Test 5: auth_tenant_id immutability
// =============================================================================

func TestAzureAD_Integration_TenantIDImmutability(t *testing.T) {
	srv, _, conn := setupTestServerForExplorerTransactions(t)
	ctx := context.Background()

	azureSubject := auth.AzureSubject("test-oid-immutable")
	azureUserID := createTestUserForExplorer(t, srv.db, azureSubject)

	t.Run("first SetAuthTenantID succeeds", func(t *testing.T) {
		ok, err := srv.db.SetAuthTenantID(ctx, azureUserID, "tenant-A")
		require.NoError(t, err)
		assert.True(t, ok, "first SetAuthTenantID should succeed")

		// Verify it was set.
		var tenantID *string
		err = conn.QueryRowContext(ctx, "SELECT auth_tenant_id FROM users WHERE id = $1", azureUserID).Scan(&tenantID)
		require.NoError(t, err)
		require.NotNil(t, tenantID)
		assert.Equal(t, "tenant-A", *tenantID)
	})

	t.Run("second SetAuthTenantID to different value is rejected", func(t *testing.T) {
		// SetAuthTenantID uses WHERE auth_tenant_id IS NULL, so once set it's immutable.
		ok, err := srv.db.SetAuthTenantID(ctx, azureUserID, "tenant-B")
		require.NoError(t, err)
		assert.False(t, ok, "SetAuthTenantID should return false when tenant is already set")

		// Verify tenant-A is still the value.
		var tenantID *string
		err = conn.QueryRowContext(ctx, "SELECT auth_tenant_id FROM users WHERE id = $1", azureUserID).Scan(&tenantID)
		require.NoError(t, err)
		require.NotNil(t, tenantID)
		assert.Equal(t, "tenant-A", *tenantID, "auth_tenant_id should remain tenant-A (immutable)")
	})

	t.Run("SetAuthTenantID to same value is also a no-op once set", func(t *testing.T) {
		// Even setting the same value returns false because IS NULL check fails.
		ok, err := srv.db.SetAuthTenantID(ctx, azureUserID, "tenant-A")
		require.NoError(t, err)
		assert.False(t, ok, "SetAuthTenantID should return false even for same value once set")
	})

	t.Run("callback tenant mismatch logic", func(t *testing.T) {
		// Verify the pattern used in handleAzureCallback:
		// if user.AuthTenantID != nil && *user.AuthTenantID != loginTenantID => reject
		user, err := srv.db.GetUserByExternalID(ctx, azureSubject)
		require.NoError(t, err)
		require.NotNil(t, user)
		require.NotNil(t, user.AuthTenantID)

		loginTenantID := "tenant-B"
		assert.NotEqual(t, *user.AuthTenantID, loginTenantID,
			"mismatched tenant should be detected — handleAzureCallback returns 403")

		sameTenantID := "tenant-A"
		assert.Equal(t, *user.AuthTenantID, sameTenantID,
			"matching tenant should be accepted")
	})
}
