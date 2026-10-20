package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchMoveContracts(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-move-org")

	// Create 2 auto-created groups via direct DB insertion
	autoGroup1 := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-group-1",
		Name:        "Auto Group 1",
		Depth:       0,
		Path:        "auto-group-1",
		AutoCreated: true,
	}
	autoGroup2 := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-group-2",
		Name:        "Auto Group 2",
		Depth:       0,
		Path:        "auto-group-2",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup1))
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup2))

	// Create group access with deploy claims for both auto groups
	for _, g := range []*rbac.Group{autoGroup1, autoGroup2} {
		require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        g.ID,
			AllowedMethods: []string{"*"},
			Claims:         []rbac.Claim{rbac.ClaimDeploy},
		}))
	}

	// Create 2 contracts
	addr1 := "0x1111111111111111111111111111111111111111"
	addr2 := "0x2222222222222222222222222222222222222222"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Contract 2")

	// Create contract grants linking each contract to its auto-created group
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup1.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    autoGroup2.ID,
	}))

	// Call batch-move
	body := map[string]any{
		"contract_ids": []string{contractID1, contractID2},
		"new_group": map[string]any{
			"slug": "production",
			"name": "Production",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, float64(2), result["moved_count"])
	assert.NotEmpty(t, result["target_group_id"])

	targetGroupID := result["target_group_id"].(string)

	// Verify the new group was created
	targetGroup, err := server.db.GetGroup(ctx, targetGroupID)
	require.NoError(t, err)
	require.NotNil(t, targetGroup)
	assert.Equal(t, "production", targetGroup.Slug)
	assert.Equal(t, "Production", targetGroup.Name)

	// Verify auto-created groups were deleted (they should be empty now)
	deletedGroup1, err := server.db.GetGroup(ctx, autoGroup1.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedGroup1)

	deletedGroup2, err := server.db.GetGroup(ctx, autoGroup2.ID)
	require.NoError(t, err)
	assert.Nil(t, deletedGroup2)

	// Verify contracts now have grants to the new target group
	grants1, err := server.db.ListContractGrantsByContract(ctx, contractID1)
	require.NoError(t, err)
	require.Len(t, grants1, 1)
	assert.Equal(t, targetGroupID, grants1[0].GroupID)

	grants2, err := server.db.ListContractGrantsByContract(ctx, contractID2)
	require.NoError(t, err)
	require.Len(t, grants2, 1)
	assert.Equal(t, targetGroupID, grants2[0].GroupID)
}

func TestBatchMovePreservesManualGrants(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-preserve-org")

	// Create a manual group via API
	manualGroup := createTestGroup(t, server, org.ID, "manual-group")

	// Create an auto-created group via direct DB
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-preserve",
		Name:        "Auto Preserve",
		Depth:       0,
		Path:        "auto-preserve",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))
	require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        autoGroup.ID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
	}))

	// Create a contract with grants to both groups
	addr := "0x3333333333333333333333333333333333333333"
	contractID := createTestContract(t, server, org.ID, addr, "Dual Grant Contract")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    manualGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID,
		GroupID:    autoGroup.ID,
	}))

	// Call batch-move to a new target group
	body := map[string]any{
		"contract_ids": []string{contractID},
		"new_group": map[string]any{
			"slug": "target-preserve",
			"name": "Target Preserve",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	targetGroupID := result["target_group_id"].(string)

	// Verify the manual grant still exists alongside the new target grant
	grants, err := server.db.ListContractGrantsByContract(ctx, contractID)
	require.NoError(t, err)

	groupIDs := make(map[string]bool)
	for _, g := range grants {
		groupIDs[g.GroupID] = true
	}

	assert.True(t, groupIDs[manualGroup.ID], "manual grant should still exist")
	assert.True(t, groupIDs[targetGroupID], "new target grant should exist")
	assert.False(t, groupIDs[autoGroup.ID], "auto-created group grant should be removed")
}

func TestBatchMoveDoesNotDeleteNonEmptyAutoGroups(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-nonempty-org")

	// Create an auto-created group with 2 contracts
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "auto-nonempty",
		Name:        "Auto Non-Empty",
		Depth:       0,
		Path:        "auto-nonempty",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))
	require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        autoGroup.ID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
	}))

	addr1 := "0x4444444444444444444444444444444444444444"
	addr2 := "0x5555555555555555555555555555555555555555"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Contract Stay")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Contract Move")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    autoGroup.ID,
	}))

	// Batch-move only 1 contract
	body := map[string]any{
		"contract_ids": []string{contractID2},
		"new_group": map[string]any{
			"slug": "target-nonempty",
			"name": "Target Non-Empty",
		},
		"delete_empty_auto_groups": true,
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify the auto-created group still exists (it still has 1 contract)
	group, err := server.db.GetGroup(ctx, autoGroup.ID)
	require.NoError(t, err)
	assert.NotNil(t, group, "auto-created group should still exist because it still has contracts")
}

func TestBatchMoveCrossOrgRejection(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org1 := createTestOrganization(t, server, "batch-cross-org1")
	org2 := createTestOrganization(t, server, "batch-cross-org2")

	addr := "0x6666666666666666666666666666666666666666"
	contractID := createTestContract(t, server, org1.ID, addr, "Cross Org Contract")

	// Try to batch-move org1's contract under org2
	body := map[string]any{
		"contract_ids": []string{contractID},
		"new_group": map[string]any{
			"slug": "stolen-group",
			"name": "Stolen Group",
		},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org2.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	// RD-934: response is opaque ("batch move failed: invalid request").
	// The specific "does not belong" reason is logged server-side via slog,
	// not exposed on the wire — preserving cross-org enumeration resistance.
	assert.Contains(t, result["error"], "batch move failed")
}

func TestBatchDeleteGroups(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-delete-org")

	// Create 2 groups with access, memberships, and grants
	group1 := createTestGroup(t, server, org.ID, "delete-group-1")
	group2 := createTestGroup(t, server, org.ID, "delete-group-2")

	// Add access to both groups
	for _, g := range []*rbac.Group{group1, group2} {
		require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        g.ID,
			AllowedMethods: []string{"eth_call"},
			Claims:         []rbac.Claim{},
		}))
	}

	// Create a user and memberships
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:batch-delete-user",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))

	for _, g := range []*rbac.Group{group1, group2} {
		require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: g.ID,
			Source:  rbac.MembershipSourceAdmin,
		}))
	}

	// Create contracts and grants
	addr1 := "0x7777777777777777777777777777777777777777"
	addr2 := "0x8888888888888888888888888888888888888888"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Delete Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Delete Contract 2")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    group1.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    group2.ID,
	}))

	// Call batch-delete
	body := map[string]any{
		"group_ids": []string{group1.ID, group2.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, float64(2), result["deleted_count"])

	// Verify groups are gone
	g1, err := server.db.GetGroup(ctx, group1.ID)
	require.NoError(t, err)
	assert.Nil(t, g1)

	g2, err := server.db.GetGroup(ctx, group2.ID)
	require.NoError(t, err)
	assert.Nil(t, g2)
}

func TestBatchDeletePreview(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "batch-preview-org")

	// Create an auto group and a manual group
	autoGroup := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       org.ID,
		Slug:        "preview-auto",
		Name:        "Preview Auto",
		Depth:       0,
		Path:        "preview-auto",
		AutoCreated: true,
	}
	require.NoError(t, server.db.CreateGroup(ctx, autoGroup))

	manualGroup := createTestGroup(t, server, org.ID, "preview-manual")

	// Add contracts and members to both
	addr1 := "0x9999999999999999999999999999999999999999"
	addr2 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab"
	contractID1 := createTestContract(t, server, org.ID, addr1, "Preview Contract 1")
	contractID2 := createTestContract(t, server, org.ID, addr2, "Preview Contract 2")

	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID1,
		GroupID:    autoGroup.ID,
	}))
	require.NoError(t, server.db.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID:         uuid.New().String(),
		ContractID: contractID2,
		GroupID:    manualGroup.ID,
	}))

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:preview-user",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))
	require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: autoGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	// Call batch-delete-preview
	body := map[string]any{
		"group_ids": []string{autoGroup.ID, manualGroup.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete-preview", org.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))

	groups := result["groups"].([]any)
	require.Len(t, groups, 2)

	// Build a map by ID for easier assertions
	previews := make(map[string]map[string]any)
	for _, g := range groups {
		gm := g.(map[string]any)
		previews[gm["id"].(string)] = gm
	}

	// Auto group: 1 contract, 1 member
	autoPreview := previews[autoGroup.ID]
	require.NotNil(t, autoPreview)
	assert.Equal(t, float64(1), autoPreview["contract_count"])
	assert.Equal(t, float64(1), autoPreview["member_count"])

	// Manual group: 1 contract, 0 members
	manualPreview := previews[manualGroup.ID]
	require.NotNil(t, manualPreview)
	assert.Equal(t, float64(1), manualPreview["contract_count"])
	assert.Equal(t, float64(0), manualPreview["member_count"])
}

func TestBatchDeleteCrossOrgRejection(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org1 := createTestOrganization(t, server, "batch-del-cross-org1")
	org2 := createTestOrganization(t, server, "batch-del-cross-org2")

	group := createTestGroup(t, server, org1.ID, "cross-org-group")

	// Try to batch-delete org1's group under org2
	body := map[string]any{
		"group_ids": []string{group.ID},
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org2.ID), bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var result map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Contains(t, result["error"], "not found")
}

func TestGrantContractToDeployerGroup(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "deployer-grant-org")

	// Create a user
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:deployer-grant",
		Metadata:   map[string]any{},
	}
	require.NoError(t, server.db.CreateUser(ctx, user))

	// Create a deploy group with deploy claim and add user as member
	deployGroup := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: org.ID,
		Slug:  "deployers",
		Name:  "Deployers",
		Depth: 0,
		Path:  "deployers",
	}
	require.NoError(t, server.db.CreateGroup(ctx, deployGroup))
	require.NoError(t, server.db.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        deployGroup.ID,
		AllowedMethods: []string{"*"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
	}))
	require.NoError(t, server.db.CreateMembership(ctx, &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: deployGroup.ID,
		Source:  rbac.MembershipSourceAdmin,
	}))

	t.Run("contract granted to existing deploy group", func(t *testing.T) {
		contractID := createTestContract(t, server, org.ID,
			"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc", "First Contract")

		err := server.db.GrantContractToDeployerGroup(ctx, org.ID, contractID, user.ID)
		require.NoError(t, err)

		grants, err := server.db.ListContractGrantsByContract(ctx, contractID)
		require.NoError(t, err)
		require.Len(t, grants, 1, "contract should have exactly one grant")
		assert.Equal(t, deployGroup.ID, grants[0].GroupID,
			"grant should point to the pre-existing deploy group, not a new one")
	})

	t.Run("second contract goes to same group", func(t *testing.T) {
		contractID2 := createTestContract(t, server, org.ID,
			"0xcccccccccccccccccccccccccccccccccccccccc", "Second Contract")

		err := server.db.GrantContractToDeployerGroup(ctx, org.ID, contractID2, user.ID)
		require.NoError(t, err)

		grants, err := server.db.ListContractGrantsByContract(ctx, contractID2)
		require.NoError(t, err)
		require.Len(t, grants, 1)
		assert.Equal(t, deployGroup.ID, grants[0].GroupID,
			"second contract should also be granted to the same deploy group")
	})

	t.Run("idempotent — duplicate grant is no-op", func(t *testing.T) {
		// Use direct DB insert to avoid API-level unique address check
		contractID := uuid.New().String()
		_, err := server.db.Conn().ExecContext(ctx,
			"INSERT INTO contracts (id, org_id, address, name) VALUES ($1, $2, $3, $4)",
			contractID, org.ID, "0xdddddddddddddddddddddddddddddddddddddd", "Third Contract")
		require.NoError(t, err)

		require.NoError(t, server.db.GrantContractToDeployerGroup(ctx, org.ID, contractID, user.ID))
		require.NoError(t, server.db.GrantContractToDeployerGroup(ctx, org.ID, contractID, user.ID))

		grants, err := server.db.ListContractGrantsByContract(ctx, contractID)
		require.NoError(t, err)
		assert.Len(t, grants, 1, "duplicate call should not create a second grant")
	})

	t.Run("no deploy group returns error", func(t *testing.T) {
		// User with no deploy group
		noDeployUser := &rbac.User{
			ID:         uuid.New().String(),
			ExternalID: "did:test:no-deploy-group",
			Metadata:   map[string]any{},
		}
		require.NoError(t, server.db.CreateUser(ctx, noDeployUser))

		contractID := createTestContract(t, server, org.ID,
			"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "Orphan Contract")

		err := server.db.GrantContractToDeployerGroup(ctx, org.ID, contractID, noDeployUser.ID)
		assert.Error(t, err, "should fail when user has no deploy group")
		assert.Contains(t, err.Error(), "no group with deploy claim")
	})
}

func TestContractListSearch(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "contract-search-org")
	createTestContract(t, server, org.ID, "0xaaaa000000000000000000000000000000000001", "Alpha Token")
	createTestContract(t, server, org.ID, "0xbbbb000000000000000000000000000000000002", "Beta Token")
	createTestContract(t, server, org.ID, "0xcccc000000000000000000000000000000000003", "Gamma Contract")
	_ = ctx

	t.Run("search by name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?search=Token", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(2), result["total"])
	})

	t.Run("search by address prefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?search=0xaaaa", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(1), result["total"])
	})

	t.Run("search with no results", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?search=nonexistent", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(0), result["total"])
	})

	t.Run("search with ILIKE wildcard is escaped", func(t *testing.T) {
		// Searching for "%" should not match everything
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?search=%%25", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		// "%" is not in any name or address, so should return 0
		assert.Equal(t, float64(0), result["total"])
	})
}

func TestContractListDateFilter(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "contract-date-org")
	createTestContract(t, server, org.ID, "0xdddd000000000000000000000000000000000001", "Old Contract")
	createTestContract(t, server, org.ID, "0xeeee000000000000000000000000000000000002", "New Contract")

	t.Run("created_after filters old contracts", func(t *testing.T) {
		// Use tomorrow's date — should return 0 since all contracts were just created
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?created_after=2099-01-01T00:00:00Z", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(0), result["total"])
	})

	t.Run("created_before filters future contracts", func(t *testing.T) {
		// Use a date far in the past — should return 0
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?created_before=2020-01-01T00:00:00Z", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(0), result["total"])
	})

	t.Run("wide date range returns all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts?created_after=2020-01-01T00:00:00Z&created_before=2099-12-31T23:59:59Z", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(2), result["total"])
	})

	t.Run("no date filter returns all", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/contracts", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(2), result["total"])
	})
}

func TestBatchSizeCap(t *testing.T) {
	server := setupTestServerForRBAC(t)

	org := createTestOrganization(t, server, "batch-cap-org")

	t.Run("batch-move rejects over 200 contract_ids", func(t *testing.T) {
		ids := make([]string, 201)
		for i := range ids {
			ids[i] = uuid.New().String()
		}
		body := map[string]any{
			"contract_ids":    ids,
			"target_group_id": uuid.New().String(),
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Contains(t, result["error"], "max 200")
	})

	t.Run("batch-delete rejects over 200 group_ids", func(t *testing.T) {
		ids := make([]string, 201)
		for i := range ids {
			ids[i] = uuid.New().String()
		}
		body := map[string]any{"group_ids": ids}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Contains(t, result["error"], "max 200")
	})

	t.Run("batch-delete-preview rejects over 200 group_ids", func(t *testing.T) {
		ids := make([]string, 201)
		for i := range ids {
			ids[i] = uuid.New().String()
		}
		body := map[string]any{"group_ids": ids}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/groups/batch-delete-preview", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Contains(t, result["error"], "max 200")
	})

	t.Run("batch-move accepts 200 or fewer", func(t *testing.T) {
		// Just verify it doesn't reject — it'll fail on contract lookup but not on size
		ids := make([]string, 2)
		for i := range ids {
			ids[i] = uuid.New().String()
		}
		body := map[string]any{
			"contract_ids":    ids,
			"target_group_id": uuid.New().String(),
		}
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/orgs/%s/contracts/batch-move", org.ID), bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		// Should not contain the "max 200" error — it may fail for other reasons (contract not found)
		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		if errMsg, ok := result["error"].(string); ok {
			assert.NotContains(t, errMsg, "max 200", "should not reject for size")
		}
	})
}

func TestGroupListSearch(t *testing.T) {
	server := setupTestServerForRBAC(t)
	ctx := context.Background()

	org := createTestOrganization(t, server, "group-search-org")
	_ = ctx

	// Create groups with distinct names (name = slug + " Group")
	createTestGroup(t, server, org.ID, "deploy-alpha")
	createTestGroup(t, server, org.ID, "infra-beta")
	createTestGroup(t, server, org.ID, "deploy-gamma")

	t.Run("search by slug prefix", func(t *testing.T) {
		// "deploy-alpha" and "deploy-gamma" slugs match "deploy"
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups?search=deploy", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(2), result["total"])
	})

	t.Run("search by unique slug", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/orgs/%s/groups?search=infra-beta", org.ID), nil)
		w := httptest.NewRecorder()
		server.router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var result map[string]any
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
		assert.Equal(t, float64(1), result["total"])
	})
}
