package db

import (
	"context"
	"testing"

	"privacy-proxy/internal/rbac"

	"github.com/google/uuid"
)

// ensureDefaultOrgAndGroup creates the default organization and group if they don't exist.
// This is needed for tests that use rbac.DefaultOrgID and rbac.DefaultGroupID.
func ensureDefaultOrgAndGroup(t *testing.T, db *DB, ctx context.Context) {
	// Create default organization if it doesn't exist
	org := &rbac.Organization{
		ID:       rbac.DefaultOrgID,
		Slug:     "default",
		Name:     "Default Organization",
		Settings: map[string]any{},
	}
	_ = db.CreateOrganization(ctx, org) // Ignore error if already exists

	// Create default group if it doesn't exist
	group := &rbac.Group{
		ID:    rbac.DefaultGroupID,
		OrgID: rbac.DefaultOrgID,
		Slug:  "default",
		Name:  "Default Group",
		Depth: 0,
		Path:  "default",
	}
	_ = db.CreateGroup(ctx, group) // Ignore error if already exists
}

func TestWithTxCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	// Create a contract within a transaction
	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    rbac.DefaultOrgID,
		Address:  "0x1234567890123456789012345678901234567890",
		Name:     "Test Contract",
		Metadata: map[string]any{},
	}

	err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.CreateContract(ctx, contract)
	})
	if err != nil {
		t.Fatalf("WithTx failed: %v", err)
	}

	// Verify the contract was created
	found, err := db.GetContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if found == nil {
		t.Fatal("Contract should exist after committed transaction")
	}
	if found.Name != "Test Contract" {
		t.Errorf("Expected name 'Test Contract', got %q", found.Name)
	}
}

func TestWithTxRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	contractID := uuid.New().String()

	// Create a contract but return an error to trigger rollback
	err := db.WithTx(ctx, func(tx *Tx) error {
		contract := &rbac.Contract{
			ID:       contractID,
			OrgID:    rbac.DefaultOrgID,
			Address:  "0x2234567890123456789012345678901234567890",
			Name:     "Rollback Contract",
			Metadata: map[string]any{},
		}
		if err := tx.CreateContract(ctx, contract); err != nil {
			return err
		}
		// Return error to trigger rollback
		return context.Canceled
	})
	if err == nil {
		t.Fatal("Expected error from WithTx")
	}

	// Verify the contract was NOT created (rolled back)
	found, err := db.GetContract(ctx, contractID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if found != nil {
		t.Fatal("Contract should not exist after rolled back transaction")
	}
}

func TestCreateContractWithGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    rbac.DefaultOrgID,
		Address:  "0x3234567890123456789012345678901234567890",
		Name:     "Contract With Grant",
		Metadata: map[string]any{},
	}

	grant := &rbac.ContractGrant{
		ID:      uuid.New().String(),
		GroupID: rbac.DefaultGroupID,
	}

	err := db.CreateContractWithGrant(ctx, contract, grant)
	if err != nil {
		t.Fatalf("CreateContractWithGrant failed: %v", err)
	}

	// Verify contract was created
	foundContract, err := db.GetContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if foundContract == nil {
		t.Fatal("Contract should exist")
	}

	// Verify grant was created with correct contract ID
	foundGrant, err := db.GetContractGrantByContractAndGroup(ctx, contract.ID, rbac.DefaultGroupID)
	if err != nil {
		t.Fatalf("GetContractGrantByContractAndGroup failed: %v", err)
	}
	if foundGrant == nil {
		t.Fatal("Grant should exist")
	}
	if foundGrant.ContractID != contract.ID {
		t.Errorf("Grant should have contract ID %s, got %s", contract.ID, foundGrant.ContractID)
	}
}

func TestDeleteContractWithGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	// First create a contract with a grant
	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    rbac.DefaultOrgID,
		Address:  "0x4234567890123456789012345678901234567890",
		Name:     "Contract To Delete",
		Metadata: map[string]any{},
	}

	grant := &rbac.ContractGrant{
		ID:      uuid.New().String(),
		GroupID: rbac.DefaultGroupID,
	}

	err := db.CreateContractWithGrant(ctx, contract, grant)
	if err != nil {
		t.Fatalf("CreateContractWithGrant failed: %v", err)
	}

	// Now delete the contract with grants
	err = db.DeleteContractWithGrants(ctx, contract.ID)
	if err != nil {
		t.Fatalf("DeleteContractWithGrants failed: %v", err)
	}

	// Verify contract was deleted
	foundContract, err := db.GetContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if foundContract != nil {
		t.Fatal("Contract should not exist after deletion")
	}

	// Verify grant was also deleted
	grants, err := db.ListContractGrantsByContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("ListContractGrantsByContract failed: %v", err)
	}
	if len(grants) > 0 {
		t.Fatal("Grants should not exist after contract deletion")
	}
}

func TestDeleteGroupWithDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	// Create a group
	group := &rbac.Group{
		ID:          uuid.New().String(),
		OrgID:       rbac.DefaultOrgID,
		Slug:        "test-delete-group",
		Name:        "Test Delete Group",
		Description: "Group to test deletion",
		Depth:       0,
		Path:        "test-delete-group",
	}
	err := db.CreateGroup(ctx, group)
	if err != nil {
		t.Fatalf("CreateGroup failed: %v", err)
	}

	// Create group access
	access := &rbac.GroupAccess{
		ID:             uuid.New().String(),
		GroupID:        group.ID,
		AllowedMethods: []string{"eth_call"},
		Claims:  []rbac.Claim{},
	}
	err = db.CreateGroupAccess(ctx, access)
	if err != nil {
		t.Fatalf("CreateGroupAccess failed: %v", err)
	}

	// Create a user and membership to this group
	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:delete-group-user",
		Metadata:   map[string]any{},
	}
	err = db.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	membership := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  user.ID,
		GroupID: group.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	err = db.CreateMembership(ctx, membership)
	if err != nil {
		t.Fatalf("CreateMembership failed: %v", err)
	}

	// Now delete the group with dependencies
	err = db.DeleteGroupWithDependencies(ctx, group.ID)
	if err != nil {
		t.Fatalf("DeleteGroupWithDependencies failed: %v", err)
	}

	// Verify group was deleted
	foundGroup, err := db.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroup failed: %v", err)
	}
	if foundGroup != nil {
		t.Fatal("Group should not exist after deletion")
	}

	// Verify group access was deleted
	foundAccess, err := db.GetGroupAccess(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroupAccess failed: %v", err)
	}
	if foundAccess != nil {
		t.Fatal("Group access should not exist after group deletion")
	}

	// Verify membership was deleted
	memberships, err := db.ListGroupMembers(ctx, group.ID)
	if err != nil {
		t.Fatalf("ListGroupMembers failed: %v", err)
	}
	if len(memberships) > 0 {
		t.Fatal("Memberships should not exist after group deletion")
	}
}

func TestBeginTxManualCommit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	// Test manual transaction management
	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}

	contract := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    rbac.DefaultOrgID,
		Address:  "0x5234567890123456789012345678901234567890",
		Name:     "Manual Tx Contract",
		Metadata: map[string]any{},
	}

	err = tx.CreateContract(ctx, contract)
	if err != nil {
		tx.Rollback()
		t.Fatalf("CreateContract in tx failed: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatalf("Commit failed: %v", err)
	}

	// Verify the contract was created
	found, err := db.GetContract(ctx, contract.ID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if found == nil {
		t.Fatal("Contract should exist after committed transaction")
	}
}

func TestBeginTxManualRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	db := setupTestDB(t)
	ctx := context.Background()
	ensureDefaultOrgAndGroup(t, db, ctx)

	contractID := uuid.New().String()

	// Test manual transaction management with rollback
	tx, err := db.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx failed: %v", err)
	}

	contract := &rbac.Contract{
		ID:       contractID,
		OrgID:    rbac.DefaultOrgID,
		Address:  "0x6234567890123456789012345678901234567890",
		Name:     "Rollback Tx Contract",
		Metadata: map[string]any{},
	}

	err = tx.CreateContract(ctx, contract)
	if err != nil {
		tx.Rollback()
		t.Fatalf("CreateContract in tx failed: %v", err)
	}

	err = tx.Rollback()
	if err != nil {
		t.Fatalf("Rollback failed: %v", err)
	}

	// Verify the contract was NOT created
	found, err := db.GetContract(ctx, contractID)
	if err != nil {
		t.Fatalf("GetContract failed: %v", err)
	}
	if found != nil {
		t.Fatal("Contract should not exist after rolled back transaction")
	}
}
