package db

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"privacy-proxy/internal/rbac"
)

// TestCrossOrgIsolationIntegration tests the full cross-org isolation flow with real database queries.
// This test mirrors what the E2E tests do: create orgs, groups, users, contracts, memberships,
// and then verify cross-org access is properly denied.
func TestCrossOrgIsolationIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer database.Close()

	ctx := context.Background()

	// Create Organization A
	orgA := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "cross-org-test-a",
		Name:     "Cross Org Test A",
		Settings: map[string]interface{}{},
	}
	if err := database.CreateOrganization(ctx, orgA); err != nil {
		t.Fatalf("Failed to create org A: %v", err)
	}

	// Create Organization B
	orgB := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "cross-org-test-b",
		Name:     "Cross Org Test B",
		Settings: map[string]interface{}{},
	}
	if err := database.CreateOrganization(ctx, orgB); err != nil {
		t.Fatalf("Failed to create org B: %v", err)
	}

	// Create Group A in Org A
	groupA := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgA.ID,
		Slug:  "group-a",
		Name:  "Group A",
	}
	if err := database.CreateGroup(ctx, groupA); err != nil {
		t.Fatalf("Failed to create group A: %v", err)
	}

	// Create Group B in Org B
	groupB := &rbac.Group{
		ID:    uuid.New().String(),
		OrgID: orgB.ID,
		Slug:  "group-b",
		Name:  "Group B",
	}
	if err := database.CreateGroup(ctx, groupB); err != nil {
		t.Fatalf("Failed to create group B: %v", err)
	}

	// Create Contract A in Org A
	contractA := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgA.ID,
		Address:  "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Name:     "Contract A",
		Metadata: map[string]interface{}{},
	}
	if err := database.CreateContract(ctx, contractA); err != nil {
		t.Fatalf("Failed to create contract A: %v", err)
	}

	// Create Contract B in Org B
	contractB := &rbac.Contract{
		ID:       uuid.New().String(),
		OrgID:    orgB.ID,
		Address:  "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		Name:     "Contract B",
		Metadata: map[string]interface{}{},
	}
	if err := database.CreateContract(ctx, contractB); err != nil {
		t.Fatalf("Failed to create contract B: %v", err)
	}

	// Verify contracts are registered
	t.Run("Verify Contract A is registered to Org A", func(t *testing.T) {
		ownerOrgID, err := database.GetContractOwnerOrgID(ctx, contractA.Address)
		if err != nil {
			t.Fatalf("GetContractOwnerOrgID error: %v", err)
		}
		if ownerOrgID != orgA.ID {
			t.Errorf("Expected contract A owner = %s, got %s", orgA.ID, ownerOrgID)
		}
	})

	t.Run("Verify Contract B is registered to Org B", func(t *testing.T) {
		ownerOrgID, err := database.GetContractOwnerOrgID(ctx, contractB.Address)
		if err != nil {
			t.Fatalf("GetContractOwnerOrgID error: %v", err)
		}
		if ownerOrgID != orgB.ID {
			t.Errorf("Expected contract B owner = %s, got %s", orgB.ID, ownerOrgID)
		}
	})

	// Create User A
	userA := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:cross-org-user-a",
		KYC:        true,
	}
	if err := database.CreateUser(ctx, userA); err != nil {
		t.Fatalf("Failed to create user A: %v", err)
	}

	// Create User B
	userB := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:cross-org-user-b",
		KYC:        true,
	}
	if err := database.CreateUser(ctx, userB); err != nil {
		t.Fatalf("Failed to create user B: %v", err)
	}

	// Add User A to Group A (Org A)
	membershipA := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userA.ID,
		GroupID: groupA.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	if err := database.CreateMembership(ctx, membershipA); err != nil {
		t.Fatalf("Failed to create membership A: %v", err)
	}

	// Add User B to Group B (Org B)
	membershipB := &rbac.UserMembership{
		ID:      uuid.New().String(),
		UserID:  userB.ID,
		GroupID: groupB.ID,
		Source:  rbac.MembershipSourceAdmin,
	}
	if err := database.CreateMembership(ctx, membershipB); err != nil {
		t.Fatalf("Failed to create membership B: %v", err)
	}

	// Verify User A's memberships
	t.Run("Verify User A memberships", func(t *testing.T) {
		memberships, err := database.ListUserMembershipsWithDetails(ctx, userA.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsWithDetails error: %v", err)
		}
		if len(memberships) != 1 {
			t.Fatalf("Expected 1 membership for user A, got %d", len(memberships))
		}
		if memberships[0].Group.OrgID != orgA.ID {
			t.Errorf("Expected user A to be in org A (%s), got %s", orgA.ID, memberships[0].Group.OrgID)
		}
	})

	// Verify User B's memberships
	t.Run("Verify User B memberships", func(t *testing.T) {
		memberships, err := database.ListUserMembershipsWithDetails(ctx, userB.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsWithDetails error: %v", err)
		}
		if len(memberships) != 1 {
			t.Fatalf("Expected 1 membership for user B, got %d", len(memberships))
		}
		if memberships[0].Group.OrgID != orgB.ID {
			t.Errorf("Expected user B to be in org B (%s), got %s", orgB.ID, memberships[0].Group.OrgID)
		}
	})

	// Now test the cross-org isolation logic
	// This simulates what NewOrgContext does

	t.Run("Cross-org check: User A trying to access Contract B", func(t *testing.T) {
		// Get user A's org memberships
		memberships, err := database.ListUserMembershipsWithDetails(ctx, userA.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsWithDetails error: %v", err)
		}

		userOrgIDs := make(map[string]bool)
		for _, m := range memberships {
			if m.Group != nil {
				userOrgIDs[m.Group.OrgID] = true
			}
		}

		// Get contract B's owner org
		ownerOrgID, err := database.GetContractOwnerOrgID(ctx, contractB.Address)
		if err != nil {
			t.Fatalf("GetContractOwnerOrgID error: %v", err)
		}

		// Cross-org check
		if ownerOrgID == "" {
			t.Error("Contract B should be registered to org B, but GetContractOwnerOrgID returned empty")
		}

		if userOrgIDs[ownerOrgID] {
			t.Errorf("User A should NOT be a member of org B, but check passed. userOrgIDs=%v, ownerOrgID=%s", userOrgIDs, ownerOrgID)
		}

		// Verify the check correctly denies access
		if ownerOrgID != "" && !userOrgIDs[ownerOrgID] {
			t.Logf("PASS: User A (orgs=%v) correctly denied access to Contract B (owner org=%s)", userOrgIDs, ownerOrgID)
		}
	})

	t.Run("Cross-org check: User A accessing their own Contract A", func(t *testing.T) {
		// Get user A's org memberships
		memberships, err := database.ListUserMembershipsWithDetails(ctx, userA.ID)
		if err != nil {
			t.Fatalf("ListUserMembershipsWithDetails error: %v", err)
		}

		userOrgIDs := make(map[string]bool)
		for _, m := range memberships {
			if m.Group != nil {
				userOrgIDs[m.Group.OrgID] = true
			}
		}

		// Get contract A's owner org
		ownerOrgID, err := database.GetContractOwnerOrgID(ctx, contractA.Address)
		if err != nil {
			t.Fatalf("GetContractOwnerOrgID error: %v", err)
		}

		// User A should be allowed to access contract A
		if !userOrgIDs[ownerOrgID] {
			t.Errorf("User A should be a member of org A, but check failed. userOrgIDs=%v, ownerOrgID=%s", userOrgIDs, ownerOrgID)
		} else {
			t.Logf("PASS: User A (orgs=%v) correctly allowed access to Contract A (owner org=%s)", userOrgIDs, ownerOrgID)
		}
	})

	t.Run("Case insensitive address lookup", func(t *testing.T) {
		// Test with different case
		upperAddr := "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		lowerAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		mixedAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"

		ownerUpper, _ := database.GetContractOwnerOrgID(ctx, upperAddr)
		ownerLower, _ := database.GetContractOwnerOrgID(ctx, lowerAddr)
		ownerMixed, _ := database.GetContractOwnerOrgID(ctx, mixedAddr)

		if ownerUpper != orgA.ID {
			t.Errorf("Uppercase lookup failed: expected %s, got %s", orgA.ID, ownerUpper)
		}
		if ownerLower != orgA.ID {
			t.Errorf("Lowercase lookup failed: expected %s, got %s", orgA.ID, ownerLower)
		}
		if ownerMixed != orgA.ID {
			t.Errorf("Mixed case lookup failed: expected %s, got %s", orgA.ID, ownerMixed)
		}
	})
}
