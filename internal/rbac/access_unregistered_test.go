package rbac

import (
	"context"
	"testing"
	"time"
)

// TestUnregisteredContractAccess verifies that unregistered contracts (not registered
// to any org) are now DENIED — all contracts are private by default. Only EVM
// precompiles (0x01-0x09) are truly public. Cross-org isolation is unchanged.
func TestUnregisteredContractAccess(t *testing.T) {
	const (
		unregisteredAddr = "0xeeee000000000000000000000000000000000001"
		crossOrgAddr     = "0xbbbb000000000000000000000000000000000002" // owned by org-b
		precompileAddr   = "0x0000000000000000000000000000000000000001" // ecrecover
	)

	ctx := context.Background()

	// Helper: create a store and controller with a user in org-a.
	// crossOrgAddr is registered to org-b, unregisteredAddr is not registered anywhere.
	setup := func(claims []Claim) (*MockCrossOrgStore, *AccessController) {
		store := NewMockCrossOrgStore()

		orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
		orgB := &Organization{ID: "org-b", Slug: "org-b", Name: "Org B"}
		store.organizations["org-a"] = orgA
		store.organizations["org-b"] = orgB

		user := &User{ID: "test-user", ExternalID: "did:test:user", KYC: true, Banned: false}
		store.users["did:test:user"] = user

		groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
		store.memberships["test-user"] = []*MembershipWithDetails{
			{Membership: &UserMembership{ID: "m1", UserID: "test-user", GroupID: "group-a"}, Group: groupA},
		}

		store.groupAccess["group-a"] = &GroupAccess{
			ID: "ga-a", GroupID: "group-a",
			Claims:         claims,
			AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getCode", "eth_getBalance", "eth_getLogs"},
		}

		store.cachedPermissions["test-user:org-a"] = &EffectivePermissions{
			ID:             "perms",
			UserID:         "test-user",
			OrgID:          "org-a",
			AllowedMethods: []string{"eth_call", "eth_sendTransaction", "eth_getCode", "eth_getBalance", "eth_getLogs"},
			ContractAccess: map[string]ContractAccess{},
			Claims:         claims,
			ComputedAt:     time.Now(),
			ExpiresAt:      time.Now().Add(1 * time.Hour),
		}

		// Cross-org contract ownership
		store.contractOwners[crossOrgAddr] = "org-b"
		store.registeredToAnyOrg[crossOrgAddr] = true
		store.addressOwnedByOrg[crossOrgAddr] = map[string]bool{"org-b": true}
		// unregisteredAddr has NO owner — not in contractOwners

		controller := NewAccessController(store, 5*time.Minute)
		return store, controller
	}

	t.Run("read-only user DENIED on unregistered contract (private by default)", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": unregisteredAddr, "data": "0x"}, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected unregistered contract to be denied (private by default)")
		}
	})

	t.Run("write user DENIED on unregistered contract (private by default)", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID:   "did:test:user",
			Method:           "eth_sendTransaction",
			Params:           []any{map[string]any{"to": unregisteredAddr, "data": "0xa9059cbb0000000000000000000000000000000000000000000000000000000000000001"}},
			TargetAddress:    unregisteredAddr,
			FunctionSelector: "0xa9059cbb",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected unregistered contract to be denied (private by default)")
		}
	})

	t.Run("user CANNOT call contract registered to another org", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": crossOrgAddr, "data": "0x"}, "latest"},
			TargetAddress:  crossOrgAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected cross-org contract access to be denied")
		}
	})

	t.Run("anonymous user cannot call unregistered contract", func(t *testing.T) {
		store := NewMockCrossOrgStore()
		controller := NewAccessController(store, 5*time.Minute)

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "", // anonymous
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": unregisteredAddr, "data": "0x"}, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected anonymous access to unregistered contract to be denied")
		}
	})

	t.Run("deploy user DENIED on unregistered contract (private by default)", func(t *testing.T) {
		_, controller := setup([]Claim{ClaimDeploy})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": unregisteredAddr, "data": "0x"}, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected unregistered contract to be denied (private by default)")
		}
	})

	t.Run("read user DENIED eth_getLogs on unregistered contract", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": unregisteredAddr}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected eth_getLogs on unregistered contract to be denied (private by default)")
		}
	})

	t.Run("read user DENIED eth_getCode on unregistered address (all private)", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_getCode",
			Params:         []any{unregisteredAddr, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected eth_getCode on unregistered address to be denied (all contracts private)")
		}
	})

	t.Run("user with no claims cannot access unregistered contract", func(t *testing.T) {
		_, controller := setup([]Claim{}) // No claims at all

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": unregisteredAddr, "data": "0x"}, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Allowed {
			t.Error("expected user with no claims to be denied even on unregistered contract")
		}
	})

	// Precompile tests — precompiles are always accessible
	t.Run("read user can call precompile address", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			OrgID:          "org-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": precompileAddr, "data": "0x"}, "latest"},
			TargetAddress:  precompileAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected precompile access to be allowed, got denied: %s", result.Reason)
		}
	})

	t.Run("eth_getLogs on precompile is allowed", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			OrgID:          "org-a",
			Method:         "eth_getLogs",
			Params:         []any{map[string]any{"address": precompileAddr}},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected eth_getLogs on precompile to be allowed, got denied: %s", result.Reason)
		}
	})

	// Value transfer and basic address query paths must still work for unregistered EOAs
	t.Run("value transfer to unregistered EOA still allowed", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			OrgID:          "org-a",
			Method:         "eth_sendTransaction",
			Params:         []any{map[string]any{"to": unregisteredAddr, "value": "0x1"}},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected value transfer to unregistered EOA to be allowed, got denied: %s", result.Reason)
		}
	})

	t.Run("eth_getBalance on unregistered address still allowed (basic query)", func(t *testing.T) {
		_, controller := setup([]Claim{})

		result, err := controller.CheckAccess(ctx, &AccessCheckRequest{
			UserExternalID: "did:test:user",
			OrgID:          "org-a",
			Method:         "eth_getBalance",
			Params:         []any{unregisteredAddr, "latest"},
			TargetAddress:  unregisteredAddr,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.Allowed {
			t.Errorf("expected eth_getBalance on unregistered address to be allowed (basic query), got denied: %s", result.Reason)
		}
	})
}
