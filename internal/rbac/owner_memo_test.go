package rbac

import (
	"context"
	"strings"
	"testing"
)

// countingOwnerStore wraps a Store and counts GetContractOwnerOrgID calls. It
// embeds the Store interface so every other method delegates unchanged; only
// the owner lookup is instrumented. Used to prove the OrgContext memo
// eliminates the duplicate contract-owner lookups CheckAccess used to issue on
// the hot path (RD-1112): pre-fix a simple value transfer resolved the target's
// owner once while building OrgContext and again in the value-transfer
// carve-out (a second DB round-trip); now the second is a memo hit.
type countingOwnerStore struct {
	Store
	ownerCalls int
}

func (c *countingOwnerStore) GetContractOwnerOrgID(ctx context.Context, addr string) (string, error) {
	c.ownerCalls++
	return c.Store.GetContractOwnerOrgID(ctx, addr)
}

func TestOrgContextOwnerOrgIDMemoizedDedup(t *testing.T) {
	base := NewMockCrossOrgStore()
	base.users["did:test:u1"] = &User{ID: "u1", ExternalID: "did:test:u1"}
	store := &countingOwnerStore{Store: base}
	user := &User{ID: "u1", ExternalID: "did:test:u1"}

	ctx := context.Background()
	target := "0x1111111111111111111111111111111111111111" // unregistered → public

	// Construction resolves the target's owner exactly once.
	orgCtx, err := NewOrgContext(ctx, store, user, target)
	if err != nil {
		t.Fatalf("NewOrgContext: %v", err)
	}
	if store.ownerCalls != 1 {
		t.Fatalf("construction should resolve target owner once, got %d", store.ownerCalls)
	}

	// Repeat lookups of the SAME target are the duplicates CheckAccess used to
	// issue against the DB. They must now all be served from the memo.
	for i := 0; i < 5; i++ {
		if _, err := orgCtx.OwnerOrgID(ctx, target); err != nil {
			t.Fatalf("OwnerOrgID(target): %v", err)
		}
	}
	if store.ownerCalls != 1 {
		t.Errorf("repeat target lookups must hit the memo; want 1 store call total, got %d", store.ownerCalls)
	}

	// A genuinely different address is a real miss → exactly one more store call.
	other := "0x2222222222222222222222222222222222222222"
	if _, err := orgCtx.OwnerOrgID(ctx, other); err != nil {
		t.Fatalf("OwnerOrgID(other): %v", err)
	}
	if store.ownerCalls != 2 {
		t.Errorf("distinct address should miss the memo; want 2 store calls, got %d", store.ownerCalls)
	}

	// Normalization: a mixed-case / whitespace-padded form of the target must
	// still resolve to the memoized entry (no extra store call).
	if _, err := orgCtx.OwnerOrgID(ctx, "  "+strings.ToUpper(target)+"  "); err != nil {
		t.Fatalf("OwnerOrgID(normalized target): %v", err)
	}
	if store.ownerCalls != 2 {
		t.Errorf("normalized target must hit the memo; want 2 store calls, got %d", store.ownerCalls)
	}
}
