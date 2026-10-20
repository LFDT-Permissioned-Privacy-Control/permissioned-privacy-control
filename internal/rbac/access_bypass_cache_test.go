package rbac

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// RD-928 — BypassCache semantics on AccessCheckRequest.
//
// The impersonation surface (internal/server/impersonation.go) sets
// AccessCheckRequest.BypassCache = true so a tier-2 admin browsing as user X
// always sees X's freshly-resolved permissions, never a stale snapshot held
// by the AccessController's in-memory cache. This file pins the two
// invariants that protect that contract from regression:
//
//  1. BypassCache=true reads through the cache: a stale entry must NOT be
//     served, the resolver is consulted and the underlying store re-read.
//     (TestCheckAccess_BypassCacheServesFreshAfterMutation)
//  2. BypassCache=true does NOT populate the cache afterwards: an impersonated
//     CheckAccess must not poison the hot path's snapshot for the next
//     non-impersonated caller.
//     (TestCheckAccess_BypassCacheDoesNotPopulateCache)
//
// Both invariants are enforced by the two `if !req.BypassCache` branches in
// AccessController.CheckAccess. If either is silently removed, the
// impersonation surface starts serving the admin a stale view of the target
// user's perms (or worse, persists a forged view back into the hot-path
// cache).

// countingBypassStore wraps MockCrossOrgStore and counts how many times
// GetCachedPermissions is consulted. When the in-memory AccessController
// cache hits, the resolver — and therefore the store's GetCachedPermissions —
// is NOT called. So a delta on this counter is a faithful proxy for "the
// in-memory cache was bypassed and the resolver was invoked".
type countingBypassStore struct {
	*MockCrossOrgStore
	getCachedCalls atomic.Int64
}

func newCountingBypassStore() *countingBypassStore {
	return &countingBypassStore{MockCrossOrgStore: NewMockCrossOrgStore()}
}

func (s *countingBypassStore) GetCachedPermissions(ctx context.Context, userID, orgID string) (*EffectivePermissions, error) {
	s.getCachedCalls.Add(1)
	return s.MockCrossOrgStore.GetCachedPermissions(ctx, userID, orgID)
}

// seedBypassCacheScenario sets up a single-org user with one registered
// contract and an explicit grant. eth_call against the contract is allowed.
// The store-level cachedPermissions row is the "truth" the resolver reads.
func seedBypassCacheScenario(store *countingBypassStore) {
	orgA := &Organization{ID: "org-a", Slug: "org-a", Name: "Org A"}
	store.organizations["org-a"] = orgA

	userA := &User{ID: "user-a", ExternalID: "did:test:user-a", KYC: true, Banned: false}
	store.users["did:test:user-a"] = userA

	groupA := &Group{ID: "group-a", OrgID: "org-a", Slug: "group-a", Name: "Group A"}
	store.memberships["user-a"] = []*MembershipWithDetails{
		{Membership: &UserMembership{ID: "mem-a", UserID: "user-a", GroupID: "group-a"}, Group: groupA},
	}
	store.groupAccess["group-a"] = &GroupAccess{
		ID:             "access-a",
		GroupID:        "group-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		Claims:         []Claim{},
	}

	contractA := "0xaaaa000000000000000000000000000000000001"
	store.contractOwners[contractA] = "org-a"
	store.registeredToAnyOrg[contractA] = true
	store.addressOwnedByOrg[contractA] = map[string]bool{"org-a": true}

	// Initial "fresh" cached permissions: user-a has explicit grant on
	// contractA, so eth_call is allowed.
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{
			contractA: {Claims: []Claim{}},
		},
		Claims:     []Claim{},
		ComputedAt: time.Now(),
		ExpiresAt:  time.Now().Add(1 * time.Hour),
	}
}

// TestCheckAccess_BypassCacheServesFreshAfterMutation pins the "BypassCache
// reads through the in-memory cache" invariant.
//
// Sequence:
//  1. CheckAccess populates the AccessController in-memory cache with the
//     ALLOWED snapshot.
//  2. The underlying store mutates — user-a's explicit grant on contractA is
//     dropped (simulating an admin revocation that happens between the
//     cache fill and the impersonated call). The cache is intentionally NOT
//     invalidated here — we want to demonstrate that a stale entry exists.
//  3. CheckAccess with BypassCache=false → STILL ALLOWED (cache hit served
//     the stale "allowed" snapshot).
//  4. CheckAccess with BypassCache=true → DENIED (cache bypassed, resolver
//     re-read the mutated store, contractA no longer in ContractAccess).
//
// If the `if !req.BypassCache` guard around c.cache.Get is removed, step 4
// will (incorrectly) return ALLOWED from the still-populated cache.
func TestCheckAccess_BypassCacheServesFreshAfterMutation(t *testing.T) {
	ctx := context.Background()
	store := newCountingBypassStore()
	seedBypassCacheScenario(store)

	controller := NewAccessController(store, 5*time.Minute)
	defer controller.Stop()

	contractA := "0xaaaa000000000000000000000000000000000001"
	req := func() *AccessCheckRequest {
		return &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
		}
	}

	// Step 1 — initial CheckAccess populates the in-memory cache.
	result, err := controller.CheckAccess(ctx, req())
	if err != nil {
		t.Fatalf("initial CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("step 1: expected initial CheckAccess to allow (fresh cache), got denied: %s", result.Reason)
	}
	callsAfterStep1 := store.getCachedCalls.Load()
	if callsAfterStep1 == 0 {
		t.Fatalf("step 1: expected resolver to read store on first call, got 0 GetCachedPermissions calls")
	}

	// Step 2 — mutate the store: drop the explicit grant on contractA.
	// We do NOT call cache.InvalidateUser — that's the whole point of the
	// test, we want a stale cache entry alongside a fresh store.
	store.cachedPermissions["user-a:org-a"] = &EffectivePermissions{
		ID:             "perms-a-mutated",
		UserID:         "user-a",
		OrgID:          "org-a",
		AllowedMethods: []string{"eth_call", "eth_getBalance"},
		ContractAccess: map[string]ContractAccess{}, // grant revoked
		Claims:         []Claim{},
		ComputedAt:     time.Now(),
		ExpiresAt:      time.Now().Add(1 * time.Hour),
	}

	// Step 3 — CheckAccess WITHOUT BypassCache: must hit the stale snapshot
	// and return Allowed. This pins "the cache is otherwise stale" and
	// makes step 4's flip a meaningful demonstration of the bypass.
	result, err = controller.CheckAccess(ctx, req())
	if err != nil {
		t.Fatalf("step 3 CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Errorf("step 3: expected stale cache to still allow, got denied: %s — "+
			"this means the cache was not populated in step 1 and the test premise is broken", result.Reason)
	}
	callsAfterStep3 := store.getCachedCalls.Load()
	if callsAfterStep3 != callsAfterStep1 {
		t.Errorf("step 3: expected the in-memory cache to hit (no new GetCachedPermissions reads); "+
			"got %d new store reads (before=%d, after=%d)", callsAfterStep3-callsAfterStep1, callsAfterStep1, callsAfterStep3)
	}

	// Step 4 — CheckAccess WITH BypassCache: must read through, see the
	// mutated store, and deny.
	bypassReq := req()
	bypassReq.BypassCache = true
	result, err = controller.CheckAccess(ctx, bypassReq)
	if err != nil {
		t.Fatalf("step 4 CheckAccess: %v", err)
	}
	if result.Allowed {
		t.Fatalf("step 4: BypassCache=true must not serve the stale cache; expected denied, got allowed")
	}
	callsAfterStep4 := store.getCachedCalls.Load()
	if callsAfterStep4 == callsAfterStep3 {
		t.Errorf("step 4: BypassCache=true must consult the resolver/store; "+
			"GetCachedPermissions call count unchanged (%d) — c.cache.Get short-circuited despite BypassCache",
			callsAfterStep4)
	}
}

// TestCheckAccess_BypassCacheDoesNotPopulateCache pins the second half of
// the BypassCache contract: an impersonated call must not write back into
// the in-memory cache, otherwise the next non-impersonated caller for the
// same (user, org) pair would be served the impersonated view's snapshot.
//
// The cache.Set guard is also under `if !req.BypassCache` in access.go. If
// it's removed, this test catches the regression by counting store reads:
//
//   - Run 1: BypassCache=true. Resolver reads store (count +1). Cache must
//     NOT be populated.
//   - Run 2: BypassCache=false on the same user+org. If run 1 had poisoned
//     the cache, the AccessController would hit the in-memory entry and skip
//     the resolver — store counter would NOT advance. We assert the
//     opposite: the counter advances, proving the cache was not poisoned.
//   - Run 3 (positive control): BypassCache=false again. Now the cache MUST
//     be populated (the previous non-bypass call did c.cache.Set), so the
//     store counter MUST NOT advance. This proves the test's mechanism is
//     working: it correctly stays put on real cache hits.
func TestCheckAccess_BypassCacheDoesNotPopulateCache(t *testing.T) {
	ctx := context.Background()
	store := newCountingBypassStore()
	seedBypassCacheScenario(store)

	controller := NewAccessController(store, 5*time.Minute)
	defer controller.Stop()

	contractA := "0xaaaa000000000000000000000000000000000001"
	req := func(bypass bool) *AccessCheckRequest {
		return &AccessCheckRequest{
			UserExternalID: "did:test:user-a",
			Method:         "eth_call",
			Params:         []any{map[string]any{"to": contractA, "data": "0x"}, "latest"},
			TargetAddress:  contractA,
			BypassCache:    bypass,
		}
	}

	// Run 1: bypass call must read the store.
	result, err := controller.CheckAccess(ctx, req(true))
	if err != nil {
		t.Fatalf("bypass CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed, got denied: %s", result.Reason)
	}
	storeReadsAfterBypass := store.getCachedCalls.Load()
	if storeReadsAfterBypass == 0 {
		t.Fatalf("bypass call must read the store; got 0 GetCachedPermissions calls")
	}

	// Run 2: subsequent NON-bypass call. If the bypass call had populated
	// the in-memory cache, this would be served from the cache and the
	// store counter would NOT advance. We assert the opposite — the
	// counter advances, proving the cache was not poisoned by the bypass.
	result, err = controller.CheckAccess(ctx, req(false))
	if err != nil {
		t.Fatalf("non-bypass CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed on follow-up call, got denied: %s", result.Reason)
	}
	storeReadsAfterFollowup := store.getCachedCalls.Load()
	if storeReadsAfterFollowup == storeReadsAfterBypass {
		t.Errorf("non-bypass follow-up served from in-memory cache (no new store reads, count=%d); "+
			"this means the prior BypassCache=true call populated the cache — c.cache.Set ran despite BypassCache",
			storeReadsAfterFollowup)
	}

	// Run 3 (positive control): a second non-bypass call. The cache MUST
	// now be populated (run 2 did c.cache.Set), so the store counter must
	// NOT advance. This is the positive control — it proves the test's
	// store-counter mechanism is working: it correctly stays put on cache
	// hits and only the bypass path inflates the count.
	result, err = controller.CheckAccess(ctx, req(false))
	if err != nil {
		t.Fatalf("second non-bypass CheckAccess: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("expected allowed on second non-bypass call, got denied: %s", result.Reason)
	}
	storeReadsAfterControl := store.getCachedCalls.Load()
	if storeReadsAfterControl != storeReadsAfterFollowup {
		t.Errorf("control: expected the second non-bypass call to hit the in-memory cache "+
			"populated by the first non-bypass call (no new store reads); "+
			"got %d new GetCachedPermissions reads — cache.Set on the non-bypass path appears broken",
			storeReadsAfterControl-storeReadsAfterFollowup)
	}
}
