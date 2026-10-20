package server

import (
	"context"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dbAdminContractsResolver implements explorer.AdminContractsResolver
// by mirroring the JSON-RPC layer's viewerAdminContracts resolver
// (internal/server/processor_event_rules.go). This guarantees both
// layers honour identical admin-bypass sets per (viewer, contract) —
// required by the access/visibility symmetry invariant in
// REDACTION_SPEC.md.
//
// Algorithm (per call, on a deduped address list):
//  1. Look up the viewer's user-membership orgs once.
//  2. For each contract address, look up its owning org. Skip
//     unregistered / lookup-error addresses (deny by spec).
//  3. If the viewer is NOT a member of the contract's owning org,
//     skip — defense in depth against migration 035 ever weakening
//     the unique-address constraint (cross-org admin denied at
//     runtime).
//  4. Cache effective permissions per (user, owning-org) within the
//     call.
//  5. orgPerms.HasAdminOnContract(addr) handles both tier 2
//     (is_org_admin materialises admin claim across all org contracts)
//     and tier 3 (admin claim explicitly granted on specific contracts).
type dbAdminContractsResolver struct {
	access *rbac.AccessController
}

func newDBAdminContractsResolver(access *rbac.AccessController) *dbAdminContractsResolver {
	return &dbAdminContractsResolver{access: access}
}

// Resolve returns the subset of addresses where the viewer holds
// admin-equivalent privileges. See explorer.AdminContractsResolver for
// the full contract.
func (r *dbAdminContractsResolver) Resolve(ctx context.Context, viewerDID string, addresses []string) map[string]bool {
	result := make(map[string]bool)
	if r.access == nil || viewerDID == "" || len(addresses) == 0 {
		return result
	}

	// De-dupe (callers pass lowercase but normalise here for defense in depth).
	seen := make(map[string]struct{}, len(addresses))
	unique := make([]string, 0, len(addresses))
	for _, a := range addresses {
		if a == "" {
			continue
		}
		al := strings.ToLower(a)
		if _, ok := seen[al]; ok {
			continue
		}
		seen[al] = struct{}{}
		unique = append(unique, al)
	}
	if len(unique) == 0 {
		return result
	}

	// Translate DID → internal user UUID. The explorer hands us a DID
	// (eth_address_links keyspace); user_memberships and the rbac
	// resolver are keyed by internal UUIDs. Without this translation
	// every DB lookup below silently returned the empty set, which
	// rendered the RD-890 admin bypass a no-op in production. Fixed
	// here as part of the post-RD-890 wiring audit.
	userID := resolveViewerInternalID(ctx, r.access.Store(), viewerDID)
	if userID == "" {
		return result
	}

	userOrgIDs, err := r.access.GetUserOrgIDs(ctx, userID)
	if err != nil || len(userOrgIDs) == 0 {
		return result
	}
	userOrgSet := make(map[string]struct{}, len(userOrgIDs))
	for _, o := range userOrgIDs {
		userOrgSet[o] = struct{}{}
	}

	// Cache per-(viewer, owning-org) permissions within this call.
	permsByOrg := make(map[string]*rbac.EffectivePermissions)

	for _, addr := range unique {
		ownerOrgID, err := r.access.Store().GetContractOwnerOrgID(ctx, addr)
		if err != nil || ownerOrgID == "" {
			continue // unregistered or lookup error — no admin
		}
		if _, member := userOrgSet[ownerOrgID]; !member {
			continue // viewer not a member of contract's owning org
		}
		orgPerms, cached := permsByOrg[ownerOrgID]
		if !cached {
			op, err := r.access.GetEffectivePermissionsByIDs(ctx, userID, ownerOrgID)
			if err != nil {
				permsByOrg[ownerOrgID] = nil
				continue
			}
			permsByOrg[ownerOrgID] = op
			orgPerms = op
		}
		if orgPerms != nil && orgPerms.HasAdminOnContract(addr) {
			result[addr] = true
		}
	}
	return result
}

// Compile-time assertion that *dbAdminContractsResolver satisfies
// explorer.AdminContractsResolver.
var _ explorer.AdminContractsResolver = (*dbAdminContractsResolver)(nil)
