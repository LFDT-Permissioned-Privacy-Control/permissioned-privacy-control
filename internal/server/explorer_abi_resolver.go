package server

import (
	"context"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dbABIResolver implements explorer.ABIResolver by consulting the RBAC
// store (the same store the JSON-RPC layer's storeABIProvider uses) and
// applying the unified rbac.ResolveContractABI logic — custom ABI first,
// built-in registry fallback (ERC-20 / ERC-721 from metadata.token_type).
//
// Wiring this into RedactionEngine at server startup closes the
// pre-RD-889 explorer-side gap where the redactor consulted only the
// explorer's local ContractStore (no metadata field, no built-in
// fallback). After this resolver is wired, both layers consult one
// source of truth — required by the access/visibility symmetry
// invariant in REDACTION_SPEC.md.
//
// Per-request caching is deliberately omitted here because the
// RedactionEngine already caches resolved ABIs in its Phase 3 map for
// the duration of a single RedactLogs call. If we ever reuse this
// resolver from a longer-lived context we should add a TTL cache, but
// the current call sites are short-lived per HTTP request.
type dbABIResolver struct {
	store rbac.Store
}

func newDBABIResolver(store rbac.Store) *dbABIResolver {
	return &dbABIResolver{store: store}
}

// Resolve returns the resolved ABI JSON for the given contract address,
// or "" when no ABI is resolvable. See explorer.ABIResolver for the
// contract.
//
// Delegates to rbac.ResolveContractABI — the single source of truth
// for "what ABI applies to this contract" (custom upload first,
// built-in registry fallback keyed by metadata.token_type). RD-875
// landed that helper, and RD-889's original inlined body is no longer
// necessary.
func (r *dbABIResolver) Resolve(ctx context.Context, address string) string {
	if r.store == nil {
		return ""
	}
	contract, err := r.store.GetContractByAddressGlobal(ctx, address)
	if err != nil || contract == nil {
		return ""
	}
	return rbac.ResolveContractABI(contract)
}

// Compile-time assertion that *dbABIResolver satisfies explorer.ABIResolver.
var _ explorer.ABIResolver = (*dbABIResolver)(nil)
