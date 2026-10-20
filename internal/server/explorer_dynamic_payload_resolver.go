package server

import (
	"context"
	"log/slog"
	"strings"

	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"
)

// dynamicPayloadStore is the narrow interface the M15 resolver needs.
// Implemented by *db.DB (the canonical store) but isolated so the
// resolver can be unit-tested with a small fake.
type dynamicPayloadStore interface {
	GetBatchEventsAllowDynamicPayload(ctx context.Context, addresses []string) (map[string]bool, error)
}

// dbDynamicPayloadAllowedResolver implements
// explorer.DynamicPayloadAllowedResolver by batch-reading the per-
// contract `events_allow_dynamic_payload` flag (the same DB row the
// JSON-RPC layer's storeABIProvider consults via the optional
// rbac.DynamicPayloadAllower interface).
//
// Wired into RedactionEngine at server startup, this closes the
// explorer side of the M15 drop gate (security audit follow-up to
// RD-915). Pre-M15 the static-slot scanner ignored dynamic non-indexed
// event params (`bytes`, `string`, dynamic arrays / structs), so any
// contract that embeds addresses inside a `bytes` payload (bridge,
// forwarder, smart-wallet flows) leaked foreign-org addresses to
// non-Full viewers verbatim. The drop is close-by-default; operators
// opt out per contract via the super-admin PUT endpoint.
type dbDynamicPayloadAllowedResolver struct {
	store dynamicPayloadStore
}

// newDBDynamicPayloadAllowedResolver accepts a rbac.Store for symmetry
// with the other resolvers in this package; the concrete production
// type (*db.DB) implements both. If the supplied store does NOT
// implement the batch method (e.g., a stripped-down mock in early
// startup), the resolver falls back to a permissive no-op (returns an
// empty map), which means **drop** under close-by-default — fail-safe.
func newDBDynamicPayloadAllowedResolver(store rbac.Store) *dbDynamicPayloadAllowedResolver {
	if dp, ok := store.(dynamicPayloadStore); ok {
		return &dbDynamicPayloadAllowedResolver{store: dp}
	}
	return &dbDynamicPayloadAllowedResolver{store: nil}
}

// Resolve returns a lowercase-address → bool map. Entry is true iff the
// contract row has `events_allow_dynamic_payload = TRUE`. Missing or
// false entries mean "drop dynamic-payload events" (close-by-default).
//
// Failure mode is fail-closed: any DB error returns an empty map, which
// means every contract drops dynamic-payload events for non-bypass
// viewers. Better an over-redacted log batch than a leak.
func (r *dbDynamicPayloadAllowedResolver) Resolve(ctx context.Context, addresses []string) map[string]bool {
	if r.store == nil || len(addresses) == 0 {
		return map[string]bool{}
	}
	lower := make([]string, 0, len(addresses))
	for _, a := range addresses {
		lower = append(lower, strings.ToLower(a))
	}
	out, err := r.store.GetBatchEventsAllowDynamicPayload(ctx, lower)
	if err != nil {
		slog.Error("M15 resolver: db read failed (fail-closed: drop all dynamic-payload events for non-bypass viewers)", "err", err)
		return map[string]bool{}
	}
	return out
}

// Compile-time assertion that *dbDynamicPayloadAllowedResolver satisfies
// explorer.DynamicPayloadAllowedResolver.
var _ explorer.DynamicPayloadAllowedResolver = (*dbDynamicPayloadAllowedResolver)(nil)
