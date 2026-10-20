package indexerclient

import (
	"strings"

	"privacy-proxy/internal/explorer"
)

// matchesFilter reports whether a single transaction passes the given
// VisibilityFilter. Mirrors the SQL WHERE clause in
// *Store.visibilityWhereClause so gRPC-path results match the legacy SQL
// path result set element-by-element when both are evaluated over the same
// transaction list.
//
// Rules (mirroring SQL):
//   - filter nil or inactive → always visible
//   - VisibleTxHashes is an always-win override (visibleTo feature)
//   - AllPrivate (allowlist) mode → visible iff at least one participant is
//     in VisibleAddresses, OR tx hash is in VisibleTxHashes
//   - blocklist mode → visible unless BOTH from and to are in
//     HiddenAddresses, with to=NULL (contract creation) treated as
//     "from hidden means hidden"
//
// The filter predicate is O(n*k) over the input transaction list times the
// set sizes; for k > ~10 consider switching callers to pre-build maps. For
// the current use case (viewer-specific filters, tens of addresses) linear
// scan is cheap and matches the SQL cost.
func matchesFilter(tx *explorer.Transaction, filter *explorer.VisibilityFilter) bool {
	if tx == nil {
		return false
	}
	if filter == nil {
		return true
	}
	// VisibleTxHashes: always visible when matched (applies in both modes).
	if inStringSet(tx.Hash, filter.VisibleTxHashes) {
		return true
	}
	if filter.AllPrivate {
		if len(filter.VisibleAddresses) == 0 && len(filter.VisibleTxHashes) == 0 {
			// Empty allowlist with no hash overrides = fail-closed (hide everything).
			return false
		}
		if inStringSet(strings.ToLower(tx.From), filter.VisibleAddresses) {
			return true
		}
		if tx.To != nil && inStringSet(strings.ToLower(*tx.To), filter.VisibleAddresses) {
			return true
		}
		return false
	}
	// Blocklist mode.
	if len(filter.HiddenAddresses) == 0 {
		return true
	}
	fromHidden := inStringSet(strings.ToLower(tx.From), filter.HiddenAddresses)
	if tx.To == nil {
		// Contract creation: hide only if sender is hidden.
		return !fromHidden
	}
	toHidden := inStringSet(strings.ToLower(*tx.To), filter.HiddenAddresses)
	return !(fromHidden && toHidden)
}

// inStringSet is a small membership helper. set is expected to contain
// lowercase strings (caller's responsibility).
func inStringSet(v string, set []string) bool {
	if v == "" || len(set) == 0 {
		return false
	}
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

// filterTxs returns the subset of txs that passes the filter, preserving
// order. Caller is responsible for sizing.
func filterTxs(txs []explorer.Transaction, filter *explorer.VisibilityFilter) []explorer.Transaction {
	if filter == nil {
		return txs
	}
	out := txs[:0] // reuse the underlying array when safe
	for i := range txs {
		if matchesFilter(&txs[i], filter) {
			out = append(out, txs[i])
		}
	}
	return out
}

// overfetchMultiplier is the amount we multiply `limit` by when pre-fetching
// pages that will be post-filtered, to reduce the chance of returning fewer
// than `limit` rows when filter pass-through rate is high. Tuned to
// work on typical privacy-mode filter sizes (viewer sees most txs).
const overfetchMultiplier = 2

// overfetchCap prevents unbounded fetch sizes when many rows would be
// filtered out. With a typical page size of 25, overfetchCap=200 means at
// most 200 rows are pulled per call, at which point the returned page may
// legitimately have < 25 visible rows.
const overfetchCap = 200

// overfetchLimit returns the number of rows to fetch before filtering to
// satisfy a caller that wanted `want`. Caps at overfetchCap.
func overfetchLimit(want int) int {
	n := want * overfetchMultiplier
	if n > overfetchCap {
		return overfetchCap
	}
	if n < want {
		return want
	}
	return n
}
