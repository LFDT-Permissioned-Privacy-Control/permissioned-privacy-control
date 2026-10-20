// Stage 2b: filtered-variant overrides.
//
// These methods use Go-layer visibility filtering on top of unfiltered
// gRPC fetches. Matches SQL semantics element-for-element when given the
// same input set (see filter.go::matchesFilter).
//
// Performance note: over-fetch by a fixed multiplier to reduce the chance
// of returning short pages when the filter has high exclusion rate. For
// deployments where filters exclude a large fraction of rows, consider
// raising overfetchCap in filter.go or switching to a fetch-and-filter
// loop in the handler.
//
// Intentionally NOT overridden (falls through to embedded *Store):
//
//   - GetChainStatsFiltered
//   - GetTransactionHistoryFiltered
//
// These subtract filtered counts / buckets from aggregate stats, which
// would require scanning every row on the chain. See
// docs/rd-855-behavioral-shifts.md §9 / §10 for the product decision
// still pending.

package indexerclient

import (
	"context"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// ----- Blocks -----

// GetBlocksFiltered fetches blocks unfiltered from the indexer and then
// replaces each block's TransactionCount with the post-filter count (by
// fetching that block's transactions and counting survivors). Matches
// legacy *Store.GetBlocksFiltered observable result.
//
// Cost: `len(blocks)` extra round trips. For a normal page (≤25 blocks)
// this is tolerable; for very large limits consider adding an indexer RPC
// like BatchGetBlockTransactionCountsFiltered that accepts a filter spec.
func (b *Backend) GetBlocksFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *explorer.VisibilityFilter) ([]explorer.Block, error) {
	blocks, err := b.GetBlocks(ctx, limit, beforeBlock)
	if err != nil || len(blocks) == 0 || !explorerFilterActive(filter) {
		return blocks, err
	}
	for i := range blocks {
		count, cerr := b.GetBlockTransactionCountFiltered(ctx, blocks[i].Number, filter)
		if cerr != nil {
			return nil, cerr
		}
		blocks[i].TransactionCount = count
	}
	return blocks, nil
}

// GetBlockTransactionCountFiltered fetches every transaction in a block
// (bounded — block tx counts are naturally small) and counts survivors.
func (b *Backend) GetBlockTransactionCountFiltered(ctx context.Context, blockNumber uint64, filter *explorer.VisibilityFilter) (int, error) {
	if !explorerFilterActive(filter) {
		// No filter: use the cheap per-block batch count RPC.
		resp, err := b.client.BatchGetBlockTransactionCounts(ctx, &indexerv1.BatchGetBlockTransactionCountsRequest{
			BlockNumbers: []uint64{blockNumber},
		})
		if err != nil {
			return 0, err
		}
		return int(resp.GetCounts()[blockNumber]), nil
	}
	txs, err := b.GetTransactionsByBlock(ctx, blockNumber)
	if err != nil {
		return 0, err
	}
	count := 0
	for i := range txs {
		if matchesFilter(&txs[i], filter) {
			count++
		}
	}
	return count, nil
}

// ----- Transaction feeds -----

// GetTransactionsFiltered fetches `overfetchLimit(limit)` rows unfiltered
// from the indexer and applies the filter in Go. Returns at most `limit`
// rows — may return fewer if the filter excludes a large fraction.
func (b *Backend) GetTransactionsFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *explorer.VisibilityFilter) ([]explorer.Transaction, error) {
	txs, err := b.GetTransactions(ctx, overfetchLimit(limit), beforeBlock)
	if err != nil {
		return nil, err
	}
	return trimToLimit(filterTxs(txs, filter), limit), nil
}

// GetTransactionsWithCategoriesFiltered is identical at the indexer level
// (categories are materialized on every row); kept for API symmetry.
func (b *Backend) GetTransactionsWithCategoriesFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *explorer.VisibilityFilter) ([]explorer.Transaction, error) {
	return b.GetTransactionsFiltered(ctx, limit, beforeBlock, filter)
}

// GetTransactionsPaginatedFiltered uses offset pagination. The indexer
// doesn't expose offset pagination on ListTransactions; we translate to
// fetch (page * pageSize) rows in cursor mode and skip the first
// ((page-1) * pageSize). Inefficient for deep pages; acceptable for the
// first few pages — typical UI use.
//
// Total is the visibility-aware, DB-wide COUNT(*) from the embedded SQL
// *Store (CountTransactionsFiltered) — the same count GetChainStatsFiltered
// already relies on through this backend. Previously this returned
// len(filtered rows after skip), a page-local total that grew as the client
// paginated (e.g. 47 on page 1, 70 on page 2), inflating the computed page
// count and producing phantom pages. The rows still come from the indexer;
// only the total is sourced from SQL. See docs/rd-855-behavioral-shifts.md §1.
func (b *Backend) GetTransactionsPaginatedFiltered(ctx context.Context, page, pageSize int, filter *explorer.VisibilityFilter) ([]explorer.Transaction, int64, error) {
	if page < 1 {
		page = 1
	}
	// Stable, visibility-aware total — independent of the requested page.
	total, err := b.Store.CountTransactionsFiltered(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	fetchCount := overfetchLimit(page * pageSize)
	txs, err := b.GetTransactions(ctx, fetchCount, nil)
	if err != nil {
		return nil, 0, err
	}
	filtered := filterTxs(txs, filter)
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return nil, total, nil
	}
	end := start + pageSize
	if end > len(filtered) {
		end = len(filtered)
	}
	window := filtered[start:end]
	return window, total, nil
}

// GetTransactionsPaginatedWithCategoriesFiltered — same call, kept
// separately for legacy API symmetry.
func (b *Backend) GetTransactionsPaginatedWithCategoriesFiltered(ctx context.Context, page, pageSize int, filter *explorer.VisibilityFilter) ([]explorer.Transaction, int64, error) {
	return b.GetTransactionsPaginatedFiltered(ctx, page, pageSize, filter)
}

// ----- Address tx count -----

// GetAddressTransactionCountFiltered fetches the address's transactions
// (bounded by the indexer's page cap) and counts survivors. For very
// active addresses (thousands of txs) this is imprecise — the indexer
// caps page size, so we only sample the top page.
//
// RD-1149: walks the feed on the indexer's continuation cursor and counts
// matching rows across pages, bounded by overfetchCap rows fetched in total
// (each fetch is server-clamped to the indexer max, ~100). Beyond the cap the
// count under-reports, which is the safe direction. An exact server-side
// count would need a new indexer RPC; see docs/rd-855-behavioral-shifts.md.
func (b *Backend) GetAddressTransactionCountFiltered(ctx context.Context, address string, filter *explorer.VisibilityFilter) (int, error) {
	count, fetched := 0, 0
	var cursor string
	for fetched < overfetchCap {
		txs, next, err := b.GetTransactionsByAddress(ctx, address, overfetchCap-fetched, explorer.AddressPage{Cursor: cursor})
		if err != nil {
			return 0, err
		}
		if len(txs) == 0 {
			break
		}
		// A non-advancing cursor means the backend re-served the previous
		// page: discard this fetch uncounted and stop — fail-safe undercount,
		// never a double-count (mirrors countAcrossPages).
		if next != "" && next == cursor {
			break
		}
		fetched += len(txs)
		for i := range txs {
			if matchesFilter(&txs[i], filter) {
				count++
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return count, nil
}

// ----- Helpers -----

// explorerFilterActive is a local copy of explorer.isFilterActive so we
// don't have to export it.
func explorerFilterActive(filter *explorer.VisibilityFilter) bool {
	if filter == nil {
		return false
	}
	if filter.AllPrivate {
		return true
	}
	return len(filter.HiddenAddresses) > 0
}

func trimToLimit(txs []explorer.Transaction, limit int) []explorer.Transaction {
	if limit <= 0 || len(txs) <= limit {
		return txs
	}
	return txs[:limit]
}
