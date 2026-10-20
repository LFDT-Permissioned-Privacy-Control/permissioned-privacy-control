package indexerclient

import (
	"context"
	"strconv"
	"testing"

	"google.golang.org/grpc"

	indexerv1 "privacy-proxy/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// fakeIndexerClient stubs the two by-address list RPCs and clamps the page
// size the way the real chain-indexer does (MaxPageSize, default 100 — 3 here
// so tests stay small). Cursors are the stringified index of the next row —
// opaque to the adapter, exactly like production. Any other RPC panics via
// the nil embedded interface.
type fakeIndexerClient struct {
	indexerv1.IndexerServiceClient

	clamp int32
	txs   []*indexerv1.Transaction
	trs   []*indexerv1.TokenTransfer

	lastTxReq *indexerv1.ListTransactionsRequest
}

func pageWindow(cursor string, n, total int) (start, end int, next string) {
	if cursor != "" {
		start, _ = strconv.Atoi(cursor)
	}
	if start >= total {
		return total, total, ""
	}
	end = start + n
	if end > total {
		end = total
	}
	if end < total {
		next = strconv.Itoa(end)
	}
	return start, end, next
}

func (f *fakeIndexerClient) ListTransactions(_ context.Context, req *indexerv1.ListTransactionsRequest, _ ...grpc.CallOption) (*indexerv1.ListTransactionsResponse, error) {
	f.lastTxReq = req
	n := req.GetPage().GetPageSize()
	if n <= 0 || n > f.clamp {
		n = f.clamp // the real indexer clamps silently
	}
	start, end, next := pageWindow(req.GetPage().GetCursor(), int(n), len(f.txs))
	return &indexerv1.ListTransactionsResponse{
		Transactions: f.txs[start:end],
		Page:         &indexerv1.PageResponse{NextCursor: next},
	}, nil
}

func (f *fakeIndexerClient) ListTokenTransfers(_ context.Context, req *indexerv1.ListTokenTransfersRequest, _ ...grpc.CallOption) (*indexerv1.ListTokenTransfersResponse, error) {
	n := req.GetPage().GetPageSize()
	if n <= 0 || n > f.clamp {
		n = f.clamp
	}
	start, end, next := pageWindow(req.GetPage().GetCursor(), int(n), len(f.trs))
	return &indexerv1.ListTokenTransfersResponse{
		Transfers: f.trs[start:end],
		Page:      &indexerv1.PageResponse{NextCursor: next},
	}, nil
}

// TestGetTransactionsByAddress_CursorRoundTrip is the RD-1149 gRPC contract
// test (the gap that sank PR #399): the adapter must iterate the indexer's
// REAL opaque continuation, not infer exhaustion from its own requested page
// size — the server clamps every page (MaxPageSize ~100), so "short page"
// tells the caller nothing. Qualifying rows sit beyond the first clamped
// page, including several within one block (the RD-1148 boundary shape).
func TestGetTransactionsByAddress_CursorRoundTrip(t *testing.T) {
	// 8 txs: 3 in block 100, 4 in block 99, 1 in block 98 — with clamp=3 every
	// page boundary lands inside a block.
	var txs []*indexerv1.Transaction
	mk := func(block uint64, idx uint32) *indexerv1.Transaction {
		return &indexerv1.Transaction{
			Hash:             "0xtx" + strconv.FormatUint(block, 10) + "_" + strconv.Itoa(int(idx)),
			BlockNumber:      block,
			TransactionIndex: idx,
			From:             "0xaaaa000000000000000000000000000000000001",
		}
	}
	for i := 2; i >= 0; i-- {
		txs = append(txs, mk(100, uint32(i)))
	}
	for i := 3; i >= 0; i-- {
		txs = append(txs, mk(99, uint32(i)))
	}
	txs = append(txs, mk(98, 0))

	fake := &fakeIndexerClient{clamp: 3, txs: txs}
	b := &Backend{client: fake}
	ctx := context.Background()

	var got []string
	page := explorer.AddressPage{}
	for range [10]int{} { // must terminate well within this
		rows, next, err := b.GetTransactionsByAddress(ctx, "0xaaaa000000000000000000000000000000000001", 1000, page)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for _, tx := range rows {
			got = append(got, tx.Hash)
		}
		if next == "" {
			break
		}
		page = explorer.AddressPage{Cursor: next}
	}

	if len(got) != len(txs) {
		t.Fatalf("walked %d txs, want %d — the adapter must follow next_cursor past the server's clamped first page", len(got), len(txs))
	}
	for i, tx := range txs {
		if got[i] != tx.Hash {
			t.Fatalf("row %d = %s, want %s (feed order must be preserved)", i, got[i], tx.Hash)
		}
	}
}

// TestGetTransactionsByAddress_BeforeBlockMapsToExclusiveToBlock pins the
// legacy-bound translation: both the REST ?before= and the proto
// block_range.to_block are exclusive (BlockRange is half-open), so before=N
// passes through unchanged — only on the first page (no cursor) — and
// before=0 short-circuits to an empty page (to_block=0 would mean unbounded
// and restart the feed).
func TestGetTransactionsByAddress_BeforeBlockMapsToExclusiveToBlock(t *testing.T) {
	fake := &fakeIndexerClient{clamp: 3}
	b := &Backend{client: fake}
	before := uint64(100)

	if _, _, err := b.GetTransactionsByAddress(context.Background(), "0xa", 10, explorer.AddressPage{BeforeBlock: &before}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tb := fake.lastTxReq.GetBlockRange().GetToBlock(); tb != 100 {
		t.Errorf("to_block = %d, want 100 (exclusive passthrough)", tb)
	}

	zero := uint64(0)
	rows, next, err := b.GetTransactionsByAddress(context.Background(), "0xa", 10, explorer.AddressPage{BeforeBlock: &zero})
	if err != nil || len(rows) != 0 || next != "" {
		t.Errorf("before=0 must short-circuit to an empty terminal page, got rows=%d next=%q err=%v", len(rows), next, err)
	}

	// With a cursor present, the legacy bound must NOT be sent — the indexer
	// ignores block_range once a cursor positions the page, and sending both
	// would suggest otherwise to a reader.
	if _, _, err := b.GetTransactionsByAddress(context.Background(), "0xa", 10, explorer.AddressPage{Cursor: "0", BeforeBlock: &before}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fake.lastTxReq.GetBlockRange() != nil {
		t.Errorf("block_range must be omitted when a cursor is present")
	}
}

// TestGetTransfersByAddress_CursorRoundTrip mirrors the tx contract test for
// the token-transfer feed.
func TestGetTransfersByAddress_CursorRoundTrip(t *testing.T) {
	var trs []*indexerv1.TokenTransfer
	for i := 4; i >= 0; i-- { // 5 transfers in one block — clamp=3 splits it
		trs = append(trs, &indexerv1.TokenTransfer{
			TransactionHash: "0xtr" + strconv.Itoa(i),
			LogIndex:        uint32(i),
			BlockNumber:     42,
		})
	}
	fake := &fakeIndexerClient{clamp: 3, trs: trs}
	b := &Backend{client: fake}

	var got int
	page := explorer.AddressPage{}
	for range [10]int{} {
		rows, next, err := b.GetTransfersByAddress(context.Background(), "0xa", 1000, page)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got += len(rows)
		if next == "" {
			break
		}
		page = explorer.AddressPage{Cursor: next}
	}
	if got != len(trs) {
		t.Fatalf("walked %d transfers, want %d", got, len(trs))
	}
}
