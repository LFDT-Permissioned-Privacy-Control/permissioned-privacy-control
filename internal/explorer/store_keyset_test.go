package explorer

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
)

// RD-1149 regression guards for the SQL store: walking the by-address feeds
// on the returned opaque cursor must visit every row exactly once, even when
// a page boundary falls inside a block (the old bare `block_number < $before`
// bound dropped the boundary block's remaining rows). Also pins the legacy
// ?before= mapping and the fail-closed malformed-cursor error.
func TestStoreGetTransactionsByAddress_CursorWalk(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	setupExplorerSchema(t, sqlDB)

	const addr = "0xaaaa0000000000000000000000000000000000aa"
	ctx := context.Background()

	seedBlock := func(n uint64) {
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
			VALUES ($1, $2, $3, $4, 21000, 30000000, 1)`,
			n, fmt.Sprintf("0xkb%x", n), fmt.Sprintf("0xkb%x", n-1), 1000+n); err != nil {
			t.Fatalf("insert block: %v", err)
		}
	}
	seedTx := func(block uint64, txIndex int) string {
		hash := fmt.Sprintf("0xktx%d_%d", block, txIndex)
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
			VALUES ($1, $2, $3, $4, '0xbbbb0000000000000000000000000000000000bb', 0, 21000, 1, '0x', 1)`,
			hash, block, txIndex, addr); err != nil {
			t.Fatalf("insert tx: %v", err)
		}
		return hash
	}

	// Feed order (block DESC, tx_index DESC): block 101 holds 4 txs — limit 2
	// puts two page boundaries inside it.
	seedBlock(100)
	seedBlock(101)
	seedBlock(102)
	var want []string
	want = append(want, seedTx(102, 0))
	for i := 3; i >= 0; i-- {
		want = append(want, seedTx(101, i))
	}
	want = append(want, seedTx(100, 1), seedTx(100, 0))

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	t.Run("cursor walk visits every row exactly once", func(t *testing.T) {
		const limit = 2
		var got []string
		page := AddressPage{}
		for range [10]int{} {
			txs, next, err := store.GetTransactionsByAddress(ctx, addr, limit, page)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, tx := range txs {
				got = append(got, tx.Hash)
			}
			if next == "" {
				break
			}
			page = AddressPage{Cursor: next}
		}
		if len(got) != len(want) {
			t.Fatalf("walked %d txs, want %d (mid-block page boundary must not drop rows): %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("row %d = %s, want %s (feed order)", i, got[i], want[i])
			}
		}
	})

	t.Run("legacy before is block-exclusive", func(t *testing.T) {
		before := uint64(101)
		txs, _, err := store.GetTransactionsByAddress(ctx, addr, 10, AddressPage{BeforeBlock: &before})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(txs) != 2 {
			t.Fatalf("before=101 returned %d txs, want 2 (only block 100)", len(txs))
		}
		for _, tx := range txs {
			if tx.BlockNumber >= before {
				t.Errorf("before=%d returned tx in block %d", before, tx.BlockNumber)
			}
		}
	})

	t.Run("malformed cursor fails closed", func(t *testing.T) {
		_, _, err := store.GetTransactionsByAddress(ctx, addr, 10, AddressPage{Cursor: "!!not-base64!!"})
		if err == nil {
			t.Fatal("malformed cursor must error, not restart the feed")
		}
		if !isBadCursor(err) {
			t.Fatalf("error = %v, want ErrBadCursor", err)
		}
	})

	t.Run("cursor absent on the final page", func(t *testing.T) {
		txs, next, err := store.GetTransactionsByAddress(ctx, addr, len(want), AddressPage{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(txs) != len(want) {
			t.Fatalf("got %d txs, want %d", len(txs), len(want))
		}
		if next != "" {
			t.Errorf("exact-fit page must not return a cursor, got %q", next)
		}
	})
}

// TestStoreGetTransfersByAddress_CursorWalk is the transfer half of the RD-1149
// SQL keyset guard (the transaction walk above only covered transactions; the
// transfer query is independently implemented and keysets on (block, log_index)
// rather than (block, tx_index), so it needs its own boundary-inside-a-block
// proof). Walking the cursor must visit every transfer exactly once even when a
// page boundary falls inside a block; also pins legacy ?before=, the
// malformed-cursor fail-closed, and exact-fit exhaustion.
func TestStoreGetTransfersByAddress_CursorWalk(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()
	setupExplorerSchema(t, sqlDB)

	const addr = "0xaaaa0000000000000000000000000000000000aa"
	const other = "0xbbbb0000000000000000000000000000000000bb"
	const token = "0xcccc0000000000000000000000000000000000cc"
	ctx := context.Background()

	seedBlock := func(n uint64) {
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
			VALUES ($1, $2, $3, $4, 21000, 30000000, 1)`,
			n, fmt.Sprintf("0xtb%x", n), fmt.Sprintf("0xtb%x", n-1), 1000+n); err != nil {
			t.Fatalf("insert block: %v", err)
		}
	}
	// One tx per block satisfies the token_transfers.tx_hash FK; multiple
	// transfers share it via distinct log_index (a block with several transfers).
	seedTx := func(block uint64) string {
		hash := fmt.Sprintf("0xttx%d", block)
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, input_data, status)
			VALUES ($1, $2, 0, $3, $4, 0, 21000, 1, '0x', 1)`,
			hash, block, addr, other); err != nil {
			t.Fatalf("insert tx: %v", err)
		}
		return hash
	}
	// seedTransfer returns the row's feed identity "block_logIndex".
	seedTransfer := func(block uint64, txHash string, logIndex int) string {
		if _, err := sqlDB.ExecContext(ctx, `
			INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number, timestamp, transfer_type, token_type)
			VALUES ($1, $2, $3, $4, $5, 1000, $6, $7, 'transfer', 'ERC20')`,
			txHash, logIndex, token, addr, other, block, 1000+block); err != nil {
			t.Fatalf("insert transfer: %v", err)
		}
		return fmt.Sprintf("%d_%d", block, logIndex)
	}

	// Feed order (block DESC, log_index DESC): block 101 holds 4 transfers —
	// limit 2 puts two page boundaries inside it.
	seedBlock(100)
	seedBlock(101)
	seedBlock(102)
	tx100, tx101, tx102 := seedTx(100), seedTx(101), seedTx(102)
	var want []string
	want = append(want, seedTransfer(102, tx102, 0))
	for i := 3; i >= 0; i-- {
		want = append(want, seedTransfer(101, tx101, i))
	}
	want = append(want, seedTransfer(100, tx100, 1), seedTransfer(100, tx100, 0))

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	key := func(tr TokenTransfer) string { return fmt.Sprintf("%d_%d", tr.BlockNumber, tr.LogIndex) }

	t.Run("cursor walk visits every transfer exactly once", func(t *testing.T) {
		const limit = 2
		var got []string
		page := AddressPage{}
		for range [10]int{} {
			xfers, next, err := store.GetTransfersByAddress(ctx, addr, limit, page)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, tr := range xfers {
				got = append(got, key(tr))
			}
			if next == "" {
				break
			}
			page = AddressPage{Cursor: next}
		}
		if len(got) != len(want) {
			t.Fatalf("walked %d transfers, want %d (mid-block page boundary must not drop/dup rows): %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("row %d = %s, want %s (feed order)", i, got[i], want[i])
			}
		}
	})

	t.Run("legacy before is block-exclusive", func(t *testing.T) {
		before := uint64(101)
		xfers, _, err := store.GetTransfersByAddress(ctx, addr, 10, AddressPage{BeforeBlock: &before})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(xfers) != 2 {
			t.Fatalf("before=101 returned %d transfers, want 2 (only block 100)", len(xfers))
		}
		for _, tr := range xfers {
			if tr.BlockNumber >= before {
				t.Errorf("before=%d returned transfer in block %d", before, tr.BlockNumber)
			}
		}
	})

	t.Run("malformed cursor fails closed", func(t *testing.T) {
		_, _, err := store.GetTransfersByAddress(ctx, addr, 10, AddressPage{Cursor: "!!not-base64!!"})
		if err == nil {
			t.Fatal("malformed cursor must error, not restart the feed")
		}
		if !isBadCursor(err) {
			t.Fatalf("error = %v, want ErrBadCursor", err)
		}
	})

	t.Run("cursor absent on the final page", func(t *testing.T) {
		xfers, next, err := store.GetTransfersByAddress(ctx, addr, len(want), AddressPage{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(xfers) != len(want) {
			t.Fatalf("got %d transfers, want %d", len(xfers), len(want))
		}
		if next != "" {
			t.Errorf("exact-fit page must not return a cursor, got %q", next)
		}
	})
}

func isBadCursor(err error) bool {
	for e := err; e != nil; {
		if e == ErrBadCursor {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
