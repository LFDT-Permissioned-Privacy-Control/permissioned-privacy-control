package explorer

import (
	"context"
	"database/sql"
	"testing"
)

// TestFindTransferParticipantTxs_RD1009 exercises the new store method that
// underpins the cross-redactor row-survival fix. The method returns the subset
// of tx hashes whose token_transfers row references any address in the
// viewer-visible set on either side (from / to). It is the building block
// the server-level buildVisibilityFilter unions into VisibilityFilter.VisibleTxHashes
// so a tx that calls a private token contract on behalf of an admin-visible
// recipient survives the SQL allowlist filter and the redactor's bothHidden
// branch — matching the survival of its derived transfer row.
func TestFindTransferParticipantTxs_RD1009(t *testing.T) {
	dbURL, cleanup := setupTestContainer(t)
	defer cleanup()

	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()

	setupExplorerSchema(t, sqlDB)
	seedTransferParticipantFixtures(t, sqlDB)

	store, err := NewStore(dbURL)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	ctx := context.Background()

	t.Run("matches transfer with visible recipient", func(t *testing.T) {
		got, err := store.FindTransferParticipantTxs(ctx,
			[]string{"0xadmin_visible_orgmate"}, nil /* beforeBlock */, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		// tx_visible_recipient has a transfer whose to_address is the admin-visible orgmate.
		if !got["0xtx_visible_recipient"] {
			t.Errorf("expected 0xtx_visible_recipient in result, got %v", got)
		}
		// tx_both_hidden has no transfer with this address — must NOT be in the union.
		if got["0xtx_both_hidden"] {
			t.Errorf("did not expect 0xtx_both_hidden in result, got %v", got)
		}
	})

	t.Run("matches transfer with visible sender", func(t *testing.T) {
		got, err := store.FindTransferParticipantTxs(ctx,
			[]string{"0xadmin_visible_sender"}, nil, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		if !got["0xtx_visible_sender"] {
			t.Errorf("expected 0xtx_visible_sender in result, got %v", got)
		}
	})

	t.Run("no match when neither side visible", func(t *testing.T) {
		// Address that appears in no transfer.
		got, err := store.FindTransferParticipantTxs(ctx,
			[]string{"0xnobody_address"}, nil, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty result for unseen address, got %v", got)
		}
	})

	t.Run("empty input addresses → empty map", func(t *testing.T) {
		got, err := store.FindTransferParticipantTxs(ctx, nil, nil, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected empty map for empty input, got %v", got)
		}
	})

	t.Run("beforeBlock cursor bounds the scan", func(t *testing.T) {
		// tx_visible_recipient is at block 2; tx_visible_sender is at block 5.
		// With beforeBlock=3 we should only see the block-2 tx.
		bb := uint64(3)
		got, err := store.FindTransferParticipantTxs(ctx,
			[]string{"0xadmin_visible_orgmate", "0xadmin_visible_sender"}, &bb, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		if !got["0xtx_visible_recipient"] {
			t.Errorf("expected 0xtx_visible_recipient (block 2) in result, got %v", got)
		}
		if got["0xtx_visible_sender"] {
			t.Errorf("did not expect 0xtx_visible_sender (block 5, beyond cursor), got %v", got)
		}
	})

	t.Run("mixed-case input is normalised", func(t *testing.T) {
		got, err := store.FindTransferParticipantTxs(ctx,
			[]string{"  0xADMIN_VISIBLE_ORGMATE  "}, nil, 100)
		if err != nil {
			t.Fatalf("FindTransferParticipantTxs: %v", err)
		}
		// Whitespace + uppercase must not poison the query — store contract is
		// lowercase 0x-prefixed and we normalise once on the way in.
		if !got["0xtx_visible_recipient"] {
			t.Errorf("normalisation broken — expected match, got %v", got)
		}
	})
}

// seedTransferParticipantFixtures inserts four transactions covering the
// matrix RD-1009 needs to exercise. Addresses are referred to by descriptive
// sentinel names rather than realistic hex so the fixture intent is obvious in
// failure output.
//
//	tx_both_hidden          : EOA→EOA, no transfer rows. Used to confirm we
//	                          don't false-positive on unrelated txs.
//	tx_visible_recipient    : private EOA calls private token contract;
//	                          transfer has to=admin-visible orgmate. THIS is
//	                          the RD-1009 scenario.
//	tx_visible_sender       : admin-visible sender calls a private token;
//	                          transfer.from = admin-visible. Symmetric case.
//	tx_full_hidden_transfer : both transfer.from and transfer.to hidden;
//	                          must NOT be matched by any visible-addr query.
func seedTransferParticipantFixtures(t *testing.T, sqlDB *sql.DB) {
	t.Helper()
	ctx := context.Background()

	stmts := []string{
		// Two blocks so we can exercise the beforeBlock cursor.
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		 VALUES (2, '0xblock2', '0xparent1', 2000, 21000, 30000000, 2)`,
		`INSERT INTO blocks (number, hash, parent_hash, timestamp, gas_used, gas_limit, transaction_count)
		 VALUES (5, '0xblock5', '0xparent4', 5000, 21000, 30000000, 2)`,

		// tx_both_hidden: plain EOA→EOA, no transfer row. Must never show up.
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
		 VALUES ('0xtx_both_hidden', 2, 0, '0xprivate_eoa_a', '0xprivate_eoa_b', 100, 21000, 1000000000, 1)`,

		// tx_visible_recipient: the RD-1009 reproducer. Tx.to is the token contract,
		// transfer.to is the admin-visible orgmate.
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
		 VALUES ('0xtx_visible_recipient', 2, 1, '0xprivate_eoa_caller', '0xprivate_token_contract', 0, 50000, 1000000000, 1)`,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ('0xtx_visible_recipient', 0, '0xprivate_token_contract', '0xprivate_eoa_caller', '0xadmin_visible_orgmate', 500, 2)`,

		// tx_visible_sender: symmetric. transfer.from = admin-visible.
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
		 VALUES ('0xtx_visible_sender', 5, 0, '0xadmin_visible_sender', '0xprivate_token_contract', 0, 50000, 1000000000, 1)`,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ('0xtx_visible_sender', 0, '0xprivate_token_contract', '0xadmin_visible_sender', '0xprivate_eoa_recipient', 500, 5)`,

		// tx_full_hidden_transfer: transfer both sides hidden — control row that
		// must not surface for any of the visible-addr queries above.
		`INSERT INTO transactions (hash, block_number, tx_index, from_address, to_address, value, gas_used, gas_price, status)
		 VALUES ('0xtx_full_hidden_transfer', 5, 1, '0xprivate_eoa_a', '0xprivate_token_contract', 0, 50000, 1000000000, 1)`,
		`INSERT INTO token_transfers (tx_hash, log_index, token_address, from_address, to_address, value, block_number)
		 VALUES ('0xtx_full_hidden_transfer', 0, '0xprivate_token_contract', '0xprivate_eoa_a', '0xprivate_eoa_b', 500, 5)`,
	}
	for _, s := range stmts {
		if _, err := sqlDB.ExecContext(ctx, s); err != nil {
			t.Fatalf("seed fixture: %v\nSQL: %s", err, s)
		}
	}
}
