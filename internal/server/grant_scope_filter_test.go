package server

import (
	"testing"
	"time"

	"privacy-proxy/internal/disclosure"
	"privacy-proxy/internal/explorer"
)

// mkTx builds a transaction with the given from/to (empty to => nil recipient)
// and block timestamp (unix seconds; 0 = missing).
func mkTx(from, to string, ts uint64) explorer.Transaction {
	tx := explorer.Transaction{From: from, BlockTimestamp: ts}
	if to != "" {
		tx.To = &to
	}
	return tx
}

func txKeys(txs []explorer.Transaction) []string {
	out := make([]string, 0, len(txs))
	for _, tx := range txs {
		out = append(out, tx.Hash)
	}
	return out
}

// TestFilterTxsByGrantScope covers RD-1164 #9: disclosed transactions must be
// bounded by the grant's own scope (date range + contract addresses), with a
// fail-closed exclusion for missing/out-of-range timestamps. Directly exercises
// the filtering branches (the existing grant handler tests only create
// unscoped grants, hitting the early-return path).
func TestFilterTxsByGrantScope(t *testing.T) {
	jan := &disclosure.DateRange{
		Start: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC),
	}
	inRange := uint64(time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC).Unix())
	beforeRange := uint64(time.Date(2025, 12, 20, 0, 0, 0, 0, time.UTC).Unix())
	afterRange := uint64(time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC).Unix())

	const (
		addrA = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		addrB = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		addrC = "0xcccccccccccccccccccccccccccccccccccccccc"
	)

	tests := []struct {
		name  string
		scope disclosure.Scope
		txs   []explorer.Transaction
		want  []string // expected surviving tx hashes, in order
	}{
		{
			name:  "no scope is a passthrough",
			scope: disclosure.Scope{},
			txs: []explorer.Transaction{
				{Hash: "t1", From: addrA, BlockTimestamp: 0},
				{Hash: "t2", From: addrB, BlockTimestamp: afterRange},
			},
			want: []string{"t1", "t2"},
		},
		{
			name:  "date range keeps in-range, drops out-of-range",
			scope: disclosure.Scope{DateRange: jan},
			txs: []explorer.Transaction{
				{Hash: "in", From: addrA, BlockTimestamp: inRange},
				{Hash: "before", From: addrA, BlockTimestamp: beforeRange},
				{Hash: "after", From: addrA, BlockTimestamp: afterRange},
			},
			want: []string{"in"},
		},
		{
			name:  "date range fail-closed on missing (0) timestamp",
			scope: disclosure.Scope{DateRange: jan},
			txs: []explorer.Transaction{
				{Hash: "in", From: addrA, BlockTimestamp: inRange},
				{Hash: "zero", From: addrA, BlockTimestamp: 0},
			},
			want: []string{"in"},
		},
		{
			name:  "address scope keeps txs touching a scoped address (case-insensitive), drops others",
			scope: disclosure.Scope{Addresses: []string{"0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}},
			txs: []explorer.Transaction{
				mkTxHash("from-a", addrA, addrC, inRange),
				mkTxHash("to-a", addrC, addrA, inRange),
				mkTxHash("no-a", addrB, addrC, inRange),
				mkTxHash("no-recipient-b", addrB, "", inRange),
			},
			want: []string{"from-a", "to-a"},
		},
		{
			name:  "date and address scope combine (both must pass)",
			scope: disclosure.Scope{DateRange: jan, Addresses: []string{addrA}},
			txs: []explorer.Transaction{
				mkTxHash("in-and-a", addrA, addrC, inRange),   // in range + touches A -> keep
				mkTxHash("in-not-a", addrB, addrC, inRange),   // in range but no A   -> drop
				mkTxHash("out-and-a", addrA, addrC, afterRange), // touches A but out of range -> drop
			},
			want: []string{"in-and-a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := txKeys(filterTxsByGrantScope(tt.txs, tt.scope))
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// mkTxHash is mkTx plus a hash label for assertions.
func mkTxHash(hash, from, to string, ts uint64) explorer.Transaction {
	tx := mkTx(from, to, ts)
	tx.Hash = hash
	return tx
}
