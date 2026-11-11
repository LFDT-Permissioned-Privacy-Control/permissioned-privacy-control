package rpcexecution

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	"testing"
	"time"
)

func TestIncludedHistoryBatchOwnedBindingsSharedBudgetAndFinalReorg(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false), historySigned(t, 2, 1, false, false))
	c := f.readClient(t, DefaultHistoryReadLimits())
	hashes := []common.Hash{f.txs[0].Hash(), f.txs[1].Hash()}
	anchor := &HistoryHeader{Number: 1, Hash: f.header.Hash()}
	b, err := c.AcquireIncludedBatch(t.Context(), hashes, anchor, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}, 1024)
	if err != nil || len(b.Transactions()) != 2 || len(b.Receipts()) != 2 {
		t.Fatal("actual signed/receipt batch", err)
	}
	if b.staged.valid() {
		t.Fatal("batch staging became a public history/block observation")
	}
	if err = b.Recheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.reorg = true
	if b.Recheck(t.Context()) == nil {
		t.Fatal("final selected numeric branch changed")
	}
	f.reorg = false
	// A contradictory receipt invalidates the whole owned batch.
	f.change = func(method string, value any) any {
		if method == "eth_getTransactionReceipt" {
			row := includedObject(t, value)
			row["transactionHash"] = common.Hash{19}.Hex()
			return row
		}
		return value
	}
	if got, e := c.AcquireIncludedBatch(t.Context(), hashes, anchor, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}, 0); e == nil || got != nil {
		t.Fatal("cross-transaction receipt accepted")
	}
	f.change = nil
	// The same RPC-item counters constrain subsequent checks; neither a fresh
	// context nor recheck creates a renewed budget/caller lifetime.
	limits := DefaultHistoryReadLimits()
	limits.MaxRPCItems = 16
	limited := f.readClient(t, limits)
	b, err = limited.AcquireIncludedBatch(t.Context(), hashes, anchor, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Recheck(t.Context()); err != nil {
		t.Fatal(err)
	}
	if b.Recheck(context.Background()) == nil {
		t.Fatal("final check reset shared item budget")
	}
	parent, cancel := context.WithCancel(t.Context())
	b, err = c.AcquireIncludedBatch(parent, hashes, anchor, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second), Done: parent.Done()}, 0)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if b.Recheck(context.Background()) == nil {
		t.Fatal("fresh parent renewed original cancellation")
	}
}
