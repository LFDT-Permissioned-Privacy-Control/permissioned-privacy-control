package rpcexecution

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"strings"
	"testing"
	"time"
)

func TestIndexedInternalFramesRequireFullNodeMatchAndCacheOriginalTrace(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
	client := f.readClient(t, DefaultHistoryReadLimits())
	batch, e := client.AcquireIncludedBatch(t.Context(), []common.Hash{f.txs[0].Hash()}, &HistoryHeader{Number: 1, Hash: f.header.Hash()}, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}, 0)
	if e != nil {
		t.Fatal(e)
	}
	tx := batch.Transactions()[0].Transaction
	to, _ := tx.To()
	childTo := common.HexToAddress("0x5555555555555555555555555555555555555555")
	trace := map[string]any{"type": "CALL", "from": tx.From().Hex(), "to": to.Hex(), "value": "0x" + tx.Value().Text(16), "input": "0x" + hex.EncodeToString(tx.Input()), "output": "0x", "gas": "0x100", "gasUsed": "0x10", "calls": []any{map[string]any{"type": "CALL", "from": to.Hex(), "to": childTo.Hex(), "value": "0x1", "input": "0xab", "output": "0xcd", "gas": "0x40", "gasUsed": "0x8"}}}
	f.mu.Lock()
	f.traces = map[string]any{tx.Hash().Hex(): trace}
	f.mu.Unlock()
	gas, used := uint64(64), uint64(8)
	frame := IndexedInternalFrame{TransactionHash: tx.Hash(), BlockNumber: 1, Path: "0", From: to, To: &childTo, Value: "1", Input: []byte{0xab}, Output: []byte{0xcd}, Type: "call", Gas: &gas, GasUsed: &used}
	if e = batch.VerifyIndexedFrames(t.Context(), []IndexedInternalFrame{frame}); e != nil {
		t.Fatal(e)
	}
	if e = batch.VerifyIndexedFrames(t.Context(), []IndexedInternalFrame{frame}); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	calls := f.methods["debug_traceTransaction"]
	f.mu.Unlock()
	if calls != 1 {
		t.Fatal("parent trace refetched", calls)
	}
	for _, change := range []func(*IndexedInternalFrame){func(x *IndexedInternalFrame) { x.Path = "0,1" }, func(x *IndexedInternalFrame) { x.Type = "delegatecall" }, func(x *IndexedInternalFrame) { x.From = childTo }, func(x *IndexedInternalFrame) { x.To = nil }, func(x *IndexedInternalFrame) { x.Value = "2" }, func(x *IndexedInternalFrame) { x.Input = []byte{9} }, func(x *IndexedInternalFrame) { x.Output = []byte{9} }, func(x *IndexedInternalFrame) { x.Gas = nil }, func(x *IndexedInternalFrame) { x.GasUsed = nil }, func(x *IndexedInternalFrame) { x.Error = "invented" }} {
		bad := frame
		change(&bad)
		if batch.VerifyIndexedFrames(t.Context(), []IndexedInternalFrame{bad}) == nil {
			t.Fatal("wrong indexed frame accepted")
		}
	}
	if e = batch.Recheck(t.Context()); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	f.reorg = true
	f.mu.Unlock()
	if batch.Recheck(t.Context()) == nil {
		t.Fatal("reorg accepted after trace verification")
	}
}
func TestFlattenIndexedTraceUsesExactPathsAndEmptyValueSemantics(t *testing.T) {
	out := map[string]IndexedInternalFrame{}
	w := indexedTraceWire{Type: "CALL", From: "0x" + strings.Repeat("1", 40), To: "0x" + strings.Repeat("2", 40), Calls: []indexedTraceWire{{Type: "STATICCALL", From: "0x" + strings.Repeat("2", 40), To: "0x" + strings.Repeat("3", 40), Calls: []indexedTraceWire{{Type: "CALL", From: "0x" + strings.Repeat("3", 40)}}}}}
	if e := flattenIndexedTrace(w, "", out); e != nil {
		t.Fatal(e)
	}
	if len(out) != 3 || out["0,0"].Type != "call" || out["0"].Value != "0" || out["0,0"].To != nil {
		t.Fatal(out)
	}
}

func TestIndexedInternalFramesBatchDistinctParentTraces(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false), historySigned(t, 0, 1, false, false))
	c := f.readClient(t, DefaultHistoryReadLimits())
	hashes := []common.Hash{f.txs[0].Hash(), f.txs[1].Hash()}
	b, e := c.AcquireIncludedBatch(t.Context(), hashes, &HistoryHeader{Number: 1, Hash: f.header.Hash()}, HistoryOperationFence{Deadline: time.Now().Add(3 * time.Second)}, 0)
	if e != nil {
		t.Fatal(e)
	}
	wanted := []IndexedInternalFrame{}
	f.mu.Lock()
	f.traces = map[string]any{}
	for _, p := range b.Transactions() {
		tx := p.Transaction
		to, _ := tx.To()
		gas, used := uint64(256), uint64(16)
		f.traces[tx.Hash().Hex()] = map[string]any{"type": "CALL", "from": tx.From().Hex(), "to": to.Hex(), "value": "0x" + tx.Value().Text(16), "input": "0x" + hex.EncodeToString(tx.Input()), "output": "0x", "gas": "0x100", "gasUsed": "0x10"}
		a := to
		wanted = append(wanted, IndexedInternalFrame{TransactionHash: tx.Hash(), BlockNumber: 1, Path: "", From: tx.From(), To: &a, Value: tx.Value().String(), Input: tx.Input(), Type: "call", Gas: &gas, GasUsed: &used})
	}
	before := f.physical
	f.mu.Unlock()
	if e = b.VerifyIndexedFrames(t.Context(), wanted); e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.physical-before != 1 || f.methods["debug_traceTransaction"] != 2 {
		t.Fatal("parent traces were not batched", f.physical-before, f.methods["debug_traceTransaction"])
	}
}
