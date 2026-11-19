package rpcexecution

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/executionfacts"
)

// IndexedInternalFrame describes one retained indexed frame to verify, not a
// claim that the indexer contains every node frame or every historical trace.
type IndexedInternalFrame struct {
	TransactionHash common.Hash
	BlockNumber     uint64
	Path            string
	From            common.Address
	To              *common.Address
	Value           string
	Input, Output   []byte
	Type            string
	Gas, GasUsed    *uint64
	Error           string
}
type indexedTraceWire struct {
	Type, From, To, Value, Gas, GasUsed, Input, Output, Error string
	Calls                                                     []indexedTraceWire
}

func traceQuantity(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	if !strings.HasPrefix(s, "0x") {
		return 0, failure(InvalidEvidence)
	}
	return strconv.ParseUint(s[2:], 16, 64)
}
func traceBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	if !strings.HasPrefix(s, "0x") {
		return nil, failure(InvalidEvidence)
	}
	return hex.DecodeString(s[2:])
}
func flattenIndexedTrace(w indexedTraceWire, path string, out map[string]IndexedInternalFrame) error {
	if len(out) >= 4096 {
		return failure(EvidenceLimit)
	}
	gas, e := traceQuantity(w.Gas)
	if e != nil {
		return e
	}
	used, e := traceQuantity(w.GasUsed)
	if e != nil {
		return e
	}
	input, e := traceBytes(w.Input)
	if e != nil {
		return e
	}
	output, e := traceBytes(w.Output)
	if e != nil {
		return e
	}
	value := "0"
	if w.Value != "" {
		n, ok := new(big.Int).SetString(strings.TrimPrefix(w.Value, "0x"), 16)
		if !ok || n.Sign() < 0 {
			return failure(InvalidEvidence)
		}
		value = n.String()
	}
	f := IndexedInternalFrame{Path: path, From: common.HexToAddress(w.From), Value: value, Input: input, Output: output, Type: strings.ToLower(w.Type), Gas: &gas, GasUsed: &used, Error: w.Error}
	if w.To != "" {
		a := common.HexToAddress(w.To)
		f.To = &a
	}
	out[path] = f
	for i, child := range w.Calls {
		p := strconv.Itoa(i)
		if path != "" {
			p = path + "," + p
		}
		if e = flattenIndexedTrace(child, p, out); e != nil {
			return e
		}
	}
	return nil
}

// VerifyIndexedFrames borrows the batch's existing original fence, node
// identity, header/receipt/transaction qualification and cumulative budget.
// It fetches a parent trace once and compares every displayed indexed field.
func (b *IncludedHistoryBatch) VerifyIndexedFrames(ctx context.Context, wanted []IndexedInternalFrame) error {
	if b == nil || b.digest == (common.Hash{}) || len(wanted) > 20000 {
		return failure(InvalidBinding)
	}
	bound, cancel, e := b.staged.fence.bind(ctx, b.owner.limits.Timeout)
	if e != nil {
		return e
	}
	defer cancel()
	if b.traces == nil {
		b.traces = map[common.Hash]map[string]IndexedInternalFrame{}
	}
	parents := map[common.Hash]LocatedHistoryTransaction{}
	for _, p := range b.staged.transactions {
		parents[p.Transaction.Hash()] = p
	}
	missing := []common.Hash{}
	seen := map[common.Hash]bool{}
	items := []historyRPCItem{}
	for _, w := range wanted {
		parent, ok := parents[w.TransactionHash]
		if !ok || parent.Location.BlockNumber != w.BlockNumber {
			return failure(InvalidEvidence)
		}
		if _, cached := b.traces[w.TransactionHash]; !cached && !seen[w.TransactionHash] {
			seen[w.TransactionHash] = true
			missing = append(missing, w.TransactionHash)
			items = append(items, historyRPCItem{"debug_traceTransaction", []any{w.TransactionHash.Hex(), map[string]any{"tracer": "callTracer", "tracerConfig": map[string]any{"onlyTopCall": false}}}, 8 << 20})
		}
	}
	if len(items) > 0 {
		raw, err := b.owner.batch(bound, b.staged.budget, items)
		if err != nil || len(raw) != len(items) {
			return failure(InvalidEvidence)
		}
		for i, h := range missing {
			value := raw[i]
			if e = b.staged.budget.reserveOwned(len(value)*3 + bytes.Count(value, []byte(`"type"`))*1024 + 512); e != nil {
				return e
			}
			tx := parents[h].Transaction
			expected := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: tx.From(), Input: tx.Input(), Value: tx.Value()}
			if to, ok := tx.To(); ok {
				expected.To = executionfacts.Address{Known: true, Value: to}
			} else {
				expected.Kind = executionfacts.Create
				expected.CreatedAddress = executionfacts.Address{Known: true, Value: crypto.CreateAddress(tx.From(), tx.Nonce())}
			}
			tree, e := executionfacts.Parse(value, expected, executionfacts.GethCallTracerProfile(), executionfacts.DefaultLimits())
			if e != nil || tree == nil {
				return failure(InvalidEvidence)
			}
			var wire indexedTraceWire
			if json.Unmarshal(value, &wire) != nil {
				return failure(InvalidEvidence)
			}
			frames := map[string]IndexedInternalFrame{}
			if e = flattenIndexedTrace(wire, "", frames); e != nil {
				return e
			}
			b.traces[h] = frames
		}
	}
	for _, w := range wanted {
		var parent *LocatedHistoryTransaction
		for i := range b.staged.transactions {
			if b.staged.transactions[i].Transaction.Hash() == w.TransactionHash {
				parent = &b.staged.transactions[i]
				break
			}
		}
		if parent == nil || parent.Location.BlockNumber != w.BlockNumber {
			return failure(InvalidEvidence)
		}

		got, ok := b.traces[w.TransactionHash][w.Path]
		if !ok || got.From != w.From || got.Type != strings.ToLower(w.Type) || got.Value != w.Value || got.Error != w.Error || (got.To == nil) != (w.To == nil) || got.To != nil && *got.To != *w.To || !bytes.Equal(got.Input, w.Input) || !bytes.Equal(got.Output, w.Output) {
			return failure(InvalidEvidence)
		}
		gas, used := uint64(0), uint64(0)
		if w.Gas != nil {
			gas = *w.Gas
		}
		if w.GasUsed != nil {
			used = *w.GasUsed
		}
		if got.Gas == nil || *got.Gas != gas || got.GasUsed == nil || *got.GasUsed != used {
			return failure(InvalidEvidence)
		}
	}
	if !b.staged.fence.live() || bound.Err() != nil {
		return failure(NodeFailure)
	}
	b.digest, e = b.computeDigest()
	return e
}
