package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type historyRequestedLog struct {
	raw      json.RawMessage
	location HistoryLocation
	tx       common.Hash
	index    uint32
	removed  bool
}

func (c *HistoryReadClient) acquireReadLogs(ctx context.Context, o *HistoryReadObservation) error {
	q := o.query.logs
	filter := map[string]any{}
	// The normalized filter's nested arrays are already owned and bounded by
	// ParseHistoryReadQuery. Only the two range selectors are replaced here.
	for k, v := range o.query.params[0].(map[string]any) {
		filter[k] = v
	}
	canonical := q.hash == nil
	var from, to uint64
	if canonical {
		if q.from.Kind == StatePending || q.to.Kind == StatePending {
			// Ask the actual backend; geth reports unsupported. Even an unusual
			// successful response cannot become a fabricated stable pending range.
			_, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getLogs", []any{filter}, c.limits.MaxResultBytes}})
			if err != nil {
				return err
			}
			return failure(UnsupportedEvidence)
		}
		resolved := map[StateBlockKind]*types.Header{}
		resolve := func(meta StateBlockMetadata) (uint64, error) {
			if meta.Kind == StateNumber {
				return meta.Number, nil
			}
			if meta.Kind == StateEarliest {
				return 0, nil
			}
			if h := resolved[meta.Kind]; h != nil {
				return h.Number.Uint64(), nil
			}
			h, err := c.readHeader(ctx, o, historyBlockTag(meta), false)
			if err != nil {
				return 0, err
			}
			if h == nil {
				return 0, failure(InvalidEvidence)
			}
			resolved[meta.Kind] = h
			if err = c.addHeader(o, h, true); err != nil {
				return 0, err
			}
			return h.Number.Uint64(), nil
		}
		var err error
		from, err = resolve(q.from)
		if err != nil {
			return err
		}
		to, err = resolve(q.to)
		if err != nil {
			return err
		}
		if to < from || to-from >= uint64(c.limits.MaxBlockSpan) {
			return failure(EvidenceLimit)
		}
		filter["fromBlock"], filter["toBlock"] = historyNumber(from), historyNumber(to)
	}
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getLogs", []any{filter}, c.limits.MaxResultBytes}})
	if err != nil {
		return err
	}
	// Validate token/field/array depth before copying per-log wire fragments.
	if _, err = readJSONFieldArrays(r[0], func(depth int, field string) int {
		if depth == 0 {
			return c.limits.MaxLogs
		}
		if field == "topics" {
			return 4
		}
		return 0
	}); err != nil {
		return err
	}
	requested := []historyRequestedLog{}
	parents := map[common.Hash]HistoryLocation{}
	headerHashes := map[common.Hash]bool{}
	seenHash := map[common.Hash]map[uint32]bool{}
	err = includedArray(r[0], c.limits.MaxLogs, func(raw json.RawMessage) error {
		f, err := closedRawObject(raw, 12)
		if err != nil {
			return err
		}
		pos, err := decodeIncludedPosition(f)
		if err != nil {
			return failure(InvalidEvidence)
		}
		txBytes, err := includedData(f["transactionHash"], 32)
		if err != nil {
			return err
		}
		hash := common.BytesToHash(txBytes)
		if hash == (common.Hash{}) {
			return failure(InvalidEvidence)
		}
		index, err := includedQuantity(f["logIndex"], 31)
		if err != nil {
			return err
		}
		removed := false
		if raw, ok := f["removed"]; ok {
			if json.Unmarshal(raw, &removed) != nil {
				return failure(InvalidEvidence)
			}
		}
		if canonical && (removed || pos.Number < from || pos.Number > to) || q.hash != nil && pos.Hash != *q.hash {
			return failure(InvalidEvidence)
		}
		location := historyIncludedLocation(pos)
		if before, found := parents[hash]; found && before != location {
			return failure(InvalidEvidence)
		}
		if seenHash[pos.Hash] == nil {
			seenHash[pos.Hash] = map[uint32]bool{}
		}
		if seenHash[pos.Hash][uint32(index)] {
			return failure(InvalidEvidence)
		}
		seenHash[pos.Hash][uint32(index)] = true
		// Raw log copies are temporary staging, precharged under the same owned
		// ceiling; parsed retained logs are charged separately and never refunded.
		if err = o.budget.reserveOwned(len(raw) + 192); err != nil {
			return err
		}
		parents[hash] = location
		headerHashes[pos.Hash] = true
		if len(parents) > c.limits.MaxParents || len(headerHashes) > c.limits.MaxHeaders {
			return failure(EvidenceLimit)
		}
		requested = append(requested, historyRequestedLog{raw, location, hash, uint32(index), removed})
		return nil
	})
	if err != nil {
		return err
	}
	r = nil
	if err = c.acquireLogHeaders(ctx, o, headerHashes, canonical); err != nil {
		return err
	}
	hashes := make([]common.Hash, 0, len(parents))
	for hash := range parents {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Hex() < hashes[j].Hex() })
	parentIndex := map[common.Hash]int{}
	// Pair each actual transaction with its actual receipt in bounded batches.
	// A batch size of one is still supported by two separate physical batches.
	for start := 0; start < len(hashes); {
		count := min(max(1, c.limits.MaxBatchItems/2), len(hashes)-start)
		items := make([]historyRPCItem, 0, count*2)
		for _, hash := range hashes[start : start+count] {
			items = append(items, historyRPCItem{"eth_getTransactionByHash", []any{hash.Hex()}, int64(c.limits.Block.MaxTransactionBytes)}, historyRPCItem{"eth_getTransactionReceipt", []any{hash.Hex()}, int64(c.limits.Block.MaxReceiptBytes)})
		}
		var values []json.RawMessage
		for next := 0; next < len(items); next += c.limits.MaxBatchItems {
			end := min(next+c.limits.MaxBatchItems, len(items))
			part, err := c.batch(ctx, o.budget, items[next:end])
			if err != nil {
				return err
			}
			values = append(values, part...)
		}
		for i, hash := range hashes[start : start+count] {
			location := parents[hash]
			rawTx, rawReceipt := values[i*2], values[i*2+1]
			if historyNull(rawTx) || historyNull(rawReceipt) {
				return failure(InvalidEvidence)
			}
			got, pending, err := decodeHistoryLocation(rawTx, false)
			if err != nil || pending || got != location {
				return failure(InvalidEvidence)
			}
			h := o.headers[location.BlockHash]
			if h == nil || h.Number.Uint64() != location.BlockNumber {
				return failure(InvalidEvidence)
			}
			if err = historyJSONShape(rawTx, c.limits.Block, false); err != nil {
				return err
			}
			pos := includedPosition{Hash: location.BlockHash, Number: location.BlockNumber, Index: location.TransactionIndex}
			t, n, err := decodeHistoryTransaction(rawTx, pos, c.source.Network.ChainID, h, c.limits.Block)
			if err != nil {
				return err
			}
			if t.Hash() != hash {
				return failure(InvalidEvidence)
			}
			receipt, rn, err := decodeStandaloneHistoryReceipt(rawReceipt, t, location, h, c.limits.Block)
			if err != nil {
				return err
			}
			if err = o.budget.reserveOwned(n + rn + 192); err != nil {
				return err
			}
			price, err := historyEffectivePrice(t, h.BaseFee)
			if err != nil {
				return err
			}
			parentIndex[hash] = len(o.transactions)
			o.transactions = append(o.transactions, LocatedHistoryTransaction{t, location, price})
			o.receipts = append(o.receipts, LocatedHistoryReceipt{receipt, hash, location})
		}
		start += count
	}
	for _, want := range requested {
		h := o.headers[want.location.BlockHash]
		raw := want.raw
		if want.removed {
			f, err := closedRawObject(raw, 12)
			if err != nil {
				return err
			}
			f["removed"] = json.RawMessage("false")
			raw, err = json.Marshal(f)
			if err != nil {
				return failure(InvalidEvidence)
			}
		}
		pos := includedPosition{Hash: want.location.BlockHash, Number: want.location.BlockNumber, Index: want.location.TransactionIndex, Timestamp: h.Time, TimestampKnown: true}
		log, n, err := decodeHistoryLog(raw, pos, want.tx, want.index, c.limits.Block)
		if err != nil {
			return err
		}
		if !historyLogMatchesFilter(log, q) {
			return failure(InvalidEvidence)
		}
		receipt := o.receipts[parentIndex[want.tx]].Receipt
		found := false
		for _, actual := range receipt.logs {
			if actual.LogIndex == log.LogIndex {
				if !historySameLog(actual, log) {
					return failure(InvalidEvidence)
				}
				found = true
				break
			}
		}
		if !found {
			return failure(InvalidEvidence)
		}
		if err = o.budget.reserveOwned(n + 96); err != nil {
			return err
		}
		o.logs = append(o.logs, LocatedHistoryLog{log, want.tx, want.location, want.removed})
	}
	if canonical {
		o.kind = HistoryCanonical
	} else {
		o.kind = HistoryLocated
	}
	return nil
}
func (c *HistoryReadClient) acquireLogHeaders(ctx context.Context, o *HistoryReadObservation, wanted map[common.Hash]bool, canonical bool) error {
	hashes := make([]common.Hash, 0, len(wanted))
	for hash := range wanted {
		if o.headers[hash] == nil {
			hashes = append(hashes, hash)
		}
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Hex() < hashes[j].Hex() })
	for start := 0; start < len(hashes); start += c.limits.MaxBatchItems {
		end := min(start+c.limits.MaxBatchItems, len(hashes))
		items := make([]historyRPCItem, 0, end-start)
		for _, hash := range hashes[start:end] {
			items = append(items, historyRPCItem{"eth_getHeaderByHash", []any{hash.Hex()}, 16 << 10})
		}
		values, err := c.batch(ctx, o.budget, items)
		if err != nil {
			return err
		}
		for i, raw := range values {
			qualified, err := decodeQualifiedHeader(raw)
			if err != nil || qualified.Hash != hashes[start+i] {
				return failure(InvalidEvidence)
			}
			var h types.Header
			if json.Unmarshal(raw, &h) != nil {
				return failure(InvalidEvidence)
			}
			if err = c.addHeader(o, &h, canonical); err != nil {
				return err
			}
		}
	}
	return nil
}
func historySameLog(a, b HistoryLog) bool {
	if a.Address != b.Address || a.TransactionIndex != b.TransactionIndex || a.LogIndex != b.LogIndex || !bytes.Equal(a.Data, b.Data) || len(a.Topics) != len(b.Topics) {
		return false
	}
	for i := range a.Topics {
		if a.Topics[i] != b.Topics[i] {
			return false
		}
	}
	return true
}
func historyLogMatchesFilter(log HistoryLog, q historyLogQuery) bool {
	if len(q.addresses) > 0 {
		found := false
		for _, a := range q.addresses {
			if a == log.Address {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(q.topics) > len(log.Topics) {
		return false
	}
	for i, choices := range q.topics {
		if len(choices) == 0 {
			continue
		}
		found := false
		for _, topic := range choices {
			if topic == log.Topics[i] {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
