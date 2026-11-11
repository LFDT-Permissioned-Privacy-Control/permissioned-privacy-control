package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func (c *HistoryReadClient) acquirePendingBlock(ctx context.Context, o *HistoryReadObservation) error {
	l, err := c.blockReadLimits(o)
	if err != nil {
		return err
	}
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getBlockByNumber", []any{"pending", true}, l.MaxBlockBytes}})
	if err != nil {
		return err
	}
	if historyNull(r[0]) {
		if o.query.method == HistoryBlockReceipts {
			// A missing auxiliary body does not answer the requested receipt method.
			// Preserve the actual backend error/null and never invent an empty set.
			receipts, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getBlockReceipts", []any{"pending"}, l.MaxReceiptSetBytes}})
			if err != nil {
				return err
			}
			if !historyNull(receipts[0]) {
				return failure(UnsupportedEvidence)
			}
		}
		o.kind = HistoryNotFound
		return nil
	}
	if err = historyJSONShape(r[0], l, false); err != nil {
		return err
	}
	f, err := nullableRawObject(r[0], 32, map[string]bool{"hash": true, "nonce": true, "miner": true, "totalDifficulty": true, "size": true, "baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true, "excessBlobGas": true, "parentBeaconBlockRoot": true, "requestsHash": true, "blockAccessListHash": true, "slotNumber": true})
	if err != nil {
		return err
	}
	txs, ok := f["transactions"]
	if !ok {
		return failure(InvalidEvidence)
	}
	uncles, ok := f["uncles"]
	if !ok {
		return failure(InvalidEvidence)
	}
	withdrawals, hasWithdrawals := f["withdrawals"]
	p := &PendingHistoryBlock{}
	for _, field := range []string{"hash", "nonce", "miner"} {
		raw, ok := f[field]
		if !ok {
			return failure(InvalidEvidence)
		}
		present := !historyNull(raw)
		switch field {
		case "hash":
			p.HashPresent = present
			if present {
				b, err := includedData(raw, 32)
				if err != nil {
					return err
				}
				p.Hash = common.BytesToHash(b)
			}
		case "nonce":
			p.NoncePresent = present
			if !present {
				f[field] = json.RawMessage(`"0x0000000000000000"`)
			}
		case "miner":
			p.MinerPresent = present
			if !present {
				f[field] = json.RawMessage(`"0x0000000000000000000000000000000000000000"`)
			}
		}
	}
	if raw, ok := f["size"]; ok {
		p.SizePresence = HistoryNull
		if !historyNull(raw) {
			p.ReportedSize, err = includedQuantity(raw, 64)
			if err != nil {
				return err
			}
			p.SizePresence = HistoryPresent
		}
	}
	if raw, ok := f["totalDifficulty"]; ok {
		p.TDPresence = HistoryNull
		if !historyNull(raw) {
			p.TotalDifficulty, err = historyBig(raw)
			if err != nil {
				return err
			}
			p.TDPresence = HistoryPresent
		}
	}
	for _, field := range []string{"transactions", "uncles", "withdrawals", "size", "totalDifficulty"} {
		delete(f, field)
	}
	// Validate a typed parsing container after replacing only explicitly null
	// pending fields. Its computed hash is never a returned/canonical block hash.
	headerRaw, err := json.Marshal(f)
	if err != nil {
		return failure(InvalidEvidence)
	}
	var h types.Header
	if json.Unmarshal(headerRaw, &h) != nil {
		return failure(InvalidEvidence)
	}
	if p.HashPresent && p.NoncePresent && p.MinerPresent && p.Hash != h.Hash() {
		return failure(InvalidEvidence)
	}
	f["hash"], _ = json.Marshal(h.Hash())
	headerRaw, _ = json.Marshal(f)
	if _, err = decodeQualifiedHeader(headerRaw); err != nil {
		return err
	}
	p.Header = &h
	if err = o.budget.reserveOwned(2048 + len(h.Extra)); err != nil {
		return err
	}
	err = includedArray(uncles, 8192, func(raw json.RawMessage) error {
		b, err := includedData(raw, 32)
		if err != nil {
			return err
		}
		if err = o.budget.reserveOwned(32); err != nil {
			return err
		}
		p.Uncles = append(p.Uncles, common.BytesToHash(b))
		return nil
	})
	if err != nil {
		return err
	}
	if hasWithdrawals {
		if h.WithdrawalsHash == nil {
			return failure(InvalidEvidence)
		}
		p.Withdrawals = []*types.Withdrawal{}
		err = includedArray(withdrawals, 8192, func(raw json.RawMessage) error {
			f, err := closedRawObject(raw, 4)
			if err != nil || len(f) != 4 {
				return failure(InvalidEvidence)
			}
			for _, k := range []string{"index", "validatorIndex", "amount"} {
				if _, err = includedQuantity(f[k], 64); err != nil {
					return err
				}
			}
			if _, err = includedData(f["address"], 20); err != nil {
				return err
			}
			if err = o.budget.reserveOwned(64); err != nil {
				return err
			}
			var w types.Withdrawal
			if json.Unmarshal(raw, &w) != nil {
				return failure(InvalidEvidence)
			}
			p.Withdrawals = append(p.Withdrawals, &w)
			return nil
		})
		if err != nil {
			return err
		}
	} else if h.WithdrawalsHash != nil {
		return failure(InvalidEvidence)
	}
	seen := map[common.Hash]bool{}
	var providedHash *common.Hash
	err = includedArray(txs, l.MaxTransactions, func(raw json.RawMessage) error {
		location, pending, err := decodeHistoryLocation(raw, true)
		if err != nil {
			return err
		}
		if !pending {
			if location.BlockNumber != h.Number.Uint64() || uint64(location.TransactionIndex) != uint64(len(o.transactions)) {
				return failure(InvalidEvidence)
			}
			if p.HashPresent && p.Hash != location.BlockHash {
				return failure(InvalidEvidence)
			}
			if providedHash != nil && *providedHash != location.BlockHash {
				return failure(InvalidEvidence)
			}
			hash := location.BlockHash
			providedHash = &hash
		}
		t, n, err := decodeHistoryTransactionValue(raw, includedPosition{}, c.source.Network.ChainID, &h, l, true)
		if err != nil {
			return err
		}
		if seen[t.Hash()] {
			return failure(InvalidEvidence)
		}
		seen[t.Hash()] = true
		if err = o.budget.reserveOwned(n + 128); err != nil {
			return err
		}
		price, err := historyEffectivePrice(t, h.BaseFee)
		if err != nil {
			return err
		}
		o.transactions = append(o.transactions, LocatedHistoryTransaction{t, location, price})
		return nil
	})
	if err != nil {
		return err
	}
	o.pending = p
	o.kind = HistoryPending
	if o.query.method == HistoryBlockReceipts {
		if err = c.acquirePendingReceipts(ctx, o); err != nil {
			return err
		}
	}
	if o.query.method == HistoryTransactionByNumberIndex {
		if o.query.index >= uint64(len(o.transactions)) {
			o.kind = HistoryNotFound
			o.transactions = nil
			o.pending = nil
			return nil
		}
		o.transactions = []LocatedHistoryTransaction{o.transactions[o.query.index]}
		o.pending = nil
	}
	return nil
}

func (c *HistoryReadClient) acquirePendingReceipts(ctx context.Context, o *HistoryReadObservation) error {
	l, err := c.blockReadLimits(o)
	if err != nil {
		return err
	}
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getBlockReceipts", []any{"pending"}, l.MaxReceiptSetBytes}})
	if err != nil {
		return err
	}
	if historyNull(r[0]) {
		return failure(UnsupportedEvidence)
	}
	if err = historyJSONShape(r[0], l, true); err != nil {
		return err
	}
	h := o.pending.Header
	next := uint32(0)
	i := 0
	var cumulative, blobGas uint64
	var bloom types.Bloom
	var blobPrice *big.Int
	err = includedArray(r[0], l.MaxTransactions, func(raw json.RawMessage) error {
		if i >= len(o.transactions) {
			return failure(InvalidEvidence)
		}
		t := o.transactions[i]
		// Actual pending receipts must still agree with the actual pending body's
		// complete location tuple. An all-null body has no invented receipt anchor.
		if !t.Location.HashPresent || !t.Location.NumberPresent || !t.Location.IndexPresent {
			return failure(UnsupportedEvidence)
		}
		pos := includedPosition{Hash: t.Location.BlockHash, Number: t.Location.BlockNumber, Index: t.Location.TransactionIndex, Timestamp: h.Time, TimestampKnown: true}
		receipt, n, err := decodeHistoryReceipt(raw, t.Transaction, pos, h, &next, l)
		if err != nil {
			return err
		}
		if receipt.cumulativeGasUsed < cumulative || receipt.cumulativeGasUsed-cumulative != receipt.gasUsed || receipt.cumulativeGasUsed > h.GasUsed {
			return failure(InvalidEvidence)
		}
		cumulative = receipt.cumulativeGasUsed
		if receipt.blobGasPrice != nil {
			if blobPrice != nil && blobPrice.Cmp(receipt.blobGasPrice) != 0 {
				return failure(InvalidEvidence)
			}
			blobPrice = receipt.blobGasPrice
			if ^uint64(0)-blobGas < receipt.blobGasUsed {
				return failure(InvalidEvidence)
			}
			blobGas += receipt.blobGasUsed
		}
		for j, v := range receipt.bloom {
			bloom[j] |= v
		}
		if err = o.budget.reserveOwned(n + 64); err != nil {
			return err
		}
		o.receipts = append(o.receipts, LocatedHistoryReceipt{receipt, t.Transaction.Hash(), t.Location})
		for _, log := range receipt.logs {
			o.logs = append(o.logs, LocatedHistoryLog{log, t.Transaction.Hash(), t.Location, false})
		}
		i++
		return nil
	})
	if err != nil {
		return err
	}
	if i != len(o.transactions) || cumulative != h.GasUsed || bloom != h.Bloom || h.BlobGasUsed == nil && blobGas != 0 || h.BlobGasUsed != nil && *h.BlobGasUsed != blobGas {
		return failure(InvalidEvidence)
	}
	return nil
}
