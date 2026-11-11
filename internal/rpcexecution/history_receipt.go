package rpcexecution

import (
	"bytes"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func historyHashEqual(raw json.RawMessage, want common.Hash) bool {
	b, e := includedData(raw, 32)
	return e == nil && common.BytesToHash(b) == want
}
func historyAddressEqual(raw json.RawMessage, want common.Address) bool {
	b, e := includedData(raw, 20)
	return e == nil && common.BytesToAddress(b) == want
}
func historyNumberEqual(raw json.RawMessage, want uint64, bits int) bool {
	n, e := includedQuantity(raw, bits)
	return e == nil && n == want
}

func decodeHistoryLog(raw json.RawMessage, pos includedPosition, tx common.Hash, index uint32, l HistoryBlockLimits) (HistoryLog, int, error) {
	var zero HistoryLog
	f, e := closedRawObject(raw, 12)
	if e != nil {
		return zero, 0, e
	}
	for _, k := range []string{"address", "topics", "data", "blockNumber", "transactionHash", "transactionIndex", "blockHash", "logIndex"} {
		if f[k] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	for k := range f {
		switch k {
		case "address", "topics", "data", "blockNumber", "transactionHash", "transactionIndex", "blockHash", "logIndex", "removed", "blockTimestamp":
		default:
			return zero, 0, failure(InvalidEvidence)
		}
	}
	if !historyHashEqual(f["blockHash"], pos.Hash) || !historyHashEqual(f["transactionHash"], tx) || !historyNumberEqual(f["blockNumber"], pos.Number, 63) || !historyNumberEqual(f["transactionIndex"], uint64(pos.Index), 31) || !historyNumberEqual(f["logIndex"], uint64(index), 31) {
		return zero, 0, failure(InvalidEvidence)
	}
	if v, ok := f["blockTimestamp"]; ok && !historyNumberEqual(v, pos.Timestamp, 64) {
		return zero, 0, failure(InvalidEvidence)
	}
	if v, ok := f["removed"]; ok && !bytes.Equal(bytes.TrimSpace(v), []byte("false")) {
		return zero, 0, failure(InvalidEvidence)
	}
	a, e := includedData(f["address"], 20)
	if e != nil {
		return zero, 0, e
	}
	d, e := decodeCode(f["data"], l.MaxReceiptBytes)
	if e != nil {
		return zero, 0, e
	}
	out := HistoryLog{Address: common.BytesToAddress(a), Data: d, TransactionIndex: pos.Index, LogIndex: index}
	e = includedArray(f["topics"], 4, func(raw json.RawMessage) error {
		b, e := includedData(raw, 32)
		if e != nil {
			return e
		}
		out.Topics = append(out.Topics, common.BytesToHash(b))
		return nil
	})
	if e != nil {
		return zero, 0, e
	}
	return out, 128 + len(d) + 32*len(out.Topics), nil
}

func decodeHistoryReceipt(raw []byte, t HistoryTransaction, pos includedPosition, header *types.Header, nextLog *uint32, l HistoryBlockLimits) (HistoryReceipt, int, error) {
	var zero HistoryReceipt
	if len(raw) > l.MaxReceiptBytes {
		return zero, 0, failure(EvidenceLimit)
	}
	f, e := nullableRawObject(raw, 24, map[string]bool{"to": true, "contractAddress": true})
	if e != nil {
		return zero, 0, e
	}
	for _, k := range []string{"transactionHash", "blockHash", "blockNumber", "transactionIndex", "from", "to", "type", "contractAddress", "gasUsed", "cumulativeGasUsed", "effectiveGasPrice", "logsBloom", "logs"} {
		if f[k] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	for k := range f {
		switch k {
		case "transactionHash", "blockHash", "blockNumber", "transactionIndex", "from", "to", "type", "contractAddress", "gasUsed", "cumulativeGasUsed", "effectiveGasPrice", "logsBloom", "logs", "status", "root", "blobGasUsed", "blobGasPrice", "blockTimestamp":
		default:
			return zero, 0, failure(InvalidEvidence)
		}
	}
	if !historyHashEqual(f["transactionHash"], t.Hash()) || !historyHashEqual(f["blockHash"], pos.Hash) || !historyNumberEqual(f["blockNumber"], pos.Number, 63) || !historyNumberEqual(f["transactionIndex"], uint64(pos.Index), 31) || !historyAddressEqual(f["from"], t.From()) || !historyNumberEqual(f["type"], uint64(t.Type()), 8) {
		return zero, 0, failure(InvalidEvidence)
	}
	if v, ok := f["blockTimestamp"]; ok && !historyNumberEqual(v, header.Time, 64) {
		return zero, 0, failure(InvalidEvidence)
	}
	to, call := t.To()
	if call && !historyAddressEqual(f["to"], to) || !call && !historyNull(f["to"]) {
		return zero, 0, failure(InvalidEvidence)
	}
	_, status := f["status"]
	_, root := f["root"]
	if status == root {
		return zero, 0, failure(InvalidEvidence)
	}
	r := HistoryReceipt{statusPresent: status, postStatePresent: root}
	if status {
		n, e := includedQuantity(f["status"], 8)
		if e != nil || n > 1 {
			return zero, 0, failure(InvalidEvidence)
		}
		r.status = uint8(n)
	} else {
		b, e := includedData(f["root"], 32)
		if e != nil {
			return zero, 0, e
		}
		r.postState = common.BytesToHash(b)
	}
	r.gasUsed, e = includedQuantity(f["gasUsed"], 64)
	if e != nil || r.gasUsed > t.GasLimit() {
		return zero, 0, failure(InvalidEvidence)
	}
	r.cumulativeGasUsed, e = includedQuantity(f["cumulativeGasUsed"], 64)
	if e != nil {
		return zero, 0, e
	}
	r.effectiveGasPrice, e = historyBig(f["effectiveGasPrice"])
	if e != nil {
		return zero, 0, e
	}
	expected, e := historyEffectivePrice(t, header.BaseFee)
	if e != nil || r.effectiveGasPrice.Cmp(expected) != 0 {
		return zero, 0, failure(InvalidEvidence)
	}
	if !historyNull(f["contractAddress"]) {
		if call || !historyAddressEqual(f["contractAddress"], crypto.CreateAddress(t.From(), t.Nonce())) {
			return zero, 0, failure(InvalidEvidence)
		}
		r.contractAddress, r.contractPresent = crypto.CreateAddress(t.From(), t.Nonce()), true
	}
	if !call && status && r.status == 1 && !r.contractPresent {
		return zero, 0, failure(InvalidEvidence)
	}
	_, bg := f["blobGasUsed"]
	_, bp := f["blobGasPrice"]
	if t.Type() == 3 {
		if !bg || !bp || header.BlobGasUsed == nil {
			return zero, 0, failure(InvalidEvidence)
		}
		r.blobGasUsed, e = includedQuantity(f["blobGasUsed"], 64)
		if e != nil || r.blobGasUsed != uint64(len(t.tx.BlobHashes()))*131072 {
			return zero, 0, failure(InvalidEvidence)
		}
		r.blobGasPrice, e = historyBig(f["blobGasPrice"])
		if e != nil || r.blobGasPrice.Sign() == 0 || r.blobGasPrice.Cmp(t.tx.BlobGasFeeCap()) > 0 {
			return zero, 0, failure(InvalidEvidence)
		}
	} else if bg || bp {
		return zero, 0, failure(InvalidEvidence)
	}
	b, e := includedData(f["logsBloom"], 256)
	if e != nil {
		return zero, 0, e
	}
	copy(r.bloom[:], b)
	charge := 512
	e = includedArray(f["logs"], l.MaxLogs, func(raw json.RawMessage) error {
		if uint64(*nextLog) >= uint64(l.MaxLogs) {
			return failure(EvidenceLimit)
		}
		log, n, e := decodeHistoryLog(raw, pos, t.Hash(), *nextLog, l)
		if e != nil {
			return e
		}
		(*nextLog)++
		r.logs = append(r.logs, log)
		charge += n
		return nil
	})
	if e != nil {
		return zero, 0, e
	}
	if status && r.status == 0 && len(r.logs) != 0 {
		return zero, 0, failure(InvalidEvidence)
	}
	logs := make([]*types.Log, len(r.logs))
	for i, v := range r.logs {
		logs[i] = &types.Log{Address: v.Address, Topics: v.Topics, Data: v.Data}
	}
	if types.CreateBloom(&types.Receipt{Logs: logs}) != r.bloom {
		return zero, 0, failure(InvalidEvidence)
	}
	return r, charge, nil
}

func decodeHistoryReceipts(raw []byte, b *HistoryBlockObservation, l HistoryBlockLimits, charge int) error {
	if int64(len(raw)) > l.MaxReceiptSetBytes {
		return failure(EvidenceLimit)
	}
	if e := historyJSONShape(raw, l, true); e != nil {
		return e
	}
	i, nextLog := uint32(0), uint32(0)
	var cumulative, blobGas uint64
	var bloom types.Bloom
	var blobPrice *big.Int
	e := includedArray(raw, l.MaxTransactions, func(value json.RawMessage) error {
		if uint64(i) >= uint64(len(b.transactions)) {
			return failure(InvalidEvidence)
		}
		pos := includedPosition{Hash: b.header.Hash(), Number: b.header.Number.Uint64(), Index: i, Timestamp: b.header.Time, TimestampKnown: true}
		r, n, e := decodeHistoryReceipt(value, b.transactions[i], pos, b.header, &nextLog, l)
		if e != nil {
			return e
		}
		if r.cumulativeGasUsed < cumulative || r.cumulativeGasUsed-cumulative != r.gasUsed || r.cumulativeGasUsed > b.header.GasUsed {
			return failure(InvalidEvidence)
		}
		cumulative = r.cumulativeGasUsed
		if r.blobGasPrice != nil {
			if blobPrice != nil && blobPrice.Cmp(r.blobGasPrice) != 0 {
				return failure(InvalidEvidence)
			}
			blobPrice = r.blobGasPrice
			if ^uint64(0)-blobGas < r.blobGasUsed {
				return failure(InvalidEvidence)
			}
			blobGas += r.blobGasUsed
		}
		for j, v := range r.bloom {
			bloom[j] |= v
		}
		charge += n
		if charge > l.MaxObservationBytes {
			return failure(EvidenceLimit)
		}
		b.receipts = append(b.receipts, r)
		i++
		return nil
	})
	if e != nil {
		return e
	}
	if int(i) != len(b.transactions) || cumulative != b.header.GasUsed || bloom != b.header.Bloom || b.header.BlobGasUsed == nil && blobGas != 0 || b.header.BlobGasUsed != nil && blobGas != *b.header.BlobGasUsed {
		return failure(InvalidEvidence)
	}
	return nil
}
