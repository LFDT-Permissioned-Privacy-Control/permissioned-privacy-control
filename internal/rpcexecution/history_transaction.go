package rpcexecution

import (
	"bytes"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func historyNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }
func historyBig(raw json.RawMessage) (*big.Int, error) {
	s, e := includedString(raw, 66)
	if e != nil {
		return nil, e
	}
	n, ok := quantity(s, 256)
	if !ok {
		return nil, failure(InvalidEvidence)
	}
	return n, nil
}

// First apply the existing whole-value parser budgets. Subsequent raw-object
// passes preserve original per-transaction/receipt JSON sizes and closed fields.
func historyJSONShape(raw []byte, l HistoryBlockLimits, receipts bool) error {
	_, e := readJSONFieldArrays(raw, func(depth int, field string) int {
		if receipts && depth == 0 {
			return l.MaxTransactions
		}
		switch field {
		case "transactions":
			return l.MaxTransactions
		case "uncles", "withdrawals":
			return 8192
		case "accessList":
			return l.MaxAccessEntries
		case "storageKeys":
			return l.MaxStorageKeys
		case "authorizationList":
			return l.MaxAuthorizations
		case "blobVersionedHashes":
			return l.MaxSignedBytes / 32
		case "logs":
			return l.MaxLogs
		case "topics":
			return 4
		}
		return 0
	})
	return e
}

func historyAccess(raw json.RawMessage, l HistoryBlockLimits) error {
	keys := 0
	return includedArray(raw, l.MaxAccessEntries, func(entry json.RawMessage) error {
		f, e := closedRawObject(entry, 2)
		if e != nil || len(f) != 2 {
			return failure(InvalidEvidence)
		}
		if _, e = includedData(f["address"], 20); e != nil {
			return e
		}
		return includedArray(f["storageKeys"], l.MaxStorageKeys, func(key json.RawMessage) error {
			keys++
			if keys > l.MaxStorageKeys {
				return failure(EvidenceLimit)
			}
			_, e := includedData(key, 32)
			return e
		})
	})
}
func historyAuthorizations(raw json.RawMessage, l HistoryBlockLimits) error {
	count := 0
	e := includedArray(raw, l.MaxAuthorizations, func(entry json.RawMessage) error {
		count++
		f, e := closedRawObject(entry, 6)
		if e != nil || len(f) != 6 {
			return failure(InvalidEvidence)
		}
		for k, v := range f {
			switch k {
			case "chainId", "r", "s":
				if _, e := historyBig(v); e != nil {
					return e
				}
			case "nonce":
				if _, e := includedQuantity(v, 64); e != nil {
					return e
				}
			case "yParity":
				n, e := includedQuantity(v, 8)
				if e != nil || n > 1 {
					return failure(InvalidEvidence)
				}
			case "address":
				if _, e := includedData(v, 20); e != nil {
					return e
				}
			default:
				return failure(InvalidEvidence)
			}
		}
		return nil
	})
	if e != nil {
		return e
	}
	if count == 0 {
		return failure(InvalidEvidence)
	}
	return nil
}

func decodeHistoryTransaction(raw []byte, pos includedPosition, chain string, header *types.Header, l HistoryBlockLimits) (HistoryTransaction, int, error) {
	var zero HistoryTransaction
	if len(raw) > l.MaxTransactionBytes {
		return zero, 0, failure(EvidenceLimit)
	}
	f, e := nullableRawObject(raw, 32, map[string]bool{"to": true, "gasPrice": true, "maxFeePerGas": true, "maxPriorityFeePerGas": true, "chainId": true})
	if e != nil {
		return zero, 0, e
	}
	actual, e := decodeIncludedPosition(f)
	if e != nil || actual.Hash != pos.Hash || actual.Number != pos.Number || actual.Index != pos.Index || actual.TimestampKnown && actual.Timestamp != header.Time {
		return zero, 0, failure(InvalidEvidence)
	}
	kind, e := includedQuantity(f["type"], 8)
	if e != nil {
		return zero, 0, e
	}
	if kind > 4 {
		return zero, 0, failure(UnsupportedEvidence)
	}
	for _, k := range []string{"gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "chainId"} {
		if v, ok := f[k]; ok && historyNull(v) {
			if k == "gasPrice" && kind >= 2 || k != "gasPrice" && k != "chainId" && kind < 2 || k == "chainId" && kind == 0 {
				delete(f, k)
			} else {
				return zero, 0, failure(InvalidEvidence)
			}
		}
	}
	for _, k := range []string{"nonce", "to", "value", "gas", "input", "r", "s", "hash", "from"} {
		if f[k] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	allowed := map[string]bool{"type": true, "nonce": true, "to": true, "value": true, "gas": true, "input": true, "v": true, "r": true, "s": true, "hash": true, "from": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "blockTimestamp": true, "chainId": true, "gasPrice": true}
	if kind == 0 {
		if f["v"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	} else {
		allowed["yParity"], allowed["accessList"] = true, true
		if f["chainId"] == nil || f["accessList"] == nil || f["v"] == nil && f["yParity"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	if kind < 2 {
		if f["gasPrice"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	} else {
		allowed["maxFeePerGas"], allowed["maxPriorityFeePerGas"] = true, true
		if f["maxFeePerGas"] == nil || f["maxPriorityFeePerGas"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	if kind == 3 {
		allowed["maxFeePerBlobGas"], allowed["blobVersionedHashes"] = true, true
		if f["maxFeePerBlobGas"] == nil || f["blobVersionedHashes"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	if kind == 4 {
		allowed["authorizationList"] = true
		if f["authorizationList"] == nil {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	for k, v := range f {
		if !allowed[k] {
			return zero, 0, failure(InvalidEvidence)
		}
		switch k {
		case "blockHash", "blockNumber", "transactionIndex", "blockTimestamp":
		case "type", "nonce", "gas", "yParity":
			bits := 64
			if k == "type" || k == "yParity" {
				bits = 8
			}
			n, e := includedQuantity(v, bits)
			if e != nil || k == "yParity" && n > 1 {
				return zero, 0, failure(InvalidEvidence)
			}
		case "value", "v", "r", "s", "gasPrice", "maxFeePerGas", "maxPriorityFeePerGas", "maxFeePerBlobGas", "chainId":
			if _, e := historyBig(v); e != nil {
				return zero, 0, e
			}
		case "hash":
			if _, e := includedData(v, 32); e != nil {
				return zero, 0, e
			}
		case "from":
			if _, e := includedData(v, 20); e != nil {
				return zero, 0, e
			}
		case "to":
			if !historyNull(v) {
				if _, e := includedData(v, 20); e != nil {
					return zero, 0, e
				}
			}
		case "input":
			if _, e := decodeCode(v, l.MaxSignedBytes); e != nil {
				return zero, 0, e
			}
		case "accessList":
			if e := historyAccess(v, l); e != nil {
				return zero, 0, e
			}
		case "authorizationList":
			if e := historyAuthorizations(v, l); e != nil {
				return zero, 0, e
			}
		case "blobVersionedHashes":
			count := 0
			e := includedArray(v, l.MaxSignedBytes/32, func(x json.RawMessage) error {
				count++
				b, e := includedData(x, 32)
				if e != nil || b[0] != 1 {
					return failure(InvalidEvidence)
				}
				return nil
			})
			if e != nil || count == 0 {
				return zero, 0, failure(InvalidEvidence)
			}
		}
	}
	var tx types.Transaction
	if json.Unmarshal(raw, &tx) != nil {
		return zero, 0, failure(InvalidEvidence)
	}
	binary, e := tx.MarshalBinary()
	if e != nil {
		return zero, 0, failure(InvalidEvidence)
	}
	if len(binary) > l.MaxSignedBytes {
		return zero, 0, failure(EvidenceLimit)
	}
	wanted, e := includedData(f["hash"], 32)
	if e != nil || tx.Hash() != common.BytesToHash(wanted) {
		return zero, 0, failure(InvalidEvidence)
	}
	if tx.Protected() {
		if tx.ChainId().String() != chain {
			return zero, 0, failure(InvalidEvidence)
		}
	} else if kind != 0 {
		return zero, 0, failure(InvalidEvidence)
	}
	if c, ok := f["chainId"]; ok {
		n, e := historyBig(c)
		if e != nil || n.Cmp(tx.ChainId()) != 0 {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	var signer types.Signer
	if !tx.Protected() {
		signer = types.FrontierSigner{}
	} else {
		signer = types.LatestSignerForChainID(tx.ChainId())
	}
	from, e := types.Sender(signer, &tx)
	if e != nil {
		return zero, 0, failure(InvalidEvidence)
	}
	declared, e := includedData(f["from"], 20)
	if e != nil || from != common.BytesToAddress(declared) {
		return zero, 0, failure(InvalidEvidence)
	}
	t := HistoryTransaction{&tx, from, binary}
	price, e := historyEffectivePrice(t, header.BaseFee)
	if e != nil {
		return zero, 0, e
	}
	if v, ok := f["gasPrice"]; ok {
		n, e := historyBig(v)
		if e != nil || n.Cmp(price) != 0 {
			return zero, 0, failure(InvalidEvidence)
		}
	}
	// Charge both canonical signed bytes and retained decoded variable payload,
	// plus a fixed512-byte metadata allowance. This is not a heap/RSS bound.
	charge := len(binary) + len(tx.Data()) + 512
	for _, a := range tx.AccessList() {
		charge += 20 + 32*len(a.StorageKeys)
	}
	charge += 32*len(tx.BlobHashes()) + 160*len(tx.SetCodeAuthorizations())
	return t, charge, nil
}

func historyEffectivePrice(t HistoryTransaction, baseFee *big.Int) (*big.Int, error) {
	if t.tx == nil {
		return nil, failure(InvalidEvidence)
	}
	if t.Type() < 2 {
		return historyBigCopy(t.tx.GasPrice()), nil
	}
	cap, tip := t.tx.GasFeeCap(), t.tx.GasTipCap()
	if baseFee == nil || baseFee.Sign() < 0 || baseFee.BitLen() > 256 || tip.Cmp(cap) > 0 || baseFee.Cmp(cap) > 0 {
		return nil, failure(InvalidEvidence)
	}
	// Add unbounded integers, then take min. No uint256 wrap near the limit.
	price := new(big.Int).Add(baseFee, tip)
	if price.Cmp(cap) > 0 {
		price.Set(cap)
	}
	return price, nil
}
