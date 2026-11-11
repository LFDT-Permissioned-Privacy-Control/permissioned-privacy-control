package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestHistoryHistoricalUnprotectedHighSSignature(t *testing.T) {
	low := historySigned(t, 0, 0, false, true)
	v, r, s := low.RawSignatureValues()
	high := types.NewTx(&types.LegacyTx{Nonce: low.Nonce(), To: low.To(), Gas: low.Gas(), GasPrice: low.GasPrice(), Value: low.Value(), Data: low.Data(), V: new(big.Int).Sub(big.NewInt(55), v), R: r, S: new(big.Int).Sub(crypto.S256().Params().N, s)})
	want, e := types.Sender(types.FrontierSigner{}, low)
	if e != nil {
		t.Fatal(e)
	}
	f := newHistoryFixture(t, high)
	b := historyAcquire(t, f.client(t, DefaultHistoryBlockLimits()))
	actual, _ := b.Transaction(0)
	if actual.From() != want || actual.Fees().Protected || actual.Hash() != high.Hash() {
		t.Fatal("historical signature narrowed to current admission rules")
	}
}

func TestHistoryRecheckCannotResetOriginalExpiredDeadline(t *testing.T) {
	f := newHistoryFixture(t)
	c := f.client(t, DefaultHistoryBlockLimits())
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	selector, _ := HistoryBlockNumber(1)
	b, e := c.AcquireBlock(ctx, selector)
	if e != nil {
		t.Fatal(e)
	}
	if b.originalDeadline.IsZero() {
		t.Fatal("original deadline lost")
	}
	<-ctx.Done()
	before := len(f.methods)
	if e = c.Recheck(context.Background(), b); e == nil || len(f.methods) != before {
		t.Fatal("fresh context reset expired original operation")
	}
}

func TestHistoryCompleteBlockMetadataDetachedAndPresenceBound(t *testing.T) {
	f := newHistoryFixture(t)
	f.header.Extra = []byte{1, 2}
	f.header.Difficulty = big.NewInt(7)
	f.rebind(t)
	f.block["size"] = "0x123"
	f.block["totalDifficulty"] = "0x100000000000000000000"
	f.block["uncles"] = []any{common.Hash{9}.Hex()}
	f.block["withdrawals"] = []any{map[string]any{"index": "0x0", "validatorIndex": "0x1", "address": common.Address{8}.Hex(), "amount": "0x2"}}
	c := f.client(t, DefaultHistoryBlockLimits())
	b := historyAcquire(t, c)
	h := b.EthereumHeader()
	if h.Hash() != f.header.Hash() {
		t.Fatal("full typed header lost")
	}
	h.Extra[0] = 99
	h.Difficulty.SetUint64(99)
	*h.WithdrawalsHash = common.Hash{}
	if b.EthereumHeader().Extra[0] != 1 || b.EthereumHeader().Difficulty.Uint64() != 7 || *b.EthereumHeader().WithdrawalsHash == (common.Hash{}) {
		t.Fatal("header getter aliases")
	}
	u := b.Uncles()
	u[0] = common.Hash{}
	w := b.Withdrawals()
	w[0].Amount = 99
	if b.Uncles()[0] == (common.Hash{}) || b.Withdrawals()[0].Amount != 2 {
		t.Fatal("body getter aliases")
	}
	n, p := b.ReportedSize()
	td, q := b.TotalDifficulty()
	if n != 0x123 || p != HistoryPresent || q != HistoryPresent || td.BitLen() <= 64 {
		t.Fatal("reported metadata narrowed")
	}
	td.SetInt64(0)
	actual, _ := b.TotalDifficulty()
	if actual.Sign() == 0 {
		t.Fatal("TD alias")
	}
	digests := map[common.Hash]bool{}
	for _, presence := range []HistoryFieldPresence{HistoryAbsent, HistoryNull, HistoryPresent} {
		delete(f.block, "size")
		delete(f.block, "totalDifficulty")
		if presence == HistoryNull {
			f.block["size"], f.block["totalDifficulty"] = nil, nil
		}
		if presence == HistoryPresent {
			f.block["size"], f.block["totalDifficulty"] = "0x0", "0x0"
		}
		observed := historyAcquire(t, c)
		size, s := observed.ReportedSize()
		td, d := observed.TotalDifficulty()
		if s != presence || d != presence || size != 0 || presence == HistoryPresent && (td == nil || td.Sign() != 0) || presence != HistoryPresent && td != nil {
			t.Fatal("null/absent/value lost")
		}
		if digests[observed.Digest()] {
			t.Fatal("metadata presence not digest-bound")
		}
		digests[observed.Digest()] = true
	}
	for _, name := range []string{"size", "totalDifficulty"} {
		f.block[name] = "0x" + strings.Repeat("f", 65)
		selector, _ := HistoryBlockNumber(1)
		if b, e := c.AcquireBlock(t.Context(), selector); e == nil || b != nil {
			t.Fatal("oversized optional metadata accepted")
		}
		delete(f.block, name)
	}
}

func historyLogFixture(t *testing.T, root bool) *historyFixture {
	t.Helper()
	f := newHistoryFixture(t, historySigned(t, 0, 0, false, false))
	log := &types.Log{Address: common.Address{9}, Topics: []common.Hash{{3}}, Data: []byte{1, 2, 3}}
	f.header.Bloom = types.CreateBloom(&types.Receipt{Logs: []*types.Log{log}})
	f.rebind(t)
	r := f.receipts[0].(map[string]any)
	r["logsBloom"] = "0x" + common.Bytes2Hex(f.header.Bloom[:])
	r["logs"] = []any{map[string]any{"address": log.Address.Hex(), "topics": []any{log.Topics[0].Hex()}, "data": "0x010203", "blockHash": f.header.Hash().Hex(), "blockNumber": "0x1", "transactionHash": f.txs[0].Hash().Hex(), "transactionIndex": "0x0", "logIndex": "0x0", "removed": false}}
	if root {
		delete(r, "status")
		r["root"] = "0x" + strings.Repeat("12", 32)
	}
	return f
}

func TestHistoryLogsRootUnknownAndIndependentAssociations(t *testing.T) {
	for _, root := range []bool{false, true} {
		f := historyLogFixture(t, root)
		b := historyAcquire(t, f.client(t, DefaultHistoryBlockLimits()))
		r, _ := b.Receipt(0)
		status, present := r.Status()
		if present == root || !root && status != 1 {
			t.Fatal("root success inferred")
		}
		logs := r.Logs()
		if len(logs) != 1 || logs[0].Address != (common.Address{9}) {
			t.Fatal("actual emitter lost")
		}
		logs[0].Data[0] = 99
		logs[0].Topics[0] = common.Hash{}
		if r.Logs()[0].Data[0] != 1 || r.Logs()[0].Topics[0] == (common.Hash{}) {
			t.Fatal("log getter aliases")
		}
	}
	for _, name := range []string{"tx", "block", "position", "index", "removed", "topics", "data", "emitter", "unknown", "failed", "bloom", "header-bloom"} {
		t.Run(name, func(t *testing.T) {
			f := historyLogFixture(t, false)
			r := f.receipts[0].(map[string]any)
			log := r["logs"].([]any)[0].(map[string]any)
			switch name {
			case "tx":
				log["transactionHash"] = common.Hash{4}.Hex()
			case "block":
				log["blockHash"] = common.Hash{4}.Hex()
			case "position":
				log["transactionIndex"] = "0x1"
			case "index":
				log["logIndex"] = "0x1"
			case "removed":
				log["removed"] = true
			case "topics":
				log["topics"] = []any{common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex(), common.Hash{}.Hex()}
			case "data":
				log["data"] = "0x0"
			case "emitter":
				log["address"] = "0x00"
			case "unknown":
				log["not_selected"] = true
			case "failed":
				r["status"] = "0x0"
			case "bloom":
				r["logsBloom"] = "0x" + strings.Repeat("00", 256)
			case "header-bloom":
				f.header.Bloom = types.Bloom{}
				f.block["logsBloom"] = "0x" + strings.Repeat("00", 256)
			}
			c := f.client(t, DefaultHistoryBlockLimits())
			s, _ := HistoryBlockNumber(1)
			if b, e := c.AcquireBlock(t.Context(), s); e == nil || b != nil {
				t.Fatal("malformed log population accepted")
			}
		})
	}
}

func TestHistoryFeesPreserveUint256AndOverflowSafeDynamicPrice(t *testing.T) {
	key, e := crypto.HexToECDSA(strings.Repeat("11", 32))
	if e != nil {
		t.Fatal(e)
	}
	to := common.Address{9}
	for _, dynamic := range []bool{false, true} {
		price := new(big.Int).Lsh(big.NewInt(1), 80)
		var inner types.TxData
		if dynamic {
			price.Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
			inner = &types.DynamicFeeTx{ChainID: big.NewInt(1), To: &to, Gas: 30000, GasFeeCap: price, GasTipCap: new(big.Int).Sub(price, big.NewInt(1)), Value: big.NewInt(0), AccessList: types.AccessList{}}
		} else {
			inner = &types.LegacyTx{To: &to, Gas: 30000, GasPrice: price, Value: big.NewInt(0)}
		}
		tx, e := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(1)), inner)
		if e != nil {
			t.Fatal(e)
		}
		f := newHistoryFixture(t, tx)
		if dynamic {
			f.header.BaseFee = big.NewInt(2)
			f.rebind(t)
		}
		f.receipts[0].(map[string]any)["effectiveGasPrice"] = "0x" + price.Text(16)
		b := historyAcquire(t, f.client(t, DefaultHistoryBlockLimits()))
		r, _ := b.Receipt(0)
		if r.EffectiveGasPrice().Cmp(price) != 0 || r.EffectiveGasPrice().BitLen() <= 64 {
			t.Fatal("fee narrowed or wrapped")
		}
		actual, _ := b.Transaction(0)
		fees := actual.Fees()
		if dynamic && fees.MaxFeePerGas.Cmp(price) != 0 || !dynamic && fees.LegacyGasPrice.Cmp(price) != 0 {
			t.Fatal("signed fees changed")
		}
	}
}

func TestHistoryBlobSetCodeAndRawFieldLimits(t *testing.T) {
	for _, name := range []string{"blob-version", "blob-fee", "blob-gas", "blob-price", "auth-parity", "auth-extra", "auth-empty", "duplicate", "casefold"} {
		t.Run(name, func(t *testing.T) {
			kind := uint8(3)
			if strings.HasPrefix(name, "auth") {
				kind = 4
			}
			f := newHistoryFixture(t, historySigned(t, kind, 0, false, false))
			tx := f.block["transactions"].([]any)[0].(map[string]any)
			r := f.receipts[0].(map[string]any)
			switch name {
			case "blob-version":
				tx["blobVersionedHashes"] = []any{common.Hash{2}.Hex()}
			case "blob-fee":
				tx["maxFeePerBlobGas"] = "0x" + strings.Repeat("f", 65)
			case "blob-gas":
				r["blobGasUsed"] = "0x1"
			case "blob-price":
				r["blobGasPrice"] = "0x6"
			case "auth-parity":
				tx["authorizationList"].([]any)[0].(map[string]any)["yParity"] = "0x2"
			case "auth-extra":
				tx["authorizationList"].([]any)[0].(map[string]any)["extra"] = true
			case "auth-empty":
				tx["authorizationList"] = []any{}
			case "duplicate":
				raw, _ := json.Marshal(r)
				f.receipts[0] = json.RawMessage(strings.Replace(string(raw), `"status":"0x1"`, `"status":"0x1","status":"0x1"`, 1))
			case "casefold":
				r["Status"] = "0x1"
			}
			c := f.client(t, DefaultHistoryBlockLimits())
			s, _ := HistoryBlockNumber(1)
			if b, e := c.AcquireBlock(t.Context(), s); e == nil || b != nil {
				t.Fatal("unsupported/ambiguous typed payload accepted")
			}
		})
	}
	for _, name := range []string{"signed", "transaction", "receipt"} {
		for _, over := range []bool{false, true} {
			t.Run(name+fmtHistoryQuantity(uint64(boolHistory(over))), func(t *testing.T) {
				f := newHistoryFixture(t, historySigned(t, 2, 0, false, false))
				l := DefaultHistoryBlockLimits()
				n := len(txBytes(t, f.txs[0]))
				if name == "transaction" {
					b, _ := json.Marshal(f.block["transactions"].([]any)[0])
					n = len(b)
				}
				if name == "receipt" {
					b, _ := json.Marshal(f.receipts[0])
					n = len(b)
				}
				if over {
					n--
				}
				switch name {
				case "signed":
					l.MaxSignedBytes = n
				case "transaction":
					l.MaxTransactionBytes = n
				case "receipt":
					l.MaxReceiptBytes = n
				}
				c := f.client(t, l)
				s, _ := HistoryBlockNumber(1)
				b, e := c.AcquireBlock(t.Context(), s)
				if over && (e == nil || b != nil) || !over && (e != nil || b == nil) {
					t.Fatal("exact/one-over boundary", e)
				}
			})
		}
	}
}
