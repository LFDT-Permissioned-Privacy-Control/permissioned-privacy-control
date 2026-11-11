package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

type readHistoryFixture struct {
	*historyFixture
	mu              sync.Mutex
	physical, items int
	methods         map[string]int
	change          func(string, any) any
	batchChange     func([]map[string]any) []map[string]any
	rpcErrors       map[string]bool
	pendingTx       bool
	reorg           bool
	logs            []any
	block           func() any
}

func newReadHistoryFixture(t *testing.T, txs ...*types.Transaction) *readHistoryFixture {
	t.Helper()
	f := &readHistoryFixture{historyFixture: newHistoryFixture(t, txs...), methods: map[string]int{}, logs: []any{}}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.GetBody != nil || r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "history-fixture" {
			t.Error("source request binding/replay")
			w.WriteHeader(400)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			t.Error(err)
			return
		}
		batch := len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '['
		var calls []struct {
			JSONRPC string            `json:"jsonrpc"`
			ID      json.RawMessage   `json:"id"`
			Method  string            `json:"method"`
			Params  []json.RawMessage `json:"params"`
		}
		if batch {
			err = json.Unmarshal(raw, &calls)
		} else {
			calls = make([]struct {
				JSONRPC string            `json:"jsonrpc"`
				ID      json.RawMessage   `json:"id"`
				Method  string            `json:"method"`
				Params  []json.RawMessage `json:"params"`
			}, 1)
			err = json.Unmarshal(raw, &calls[0])
		}
		if err != nil {
			t.Error(err)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.physical++
		f.items += len(calls)
		out := make([]map[string]any, 0, len(calls))
		for _, q := range calls {
			f.methods[q.Method]++
			if f.rpcErrors[q.Method] {
				out = append(out, map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32000, "message": "fixture unavailable"}})
				continue
			}
			var value any
			selector := ""
			if len(q.Params) > 0 {
				_ = json.Unmarshal(q.Params[0], &selector)
			}
			switch q.Method {
			case "eth_chainId":
				value = "0x1"
			case "eth_syncing":
				value = false
			case "eth_getHeaderByNumber":
				if selector == "0x0" {
					value = f.genesis
				} else if selector == "0x999" {
					value = nil
				} else if f.reorg {
					copy := types.CopyHeader(f.header)
					copy.Extra = []byte{9}
					value = copy
				} else {
					value = f.header
				}
			case "eth_getHeaderByHash":
				if selector == f.header.Hash().Hex() {
					value = f.header
				}
			case "eth_getBlockByHash":
				if selector == f.header.Hash().Hex() {
					value = f.historyFixture.block
				}
			case "eth_getBlockByNumber":
				value = f.historyFixture.block
				if selector == "pending" {
					copy := includedObject(t, f.historyFixture.block)
					copy["hash"], copy["nonce"], copy["miner"] = nil, nil, nil
					value = copy
					if f.block != nil {
						value = f.block()
					}
				}
			case "eth_getBlockReceipts":
				value = f.receipts
			case "eth_getTransactionByHash", "eth_getTransactionByBlockHashAndIndex", "eth_getTransactionByBlockNumberAndIndex":
				index := -1
				if q.Method == "eth_getTransactionByHash" {
					for i, tx := range f.txs {
						if selector == tx.Hash().Hex() {
							index = i
							break
						}
					}
				} else if len(q.Params) > 1 {
					var s string
					_ = json.Unmarshal(q.Params[1], &s)
					n, e := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
					if e == nil && n < uint64(len(f.txs)) {
						index = int(n)
					}
				}
				if index >= 0 {
					value = f.historyFixture.block["transactions"].([]any)[index]
					if f.pendingTx {
						copy := includedObject(t, value)
						copy["blockHash"], copy["blockNumber"], copy["transactionIndex"] = nil, nil, nil
						if f.txs[index].Type() >= 2 {
							copy["gasPrice"] = "0x3"
						}
						value = copy
					}
				}
			case "eth_getTransactionReceipt":
				for i, tx := range f.txs {
					if selector == tx.Hash().Hex() && !f.pendingTx {
						value = f.receipts[i]
						break
					}
				}
			case "eth_getLogs":
				value = f.logs
			default:
				t.Error("unexpected history read method", q.Method)
				w.WriteHeader(500)
				return
			}
			if f.change != nil {
				value = f.change(q.Method, value)
			}
			out = append(out, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": value})
		}
		if batch {
			if f.batchChange != nil {
				out = f.batchChange(out)
			}
			_ = json.NewEncoder(w).Encode(out)
		} else {
			_ = json.NewEncoder(w).Encode(out[0])
		}
	}))
	t.Cleanup(srv.Close)
	f.source.URL = srv.URL
	f.transport = headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) { return srv.Client().Transport.RoundTrip(r) })
	return f
}
func (f *readHistoryFixture) readClient(t *testing.T, l HistoryReadLimits) *HistoryReadClient {
	t.Helper()
	c, err := NewHistoryReadClient(f.transport, f.source, Credential{f.source.CredentialHeader, "history-fixture"}, l)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func readHistoryQuery(t *testing.T, m HistoryMethod, raw string, l HistoryReadLimits) HistoryReadQuery {
	t.Helper()
	q, err := ParseHistoryReadQuery(m, json.RawMessage(raw), l)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func readHistoryAcquire(t *testing.T, c *HistoryReadClient, m HistoryMethod, raw string) *HistoryReadObservation {
	t.Helper()
	o, err := c.Acquire(context.Background(), readHistoryQuery(t, m, raw, c.limits))
	if err != nil {
		t.Fatal(m.String(), err)
	}
	return o
}

func TestHistoryReadActualTLSAllTenAndDetachedTypedValues(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false), historySigned(t, 2, 1, false, false))
	c := f.readClient(t, DefaultHistoryReadLimits())
	hash := f.header.Hash().Hex()
	tx := f.txs[0].Hash().Hex()
	cases := []struct {
		m      HistoryMethod
		params string
		kind   HistoryReadKind
		count  int
	}{{HistoryTransactionByHash, `["` + tx + `"]`, HistoryLocated, 1}, {HistoryTransactionReceipt, `["` + tx + `"]`, HistoryLocated, 1}, {HistoryBlockByHash, `["` + hash + `",true]`, HistoryLocated, 2}, {HistoryBlockByNumber, `["safe",false]`, HistoryCanonical, 2}, {HistoryBlockCountByHash, `["` + hash + `"]`, HistoryLocated, 2}, {HistoryBlockCountByNumber, `["finalized"]`, HistoryCanonical, 2}, {HistoryTransactionByHashIndex, `["` + hash + `","0x1"]`, HistoryLocated, 1}, {HistoryTransactionByNumberIndex, `["latest","0x1"]`, HistoryCanonical, 1}, {HistoryLogs, `[{"fromBlock":"0x1","toBlock":"0x1"}]`, HistoryCanonical, 0}, {HistoryBlockReceipts, `["0x1"]`, HistoryCanonical, 2}}
	for _, tc := range cases {
		t.Run(tc.m.String(), func(t *testing.T) {
			o := readHistoryAcquire(t, c, tc.m, tc.params)
			if o.Kind() != tc.kind || len(o.Transactions()) != tc.count {
				t.Fatal("wrong owned population", o.Kind(), len(o.Transactions()))
			}
			if err := c.Recheck(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if tc.count > 0 {
				v := o.Transactions()
				v[0].GasPrice.SetInt64(999)
				v[0].Transaction.Value().SetInt64(999)
				if o.Transactions()[0].GasPrice.Int64() == 999 || o.Transactions()[0].Transaction.Value().Int64() == 999 {
					t.Fatal("caller mutated owned signed data")
				}
			}
			if b, ok := o.BlockData(); ok {
				b.Header.Extra = []byte{99}
				if o.block.header.Extra != nil && bytes.Equal(o.block.header.Extra, []byte{99}) {
					t.Fatal("block header aliases")
				}
			}
			if tc.kind == HistoryLocated {
				if _, ok := o.Block(); ok {
					t.Fatal("located promoted to CB1 token")
				}
			}
		})
	}
}
func TestHistoryReadPendingPresenceNullAndOriginalFence(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 2, 0, false, false))
	c := f.readClient(t, DefaultHistoryReadLimits())
	f.pendingTx = true
	o := readHistoryAcquire(t, c, HistoryTransactionByHash, `["`+f.txs[0].Hash().Hex()+`"]`)
	if o.Kind() != HistoryPending || o.Transactions()[0].Location.HashPresent || o.Transactions()[0].GasPrice.Int64() != 3 {
		t.Fatal("pending transaction invented location/price")
	}
	f.pendingTx = false
	for _, m := range []HistoryMethod{HistoryBlockByNumber, HistoryBlockCountByNumber, HistoryTransactionByNumberIndex, HistoryBlockReceipts} {
		params := `["pending"]`
		if m == HistoryBlockByNumber {
			params = `["pending",true]`
		}
		if m == HistoryTransactionByNumberIndex {
			params = `["pending","0x0"]`
		}
		o := readHistoryAcquire(t, c, m, params)
		if o.Kind() != HistoryPending {
			t.Fatal("pending coerced")
		}
		if m != HistoryTransactionByNumberIndex {
			p, ok := o.PendingBlock()
			if !ok || p.HashPresent || p.NoncePresent || p.MinerPresent || p.Header.Number.Uint64() != 1 || !o.Transactions()[0].Location.HashPresent {
				t.Fatal("pending header/body presence lost")
			}
		}
	}
	for _, tc := range []struct {
		m      HistoryMethod
		params string
	}{{HistoryTransactionByHash, `["` + common.Hash{99}.Hex() + `"]`}, {HistoryBlockByNumber, `["0x999",false]`}, {HistoryTransactionByNumberIndex, `["pending","0xffff"]`}} {
		o := readHistoryAcquire(t, c, tc.m, tc.params)
		if o.Kind() != HistoryNotFound {
			t.Fatal("actual missing result lost")
		}
	}
	parent, cancel := context.WithCancel(context.Background())
	q := readHistoryQuery(t, HistoryTransactionByHash, `["`+f.txs[0].Hash().Hex()+`"]`, c.limits)
	o, err := c.Acquire(parent, q)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if c.Recheck(context.Background(), o) == nil {
		t.Fatal("fresh context renewed original cancellation")
	}
	deadline := time.Now().Add(100 * time.Millisecond)
	fence := HistoryOperationFence{Deadline: deadline}
	o, err = c.AcquireWithin(context.Background(), q, fence)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Until(deadline) + time.Millisecond)
	if c.Recheck(context.Background(), o) == nil {
		t.Fatal("fresh context renewed original deadline")
	}
}
func TestHistoryReadOrphanHashVersusCanonicalAndWholeFailure(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, true, true))
	c := f.readClient(t, DefaultHistoryReadLimits())
	hash := f.header.Hash().Hex()
	o := readHistoryAcquire(t, c, HistoryBlockByHash, `["`+hash+`",true]`)
	f.reorg = true
	if err := c.Recheck(context.Background(), o); err != nil {
		t.Fatal("genuine located orphan discarded", err)
	}
	f.reorg = false
	canonical := readHistoryAcquire(t, c, HistoryBlockByNumber, `["0x1",true]`)
	f.reorg = true
	if c.Recheck(context.Background(), canonical) == nil {
		t.Fatal("canonical reorg accepted")
	}
	f.reorg = false
	for _, mutate := range []func([]map[string]any) []map[string]any{func(v []map[string]any) []map[string]any { return append(v, v[0]) }, func(v []map[string]any) []map[string]any { return v[:len(v)-1] }, func(v []map[string]any) []map[string]any { v[0]["id"] = "foreign"; return v }, func(v []map[string]any) []map[string]any {
		delete(v[0], "result")
		v[0]["error"] = map[string]any{"message": "private backend error"}
		return v
	}} {
		f.batchChange = mutate
		o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryBlockByHash, `["`+hash+`",true]`, c.limits))
		if err == nil || o != nil || strings.Contains(err.Error(), "private") {
			t.Fatal("partial/raw batch failure exposed", err)
		}
	}
	f.batchChange = nil
	f.change = func(method string, value any) any {
		if method == "eth_getTransactionByHash" && value != nil {
			copy := includedObject(t, value)
			copy["blockNumber"] = nil
			return copy
		}
		return value
	}
	if o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionByHash, `["`+f.txs[0].Hash().Hex()+`"]`, c.limits)); err == nil || o != nil {
		t.Fatal("mixed inclusion tuple accepted")
	}
}
func TestHistoryReadLowerPhysicalItemsWireAndResultLimits(t *testing.T) {
	for _, name := range []string{"physical", "items", "wire", "result", "owned", "batch-one"} {
		t.Run(name, func(t *testing.T) {
			f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
			l := DefaultHistoryReadLimits()
			switch name {
			case "physical":
				l.MaxHTTPAttempts = 1
			case "items":
				l.MaxRPCItems = 2
			case "wire":
				l.MaxWireBytes = 100
			case "result":
				l.MaxResultBytes = 100
			case "owned":
				l.MaxChargedBytes = 1024
			case "batch-one":
				l.MaxBatchItems = 1
			}
			c := f.readClient(t, l)
			o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionByHash, `["`+f.txs[0].Hash().Hex()+`"]`, l))
			if name == "batch-one" {
				if err != nil {
					t.Fatal("valid selected lower batch must work", err)
				}
				return
			}
			if err == nil || o != nil {
				t.Fatal("selected lower ceiling ignored")
			}
			f.mu.Lock()
			physical, items := f.physical, f.items
			f.mu.Unlock()
			if physical > l.MaxHTTPAttempts || items > l.MaxRPCItems {
				t.Fatal("wire counters exceeded", physical, items)
			}
		})
	}
}

func TestHistoryReadLogParentsAreBatchedQualifiedAndFilterExact(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false), historySigned(t, 0, 1, false, false))
	address := common.Address{19: 77}
	topic := common.Hash{31: 44}
	logs := []*types.Log{{Address: address, Topics: []common.Hash{topic}, Data: []byte{1}, Index: 7}, {Address: address, Topics: []common.Hash{topic}, Data: []byte{2}, Index: 8}}
	bloom := types.CreateBloom(&types.Receipt{Logs: logs})
	f.header.Bloom = bloom
	f.rebind(t)
	rows := []any{}
	for _, log := range logs {
		rows = append(rows, map[string]any{"address": address.Hex(), "topics": []string{topic.Hex()}, "data": "0x" + common.Bytes2Hex(log.Data), "blockHash": f.header.Hash().Hex(), "blockNumber": "0x1", "transactionHash": f.txs[1].Hash().Hex(), "transactionIndex": "0x1", "logIndex": fmtHistoryQuantity(uint64(log.Index)), "removed": false})
	}
	f.receipts[1].(map[string]any)["logs"] = rows
	f.receipts[1].(map[string]any)["logsBloom"] = "0x" + common.Bytes2Hex(bloom[:])
	f.logs = []any{includedObject(t, rows[0])}
	// The first transaction accounts for the preceding global ordinals. A
	// sparse lookup fetches only the second receipt's two entries.
	earlier := []any{}
	for i := 0; i < 7; i++ {
		row := includedObject(t, rows[0])
		row["transactionHash"] = f.txs[0].Hash().Hex()
		row["transactionIndex"] = "0x0"
		row["logIndex"] = fmtHistoryQuantity(uint64(i))
		earlier = append(earlier, row)
	}
	f.receipts[0].(map[string]any)["logs"] = earlier
	f.receipts[0].(map[string]any)["logsBloom"] = "0x" + common.Bytes2Hex(bloom[:])
	limits := DefaultHistoryReadLimits()
	limits.Block.MaxLogs = 2
	c := f.readClient(t, limits)
	params := `[{"fromBlock":"0x1","toBlock":"0x1","address":"` + address.Hex() + `","topics":["` + topic.Hex() + `"]}]`
	o := readHistoryAcquire(t, c, HistoryLogs, params)
	if len(o.Transactions()) != 1 || len(o.Receipts()) != 1 || len(o.Logs()) != 1 || o.Logs()[0].Log.LogIndex != 7 || len(o.Receipts()[0].Receipt.Logs()) != 2 {
		t.Fatal("requested log and qualified receipt population conflated")
	}
	f.mu.Lock()
	if f.methods["eth_getBlockByHash"] != 0 || f.methods["eth_getBlockReceipts"] != 0 || f.methods["eth_getTransactionByHash"] != 1 || f.methods["eth_getTransactionReceipt"] != 1 {
		t.Fatal("log source fetched whole blocks or duplicated parent work", f.methods)
	}
	f.mu.Unlock()
	receiptParams := `["` + f.txs[1].Hash().Hex() + `"]`
	receipt := readHistoryAcquire(t, c, HistoryTransactionReceipt, receiptParams)
	if len(receipt.Logs()) != 2 || receipt.Logs()[0].Log.LogIndex != 7 || receipt.Logs()[1].Log.LogIndex != 8 {
		t.Fatal("sparse receipt local count replaced actual global ordinals")
	}
	// A valid large global ordinal never lifts either local count or gap checks.
	second := rows[1].(map[string]any)
	second["logIndex"] = "0x9"
	if got, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionReceipt, receiptParams, c.limits)); err == nil || got != nil {
		t.Fatal("sparse receipt log ordinal gap accepted")
	}
	second["logIndex"] = "0x8"
	third := includedObject(t, rows[1])
	third["logIndex"] = "0x9"
	f.receipts[1].(map[string]any)["logs"] = append(append([]any{}, rows...), third)
	if got, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionReceipt, receiptParams, c.limits)); err == nil || got != nil {
		t.Fatal("sparse local entry limit widened")
	}
	f.receipts[1].(map[string]any)["logs"] = rows
	copy := o.Logs()
	copy[0].Log.Data[0] = 9
	if o.Logs()[0].Log.Data[0] != 1 {
		t.Fatal("returned log aliases")
	}
	// A real orphan-by-hash log retains the explicit removed flag without any
	// numeric-canonical or C2 claim. The same flag in a numeric range is invalid.
	f.logs[0].(map[string]any)["removed"] = true
	o = readHistoryAcquire(t, c, HistoryLogs, `[{"blockHash":"`+f.header.Hash().Hex()+`"}]`)
	if o.Kind() != HistoryLocated || !o.Logs()[0].Removed {
		t.Fatal("removed/location metadata lost")
	}
	if got, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryLogs, params, c.limits)); err == nil || got != nil {
		t.Fatal("removed numeric-range row accepted")
	}
	f.logs[0].(map[string]any)["removed"] = false
	f.change = func(method string, value any) any {
		if method == "eth_getTransactionByHash" {
			copy := includedObject(t, value)
			copy["from"] = common.Address{19: 99}.Hex()
			return copy
		}
		return value
	}
	if got, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryLogs, params, c.limits)); err == nil || got != nil {
		t.Fatal("signed parent sender mismatch released")
	}
}

func TestHistoryReadTransactionDoesNotRequireUnusedReceipt(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
	f.rpcErrors = map[string]bool{"eth_getTransactionReceipt": true}
	c := f.readClient(t, DefaultHistoryReadLimits())
	hash := f.txs[0].Hash().Hex()
	for _, tc := range []struct {
		m      HistoryMethod
		params string
	}{
		{HistoryTransactionByHash, `["` + hash + `"]`},
		{HistoryTransactionByHashIndex, `["` + f.header.Hash().Hex() + `","0x0"]`},
		{HistoryTransactionByNumberIndex, `["0x1","0x0"]`},
	} {
		o := readHistoryAcquire(t, c, tc.m, tc.params)
		if len(o.Transactions()) != 1 || len(o.Receipts()) != 0 || len(o.Logs()) != 0 {
			t.Fatal("plain transaction acquired unused receipt/log population")
		}
	}
	if f.methods["eth_getTransactionReceipt"] != 0 {
		t.Fatal("plain transaction touched trapped receipt source")
	}
	if o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionReceipt, `["`+hash+`"]`, c.limits)); err == nil || o != nil {
		t.Fatal("requested receipt backend failure hidden")
	}
	f.rpcErrors = nil
	f.change = func(method string, value any) any {
		if method == "eth_getTransactionReceipt" {
			return nil
		}
		return value
	}
	if o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryTransactionReceipt, `["`+hash+`"]`, c.limits)); err == nil || o != nil {
		t.Fatal("included transaction with missing requested receipt became null success")
	}
}

func TestHistoryReadPendingNullBodyProbesRequestedReceiptMethod(t *testing.T) {
	for _, name := range []string{"backend-error", "nonnull-set", "actual-null"} {
		t.Run(name, func(t *testing.T) {
			f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
			f.block = func() any { return nil }
			if name == "backend-error" {
				f.rpcErrors = map[string]bool{"eth_getBlockReceipts": true}
			}
			if name == "actual-null" {
				f.change = func(method string, value any) any {
					if method == "eth_getBlockReceipts" {
						return nil
					}
					return value
				}
			}
			c := f.readClient(t, DefaultHistoryReadLimits())
			o, err := c.Acquire(context.Background(), readHistoryQuery(t, HistoryBlockReceipts, `["pending"]`, c.limits))
			if f.methods["eth_getBlockReceipts"] != 1 {
				t.Fatal("actual requested pending receipt lookup was skipped")
			}
			if name == "actual-null" {
				if err != nil || o.Kind() != HistoryNotFound {
					t.Fatal("actual requested null not preserved", err)
				}
			} else if err == nil || o != nil {
				t.Fatal("missing body manufactured successful requested receipt result")
			}
		})
	}
}

func TestHistoryReadLowerResultAppliesToAllBlockAcquisitions(t *testing.T) {
	for _, name := range []string{"canonical", "located", "pending"} {
		t.Run(name, func(t *testing.T) {
			txs := make([]*types.Transaction, 12)
			for i := range txs {
				txs[i] = historySigned(t, 0, uint64(i), false, false)
			}
			f := newReadHistoryFixture(t, txs...)
			l := DefaultHistoryReadLimits()
			l.MaxResultBytes = 4 << 10
			c := f.readClient(t, l)
			m, params := HistoryBlockByNumber, `["0x1",true]`
			if name == "located" {
				m, params = HistoryBlockByHash, `["`+f.header.Hash().Hex()+`",true]`
			}
			if name == "pending" {
				params = `["pending",true]`
			}
			o, err := c.Acquire(context.Background(), readHistoryQuery(t, m, params, l))
			if err == nil || o != nil {
				t.Fatal("selected result ceiling bypassed")
			}
			if f.methods["eth_getBlockByHash"]+f.methods["eth_getBlockByNumber"] == 0 {
				t.Fatal("lower ceiling rejected a fixed operation before reading its actual bounded body")
			}
		})
	}
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
	l := DefaultHistoryReadLimits()
	l.MaxResultBytes = 8 << 10
	c := f.readClient(t, l)
	for _, tc := range []struct {
		m      HistoryMethod
		params string
	}{{HistoryBlockByNumber, `["0x1",true]`}, {HistoryBlockByHash, `["` + f.header.Hash().Hex() + `",true]`}, {HistoryBlockByNumber, `["pending",true]`}} {
		readHistoryAcquire(t, c, tc.m, tc.params)
	}
}

type historyReadTestCountedBody struct {
	reader io.Reader
	read   int
}

func (r *historyReadTestCountedBody) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}
func (r *historyReadTestCountedBody) Close() error { return nil }
func TestHistoryReadBatchStopsAtEffectiveSelectedBodyBound(t *testing.T) {
	f := newReadHistoryFixture(t, historySigned(t, 0, 0, false, false))
	l := DefaultHistoryReadLimits()
	l.MaxResultBytes = 128
	c := f.readClient(t, l)
	body := &historyReadTestCountedBody{reader: strings.NewReader(`[{"jsonrpc":"2.0","id":"h1:0","result":"` + strings.Repeat("x", 200000) + `"}]`)}
	b := &historyReadBudget{base: headerLaneTransportFunc(func(*http.Request) (*http.Response, error) { return &http.Response{StatusCode: 200, Body: body}, nil }), limits: l}
	if _, err := c.batch(context.Background(), b, []historyRPCItem{{"eth_syncing", nil, 64}}); err == nil {
		t.Fatal("oversize result accepted")
	}
	if body.read > 64+4096+4 {
		t.Fatal("read whole response before selected result ceiling", body.read)
	}
}

func TestHistoryReadComposedBlockRetainedCapAppliesBeforeReceiptFetch(t *testing.T) {
	txs := make([]*types.Transaction, 50)
	for i := range txs {
		txs[i] = historySigned(t, 0, uint64(i), false, false)
	}
	f := newReadHistoryFixture(t, txs...)
	c := f.readClient(t, DefaultHistoryReadLimits())
	q := readHistoryQuery(t, HistoryBlockByNumber, `["0x1",true]`, c.limits)
	o, err := c.AcquireReservedWithin(context.Background(), q, HistoryOperationFence{Deadline: time.Now().Add(time.Second)}, c.limits.MaxChargedBytes-(16<<10))
	if err == nil || o != nil {
		t.Fatal("composed retained ceiling ignored")
	}
	if f.methods["eth_getBlockByHash"] != 1 || f.methods["eth_getBlockReceipts"] != 0 {
		t.Fatal("full block decoded and receipts fetched before applying remaining retained ceiling", f.methods)
	}
}
