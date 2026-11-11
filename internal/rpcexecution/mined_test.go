package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
)

type minedFixture struct {
	mu                                       sync.Mutex
	tx                                       *types.Transaction
	header, genesis                          *types.Header
	txObject, block, receipt, root, prestate map[string]any
	methods                                  []string
	change                                   func(string, any) any
	client                                   *Client
}

func newMinedFixture(t *testing.T, kind uint8, creation, unprotected bool) *minedFixture {
	t.Helper()
	tx := historySigned(t, kind, 7, creation, unprotected)
	g := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, BaseFee: big.NewInt(1), Extra: []byte{}}
	h := types.CopyHeader(g)
	h.Number = big.NewInt(1)
	h.Time = 2
	h.ParentHash = g.Hash()
	h.GasUsed = 21000
	if kind == 3 {
		n := uint64(len(tx.BlobHashes())) * 131072
		h.BlobGasUsed = &n
	}
	hf := &historyFixture{header: h, genesis: g, txs: []*types.Transaction{tx}}
	hf.rebind(t)
	txo := hf.block["transactions"].([]any)[0].(map[string]any)
	block := includedObject(t, h)
	block["transactions"] = []any{tx.Hash().Hex()}
	block["uncles"], block["withdrawals"] = []any{}, []any{}
	signer := types.LatestSignerForChainID(big.NewInt(1))
	if unprotected {
		signer = nil
	}
	var from common.Address
	var err error
	if unprotected {
		from, err = types.Sender(types.FrontierSigner{}, tx)
	} else {
		from, err = types.Sender(signer, tx)
	}
	if err != nil {
		t.Fatal(err)
	}
	to := common.Address{}
	if tx.To() != nil {
		to = *tx.To()
	} else {
		to = crypto.CreateAddress(from, tx.Nonce())
	}
	root := map[string]any{"type": "CALL", "from": from.Hex(), "to": to.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x186a0", "gasUsed": "0x5208", "output": "0xbeef"}
	pre := map[string]any{from.Hex(): map[string]any{"nonce": 7}, to.Hex(): map[string]any{"code": "0x6000", "nonce": 1}}
	if creation {
		root["type"] = "CREATE"
		root["output"] = "0x6000"
		pre[to.Hex()] = map[string]any{}
	}
	f := &minedFixture{tx: tx, header: h, genesis: g, txObject: txo, block: block, receipt: hf.receipts[0].(map[string]any), root: root, prestate: pre}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "mined-fixture" {
			t.Error("wrong concrete mined credential")
			w.WriteHeader(400)
			return
		}
		var q headerLaneRPC
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("bad RPC")
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		f.methods = append(f.methods, q.Method)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = false
		case "eth_getHeaderByNumber":
			var s string
			_ = json.Unmarshal(q.Params[0], &s)
			result = f.header
			if s == "0x0" {
				result = f.genesis
			}
		case "eth_getTransactionByHash":
			result = f.txObject
		case "eth_getTransactionReceipt":
			result = f.receipt
		case "eth_getBlockByHash":
			var full bool
			_ = json.Unmarshal(q.Params[1], &full)
			if full {
				t.Error("not a hash-list block")
			}
			result = f.block
		case "debug_traceTransaction":
			var config map[string]any
			_ = json.Unmarshal(q.Params[1], &config)
			if config["tracer"] != "muxTracer" {
				t.Error("not an actual mined mux")
			}
			cfg := config["tracerConfig"].(map[string]any)
			call := cfg["callTracer"].(map[string]any)
			if call["withLog"] != false {
				t.Error("client trace requested logs")
			}
			result = map[string]any{"callTracer": f.root, "prestateTracer": f.prestate, "flatCallTracer": []any{map[string]any{"blockHash": f.header.Hash().Hex(), "blockNumber": f.header.Number.Uint64(), "transactionHash": f.tx.Hash().Hex(), "transactionPosition": 0, "traceAddress": []any{}}}}
		default:
			t.Error("forbidden mined supplement/replay", q.Method)
			w.WriteHeader(500)
			return
		}
		if f.change != nil {
			result = f.change(q.Method, result)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("counted POST can replay")
		}
		return srv.Client().Transport.RoundTrip(r)
	}), NodeBinding{OrganizationID: "11111111-1111-1111-1111-111111111111", URL: srv.URL, ChainID: "1", Profile: SimulationCallProfileID, PragueStartInclusive: 1, PragueEndExclusive: 10, Credentials: map[string]Credential{"mined": {"Idempotency-Key", "mined-fixture"}}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.WithNetwork(networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: g.Hash().Hex(), DeploymentID: "mined"})
	if err != nil {
		t.Fatal(err)
	}
	f.client, err = c.WithCredential("mined")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMinedActualTLSAllSignedHistoryKindsAndOwnedExecution(t *testing.T) {
	for _, tc := range []struct {
		kind           uint8
		create, legacy bool
	}{{0, false, false}, {1, false, false}, {2, false, false}, {3, false, false}, {0, false, true}, {0, true, false}} {
		t.Run(fmtHistoryQuantity(uint64(tc.kind))+strings.Repeat("c", boolInt(tc.create))+strings.Repeat("l", boolInt(tc.legacy)), func(t *testing.T) {
			f := newMinedFixture(t, tc.kind, tc.create, tc.legacy)
			p, err := f.client.AcquireMinedEnvelope(t.Context(), f.tx.Hash(), DefaultMinedTraceLimits())
			if err != nil {
				t.Fatal("actual signed envelope", err, f.methods)
			}
			e, err := p.AcquireTrace(t.Context(), true)
			if err != nil {
				t.Fatal("actual mining-index execution", err, f.methods)
			}
			if e.Purpose() != MinedClientTraceProfileID || e.RecordCount() != 1 || e.TransactionHash() != f.tx.Hash() {
				t.Fatal("wrong genuine mined purpose")
			}
			if !tc.create {
				code, ok := e.FrameCode(0)
				if !ok || code.Hash() != crypto.Keccak256Hash([]byte{0x60, 0}) {
					t.Fatal("mined prestate code lost")
				}
			}
			a, err := e.CallTraceJSON()
			if err != nil {
				t.Fatal(err)
			}
			a[0] = '['
			b, _ := e.CallTraceJSON()
			if b[0] != '{' {
				t.Fatal("child not detached")
			}
			checkpoint, err := e.DeliveryCheckpoint()
			if err != nil || checkpoint.RequireCurrent(t.Context(), creationfacts.Header{}) != nil {
				t.Fatal("small original checkpoint", err)
			}
			copyEnvelope := *p
			if _, err := copyEnvelope.AcquireTrace(t.Context(), false); err == nil {
				t.Fatal("mined trace replayed through copied envelope")
			}
		})
	}
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func TestMinedActualTLSRejectsIndependentContradictionsWithoutStateFallback(t *testing.T) {
	for _, name := range []string{"missing-prestate", "type4", "wrong-signer", "wrong-receipt", "orphan", "wrong-genesis", "syncing", "unexpected-child", "delegated-code"} {
		t.Run(name, func(t *testing.T) {
			kind := uint8(2)
			if name == "type4" {
				kind = 4
			}
			f := newMinedFixture(t, kind, false, false)
			f.change = func(method string, v any) any {
				switch name {
				case "missing-prestate":
					if method == "debug_traceTransaction" {
						delete(f.prestate, f.tx.To().Hex())
					}
				case "wrong-signer":
					if method == "eth_getTransactionByHash" {
						f.txObject["from"] = common.Address{9}.Hex()
					}
				case "wrong-receipt":
					if method == "eth_getTransactionReceipt" {
						f.receipt["transactionIndex"] = "0x1"
					}
				case "orphan":
					if method == "eth_getHeaderByNumber" && v.(*types.Header).Number.Sign() > 0 {
						h := types.CopyHeader(f.header)
						h.Time++
						return h
					}
				case "wrong-genesis":
					if method == "eth_getHeaderByNumber" && v.(*types.Header).Number.Sign() == 0 {
						g := types.CopyHeader(f.genesis)
						g.Time++
						return g
					}
				case "syncing":
					if method == "eth_syncing" {
						return map[string]any{"startingBlock": "0x0", "currentBlock": "0x1", "highestBlock": "0x2"}
					}
				case "unexpected-child":
					if method == "debug_traceTransaction" {
						f.root["calls"] = []any{map[string]any{"type": "CALL", "from": f.tx.To().Hex(), "to": f.tx.To().Hex(), "input": "0x", "value": "0x0", "gas": "0x10", "gasUsed": "0x1", "output": "0x"}}
					}
				case "delegated-code":
					if method == "debug_traceTransaction" {
						f.prestate[f.tx.To().Hex()] = map[string]any{"code": "0xef0100" + strings.Repeat("11", 20)}
					}
				}
				return v
			}
			l := DefaultMinedTraceLimits()
			p, err := f.client.AcquireMinedEnvelope(t.Context(), f.tx.Hash(), l)
			if err == nil {
				_, err = p.AcquireTrace(t.Context(), true)
			}
			if err == nil {
				t.Fatal("contradictory mined source accepted", f.methods)
			}
		})
	}
}

func TestMinedOriginalStageDeadlineAndCancellation(t *testing.T) {
	f := newMinedFixture(t, 2, false, false)
	ctx, cancel := context.WithCancel(t.Context())
	p, err := f.client.AcquireMinedEnvelope(ctx, f.tx.Hash(), DefaultMinedTraceLimits())
	if err != nil {
		t.Fatal(err)
	}
	before := len(f.methods)
	cancel()
	if _, err := p.AcquireTrace(context.Background(), false); err == nil || len(f.methods) != before {
		t.Fatal("original caller cancellation was reset")
	}
	f = newMinedFixture(t, 2, false, false)
	p, err = f.client.AcquireMinedEnvelope(t.Context(), f.tx.Hash(), DefaultMinedTraceLimits())
	if err != nil {
		t.Fatal(err)
	}
	p.deadline = time.Now().Add(-time.Nanosecond)
	before = len(f.methods)
	if _, err := p.AcquireTrace(context.Background(), false); err == nil || len(f.methods) != before {
		t.Fatal("acquisition stage renewed deadline")
	}
}

func TestMinedSparseReceiptGlobalOrdinalsAreNotLocalEntryCounts(t *testing.T) {
	for _, scenario := range []string{"one-high-index", "two-contiguous", "gap", "duplicate", "wrong-transaction", "wrong-bloom", "local-limit"} {
		t.Run(scenario, func(t *testing.T) {
			f := newMinedFixture(t, 2, false, false)
			address := *f.tx.To()
			topic := common.Hash{1}
			data := []byte{0xfa, 0xce}
			entries := []*types.Log{{Address: address, Topics: []common.Hash{topic}, Data: data}}
			if scenario != "one-high-index" {
				entries = append(entries, &types.Log{Address: address, Topics: []common.Hash{topic}, Data: data})
			}
			bloom := types.CreateBloom(&types.Receipt{Logs: entries})
			f.header.Bloom = bloom
			f.block = includedObject(t, f.header)
			f.block["transactions"], f.block["uncles"], f.block["withdrawals"] = []any{f.tx.Hash().Hex()}, []any{}, []any{}
			f.txObject["blockHash"], f.receipt["blockHash"] = f.header.Hash().Hex(), f.header.Hash().Hex()
			logs := []any{}
			for i := range entries {
				index := uint64(65535 + i)
				if scenario == "gap" && i == 1 {
					index++
				}
				if scenario == "duplicate" && i == 1 {
					index--
				}
				hash := f.tx.Hash()
				if scenario == "wrong-transaction" {
					hash[0] ^= 1
				}
				logs = append(logs, map[string]any{"address": address.Hex(), "topics": []any{topic.Hex()}, "data": "0xface", "blockNumber": "0x1", "blockHash": f.header.Hash().Hex(), "transactionHash": hash.Hex(), "transactionIndex": "0x0", "logIndex": fmtHistoryQuantity(index), "removed": false})
			}
			f.receipt["logs"], f.receipt["logsBloom"] = logs, "0x"+common.Bytes2Hex(bloom[:])
			if scenario == "wrong-bloom" {
				f.receipt["logsBloom"] = "0x" + strings.Repeat("00", 256)
			}
			l := DefaultMinedTraceLimits()
			l.MaxReceiptLogs = 2
			if scenario == "local-limit" {
				l.MaxReceiptLogs = 1
			}
			p, err := f.client.AcquireMinedEnvelope(t.Context(), f.tx.Hash(), l)
			positive := scenario == "one-high-index" || scenario == "two-contiguous"
			if (err == nil) != positive {
				t.Fatal("global ordinal/local count conflated", scenario, err)
			}
			if positive {
				raw, _ := json.Marshal(f.receipt)
				next := uint32(65535)
				pos := includedPosition{Hash: f.header.Hash(), Number: 1, Index: 0, Timestamp: 2, TimestampKnown: true}
				if _, _, err := decodeHistoryReceipt(raw, p.Transaction(), pos, f.header, &next, l.historyLimits()); err == nil {
					t.Fatal("whole-block aggregate ceiling was widened")
				}
			}
		})
	}
}

// The source has already restored the original numeric header when queried.
// Only the SAME inspector's context distinguishes a replay on the other branch.
func TestMinedActualTLSReplayContextAndExplicitZeroPosition(t *testing.T) {
	for _, name := range []string{"zero-index-positive", "relocated-replay", "wrong-index", "missing-zero-index", "null-index", "wrong-height", "wrong-tx", "mixed-context", "missing-root", "duplicate-root", "deep-path"} {
		t.Run(name, func(t *testing.T) {
			f := newMinedFixture(t, 2, false, false)
			f.change = func(method string, v any) any {
				if method != "debug_traceTransaction" {
					return v
				}
				parts := v.(map[string]any)
				entries := parts["flatCallTracer"].([]any)
				entry := entries[0].(map[string]any)
				switch name {
				case "relocated-replay":
					other := types.CopyHeader(f.header)
					other.Extra = []byte("alternate inclusion replay; original restored before next sample")
					entry["blockHash"] = other.Hash().Hex()
				case "wrong-index":
					entry["transactionPosition"] = 1
				case "missing-zero-index":
					delete(entry, "transactionPosition")
				case "null-index":
					entry["transactionPosition"] = nil
				case "wrong-height":
					entry["blockNumber"] = 2
				case "wrong-tx":
					entry["transactionHash"] = common.Hash{9}.Hex()
				case "mixed-context":
					child := map[string]any{}
					for k, value := range entry {
						child[k] = value
					}
					child["traceAddress"] = []any{0}
					child["blockHash"] = common.Hash{9}.Hex()
					parts["flatCallTracer"] = append(entries, child)
				case "missing-root":
					entry["traceAddress"] = []any{0}
				case "duplicate-root":
					parts["flatCallTracer"] = append(entries, entry)
				case "deep-path":
					path := make([]any, 257)
					for i := range path {
						path[i] = 0
					}
					entry["traceAddress"] = path
				}
				return parts
			}
			p, err := f.client.AcquireMinedEnvelope(t.Context(), f.tx.Hash(), DefaultMinedTraceLimits())
			if err != nil {
				t.Fatal("original included envelope", err)
			}
			e, err := p.AcquireTrace(t.Context(), true)
			if name == "zero-index-positive" {
				if err != nil || e == nil {
					t.Fatal("explicit genuine zero position refused", err)
				}
			} else if err == nil || e != nil {
				t.Fatal("unbound replay context authorized execution", name)
			}
		})
	}
}
