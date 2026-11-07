package rpcexecution

import (
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/transactioninput"
)

func includedObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		t.Fatal("fixture JSON")
	}
	return fields
}

type includedFixture struct {
	mu                          sync.Mutex
	transaction                 transactioninput.VerifiedTransaction
	tx, receipt, block, genesis map[string]any
	trace                       map[string]any
	code                        string
	methods                     []string
	change                      func(string, map[string]any) any
}

func newIncludedFixture(t *testing.T, kind uint8, creation bool) *includedFixture {
	t.Helper()
	key, err := crypto.HexToECDSA(strings.Repeat("11", 32))
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress("0x1000000000000000000000000000000000000001")
	var destination *common.Address = &to
	if creation {
		destination = nil
	}
	var inner types.TxData
	switch kind {
	case 0:
		inner = &types.LegacyTx{Nonce: 7, To: destination, Value: big.NewInt(0), Gas: 500000, GasPrice: big.NewInt(3), Data: []byte{0x60, 1}}
	case 1:
		inner = &types.AccessListTx{ChainID: big.NewInt(1), Nonce: 7, To: destination, Value: big.NewInt(0), Gas: 500000, GasPrice: big.NewInt(3), Data: []byte{0x60, 1}, AccessList: types.AccessList{}}
	default:
		inner = &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 7, To: destination, Value: big.NewInt(0), Gas: 500000, GasFeeCap: big.NewInt(3), GasTipCap: big.NewInt(1), Data: []byte{0x60, 1}, AccessList: types.AccessList{}}
	}
	signed, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(1)), inner)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := transactioninput.DecodeRaw("0x"+common.Bytes2Hex(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 10, BaseFee: big.NewInt(1)}
	header := &types.Header{Number: big.NewInt(1), ParentHash: genesis.Hash(), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 11, BaseFee: big.NewInt(1)}
	tx := includedObject(t, signed)
	tx["from"] = verified.Signer().Hex()
	tx["blockHash"] = header.Hash().Hex()
	tx["blockNumber"] = "0x1"
	tx["transactionIndex"] = "0x0"
	root := map[string]any{"type": "CALL", "from": verified.Signer().Hex(), "to": to.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x10000", "gasUsed": "0x20", "output": "0x", "calls": []any{}}
	child := common.HexToAddress("0x2000000000000000000000000000000000000002")
	receipt := map[string]any{"transactionHash": signed.Hash().Hex(), "from": verified.Signer().Hex(), "to": to.Hex(), "blockHash": header.Hash().Hex(), "blockNumber": "0x1", "transactionIndex": "0x0", "status": "0x1", "contractAddress": nil, "type": "0x" + big.NewInt(int64(kind)).Text(16), "gasUsed": "0x20", "cumulativeGasUsed": "0x20", "effectiveGasPrice": "0x1", "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
	if creation {
		child = crypto.CreateAddress(verified.Signer(), verified.Nonce())
		root["type"] = "CREATE"
		root["to"] = child.Hex()
		root["output"] = "0x6000"
		receipt["to"] = nil
		receipt["contractAddress"] = child.Hex()
	} else {
		root["calls"] = []any{map[string]any{"type": "CREATE", "from": to.Hex(), "to": child.Hex(), "input": "0x6001", "output": "0x6000", "value": "0x0", "gas": "0x1000", "gasUsed": "0x10"}}
	}
	block := includedObject(t, header)
	block["transactions"] = []any{signed.Hash().Hex()}
	block["uncles"] = []any{}
	block["withdrawals"] = []any{}
	return &includedFixture{transaction: verified, tx: tx, receipt: receipt, block: block, genesis: includedObject(t, genesis), trace: root, code: "0x6000"}
}
func (f *includedFixture) serve(t *testing.T) (*IncludedClient, func()) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		var q struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&q) != nil {
			t.Error("RPC fixture decode")
			return
		}
		f.methods = append(f.methods, q.Method)
		var result any
		switch q.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_getHeaderByNumber":
			result = f.genesis
		case "eth_getTransactionByHash":
			result = f.tx
		case "eth_getTransactionReceipt":
			result = f.receipt
		case "eth_getBlockByHash", "eth_getBlockByNumber":
			result = f.block
		case "debug_traceTransaction":
			var config map[string]any
			_ = json.Unmarshal(q.Params[1], &config)
			want := map[string]any{"tracer": "muxTracer", "tracerConfig": map[string]any{"callTracer": map[string]any{"onlyTopCall": false, "withLog": true}, "prestateTracer": map[string]any{"diffMode": false, "disableCode": false, "disableStorage": true, "includeEmpty": true}}}
			a, _ := json.Marshal(config)
			b, _ := json.Marshal(want)
			if string(a) != string(b) {
				t.Error("nonfixed included trace configuration")
			}
			result = map[string]any{"callTracer": f.trace, "prestateTracer": map[string]any{}}
		case "eth_getCode":
			var anchor map[string]any
			_ = json.Unmarshal(q.Params[1], &anchor)
			if anchor["blockHash"] != f.block["hash"] || anchor["requireCanonical"] != false {
				t.Error("code fallback is not exact inclusion hash")
			}
			result = f.code
		default:
			t.Error("forbidden included RPC", q.Method)
			w.WriteHeader(500)
			return
		}
		if object, ok := result.(map[string]any); ok && f.change != nil {
			result = f.change(q.Method, object)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
	}))
	source := creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest{1}, Environment: "public-test", ChainID: "1", Genesis: common.HexToHash(f.genesis["hash"].(string)), Deployment: "test"}, URL: server.URL, Profile: IncludedProfileID, PragueStart: 10, PragueEnd: 20}
	client, err := NewIncludedClient(server.Client().Transport, source, Credential{}, DefaultIncludedLimits())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server.Close
}
func TestIncludedPrototypeProtectedTransactionsAndOpaqueDetachedProof(t *testing.T) {
	for _, kind := range []uint8{0, 1, 2} {
		for _, creation := range []bool{false, true} {
			name := big.NewInt(int64(kind)).String()
			if creation {
				name += "-root-create"
			}
			t.Run(name, func(t *testing.T) {
				f := newIncludedFixture(t, kind, creation)
				client, close := f.serve(t)
				defer close()
				proof, err := client.AcquireIncluded(t.Context(), f.transaction.Hash())
				if err != nil {
					t.Fatal(err, f.methods)
				}
				records := proof.Creations()
				if len(records) != 1 || !records[0].Survives || proof.Transaction().Signer() != f.transaction.Signer() || proof.Digest() == (common.Hash{}) {
					t.Fatal("missing verified ordinary survivor", records)
				}
				records[0].Address = common.Address{}
				if proof.Creations()[0].Address == (common.Address{}) {
					t.Fatal("mutable proof metadata escaped")
				}
				again, err := client.AcquireIncluded(t.Context(), f.transaction.Hash())
				if err != nil || again.Digest() != proof.Digest() {
					t.Fatal("stable proof digest changed across RPC IDs", err)
				}
				if len(f.methods) != 18 {
					t.Fatal("exact9physical requests per one-survivor proof", f.methods)
				}
			})
		}
	}
}
func TestIncludedPrototypeRejectsIndependentBindingAndResourceMismatches(t *testing.T) {
	for _, scenario := range []string{"from", "receipt-index", "block-membership", "root-status", "huge-nonce", "unsupported-type", "unknown-field", "wrong-final-code", "changing-canonical", "request-budget", "block-timestamp", "required-null", "fabricated-genesis"} {
		t.Run(scenario, func(t *testing.T) {
			f := newIncludedFixture(t, 2, false)
			switch scenario {
			case "block-timestamp":
				f.tx["blockTimestamp"] = "0xc"
			case "required-null":
				f.tx["nonce"] = nil
			case "fabricated-genesis":
				f.change = func(method string, object map[string]any) any {
					if method == "eth_getHeaderByNumber" {
						return map[string]any{"hash": object["hash"], "number": object["number"], "parentHash": object["parentHash"], "timestamp": object["timestamp"]}
					}
					return object
				}
			case "from":
				f.tx["from"] = common.Address{9}.Hex()
			case "receipt-index":
				f.receipt["transactionIndex"] = "0x1"
			case "block-membership":
				f.block["transactions"] = []any{common.Hash{8}.Hex()}
			case "root-status":
				f.trace["error"] = "execution reverted"
			case "huge-nonce":
				f.tx["nonce"] = "0x" + strings.Repeat("1", 1<<16)
			case "unsupported-type":
				f.tx["type"] = "0x4"
			case "unknown-field":
				f.tx["unexpected"] = true
			case "wrong-final-code":
				f.code = "0x6001"
			case "changing-canonical":
				count := 0
				f.change = func(method string, object map[string]any) any {
					if method == "eth_getBlockByNumber" {
						count++
						if count == 2 {
							copy := includedObject(t, object)
							copy["hash"] = common.Hash{9}.Hex()
							return copy
						}
					}
					return object
				}
			}
			client, close := f.serve(t)
			defer close()
			if scenario == "request-budget" {
				client.limits.MaxRequests = 8
			}
			proof, err := client.AcquireIncluded(t.Context(), f.transaction.Hash())
			if err == nil || proof != nil {
				t.Fatal("partial or mismatched included proof escaped", proof, err)
			}
			if scenario == "request-budget" && len(f.methods) > 8 {
				t.Fatal("physical request budget exceeded", len(f.methods))
			}
		})
	}
}

func TestIncludedPrototypeSelfSourceAndRollbackSurvival(t *testing.T) {
	for _, scenario := range []string{"constructor-self", "self-in-reverted-child", "beneficiary-only", "ef-output", "failed-creation", "duplicate-success-address"} {
		t.Run(scenario, func(t *testing.T) {
			f := newIncludedFixture(t, 2, false)
			child := f.trace["calls"].([]any)[0].(map[string]any)
			created := child["to"].(string)
			self := func(from, to string) map[string]any {
				return map[string]any{"type": "SELFDESTRUCT", "from": from, "to": to, "input": "0x", "output": "0x", "value": "0x0", "gas": "0x0", "gasUsed": "0x0"}
			}
			switch scenario {
			case "constructor-self":
				child["calls"] = []any{self(created, common.Address{8}.Hex())}
			case "self-in-reverted-child":
				child["calls"] = []any{map[string]any{"type": "CALL", "from": created, "to": created, "input": "0x", "output": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1", "error": "execution reverted", "calls": []any{self(created, common.Address{8}.Hex())}}}
			case "beneficiary-only":
				foreign := common.HexToAddress("0x3000000000000000000000000000000000000003").Hex()
				f.trace["calls"] = []any{child, map[string]any{"type": "CALL", "from": f.trace["to"], "to": foreign, "input": "0x", "output": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1", "calls": []any{self(foreign, created)}}}
			case "ef-output":
				child["output"] = "0xef0100"
				f.code = "0xef0100"
			case "failed-creation":
				child["error"] = "execution reverted"
			case "duplicate-success-address":
				f.trace["calls"] = []any{child, includedObject(t, child)}
			}
			client, close := f.serve(t)
			defer close()
			proof, err := client.AcquireIncluded(t.Context(), f.transaction.Hash())
			if scenario == "duplicate-success-address" {
				if err == nil || proof != nil {
					t.Fatal("duplicate same-address successful birth")
				}
				return
			}
			if err != nil {
				t.Fatal(err, f.methods)
			}
			entries := proof.Creations()
			want := scenario == "self-in-reverted-child" || scenario == "beneficiary-only"
			if len(entries) != 1 || entries[0].Survives != want {
				t.Fatal("wrong ordinary survival", entries)
			}
			codeQueries := 0
			for _, method := range f.methods {
				if method == "eth_getCode" {
					codeQueries++
				}
			}
			if want && codeQueries != 1 || !want && codeQueries != 0 {
				t.Fatal("excluded candidate code lookup", f.methods)
			}
		})
	}
}
