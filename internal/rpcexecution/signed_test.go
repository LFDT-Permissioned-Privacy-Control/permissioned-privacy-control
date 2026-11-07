package rpcexecution

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/transactioninput"
)

func signedVector(t *testing.T, kind uint8) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	to := common.HexToAddress(testTarget)
	list := types.AccessList{{Address: to, StorageKeys: []common.Hash{common.HexToHash("0xabc")}}}
	var body types.TxData
	switch kind {
	case 0:
		body = &types.LegacyTx{Nonce: 9, To: &to, Gas: 100000, GasPrice: big.NewInt(31), Value: big.NewInt(7), Data: []byte{1, 2}}
	case 1:
		body = &types.AccessListTx{ChainID: big.NewInt(1), Nonce: 9, To: &to, Gas: 100000, GasPrice: big.NewInt(31), Value: big.NewInt(7), Data: []byte{1, 2}, AccessList: list}
	case 2:
		body = &types.DynamicFeeTx{ChainID: big.NewInt(1), Nonce: 9, To: &to, Gas: 100000, GasFeeCap: big.NewInt(31), GasTipCap: big.NewInt(2), Value: big.NewInt(7), Data: []byte{1, 2}, AccessList: list}
	}
	tx, err := types.SignTx(types.NewTx(body), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSignedAcquisitionPreservesEnvelopeAndOnlyOverridesNonce(t *testing.T) {
	for _, kind := range []uint8{0, 1, 2} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			tx := signedVector(t, kind)
			methods := []string{}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Key") != "selected" {
					t.Error("credential not bound")
				}
				var q struct {
					ID     json.RawMessage
					Method string
					Params []json.RawMessage
				}
				json.NewDecoder(r.Body).Decode(&q)
				methods = append(methods, q.Method)
				var result any
				switch q.Method {
				case "eth_chainId":
					result = "0x1"
				case "eth_getBlockByNumber":
					if string(q.Params[0]) != `"latest"` {
						t.Error("default block changed")
					}
					result = map[string]any{"hash": testHash, "number": "0x1", "timestamp": "0xa"}
				case "debug_traceCall":
					var call, config map[string]any
					json.Unmarshal(q.Params[0], &call)
					json.Unmarshal(q.Params[2], &config)
					for field, want := range map[string]string{"from": tx.Signer().Hex(), "to": common.HexToAddress(testTarget).Hex(), "input": "0x0102", "value": "0x7", "gas": "0x186a0", "nonce": "0x9", "chainId": "0x1", "type": fmt.Sprintf("0x%x", kind)} {
						if call[field] != want {
							t.Errorf("%s=%v want%s", field, call[field], want)
						}
					}
					if kind < 2 {
						if call["gasPrice"] != "0x1f" || call["maxFeePerGas"] != nil {
							t.Error("legacy fee changed")
						}
					} else if call["gasPrice"] != nil || call["maxFeePerGas"] != "0x1f" || call["maxPriorityFeePerGas"] != "0x2" {
						t.Error("dynamic fee changed")
					}
					if kind == 0 {
						if call["accessList"] != nil {
							t.Error("legacy access list invented")
						}
					} else {
						want := []any{map[string]any{"address": common.HexToAddress(testTarget).Hex(), "storageKeys": []any{common.HexToHash("0xabc").Hex()}}}
						if !reflect.DeepEqual(call["accessList"], want) {
							t.Error("access list changed")
						}
					}
					if string(q.Params[1]) != `"`+testHash+`"` {
						t.Error("trace not anchored")
					}
					want := map[string]any{"tracer": "muxTracer", "stateOverrides": map[string]any{tx.Signer().Hex(): map[string]any{"nonce": "0x9"}}, "tracerConfig": map[string]any{"callTracer": map[string]any{"onlyTopCall": false, "withLog": true}, "prestateTracer": map[string]any{"diffMode": false, "disableCode": false, "disableStorage": true, "includeEmpty": true}}}
					if !reflect.DeepEqual(config, want) {
						t.Error("unexpected tracing/default override", config)
					}
					root := rootTrace()
					root["from"], root["input"], root["value"] = tx.Signer().Hex(), "0x0102", "0x7"
					result = map[string]any{"callTracer": root, "prestateTracer": map[string]any{testTarget: map[string]any{"code": "0x6000"}}}
				default:
					t.Error("unexpected node call", q.Method)
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
			}))
			defer s.Close()
			binding := testBinding(s.URL)
			binding.Profile = SignedCallProfileID
			binding.Credentials = map[string]Credential{"key": {Header: "X-Key", Value: "selected"}}
			client, err := NewClient(s.Client().Transport, binding, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			client, _ = client.WithCredential("key")
			e, err := client.AcquireSigned(t.Context(), tx)
			if err != nil {
				t.Fatal(err)
			}
			signer, ok := e.VerifiedSigner()
			hash, hashOK := e.TransactionHash()
			if !e.Signed() || !ok || !hashOK || signer != tx.Signer() || hash != tx.Hash() || e.Anchor().Profile != SignedCallProfileID {
				t.Fatal("signed provenance lost")
			}
			if !reflect.DeepEqual(methods, []string{"eth_chainId", "eth_getBlockByNumber", "debug_traceCall"}) {
				t.Fatal("extra acquisition", methods)
			}
			block, _ := ParseBlockSelector(nil)
			if _, err := client.AcquireCall(t.Context(), testCall(t), block); err == nil {
				t.Fatal("signed profile accepted simulation")
			}
		})
	}
}

func TestBroadcastValidatesExactHashAndNeverRetries(t *testing.T) {
	tx := signedVector(t, 1)
	for _, outcome := range []string{"success", "wronghash", "error", "id", "large", "redirect"} {
		t.Run(outcome, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var q struct {
					ID     json.RawMessage
					Method string
					Params []string
				}
				if json.NewDecoder(r.Body).Decode(&q) != nil || q.Method != "eth_sendRawTransaction" || len(q.Params) != 1 || q.Params[0] != tx.RawHex() {
					t.Error("broadcast modified transaction")
				}
				id := q.ID
				if outcome == "id" {
					id = json.RawMessage("999")
				}
				if outcome == "redirect" {
					w.Header().Set("Location", "http://127.0.0.1:1")
					w.WriteHeader(307)
					return
				}
				if outcome == "error" {
					fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":"secret already known"}}`, id)
					return
				}
				hash := tx.Hash().Hex()
				if outcome == "wronghash" {
					hash = common.Hash{}.Hex()
				}
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":%q}`, id, hash)
				if outcome == "large" {
					fmt.Fprint(w, strings.Repeat(" ", MaxBroadcastResponseBytes))
				}
			}))
			defer s.Close()
			b := testBinding(s.URL)
			b.Profile = SignedCallProfileID
			c, err := NewClient(s.Client().Transport, b, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			c, _ = c.WithCredential("")
			hash, err := c.BroadcastRaw(t.Context(), tx)
			if (outcome == "success") != (err == nil) {
				t.Fatal("incorrect broadcast result", outcome, err)
			}
			if err == nil && hash != tx.Hash() {
				t.Fatal("unqualified success")
			}
			if calls != 1 {
				t.Fatal("automatic retry", calls)
			}
		})
	}
}
