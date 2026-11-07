package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
)

func TestCaptureProbeUsesSameSelectedClientAndBoundedHeaderOnlyWire(t *testing.T) {
	for _, scenario := range []string{"pending", "mined", "syncing", "known-lag", "wrong-genesis", "anchor-change", "oversized-header", "unsupported-header", "wrong-receipt", "receipt-quantity", "other-client", "incomplete-header"} {
		t.Run(scenario, func(t *testing.T) {
			tx := lifecycleCreation(t)
			destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
			n := baseNode()
			n.trace = map[string]any{"type": "CREATE", "from": tx.Signer().Hex(), "to": destination.Hex(), "input": "0x3659cfe6", "value": "0x7", "gas": "0x186a0", "gasUsed": "0x1", "output": "0x6001"}
			n.pre = map[string]any{destination.Hex(): map[string]any{}, tx.Signer().Hex(): map[string]any{"nonce": tx.Nonce()}}
			genesisHeader := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 9, BaseFee: big.NewInt(1)}
			anchorHeader := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 10, BaseFee: big.NewInt(1), ParentHash: genesisHeader.Hash()}
			genesis := genesisHeader.Hash()
			var mu sync.Mutex
			var methods []string
			active := false
			anchorReads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var q struct {
					ID     json.RawMessage
					Method string
					Params []json.RawMessage
				}
				if json.Unmarshal(raw, &q) != nil {
					t.Error("bad request")
					return
				}
				mu.Lock()
				probing := active
				if probing {
					methods = append(methods, q.Method)
				}
				mu.Unlock()
				if !probing {
					if q.Method == "eth_getBlockByNumber" || q.Method == "eth_getBlockByHash" {
						json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": anchorHeader})
						return
					}
					n.ServeHTTP(w, r)
					return
				}
				var result any
				switch q.Method {
				case "eth_chainId":
					result = "0x1"
				case "eth_syncing":
					result = false
					if scenario == "syncing" {
						result = map[string]any{"currentBlock": "0x1"}
					}
				case "eth_getHeaderByNumber":
					if scenario == "unsupported-header" {
						json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "not supported"}})
						return
					}
					var selector string
					json.Unmarshal(q.Params[0], &selector)
					h := types.CopyHeader(anchorHeader)
					if selector == "0x0" {
						h = types.CopyHeader(genesisHeader)
						if scenario == "wrong-genesis" {
							h.Extra = []byte("different-genesis")
						}
					}
					if selector == "0x1" {
						mu.Lock()
						anchorReads++
						change := anchorReads == 2
						mu.Unlock()
						if scenario == "anchor-change" && change {
							h.Extra = []byte("different-anchor")
						}
					}
					encoded, _ := json.Marshal(h)
					var fields map[string]any
					_ = json.Unmarshal(encoded, &fields)
					if scenario == "oversized-header" {
						fields["padding"] = strings.Repeat("x", 17<<10)
					}
					if scenario == "incomplete-header" {
						fields = map[string]any{"hash": h.Hash().Hex(), "number": fields["number"], "parentHash": h.ParentHash.Hex(), "timestamp": fields["timestamp"]}
					}
					result = fields
				case "eth_getTransactionReceipt":
					if scenario == "mined" || scenario == "wrong-receipt" || scenario == "receipt-quantity" {
						hash := tx.Hash().Hex()
						height := "0x2"
						if scenario == "wrong-receipt" {
							hash = testHash
						}
						if scenario == "receipt-quantity" {
							height = "0x" + strings.Repeat("f", 10000)
						}
						result = map[string]any{"transactionHash": hash, "blockHash": genesis.Hex(), "blockNumber": height, "transactionIndex": "0x0", "status": "0x1", "to": nil, "contractAddress": destination.Hex()}
					}
				default:
					t.Error("unexpected capture method", q.Method)
					w.WriteHeader(400)
					return
				}
				json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
			}))
			defer server.Close()
			c := selectedLifecycleClient(t, server.Client().Transport, server.URL, LifecycleSignedProfileID)
			execution, err := c.AcquireLifecycleSigned(t.Context(), tx)
			if err != nil {
				t.Fatal("acquisition", err)
			}
			network := creationfacts.Network{Key: creationfacts.Digest{1}, Environment: "test", ChainID: "1", Genesis: genesis, Deployment: "test"}
			cp := creationfacts.Checkpoint{Network: network.Key, State: creationfacts.State{Generation: testOrg}, ObserverEpoch: testOrg, CaptureEpoch: testOrg, SourceSet: creationfacts.Digest{2}, Reference: creationfacts.Digest{3}, HighWater: creationfacts.Header{Number: 1, Hash: anchorHeader.Hash(), Parent: genesis, Timestamp: 10}, HeaderVersion: 1, LeaseFence: 1, RemainingTTL: time.Second}
			if scenario == "known-lag" {
				cp.HighWater.Number = 2
			}
			if scenario == "other-client" {
				c, _ = c.WithCredential("")
			}
			mu.Lock()
			active = true
			mu.Unlock()
			evidence, err := c.ProbeCreationCapture(t.Context(), tx, execution, cp, network)
			want := scenario == "pending" || scenario == "mined"
			if (err == nil) != want || (err != nil && evidence != nil) {
				t.Fatal("partial or wrong capture", evidence, err)
			}
			mu.Lock()
			seen := slices.Clone(methods)
			mu.Unlock()
			if len(seen) > 8 || slices.Contains(seen, "eth_getBlockByNumber") || slices.Contains(seen, "eth_getTransactionByHash") {
				t.Fatal("wrong wire/budget/pool-exclusion", seen)
			}
			if scenario == "other-client" && len(seen) != 0 {
				t.Fatal("foreign client did node work")
			}
			if want && (evidence.KnownMined() != (scenario == "mined") || evidence.RequireMatches(tx, execution) != nil) {
				t.Fatal("unbound or wrong result")
			}
			if scenario == "pending" {
				// This separate legacy call must retain its original null-rejecting
				// behavior; only the new capture receipt path permits null result.
				if _, err := c.rpcBounded(t.Context(), "eth_getTransactionReceipt", []any{tx.Hash().Hex()}, 2<<20); err == nil {
					t.Fatal("new receipt path broadened legacy RPC null handling")
				}
			}
		})
	}
}
