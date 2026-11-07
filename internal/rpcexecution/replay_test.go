package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestCountedNoncePOSTDoesNotReplayOnReusedTLSConnection(t *testing.T) {
	for _, closeAfterBody := range []bool{false, true} {
		name := "normal-response"
		if closeAfterBody {
			name = "response-lost-after-complete-body"
		}
		t.Run(name, func(t *testing.T) {
			from := common.Address{}
			destination := crypto.CreateAddress(from, 9)
			n := baseNode()
			n.trace = map[string]any{"type": "CREATE", "from": from.Hex(), "to": destination.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x10000", "gasUsed": "0x1", "output": "0x6002"}
			n.pre = map[string]any{from.Hex(): map[string]any{"nonce": 9}, destination.Hex(): map[string]any{}}
			var noncePOSTs, scopeCalls atomic.Int64
			var closed atomic.Bool
			var mu sync.Mutex
			headerPeer, noncePeer := "", ""
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
				if err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var request struct {
					ID     json.RawMessage
					Method string
				}
				if json.Unmarshal(raw, &request) != nil {
					w.WriteHeader(400)
					return
				}
				if r.Header.Get("Idempotency-Key") != "unchanged-test-credential" {
					t.Error("credential bytes changed")
				}
				if request.Method == "eth_getBlockByNumber" {
					mu.Lock()
					headerPeer = r.RemoteAddr
					mu.Unlock()
				}
				if request.Method == "eth_getTransactionCount" {
					mu.Lock()
					noncePeer = r.RemoteAddr
					mu.Unlock()
					count := noncePOSTs.Add(1)
					if closeAfterBody && count == 1 {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						closed.Store(true)
						conn.Close() // Body reached peer; the outcome is uncertain.
						return
					}
					json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": "0x9"})
					return
				}
				n.ServeHTTP(w, r)
			}))
			defer server.Close()
			binding := testBinding(server.URL)
			binding.Profile, binding.AllowUnauthenticated = SimulationCallProfileID, false
			binding.Credentials = map[string]Credential{"BOUND": {Header: "Idempotency-Key", Value: "unchanged-test-credential"}}
			limits := DefaultLimits()
			limits.MaxAnchoredCodeLookups = 1
			client, err := NewClient(server.Client().Transport, binding, limits)
			if err != nil {
				t.Fatal(err)
			}
			client, _ = client.WithCredential("BOUND")
			call, _ := NormalizeSimulationCall([]byte(`{"input":"0x6001"}`))
			block, _ := ParseBlockSelector(nil)
			execution, err := client.AcquireSimulationCall(t.Context(), call, block, func(address common.Address) bool { scopeCalls.Add(1); return address == destination })
			mu.Lock()
			reused := headerPeer != "" && headerPeer == noncePeer
			mu.Unlock()
			if !reused || noncePOSTs.Load() != 1 {
				t.Fatal("counted nonce POST was repeated or fixture did not reuse TLS connection", noncePOSTs.Load(), reused)
			}
			if closeAfterBody {
				if !closed.Load() || err == nil || execution != nil || scopeCalls.Load() != 0 {
					t.Fatal("uncertain nonce RPC was replayed/continued", err, scopeCalls.Load())
				}
			} else if err != nil || execution == nil || scopeCalls.Load() != 1 {
				t.Fatal("normal credential-bound request stopped working", err, scopeCalls.Load())
			}
		})
	}
}
