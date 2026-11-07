package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSimulationNormalizationOnlyAbsentOrNullMeansCreation(t *testing.T) {
	for _, raw := range []string{`{"input":"0x6001"}`, `{"to":null,"input":"0x6001"}`} {
		call, err := NormalizeSimulationCall([]byte(raw))
		if err != nil || !call.Creation() || call.signedInput || call.FromSupplied() {
			t.Fatal("normalizer created signer or lost creation", err)
		}
		if _, err := NormalizeCall([]byte(raw)); err == nil {
			t.Fatal("old normalizer accepted creation")
		}
		_, present := call.Object()["to"]
		if present != strings.Contains(raw, `"to"`) {
			t.Fatal("absent/null to shape was rewritten")
		}
	}
	for _, raw := range []string{`{"to":"0x0000000000000000000000000000000000000000"}`, `{"to":""}`, `{"to":"0x"}`, `{"input":"0x00","data":"0x01"}`, `{"gasPrice":"0x1","maxFeePerGas":"0x2"}`, `{"stateOverrides":{}}`, `{"nonce":"0x10000000000000000"}`} {
		if _, err := NormalizeSimulationCall([]byte(raw)); err == nil {
			t.Fatal("new mode weakened ordinary normalization", raw)
		}
	}
}

func TestSimulationNonceStallUsesWholeAcquisitionDeadline(t *testing.T) {
	n := baseNode()
	var scopeCalls, traces atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var q struct{ Method string }
		json.Unmarshal(raw, &q)
		if q.Method == "eth_getTransactionCount" {
			<-r.Context().Done()
			return
		}
		if q.Method == "debug_traceCall" {
			traces.Add(1)
		}
		n.ServeHTTP(w, r)
	}))
	defer server.Close()
	binding := testBinding(server.URL)
	binding.Profile = SimulationCallProfileID
	limits := DefaultLimits()
	limits.AcquisitionTimeout = 50 * time.Millisecond
	client, err := NewClient(server.Client().Transport, binding, limits)
	if err != nil {
		t.Fatal(err)
	}
	client, _ = client.WithCredential("")
	call, _ := NormalizeSimulationCall([]byte(`{"input":"0x6001"}`))
	block, _ := ParseBlockSelector(nil)
	execution, err := client.AcquireSimulationCall(t.Context(), call, block, func(common.Address) bool { scopeCalls.Add(1); return true })
	if err == nil || execution != nil || scopeCalls.Load() != 0 || traces.Load() != 0 {
		t.Fatal("nonce stall escaped whole deadline", err)
	}
}

func TestSimulationRootNonceCountsAtExact256SupplementBoundary(t *testing.T) {
	for _, missingAccounts := range []int{255, 256} {
		t.Run(big.NewInt(int64(missingAccounts)).String(), func(t *testing.T) {
			from := common.Address{}
			destination := crypto.CreateAddress(from, 9)
			n := baseNode()
			n.trace = map[string]any{"type": "CREATE", "from": from.Hex(), "to": destination.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x100000", "gasUsed": "0x1", "output": "0x6002"}
			n.pre = map[string]any{from.Hex(): map[string]any{"nonce": 9}, destination.Hex(): map[string]any{}}
			children := make([]any, missingAccounts)
			for i := range children {
				address := common.BigToAddress(big.NewInt(int64(i + 256)))
				children[i] = map[string]any{"type": "CALL", "from": destination.Hex(), "to": address.Hex(), "input": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1", "output": "0x"}
			}
			n.trace["calls"] = children
			var supplements atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var q struct {
					ID     json.RawMessage
					Method string
				}
				json.Unmarshal(raw, &q)
				if q.Method == "eth_getCode" || q.Method == "eth_getTransactionCount" {
					supplements.Add(1)
				}
				if q.Method == "eth_getTransactionCount" {
					json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": "0x9"})
					return
				}
				n.ServeHTTP(w, r)
			}))
			defer server.Close()
			client := selectedLifecycleClient(t, server.Client().Transport, server.URL, SimulationCallProfileID)
			call, _ := NormalizeSimulationCall([]byte(`{"input":"0x6001"}`))
			block, _ := ParseBlockSelector(nil)
			execution, err := client.AcquireSimulationCall(t.Context(), call, block, func(a common.Address) bool { return a == destination })
			if (err == nil) != (missingAccounts == 255) || supplements.Load() != 256 || (err != nil && execution != nil) {
				t.Fatal("root lookup did not share exact256 supplement ceiling", missingAccounts, supplements.Load(), err)
			}
		})
	}
}

func TestSimulationOrdinaryCallHasNoRootNonceAndNeverAcceptsSignedInput(t *testing.T) {
	n := baseNode()
	server := httptest.NewServer(n)
	defer server.Close()
	client := selectedLifecycleClient(t, server.Client().Transport, server.URL, SimulationCallProfileID)
	block, _ := ParseBlockSelector(nil)
	execution, err := client.AcquireSimulationCall(t.Context(), testCall(t), block, func(common.Address) bool {
		t.Fatal("ordinary CALL invoked creation scope callback")
		return false
	})
	if err != nil || execution.Call().Creation() || execution.Signed() {
		t.Fatal("ordinary simulation changed", err)
	}
	n.mu.Lock()
	before := len(n.methods)
	methods := slices.Clone(n.methods)
	n.mu.Unlock()
	if slices.Contains(methods, "eth_getTransactionCount") {
		t.Fatal("ordinary CALL fetched root nonce", methods)
	}
	tx := lifecycleCreation(t)
	if _, err := client.AcquireSimulationCall(t.Context(), signedCall(tx), block, func(common.Address) bool { return true }); err == nil {
		t.Fatal("signed input became simulation")
	}
	creation, _ := NormalizeSimulationCall([]byte(`{"input":"0x6001"}`))
	life := selectedLifecycleClient(t, server.Client().Transport, server.URL, LifecycleCallProfileID)
	if _, err := life.AcquireLifecycleCall(t.Context(), creation, block); err == nil {
		t.Fatal("old lifecycle entry accepted new unsigned form")
	}
	if _, err := client.AcquireLifecycleCall(t.Context(), testCall(t), block); err == nil {
		t.Fatal("new binding was relabelled as old lifecycle")
	}
	n.mu.Lock()
	after := len(n.methods)
	n.mu.Unlock()
	if after != before {
		t.Fatal("scope rejection did node work")
	}
}

func TestSimulationRootUsesStateNonceScopeAndOneAcquisitionBudget(t *testing.T) {
	for _, scenario := range []string{"absent-request-nonce", "different-request-nonce", "null-to", "scope-denied", "nil-scope", "nonce-contradiction", "missing-sender", "shared-lookup-limit", "overflow", "oversized", "lower-response-limit", "wrong-root", "cancel-after-nonce"} {
		t.Run(scenario, func(t *testing.T) {
			from := common.Address{}
			destination := crypto.CreateAddress(from, 9)
			object := map[string]any{"input": "0x6001"}
			if scenario == "different-request-nonce" {
				object["nonce"] = "0x7b"
			}
			if scenario == "null-to" {
				object["to"] = nil
			}
			raw, _ := json.Marshal(object)
			call, err := NormalizeSimulationCall(raw)
			if err != nil {
				t.Fatal(err)
			}
			n := baseNode()
			n.trace = map[string]any{"type": "CREATE", "from": from.Hex(), "to": destination.Hex(), "input": "0x6001", "value": "0x0", "gas": "0x10000", "gasUsed": "0x123", "output": "0x6002"}
			n.pre = map[string]any{destination.Hex(): map[string]any{}, from.Hex(): map[string]any{"nonce": 9}}
			if scenario == "nonce-contradiction" {
				n.pre[from.Hex()] = map[string]any{} // Present omission means zero.
			}
			if scenario == "missing-sender" || scenario == "shared-lookup-limit" {
				delete(n.pre, from.Hex())
			}
			if scenario == "wrong-root" {
				n.trace["to"] = testTarget
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var methods []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var request struct {
					ID     json.RawMessage
					Method string
					Params []json.RawMessage
				}
				json.Unmarshal(raw, &request)
				methods = append(methods, request.Method)
				if request.Method == "eth_getTransactionCount" {
					var address string
					var selector map[string]any
					json.Unmarshal(request.Params[0], &address)
					json.Unmarshal(request.Params[1], &selector)
					if address != from.Hex() || !reflect.DeepEqual(selector, map[string]any{"blockHash": testHash, "requireCanonical": false}) {
						t.Error("nonce query changed anchor/sender", address, selector)
					}
					value := "0x9"
					if scenario == "overflow" {
						value = "0x10000000000000000"
					}
					if scenario == "oversized" {
						value = "0x" + strings.Repeat("1", 4096)
					}
					if scenario == "lower-response-limit" {
						value = "0x" + strings.Repeat("1", 300)
					}
					json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": value})
					return
				}
				if request.Method == "debug_traceCall" {
					var wire, config map[string]any
					json.Unmarshal(request.Params[0], &wire)
					json.Unmarshal(request.Params[2], &config)
					if _, present := config["stateOverrides"]; present || wire["nonce"] != object["nonce"] || wire["to"] != nil {
						t.Error("unsigned creation got nonce override or rewritten request", wire, config)
					}
				}
				n.ServeHTTP(w, r)
			}))
			defer server.Close()
			binding := testBinding(server.URL)
			binding.Profile = SimulationCallProfileID
			limits := DefaultLimits()
			if scenario == "shared-lookup-limit" {
				limits.MaxAnchoredCodeLookups = 1
			}
			if scenario == "lower-response-limit" {
				limits.MaxMuxBytes = 256
			}
			client, err := NewClient(server.Client().Transport, binding, limits)
			if err != nil {
				t.Fatal(err)
			}
			client, _ = client.WithCredential("")
			block, _ := ParseBlockSelector(nil)
			calls := 0
			scope := RootCreationScopeCheck(func(address common.Address) bool {
				calls++
				if address != destination {
					t.Error("request nonce or trace selected address", address)
				}
				if scenario == "cancel-after-nonce" {
					cancel()
				}
				return scenario != "scope-denied"
			})
			if scenario == "nil-scope" {
				scope = nil
			}
			execution, err := client.AcquireSimulationCall(ctx, call, block, scope)
			allowed := slices.Contains([]string{"absent-request-nonce", "different-request-nonce", "null-to", "missing-sender"}, scenario)
			if (err == nil) != allowed || (err != nil && execution != nil) {
				t.Fatal("partial/incorrectly accepted acquisition", execution, err)
			}
			if scenario == "nil-scope" && len(methods) != 0 {
				t.Fatal("nil trusted scope did node work")
			}
			if slices.Contains([]string{"scope-denied", "overflow", "oversized", "lower-response-limit", "cancel-after-nonce"}, scenario) && slices.Contains(methods, "debug_traceCall") {
				t.Fatal("unqualified destination reached execution", methods)
			}
			if scenario == "lower-response-limit" {
				var category *Error
				if !errors.As(err, &category) || category.Code != EvidenceLimit || !slices.Contains(methods, "eth_getTransactionCount") {
					t.Fatal("root nonce failed to honor lower configured response ceiling", err, methods)
				}
			}
			if scenario == "scope-denied" {
				var category *Error
				if !errors.As(err, &category) || category.Code != RootScopeDenied || calls != 1 {
					t.Fatal("scope denial lost safe typed category/one callback", err, calls)
				}
			}
			if allowed {
				creation, known := execution.CreationContext(0)
				if !known || creation.Address.Value != destination || execution.Signed() || calls != 1 || execution.Anchor().Profile != SimulationCallProfileID {
					t.Fatal("independent root/unsigned profile lost", creation, calls)
				}
				if _, signer := execution.VerifiedSigner(); signer {
					t.Fatal("unsigned simulation invented a cryptographic signer")
				}
				if scenario == "missing-sender" {
					sender, known := execution.RuntimeCodeAt(0, from)
					nonce, present := sender.FreshnessNonce()
					if !known || !present || nonce != 9 || strings.Count(strings.Join(methods, ","), "eth_getTransactionCount") != 1 {
						t.Fatal("owned initial nonce was replaced/requeried", nonce, methods)
					}
				}
			}
			if scenario == "shared-lookup-limit" && slices.Contains(methods, "eth_getCode") {
				t.Fatal("initial root nonce was omitted from total lookup budget")
			}
			before := len(methods)
			old := testBinding(server.URL)
			legacy, _ := NewClient(server.Client().Transport, old, DefaultLimits())
			legacy, _ = legacy.WithCredential("")
			if _, err := legacy.AcquireCall(t.Context(), call, block); err == nil || len(methods) != before {
				t.Fatal("old call entry point accepted creation or touched node")
			}
		})
	}
}
