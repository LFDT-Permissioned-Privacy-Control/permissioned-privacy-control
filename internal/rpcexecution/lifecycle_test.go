package rpcexecution

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/transactioninput"
)

func lifecycleCreation(t *testing.T) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	unsigned := types.NewContractCreation(9, big.NewInt(7), 100000, big.NewInt(31), common.FromHex("0x3659cfe6"))
	tx, err := types.SignTx(unsigned, types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	verified, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func TestLifecycleMissingNonceUsesBoundedSameHashQueriesAndSharedLimit(t *testing.T) {
	tx := lifecycleCreation(t)
	destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
	for _, scenario := range []string{"missing", "oversized-nonce", "combined-lookup-limit", "combined-code-limit"} {
		t.Run(scenario, func(t *testing.T) {
			n := baseNode()
			n.trace = map[string]any{"type": "CREATE", "from": tx.Signer().Hex(), "to": destination.Hex(), "input": "0x3659cfe6", "value": "0x7", "gas": "0x186a0", "gasUsed": "0x1", "output": "0x6001"}
			n.pre = map[string]any{tx.Signer().Hex(): map[string]any{"nonce": tx.Nonce()}}
			var methods []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(raw))
				var q struct {
					ID     json.RawMessage
					Method string
					Params []json.RawMessage
				}
				json.Unmarshal(raw, &q)
				methods = append(methods, q.Method)
				if q.Method == "eth_getTransactionCount" || q.Method == "eth_getCode" {
					var address string
					var selector map[string]any
					json.Unmarshal(q.Params[0], &address)
					json.Unmarshal(q.Params[1], &selector)
					if address != destination.Hex() || !reflect.DeepEqual(selector, map[string]any{"blockHash": testHash, "requireCanonical": false}) {
						t.Error("supplement changed destination or independent hash", address, selector)
					}
				}
				if q.Method == "eth_getTransactionCount" {
					value := "0x0"
					if scenario == "oversized-nonce" {
						value = "0x" + strings.Repeat("f", 4096)
					}
					json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": value})
					return
				}
				n.ServeHTTP(w, r)
			}))
			defer server.Close()
			binding := testBinding(server.URL)
			binding.Profile = LifecycleSignedProfileID
			limits := DefaultLimits()
			if scenario == "combined-lookup-limit" {
				limits.MaxAnchoredCodeLookups = 1
			}
			if scenario == "combined-code-limit" {
				limits.MaxTotalCodeBytes = 1
			}
			client, err := NewClient(server.Client().Transport, binding, limits)
			if err != nil {
				t.Fatal(err)
			}
			client, _ = client.WithCredential("")
			execution, err := client.AcquireLifecycleSigned(t.Context(), tx)
			if (err == nil) != (scenario == "missing") || (err != nil && execution != nil) {
				t.Fatal("partial/unsupported acquisition", execution, err)
			}
			if scenario == "missing" && !reflect.DeepEqual(methods, []string{"eth_chainId", "eth_getBlockByNumber", "debug_traceCall", "eth_getCode", "eth_getTransactionCount"}) {
				t.Fatal("missing full-prestate account was assumed zero", methods)
			}
			if scenario == "combined-lookup-limit" && slices.Contains(methods, "eth_getTransactionCount") {
				t.Fatal("code/count lookups did not share one cap", methods)
			}
		})
	}
}

func selectedLifecycleClient(t *testing.T, transport Transport, url, profile string) *Client {
	t.Helper()
	binding := testBinding(url)
	binding.Profile = profile
	c, err := NewClient(transport, binding, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.WithCredential("")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestLifecycleSignedRootCreationOmitsToAndRetainsSameExecution(t *testing.T) {
	tx := lifecycleCreation(t)
	destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
	n := baseNode()
	n.trace = map[string]any{"type": "CREATE", "from": tx.Signer().Hex(), "to": destination.Hex(), "input": "0x3659cfe6", "value": "0x7", "gas": "0x186a0", "gasUsed": "0x1", "output": "0x6001"}
	n.pre = map[string]any{destination.Hex(): map[string]any{}, tx.Signer().Hex(): map[string]any{"nonce": tx.Nonce()}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var q struct {
			Method string
			Params []json.RawMessage
		}
		json.Unmarshal(raw, &q)
		if q.Method == "debug_traceCall" {
			var call, config map[string]any
			json.Unmarshal(q.Params[0], &call)
			json.Unmarshal(q.Params[2], &config)
			if _, present := call["to"]; present || call["nonce"] != "0x9" || call["input"] != "0x3659cfe6" {
				t.Error("root creation became a zero-address CALL or lost signed inputs", call)
			}
			if !reflect.DeepEqual(config["stateOverrides"], map[string]any{tx.Signer().Hex(): map[string]any{"nonce": "0x9"}}) {
				t.Error("selected nonce override changed", config)
			}
		}
		n.ServeHTTP(w, r)
	}))
	defer server.Close()
	c := selectedLifecycleClient(t, server.Client().Transport, server.URL, LifecycleSignedProfileID)
	e, err := c.AcquireLifecycleSigned(t.Context(), tx)
	if err != nil {
		t.Fatal(err)
	}
	if !e.Signed() || e.Anchor().Profile != LifecycleSignedProfileID || e.QualificationWork() == 0 {
		t.Fatal("scope or complete precomputed work missing")
	}
	creation, ok := e.CreationContext(0)
	if !ok || creation.Address.Value != destination || creation.Kind != FreshConstructor {
		t.Fatal("independent root destination missing", creation)
	}
	code, _ := e.FrameCode(0)
	account, _ := e.RuntimeCodeAt(0, destination)
	if code.Origin() != ConstructorAttempt || !bytes.Equal(code.Bytes(), tx.Input()) || account.HasCode() || !e.timeline.survivors[0] {
		t.Fatal("constructor/entry runtime/final survival collapsed")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !reflect.DeepEqual(n.methods, []string{"eth_chainId", "eth_getBlockByNumber", "debug_traceCall"}) {
		t.Fatal("known zero prestate or initcode caused unnecessary supplemental queries", n.methods)
	}
}

func TestLifecycleRetainedGuardKeepsPhysicalProfileAndOriginalBytes(t *testing.T) {
	tx := lifecycleCreation(t)
	destination := crypto.CreateAddress(tx.Signer(), tx.Nonce())
	calls, _ := json.Marshal(map[string]any{"type": "CREATE", "from": tx.Signer().Hex(), "to": destination.Hex(), "input": "0x3659cfe6", "value": "0x7", "gas": "0x186a0", "gasUsed": "0x1", "output": "0x6001"})
	pre, _ := json.Marshal(map[string]any{destination.Hex(): map[string]any{}, tx.Signer().Hex(): map[string]any{"nonce": 9}})
	evidence := TrustedGuardEvidence{Profile: GuardRetainedProfileID, Calls: calls, Prestate: pre, ChainID: 1, TransactionHash: tx.Hash(), Fingerprint: common.HexToHash("0x1"), HashMode: 3, HeaderHash: common.HexToHash(testHash), HeaderTimestamp: 10, HeaderPresent: true}
	c := selectedLifecycleClient(t, http.DefaultTransport, "http://unused.test", LifecycleGuardProfileID)
	execution, err := c.QualifyTrustedGuardLifecycleEvidence(t.Context(), tx, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Anchor().Profile != LifecycleGuardProfileID || execution.HashMode() != 3 || !bytes.Contains(execution.RawEvidence(), calls) || !bytes.Contains(execution.RawEvidence(), pre) {
		t.Fatal("consumer relabel modified physical evidence")
	}
	if _, err := c.QualifyTrustedGuardEvidence(t.Context(), tx, evidence); err == nil {
		t.Fatal("old qualifier accepted new binding")
	}
	evidence.Profile = LifecycleGuardProfileID
	if _, err := c.QualifyTrustedGuardLifecycleEvidence(t.Context(), tx, evidence); err == nil {
		t.Fatal("new consumer ID was accepted as original physical format")
	}
}

func TestLifecycleCeilingsAndEntryPointsStayClosed(t *testing.T) {
	for _, profile := range []string{LifecycleCallProfileID, LifecycleSignedProfileID, LifecycleGuardProfileID} {
		b := testBinding("http://unused.test")
		b.Profile = profile
		l := DefaultLimits()
		l.MaxAnchoredCodeLookups++
		if _, err := NewClient(http.DefaultTransport, b, l); err == nil {
			t.Fatal("new profile accepted a raised fixed lookup ceiling")
		}
		c := selectedLifecycleClient(t, http.DefaultTransport, b.URL, profile)
		block, _ := ParseBlockSelector(nil)
		if _, err := c.AcquireCall(t.Context(), testCall(t), block); err == nil {
			t.Fatal("legacy call entry point accepted lifecycle binding")
		}
		if _, err := c.AcquireSigned(t.Context(), guardTransaction(t)); err == nil {
			t.Fatal("legacy signed entry point accepted lifecycle binding")
		}
	}
}
