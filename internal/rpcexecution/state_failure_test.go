package rpcexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func stateClient(t *testing.T, source StateSource, transport Transport, limits StateLimits) *StateClient {
	t.Helper()
	c, err := NewStateClient(transport, source, Credential{source.CredentialHeader, "metadata-test-only"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestStateLowerLimitsAndCanceledParentBeforeIO(t *testing.T) {
	_, source, _ := metadataFixture(t)
	panicWire := headerLaneTransportFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid or canceled request reached node")
		return nil, nil
	})
	q := stateQuery(t, StateProof, `["`+stateTestAddress+`",["0x1","0x2"]]`)
	for _, edit := range []func(*StateLimits){
		func(l *StateLimits) { l.MaxStorageKeys = 1 },
		func(l *StateLimits) { l.MaxParamsBytes = 8 },
	} {
		limits := DefaultStateLimits()
		edit(&limits)
		if o, err := stateClient(t, source, panicWire, limits).Query(t.Context(), q); err == nil || o != nil {
			t.Fatal("lower selected input limit ignored")
		}
	}
	c := stateClient(t, source, panicWire, DefaultStateLimits())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if o, err := c.Query(ctx, q); err == nil || o != nil {
		t.Fatal("canceled parent accepted")
	}
	if o, err := c.Query(t.Context(), StateQuery{}); err == nil || o != nil {
		t.Fatal("zero query accepted")
	}
	for _, edit := range []func(*StateLimits){
		func(l *StateLimits) { l.Timeout = 0 },
		func(l *StateLimits) { l.MaxParamsBytes++ },
		func(l *StateLimits) { l.MaxResultBytes = -1 },
		func(l *StateLimits) { l.MaxCodeBytes++ },
		func(l *StateLimits) { l.MaxStorageKeys = 0 },
		func(l *StateLimits) { l.MaxProofNodesPerProof++ },
		func(l *StateLimits) { l.MaxTotalProofNodes++ },
		func(l *StateLimits) { l.MaxProofNodeBytes++ },
		func(l *StateLimits) { l.MaxTotalProofBytes++ },
	} {
		l := DefaultStateLimits()
		edit(&l)
		if o, err := NewStateClient(panicWire, source, Credential{source.CredentialHeader, "metadata-test-only"}, l); err == nil || o != nil {
			t.Fatal("invalid startup limit accepted", l)
		}
	}
}

func TestStateResultBindingAndMalformedProofs(t *testing.T) {
	q := stateQuery(t, StateProof, `["`+stateTestAddress+`",["0x1","0x2"]]`)
	for _, name := range []string{"address", "missing", "extra", "reordered", "extra-key", "missing-key", "nonce-overflow", "bad-hash", "null-storage", "null-row-proof", "null-value", "unknown-row"} {
		t.Run(name, func(t *testing.T) {
			fixture := stateProofFixture(stateTestAddress, q.StorageKeys())
			rows := fixture["storageProof"].([]any)
			switch name {
			case "address":
				fixture["address"] = "0x2222222222222222222222222222222222222222"
			case "missing":
				delete(fixture, "codeHash")
			case "extra":
				fixture["other"] = true
			case "reordered":
				rows[0], rows[1] = rows[1], rows[0]
			case "extra-key":
				fixture["storageProof"] = append(rows, rows[0])
			case "missing-key":
				fixture["storageProof"] = rows[:1]
			case "nonce-overflow":
				fixture["nonce"] = "0x10000000000000000"
			case "bad-hash":
				fixture["codeHash"] = "0x1"
			case "null-storage":
				fixture["storageProof"] = nil
			case "null-row-proof":
				rows[0].(map[string]any)["proof"] = nil
			case "null-value":
				rows[0].(map[string]any)["value"] = nil
			case "unknown-row":
				rows[0].(map[string]any)["other"] = "0x1"
			}
			raw, _ := json.Marshal(fixture)
			if result, err := stateResult(q, raw, DefaultStateLimits()); err == nil || result != nil {
				t.Fatal("invalid proof produced output")
			}
		})
	}
	for _, tc := range []struct {
		method StateMethod
		params string
		raw    string
	}{
		{StateBalance, `["` + stateTestAddress + `"]`, `"0x01"`},
		{StateBalance, `["` + stateTestAddress + `"]`, `"0x1` + strings.Repeat("0", 64) + `"`},
		{StateNonce, `["` + stateTestAddress + `"]`, `"0x10000000000000000"`},
		{StateCode, `["` + stateTestAddress + `"]`, `"0x0"`},
		{StateStorage, `["` + stateTestAddress + `","0"]`, `"0x01"`},
		{StateStorage, `["` + stateTestAddress + `","0"]`, `null`},
	} {
		if result, err := stateResult(stateQuery(t, tc.method, tc.params), []byte(tc.raw), DefaultStateLimits()); err == nil || result != nil {
			t.Fatal("malformed scalar state output accepted", tc)
		}
	}
}

func TestStateCodeAndProofBudgets(t *testing.T) {
	q := stateQuery(t, StateCode, `["`+stateTestAddress+`"]`)
	for _, count := range []int{1 << 20, (1 << 20) + 1} {
		raw, _ := json.Marshal("0x" + strings.Repeat("ab", count))
		_, err := stateResult(q, raw, DefaultStateLimits())
		if (err != nil) != (count > 1<<20) {
			t.Fatal("code byte cap", count, err)
		}
	}
	keys := make([]string, 1024)
	for i := range keys {
		keys[i] = fmt.Sprintf("0x%x", i)
	}
	rawParams, _ := json.Marshal([]any{stateTestAddress, keys})
	proof := stateQuery(t, StateProof, string(rawParams))
	fixture := stateProofFixture(stateTestAddress, proof.StorageKeys())
	raw, _ := json.Marshal(fixture)
	if _, err := stateResult(proof, raw, DefaultStateLimits()); err != nil {
		t.Fatal("1024 actual requested keys did not fit normal shape", err)
	}
	keys = append(keys, "0x0")
	rawParams, _ = json.Marshal([]any{stateTestAddress, keys})
	if _, err := ParseStateQuery(StateProof, rawParams, DefaultStateLimits()); err == nil {
		t.Fatal("1025 keys accepted")
	}
	one := stateQuery(t, StateProof, `["`+stateTestAddress+`",["0x1"]]`)
	for _, tc := range []struct {
		name   string
		edit   func(*StateLimits)
		proofs []string
		valid  bool
	}{
		{"node-8bytes", func(l *StateLimits) { l.MaxProofNodeBytes = 8 }, []string{"0x" + strings.Repeat("ab", 8)}, true},
		{"node-9bytes", func(l *StateLimits) { l.MaxProofNodeBytes = 8 }, []string{"0x" + strings.Repeat("ab", 9)}, false},
		{"total-16bytes", func(l *StateLimits) { l.MaxTotalProofBytes = 16 }, []string{"0x" + strings.Repeat("ab", 8), "0x" + strings.Repeat("ab", 8)}, true},
		{"total-17bytes", func(l *StateLimits) { l.MaxTotalProofBytes = 16 }, []string{"0x" + strings.Repeat("ab", 8), "0x" + strings.Repeat("ab", 9)}, false},
		{"one-node", func(l *StateLimits) { l.MaxTotalProofNodes = 1 }, []string{"0x01"}, true},
		{"two-nodes", func(l *StateLimits) { l.MaxTotalProofNodes = 1 }, []string{"0x01", "0x02"}, false},
		{"per-proof", func(l *StateLimits) { l.MaxProofNodesPerProof = 1 }, []string{"0x01", "0x02"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := DefaultStateLimits()
			tc.edit(&l)
			fixture := stateProofFixture(stateTestAddress, one.StorageKeys())
			fixture["storageProof"].([]any)[0].(map[string]any)["proof"] = tc.proofs
			raw, _ := json.Marshal(fixture)
			result, err := stateResult(one, raw, l)
			if (err == nil) != tc.valid || err != nil && result != nil {
				t.Fatal("proof budget mismatch", err)
			}
		})
	}
}

func TestStateActualNetworkFailureAndNoReplay(t *testing.T) {
	for _, scenario := range []string{"chain", "genesis", "redirect", "lost", "truncated", "error", "wrong-address"} {
		t.Run(scenario, func(t *testing.T) {
			n, source, transport := metadataFixture(t)
			q := stateQuery(t, StateProof, `["`+stateTestAddress+`",[]]`)
			n.mu.Lock()
			n.results[StateProof.String()] = stateProofFixture(stateTestAddress, nil)
			want := 3
			switch scenario {
			case "chain":
				n.chain, want = "0x2", 1
			case "genesis":
				source.Network.GenesisHash, want = "0x"+strings.Repeat("12", 32), 2
			case "wrong-address":
				n.results[StateProof.String()] = stateProofFixture("0x2222222222222222222222222222222222222222", nil)
			default:
				n.change = func(w http.ResponseWriter, _ *http.Request, request metadataTestRPC) bool {
					if request.Method != StateProof.String() {
						return false
					}
					switch scenario {
					case "redirect":
						w.Header().Set("Location", source.URL+"/other")
						w.WriteHeader(http.StatusTemporaryRedirect)
					case "lost":
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
						} else {
							_ = conn.Close()
						}
					case "truncated":
						_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`)
					case "error":
						_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32000, "message": "PRIVATE-NODE-STATE", "data": "PRIVATE-NODE-STATE"}})
					}
					return true
				}
			}
			n.mu.Unlock()
			observation, err := stateClient(t, source, transport, DefaultStateLimits()).Query(t.Context(), q)
			if err == nil || observation != nil || strings.Contains(err.Error(), "PRIVATE-NODE-STATE") {
				t.Fatal("bad node result escaped", err)
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			if len(n.calls) != want {
				t.Fatal("replay or continuation after failure", len(n.calls), want)
			}
			if scenario == "lost" && n.peers[StateProof.String()] != n.peers["eth_getHeaderByNumber"] {
				t.Fatal("lost-response control did not reuse a real TLS connection")
			}
		})
	}
}

func TestStateActualBodyDeadline(t *testing.T) {
	n, source, transport := metadataFixture(t)
	n.mu.Lock()
	n.change = func(w http.ResponseWriter, r *http.Request, request metadataTestRPC) bool {
		if request.Method != StateBalance.String() {
			return false
		}
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":`)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		return true
	}
	n.mu.Unlock()
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := stateClient(t, source, transport, DefaultStateLimits()).Query(ctx, stateQuery(t, StateBalance, `["`+stateTestAddress+`"]`))
	if err == nil || result != nil || time.Since(start) > time.Second {
		t.Fatal("parent deadline did not reach actual result body", err)
	}
}
