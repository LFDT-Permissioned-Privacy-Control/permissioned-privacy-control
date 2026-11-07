package rpcexecution

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

type headerLaneTransportFunc func(*http.Request) (*http.Response, error)

func (f headerLaneTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type headerLaneRPC struct {
	ID     uint64            `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type headerLaneNode struct {
	mu            sync.Mutex
	calls         []headerLaneRPC
	genesis, tip  *types.Header
	chain         any
	syncing       any
	change        func(headerLaneRPC, any) any
	blockSync     bool
	expectedValue string
}

func headerLaneFixture(t *testing.T) (*headerLaneNode, creationfacts.Source, Transport) {
	t.Helper()
	genesis := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}
	tip := types.CopyHeader(genesis)
	tip.Number, tip.Time, tip.GasUsed, tip.ParentHash = big.NewInt(1), 12, 42, genesis.Hash()
	node := &headerLaneNode{genesis: genesis, tip: tip, chain: "0x1", syncing: false, expectedValue: "header-test-only"}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Idempotency-Key") != node.expectedValue {
			t.Error("owned method/credential was not preserved")
			w.WriteHeader(400)
			return
		}
		var req headerLaneRPC
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid RPC request")
			return
		}
		node.mu.Lock()
		node.calls = append(node.calls, req)
		node.mu.Unlock()
		var result any
		switch req.Method {
		case "eth_chainId":
			result = node.chain
		case "eth_syncing":
			if node.blockSync {
				<-r.Context().Done()
				return
			}
			result = node.syncing
		case "eth_getHeaderByNumber", "eth_getHeaderByHash":
			var selector string
			if len(req.Params) != 1 || json.Unmarshal(req.Params[0], &selector) != nil {
				t.Error("invalid closed header selector")
				return
			}
			result = node.tip
			if selector == "0x0" {
				result = node.genesis
			}
		default:
			t.Error("unexpected RPC method", req.Method)
			return
		}
		if node.change != nil {
			result = node.change(req, result)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			JSONRPC string `json:"jsonrpc"`
			ID      uint64 `json:"id"`
			Result  any    `json:"result"`
		}{"2.0", req.ID, result})
	}))
	t.Cleanup(server.Close)
	source := creationfacts.Source{
		Network: creationfacts.Network{Key: creationfacts.Hash("header-test-network", []byte("one")), Environment: "test", ChainID: "1", Genesis: genesis.Hash(), Deployment: "header-test"},
		URL:     server.URL, CredentialRef: "owned-read", CredentialHeader: "Idempotency-Key", Profile: "reth-prague-included-creations/v1", PragueStart: 100, PragueEnd: 200,
	}
	transport := headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("bounded POST permits transparent transport replay")
		}
		return server.Client().Transport.RoundTrip(r)
	})
	return node, source, transport
}

func headerLaneClient(t *testing.T, source creationfacts.Source, transport Transport, limits HeaderLimits) *HeaderClient {
	t.Helper()
	client, err := NewHeaderClient(transport, source, Credential{source.CredentialHeader, "header-test-only"}, limits)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func headerLaneObject(t *testing.T, header *types.Header) map[string]json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("invalid test header")
	}
	return out
}

func TestHeaderClientActualTLSBoundNetworkHashAndDetachedBatch(t *testing.T) {
	node, source, transport := headerLaneFixture(t)
	client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
	if client.Source() != source || (*HeaderClient)(nil).Source() != (creationfacts.Source{}) {
		t.Fatal("cold binding metadata mismatch")
	}
	batch, err := client.Read(t.Context(), []HeaderQuery{{NumberOrTag: "latest"}, {Hash: node.tip.Hash()}})
	if err != nil || !batch.Synced() {
		t.Fatal(batch, err)
	}
	if len(node.calls) != 5 || node.calls[0].Method != "eth_chainId" || node.calls[1].Method != "eth_getHeaderByNumber" || node.calls[2].Method != "eth_syncing" || node.calls[4].Method != "eth_getHeaderByHash" {
		t.Fatal("physical request accounting/order", node.calls)
	}
	headers := batch.Headers()
	if len(headers) != 2 || headers[0].Hash != node.tip.Hash() || headers[0].Parent != node.genesis.Hash() || headers[0].Number != 1 || headers[0].Timestamp != 12 || batch.Source() != source {
		t.Fatal("incorrect normalized network/header facts", headers)
	}
	// These lineage headers precede the configured Prague interval. The
	// consumer, not this header-only transport, imposes its evidence window.
	headers[0].Hash = common.Hash{}
	descriptor := batch.Source()
	descriptor.URL = "changed"
	clientDescriptor := client.Source()
	clientDescriptor.URL = "also changed"
	if batch.Headers()[0].Hash != node.tip.Hash() || batch.Source().URL != source.URL || client.Source().URL != source.URL {
		t.Fatal("mutable batch alias")
	}
	raw, _ := json.Marshal(batch.Source())
	if strings.Contains(string(raw), "header-test-only") {
		t.Fatal("credential value escaped through metadata")
	}
}

func TestHeaderClientClosedSelectorsAndLimitsBeforeIO(t *testing.T) {
	for _, query := range []HeaderQuery{{}, {NumberOrTag: "safe"}, {NumberOrTag: "pending"}, {NumberOrTag: "0x01"}, {NumberOrTag: "0xA"}, {NumberOrTag: "0x8000000000000000"}, {NumberOrTag: "latest", Hash: common.HexToHash("0x1")}} {
		t.Run(fmt.Sprintf("%v", query), func(t *testing.T) {
			node, source, transport := headerLaneFixture(t)
			client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
			if _, err := client.Read(t.Context(), []HeaderQuery{query}); err == nil || len(node.calls) != 0 {
				t.Fatal("invalid selector reached network", err, node.calls)
			}
		})
	}
	node, source, transport := headerLaneFixture(t)
	limits := DefaultHeaderLimits()
	limits.MaxQueries = 1
	client := headerLaneClient(t, source, transport, limits)
	if _, err := client.Read(t.Context(), []HeaderQuery{{NumberOrTag: "latest"}, {NumberOrTag: "0x0"}}); err == nil || len(node.calls) != 0 {
		t.Fatal("query limit reached I/O")
	}
	for _, invalid := range []HeaderLimits{{}, {16 * time.Second, 128, 16 << 10}, {time.Second, 129, 16 << 10}, {time.Second, 128, (16 << 10) + 1}, {-1, 1, 1}} {
		if _, err := NewHeaderClient(transport, source, Credential{source.CredentialHeader, "header-test-only"}, invalid); err == nil {
			t.Fatal("raised/unbounded limits accepted", invalid)
		}
	}
}

func TestHeaderClientRejectsContradictoryNetworkOrHeader(t *testing.T) {
	for _, scenario := range []string{"chain", "genesis", "hash", "selector-number", "selector-hash", "missing-parent", "duplicate-key", "unknown-field", "null-required", "wide-number", "huge-quantity", "bad-bloom", "future-format", "full-block", "oversize"} {
		t.Run(scenario, func(t *testing.T) {
			node, source, transport := headerLaneFixture(t)
			query := HeaderQuery{NumberOrTag: "0x1"}
			if scenario == "chain" {
				node.chain = "0x2"
			}
			if scenario == "genesis" {
				source.Network.Genesis = common.HexToHash("0x1234")
			}
			if scenario == "selector-number" {
				query.NumberOrTag = "0x2"
			}
			if scenario == "selector-hash" {
				query = HeaderQuery{Hash: common.HexToHash("0x5678")}
			}
			node.change = func(req headerLaneRPC, result any) any {
				if req.Method != "eth_getHeaderByHash" && req.Method != "eth_getHeaderByNumber" || result != node.tip {
					return result
				}
				fields := headerLaneObject(t, node.tip)
				switch scenario {
				case "hash":
					fields["hash"] = rawString(common.HexToHash("0x99").Hex())
				case "missing-parent":
					delete(fields, "parentHash")
				case "duplicate-key":
					raw, _ := json.Marshal(fields)
					return json.RawMessage(`{"number":"0x1",` + string(raw[1:]))
				case "unknown-field":
					fields["unexpected"] = rawString("0x1")
				case "null-required":
					fields["number"] = json.RawMessage("null")
				case "wide-number":
					fields["number"] = rawString("0x8000000000000000")
				case "huge-quantity":
					fields["difficulty"] = rawString("0x" + strings.Repeat("f", 65))
				case "bad-bloom":
					fields["logsBloom"] = rawString("0x00")
				case "future-format":
					fields["slotNumber"] = rawString("0x1")
				case "full-block":
					fields["transactions"] = json.RawMessage("[]")
				case "oversize":
					fields["extraData"] = rawString("0x" + strings.Repeat("00", 16<<10))
				}
				return fields
			}
			client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
			if batch, err := client.Read(t.Context(), []HeaderQuery{query}); err == nil || batch != nil {
				t.Fatal("contradictory input produced facts", batch, err)
			}
			for _, call := range node.calls {
				if strings.HasPrefix(call.Method, "eth_getBlock") {
					t.Fatal("full-block fallback", call)
				}
			}
		})
	}
}

func TestHeaderClientSyncAndEmptyQuerySemantics(t *testing.T) {
	for _, scenario := range []struct {
		name          string
		value         any
		valid, synced bool
	}{
		{"false", false, true, true},
		{"progress", map[string]string{"startingBlock": "0x0", "currentBlock": "0x1", "highestBlock": "0x2"}, true, false},
		{"true", true, false, false}, {"null", nil, false, false},
		{"empty-object", map[string]string{}, false, false},
		{"bad-quantity", map[string]string{"startingBlock": "0x0", "currentBlock": "0x01", "highestBlock": "0x2"}, false, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			node, source, transport := headerLaneFixture(t)
			node.syncing = scenario.value
			client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
			batch, err := client.Read(t.Context(), nil)
			if (err == nil) != scenario.valid {
				t.Fatal("sync shape qualification", batch, err)
			}
			if scenario.valid && (batch.Synced() != scenario.synced || len(batch.Headers()) != 0 || len(node.calls) != 3) {
				t.Fatal("empty query implies more than network/sync observations", batch, node.calls)
			}
		})
	}
}

func TestHeaderClientMaximumBatchHasExactlyThreeStartupCalls(t *testing.T) {
	node, source, transport := headerLaneFixture(t)
	client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
	queries := make([]HeaderQuery, 128)
	for i := range queries {
		queries[i] = HeaderQuery{NumberOrTag: "latest"}
	}
	batch, err := client.Read(t.Context(), queries)
	if err != nil || len(batch.Headers()) != 128 {
		t.Fatal("maximum bounded batch", batch, err)
	}
	node.mu.Lock()
	count := len(node.calls)
	node.mu.Unlock()
	if count != 131 {
		t.Fatal("physical query accounting excludes startup or adds retries", count)
	}
	if _, err := client.Read(t.Context(), append(queries, HeaderQuery{NumberOrTag: "latest"})); err == nil {
		t.Fatal("129 selectors accepted")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if len(node.calls) != count {
		t.Fatal("oversized batch performed partial I/O")
	}
}

func TestHeaderClientEarlierParentDeadlineIncludesStartupChecks(t *testing.T) {
	node, source, transport := headerLaneFixture(t)
	node.blockSync = true
	client := headerLaneClient(t, source, transport, DefaultHeaderLimits())
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	start := time.Now()
	if batch, err := client.Read(ctx, []HeaderQuery{{NumberOrTag: "latest"}}); err == nil || batch != nil {
		t.Fatal("blocked startup ignored earlier parent deadline", batch, err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("reset/ignored parent deadline")
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if len(node.calls) > 3 {
		t.Fatal("requested headers after startup deadline", node.calls)
	}
}

func TestHeaderClientCredentialAndProfileBoundary(t *testing.T) {
	_, source, transport := headerLaneFixture(t)
	for _, credential := range []Credential{{}, {"X-Other", "header-test-only"}, {source.CredentialHeader, "bad\r\nvalue"}} {
		if _, err := NewHeaderClient(transport, source, credential, DefaultHeaderLimits()); err == nil {
			t.Fatal("unbound credential accepted")
		}
	}
	wrong := source
	wrong.Profile = SignedCallProfileID
	if _, err := NewHeaderClient(transport, wrong, Credential{source.CredentialHeader, "header-test-only"}, DefaultHeaderLimits()); err == nil {
		t.Fatal("legacy org execution profile accepted")
	}
	unauthenticated := source
	unauthenticated.CredentialRef, unauthenticated.CredentialHeader = "", ""
	if _, err := NewHeaderClient(transport, unauthenticated, Credential{}, DefaultHeaderLimits()); err != nil {
		t.Fatal("explicit owned unauthenticated reference rejected", err)
	}
}
