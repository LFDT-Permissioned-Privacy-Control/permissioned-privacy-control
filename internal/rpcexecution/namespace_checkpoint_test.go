package rpcexecution

import (
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
	"privacy-proxy/internal/historynamespace"
	"privacy-proxy/internal/networkidentity"
)

type namespaceTestNode struct {
	mu                  sync.Mutex
	calls, codeCalls    int
	code                string
	syncing             any
	changeHeader, block bool
	codeWhitespace      int
	genesis, tip        *types.Header
}

func namespaceTLSFixture(t *testing.T) (*namespaceTestNode, creationfacts.Source, historynamespace.ModelEra, Transport) {
	t.Helper()
	g := &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}
	tip := types.CopyHeader(g)
	tip.Number, tip.Time, tip.ParentHash = big.NewInt(1), 12, g.Hash()
	n := &namespaceTestNode{code: "0x60", syncing: false, genesis: g, tip: tip}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Idempotency-Key") != "public-import-fixture" {
			t.Error("wrong owned request or credential")
			w.WriteHeader(400)
			return
		}
		var req headerLaneRPC
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			t.Error("invalid RPC")
			return
		}
		n.mu.Lock()
		n.calls++
		var result any
		padding, blocked := 0, false
		switch req.Method {
		case "eth_chainId":
			result = "0x1"
		case "eth_syncing":
			result = n.syncing
		case "eth_getHeaderByNumber":
			var selector string
			if len(req.Params) != 1 || json.Unmarshal(req.Params[0], &selector) != nil {
				t.Error("bad header selector")
			}
			if selector == "0x0" {
				result = n.genesis
			} else {
				h := types.CopyHeader(n.tip)
				if n.changeHeader && n.codeCalls > 0 {
					h.Time++
				}
				result = h
			}
		case "eth_getCode":
			n.codeCalls++
			var selector map[string]any
			if len(req.Params) != 2 || json.Unmarshal(req.Params[1], &selector) != nil || len(selector) != 2 || selector["requireCanonical"] != true || selector["blockHash"] != n.tip.Hash().Hex() {
				t.Error("code was not bound to canonical checkpoint hash")
			}
			result, padding, blocked = n.code, n.codeWhitespace, n.block
		default:
			t.Error("unexpected import RPC", req.Method)
		}
		n.mu.Unlock()
		if blocked {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if padding > 0 {
			_, _ = w.Write([]byte(strings.Repeat(" ", padding)))
		}
		_ = json.NewEncoder(w).Encode(struct {
			JSONRPC string `json:"jsonrpc"`
			ID      uint64 `json:"id"`
			Result  any    `json:"result"`
		}{"2.0", req.ID, result})
	}))
	t.Cleanup(srv.Close)
	binding := networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: g.Hash().Hex(), DeploymentID: "namespace-import"}
	key, err := binding.Key()
	if err != nil {
		t.Fatal(err)
	}
	source := creationfacts.Source{Network: creationfacts.Network{Key: creationfacts.Digest(key), Environment: binding.Environment, ChainID: binding.ChainID, Genesis: g.Hash(), Deployment: binding.DeploymentID}, URL: srv.URL, CredentialRef: "import", CredentialHeader: "Idempotency-Key", Profile: IncludedProfileID, PragueStart: 0, PragueEnd: 200}
	era := historynamespace.ModelEra{EntryNumber: 0, EntryHash: historynamespace.Hash(g.Hash()), EntryTimestamp: 1, EndTimestampExclusive: 200}
	rt := headerLaneTransportFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("counted import POST permits replay")
		}
		return srv.Client().Transport.RoundTrip(r)
	})
	return n, source, era, rt
}

func namespaceTestClient(t *testing.T, source creationfacts.Source, era historynamespace.ModelEra, rt Transport, limits NamespaceCheckpointLimits) *NamespaceCheckpointClient {
	t.Helper()
	c, err := NewNamespaceCheckpointClient(rt, source, Credential{source.CredentialHeader, "public-import-fixture"}, era, limits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNamespaceCheckpointActualTLSStableProofAndPhysicalCeiling(t *testing.T) {
	n, source, era, rt := namespaceTLSFixture(t)
	c := namespaceTestClient(t, source, era, rt, DefaultNamespaceCheckpointLimits())
	addresses := make([]historynamespace.Address, 128)
	for i := range addresses {
		addresses[i][0], addresses[i][19] = 0x20, byte(i)
	}
	p, err := c.Qualify(t.Context(), 1, addresses)
	if err != nil {
		t.Fatal(err)
	}
	n.mu.Lock()
	count := n.calls
	n.mu.Unlock()
	if count != 136 || p.Source() != source || p.Facts().Hash != historynamespace.Hash(n.tip.Hash()) || p.Facts().Codes[0].RuntimeHash != historynamespace.Hash(crypto.Keccak256Hash([]byte{0x60})) {
		t.Fatal("proof binding or exact physical ceiling failed", count)
	}
	facts := p.Facts()
	facts.Codes[0].RuntimeHash = historynamespace.Hash{}
	if p.Facts().Codes[0].RuntimeHash == (historynamespace.Hash{}) {
		t.Fatal("proof metadata aliases internal state")
	}
	again, err := c.Qualify(t.Context(), 1, addresses)
	if err != nil || again.Digest() != p.Digest() {
		t.Fatal("request IDs/time changed immutable proof digest", err)
	}
	if (&NamespaceCheckpointProof{}).Digest() != (historynamespace.Digest{}) || (*NamespaceCheckpointProof)(nil).Source() != (creationfacts.Source{}) {
		t.Fatal("empty proof looked qualified")
	}
	before := count * 2
	if _, err := c.Qualify(t.Context(), 1, append(addresses, historynamespace.Address{0x30})); err == nil {
		t.Fatal("129 addresses admitted")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls != before {
		t.Fatal("oversized input performed I/O")
	}
}

func TestNamespaceCheckpointRejectsUnqualifiedAndUnboundedEvidence(t *testing.T) {
	for _, name := range []string{"empty", "EF", "changed header", "syncing", "decoded aggregate", "raw whitespace", "deadline"} {
		t.Run(name, func(t *testing.T) {
			n, source, era, rt := namespaceTLSFixture(t)
			limits := DefaultNamespaceCheckpointLimits()
			addresses := []historynamespace.Address{{0x20}}
			switch name {
			case "empty":
				n.code = "0x"
			case "EF":
				n.code = "0xef0100" + strings.Repeat("00", 20)
			case "changed header":
				n.changeHeader = true
			case "syncing":
				n.syncing = map[string]any{"startingBlock": "0x0", "currentBlock": "0x1", "highestBlock": "0x1"}
			case "decoded aggregate":
				limits.MaxTotalCodeBytes = 1
				addresses = append(addresses, historynamespace.Address{0x21})
			case "raw whitespace":
				limits.MaxWireBytes, n.codeWhitespace = 4096, 8192
			case "deadline":
				limits.Timeout, n.block = 30*time.Millisecond, true
			}
			c := namespaceTestClient(t, source, era, rt, limits)
			if p, err := c.Qualify(t.Context(), 1, addresses); err == nil || p != nil {
				t.Fatal("unqualified evidence became an import proof", err)
			}
		})
	}
}

func TestNamespaceCheckpointColdBindingAndClosedInputs(t *testing.T) {
	n, source, era, rt := namespaceTLSFixture(t)
	wrong := source
	wrong.Network.Key[0] ^= 1
	if _, err := NewNamespaceCheckpointClient(rt, wrong, Credential{source.CredentialHeader, "public-import-fixture"}, era, DefaultNamespaceCheckpointLimits()); err == nil {
		t.Fatal("noncanonical network key accepted")
	}
	c := namespaceTestClient(t, source, era, rt, DefaultNamespaceCheckpointLimits())
	for _, addresses := range [][]historynamespace.Address{nil, {{0x21}, {0x20}}, {{0x20}, {0x20}}, {historynamespace.Address(common.HexToAddress("0x01"))}} {
		if _, err := c.Qualify(t.Context(), 1, addresses); err == nil {
			t.Fatal("bad closed address set accepted")
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.calls != 0 || c.Source().Network.Key != source.Network.Key {
		t.Fatal("invalid input I/O or cold source mutation")
	}
}
