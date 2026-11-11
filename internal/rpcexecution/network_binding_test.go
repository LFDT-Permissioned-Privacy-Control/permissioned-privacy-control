package rpcexecution

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/networkidentity"
)

func TestNativeNetworkCloneAndActualTupleProbe(t *testing.T) {
	n, source, transport := metadataFixture(t)
	base, err := NewClient(transport, NodeBinding{OrganizationID: "11111111-1111-1111-1111-111111111111", URL: source.URL, ChainID: "1", Profile: NodeProfileID, PragueEndExclusive: 100, Credentials: map[string]Credential{"owned": {Header: "Idempotency-Key", Value: "metadata-test-only"}}}, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	bound, err := base.WithNetwork(source.Network)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := bound.WithCredential("owned")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := base.BoundNetwork(); ok {
		t.Fatal("network clone mutated the caller's client")
	}
	if got, ok := selected.BoundNetwork(); !ok || got != source.Network {
		t.Fatal("credential selection lost the expected tuple")
	}
	for _, bad := range []networkidentity.Binding{{}, {Environment: "test", ChainID: "1", GenesisHash: common.Hash{}.Hex(), DeploymentID: "zero"}, {Environment: "test", ChainID: "2", GenesisHash: source.Network.GenesisHash, DeploymentID: "wrong-chain"}, {Environment: "test", ChainID: "1", GenesisHash: strings.ToUpper(source.Network.GenesisHash), DeploymentID: "noncanonical"}} {
		if _, err := base.WithNetwork(bad); err == nil {
			t.Fatal("invalid cold network accepted", bad)
		}
	}
	conflict := source.Network
	conflict.DeploymentID += "-other"
	if _, err := bound.WithNetwork(conflict); err == nil {
		t.Fatal("bound client silently rebound")
	}
	if _, err := bound.WithNetwork(source.Network); err != nil {
		t.Fatal("same immutable binding cannot be reused", err)
	}
	if selected.RequireBoundNetwork(nil) == nil || bound.RequireBoundNetwork(t.Context()) == nil || base.RequireBoundNetwork(t.Context()) == nil {
		t.Fatal("missing context/credential/binding accepted")
	}
	for _, mode := range []string{"positive", "wrong-chain", "wrong-genesis", "wrong-number", "forged-hash", "oversize", "null", "earlier-parent", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			n.mu.Lock()
			before := len(n.calls)
			n.chain = "0x1"
			n.change = func(w http.ResponseWriter, r *http.Request, q metadataTestRPC) bool {
				if q.Method != "eth_getHeaderByNumber" {
					return false
				}
				if mode == "earlier-parent" {
					<-r.Context().Done()
					return true
				}
				var result any = n.genesis
				switch mode {
				case "wrong-genesis":
					header := types.CopyHeader(n.genesis)
					header.Extra = []byte("another-network")
					result = header
				case "wrong-number":
					header := types.CopyHeader(n.genesis)
					header.Number.SetUint64(1)
					result = header
				case "forged-hash":
					raw, _ := json.Marshal(n.genesis)
					var object map[string]any
					_ = json.Unmarshal(raw, &object)
					object["hash"] = common.Hash{1}.Hex()
					result = object
				case "oversize":
					result = strings.Repeat("x", 17<<10)
				case "null":
					result = nil
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
				return true
			}
			if mode == "wrong-chain" {
				n.chain = "0x2"
			}
			n.mu.Unlock()
			ctx := t.Context()
			if mode == "cancelled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mode == "earlier-parent" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			}
			err := selected.RequireBoundNetwork(ctx)
			if (mode == "positive") != (err == nil) {
				t.Fatal("tuple probe", mode, err)
			}
			want := 2
			if mode == "wrong-chain" {
				want = 1
			} else if mode == "cancelled" {
				want = 0
			}
			n.mu.Lock()
			defer n.mu.Unlock()
			if len(n.calls)-before != want {
				t.Fatal("probe retried or escaped original fence", len(n.calls)-before, want)
			}
		})
	}
}
