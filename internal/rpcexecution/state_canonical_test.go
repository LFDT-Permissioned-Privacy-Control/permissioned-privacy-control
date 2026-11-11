package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

func TestStateCanonicalAncestorSameCredentialOneNumericCall(t *testing.T) {
	n, source, transport := metadataFixture(t)
	header := &types.Header{Number: big.NewInt(42), ParentHash: n.genesis.Hash(), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 43}
	head := creationfacts.Header{Number: 42, Hash: header.Hash()}
	client := stateClient(t, source, transport, DefaultStateLimits())
	for _, mode := range []string{"positive", "reorg", "wrong-number", "missing", "bad-claimed-hash", "oversize", "earlier-parent"} {
		t.Run(mode, func(t *testing.T) {
			n.mu.Lock()
			before := len(n.calls)
			n.change = func(w http.ResponseWriter, r *http.Request, q metadataTestRPC) bool {
				if q.Method != "eth_getHeaderByNumber" || len(q.Params) != 1 || string(q.Params[0]) != `"0x2a"` {
					t.Error("not one original numeric-head call", q)
				}
				if mode == "earlier-parent" {
					<-r.Context().Done()
					return true
				}
				var result any = header
				switch mode {
				case "reorg":
					fork := types.CopyHeader(header)
					fork.Extra = []byte("new-branch")
					result = fork
				case "wrong-number":
					wrong := types.CopyHeader(header)
					wrong.Number = big.NewInt(41)
					result = wrong
				case "missing":
					result = nil
				case "bad-claimed-hash":
					raw, _ := json.Marshal(header)
					var object map[string]any
					_ = json.Unmarshal(raw, &object)
					object["hash"] = common.Hash{1}.Hex()
					result = object
				case "oversize":
					result = strings.Repeat("x", 17<<10)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
				return true
			}
			n.mu.Unlock()
			ctx := t.Context()
			var cancel context.CancelFunc
			if mode == "earlier-parent" {
				ctx, cancel = context.WithTimeout(ctx, 25*time.Millisecond)
				defer cancel()
			}
			err := client.RequireCanonicalHeader(ctx, head)
			if (mode == "positive") != (err == nil) {
				t.Fatal("canonical ancestor result", mode, err)
			}
			n.mu.Lock()
			calls := len(n.calls) - before
			n.mu.Unlock()
			if calls != 1 {
				t.Fatal("canonical check retried or requalified network", calls)
			}
		})
	}
	for _, bad := range []creationfacts.Header{{}, {Number: 42, Hash: head.Hash, Timestamp: 1}, {Number: 42, Hash: head.Hash, Parent: common.Hash{1}}, {Number: 1 << 63, Hash: head.Hash}} {
		if client.RequireCanonicalHeader(t.Context(), bad) == nil {
			t.Fatal("invalid original head accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	n.mu.Lock()
	before := len(n.calls)
	n.mu.Unlock()
	if client.RequireCanonicalHeader(ctx, head) == nil {
		t.Fatal("canceled canonical check succeeded")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.calls) != before {
		t.Fatal("invalid/canceled canonical check reached backend")
	}
}
