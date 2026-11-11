package activitylog_test

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
)

// Actual approved CreationObserved runtime, original JWT, PG, TLS frontend and
// Recorder/Pebble. Backend wire observations are fixtures, not permission DTOs.
func TestNativeCallBoundNetworkAcquisitionAndAfterActualAppend(t *testing.T) {
	db := rawPostgres(t)
	if _, err := db.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(now)
	f := metadataFixture()
	f.clock = &clock
	n := &node{}
	engine, token, financial, _ := mountedRawEngine(t, f, n, db, false)
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	originalGenesis, originalHead := types.CopyHeader(n.genesisHeader), types.CopyHeader(n.anchorHeader)
	otherGenesis := types.CopyHeader(originalGenesis)
	otherGenesis.Extra = []byte("other-private-deployment")
	otherHead := types.CopyHeader(originalHead)
	otherHead.ParentHash = otherGenesis.Hash()
	if otherGenesis.Hash().Hex() == net.GenesisHash {
		t.Fatal("negative did not change genesis")
	}
	x := setupActivityDatabase(t, network)
	appendEntered, appendRelease := make(chan struct{}), make(chan struct{})
	var holdAppend atomic.Bool
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(appendRelease) }) })
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error {
		if holdAppend.Load() {
			close(appendEntered)
			<-appendRelease
		}
		return nil
	})
	service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := service.Handler(orgA)
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewTLSServer(handler)
	t.Cleanup(front.Close)
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + addressA + `","data":"0x0102"}]}`
	reset := func() {
		clock.Store(now)
		n.mu.Lock()
		defer n.mu.Unlock()
		n.genesisHeader, n.anchorHeader = types.CopyHeader(originalGenesis), types.CopyHeader(originalHead)
		n.chainID, n.failMethod = "", ""
		n.onTrace, n.onChain, n.mutate = nil, nil, nil
	}
	for _, mode := range []string{"positive", "same-chain-wrong-genesis", "wrong-chain", "chain-change-during-trace", "genesis-change-during-trace", "late-source-error", "expiry-during-final-probe"} {
		t.Run(mode, func(t *testing.T) {
			reset()
			var chains, traces atomic.Int32
			n.mu.Lock()
			n.onChain = func() {
				if chains.Add(1) == 2 && mode == "expiry-during-final-probe" {
					clock.Store(now + 300)
				}
			}
			n.onTrace = func() {
				traces.Add(1)
				switch mode {
				case "chain-change-during-trace":
					n.chainID = "0x2" // Same original genesis: hash alone is insufficient.
				case "genesis-change-during-trace":
					n.genesisHeader, n.anchorHeader = otherGenesis, otherHead
				case "late-source-error":
					n.failMethod = "eth_getHeaderByNumber"
				}
			}
			switch mode {
			case "same-chain-wrong-genesis":
				n.genesisHeader, n.anchorHeader = otherGenesis, otherHead
			case "wrong-chain":
				n.chainID = "0x2"
			}
			n.mu.Unlock()
			before := metadataRows(t, x)
			wire := bodyResult(t, requestAsync(t, front.Client(), front.URL, token, body, t.Context()))
			if mode == "positive" {
				if !strings.Contains(string(wire), `"result":"0xfeed"`) || chains.Load() != 2 || traces.Load() != 1 {
					t.Fatal("original bound network did not pass", string(wire), chains.Load(), traces.Load())
				}
			} else {
				if strings.Contains(string(wire), `"result"`) || strings.Contains(string(wire), "0xfeed") {
					t.Fatal("different/expired source released protected bytes", string(wire))
				}
				requireMetadataCode(t, wire, -32002)
			}
			sealed := metadataSealedOne(t, x, before)
			wantOutcome := "success"
			if mode == "same-chain-wrong-genesis" || mode == "wrong-chain" {
				wantOutcome = "unavailable"
				if traces.Load() != 0 {
					t.Fatal("wrong network reached native evaluation")
				}
			}
			if sealed.Method != "eth_call" || sealed.Outcome != wantOutcome {
				t.Fatal("network gate rewrote selected completion", sealed, wantOutcome)
			}
		})
	}
	t.Run("genesis-change-during-actual-append", func(t *testing.T) {
		reset()
		before := metadataRows(t, x)
		holdAppend.Store(true)
		done := requestAsync(t, front.Client(), front.URL, token, body, t.Context())
		await(t, appendEntered)
		n.mu.Lock()
		n.genesisHeader, n.anchorHeader = otherGenesis, otherHead
		n.mu.Unlock()
		holdAppend.Store(false)
		release.Do(func() { close(appendRelease) })
		wire := bodyResult(t, done)
		requireMetadataCode(t, wire, -32002)
		if strings.Contains(string(wire), "0xfeed") {
			t.Fatal("post-Append source change leaked")
		}
		if sealed := metadataSealedOne(t, x, before); sealed.Outcome != "success" {
			t.Fatal("late source change rewrote selected success", sealed)
		}
	})
	for _, mode := range []string{"success", "revert", "wrong-network-success", "wrong-network-revert"} {
		t.Run("direct-"+mode, func(t *testing.T) {
			reset()
			n.mu.Lock()
			if strings.Contains(mode, "revert") {
				n.mutate = func(frame map[string]any) { frame["error"], frame["output"] = "execution reverted", "0xdead" }
			}
			if strings.HasPrefix(mode, "wrong-network") {
				n.onTrace = func() { n.chainID = "0x2" }
			}
			n.mu.Unlock()
			result := engine.Call(t.Context(), token, orgA, []byte(body))
			if strings.HasPrefix(mode, "wrong-network") {
				if result.Result != nil || result.Error == nil || result.Error.Code != -32002 || result.Error.Data != nil {
					t.Fatal("direct API bypassed network gate", result)
				}
			} else if mode == "revert" {
				if result.Error == nil || result.Error.Code != 3 || result.Error.Data != "0xdead" {
					t.Fatal("original direct revert changed", result)
				}
			} else if result.Result == nil || *result.Result != "0xfeed" {
				raw, _ := json.Marshal(result)
				t.Fatal("original direct success changed", string(raw))
			}
		})
	}
}
