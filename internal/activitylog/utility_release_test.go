package activitylog_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
)

func TestUtilityActualGuardTypedDefaultsAndFiniteBudgets(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"legacy-defaults", "type1-preflight", "type2-defaults", "guard-legacy", "guard-type2", "guard-type1-rejected-before-sign", "changed-nonce", "changed-fee", "probe-limit", "request-limit", "byte-limit", "alias", "foreign-org", "no-storage-method"} {
		t.Run(scenario, func(t *testing.T) {
			f := utilityFixture()
			u := &utilityActivityNode{t: t}
			n := &node{utility: u, nonce: "0x9"}
			method := "eth_sendTransaction"
			fields := `"gas":"0x186a0"`
			want := true
			limits := rpcexecution.DefaultUtilityLimits()
			switch scenario {
			case "legacy-defaults":
				fields = `"value":"0x0"`
			case "type1-preflight", "guard-type1-rejected-before-sign":
				fields += `,"type":"0x1","accessList":[]`
			case "type2-defaults", "guard-type2":
				fields += `,"type":"0x2"`
			case "changed-nonce":
				u.changeSigned = func(c map[string]any) { c["nonce"] = "0xa" }
				want = false
			case "changed-fee":
				u.changeSigned = func(c map[string]any) { c["gasPrice"] = "0x2" }
				want = false
			case "probe-limit":
				method = "eth_estimateGas"
				limits.MaxProbes = 1
				want = false
			case "request-limit":
				method = "eth_estimateGas"
				limits.MaxRequests = 16
				want = false
			case "byte-limit":
				method = "eth_estimateGas"
				limits.MaxResponseBytes = 1
				want = false
			case "foreign-org":
				want = false
			case "alias":
				method = "bank_estimate"
				m := *f.methodCatalog
				m.Assignable = append(m.Assignable, method)
				m.Aliases = map[string]string{method: "eth_estimateGas"}
				f.methodCatalog = &m
				f.groups[0].AllowedMethods = append(f.groups[0].AllowedMethods, method)
			case "no-storage-method":
				method = "eth_createAccessList"
				f.groups[0].AllowedMethods = []string{method, "eth_sendTransaction"}
			}
			if strings.HasPrefix(scenario, "guard-") {
				f.rawMode = policybundle.RawSubmissionGuardV1
			}
			if scenario == "guard-type1-rejected-before-sign" {
				want = false
			}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false, creationMountOptions{configure: func(o *rpcengine.RawOptions) {
				o.Utilities = &rpcengine.ExecutionUtilityOptions{NodeSigning: true, Limits: limits}
			}})
			defer engine.Close()
			org := orgA
			if scenario == "foreign-org" {
				org = orgB
			}
			body := `{"id":1,"method":"` + method + `","params":[{"from":"` + signedValue(t, 9).Signer().Hex() + `","to":"` + addressA + `","input":"0x0102",` + fields + `}]}`
			result := engine.UtilityObserved(t.Context(), tok, org, []byte(body))
			raw, err := result.MarshalResponseFor(engine)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Result json.RawMessage
				Error  *rpcengine.RPCError
			}
			if json.Unmarshal(raw, &wire) != nil {
				t.Fatal(string(raw))
			}
			if (wire.Error == nil) != want {
				methods, _ := n.counts()
				t.Fatal("utility release outcome", string(raw), methods, u.traceGas)
			}
			methods, _ := n.counts()
			broadcasts := 0
			for _, name := range methods {
				if name == "eth_sendTransaction" {
					t.Fatal("unchecked send fallback")
				}
				if name == "eth_sendRawTransaction" {
					broadcasts++
				}
			}
			if !want {
				if broadcasts != 0 {
					t.Fatal("rejected utility broadcast", methods)
				}
				if scenario == "guard-type1-rejected-before-sign" && u.signs != 0 {
					t.Fatal("unsupported Guard type1 reached key")
				}
			}
			if want && method == "eth_sendTransaction" {
				if u.signs != 1 || broadcasts != 1 || len(u.signedCalls) != 1 {
					t.Fatal("sign/raw cardinality", u.signs, broadcasts)
				}
				c := u.signedCalls[0]
				if c["nonce"] != "0x9" || c["chainId"] != "0x1" {
					t.Fatal("defaults not bound", c)
				}
				if scenario == "type2-defaults" || scenario == "guard-type2" {
					if c["maxFeePerGas"] != "0x1" || c["maxPriorityFeePerGas"] != "0x0" {
						t.Fatal("typed fees", c)
					}
				}
				if scenario == "legacy-defaults" && len(u.traceGas) < 2 {
					t.Fatal("default gas was not checked probe by probe")
				}
			}
			if scenario == "probe-limit" && len(u.traceGas) != 1 {
				t.Fatal("probe budget restarted", u.traceGas)
			}
			if scenario == "request-limit" && len(methods) > limits.MaxRequests {
				t.Fatal("physical request budget restarted", len(methods))
			}
			if scenario == "byte-limit" && (len(u.traceGas) != 0 || u.signs != 0) {
				t.Fatal("exhausted bytes reached execution")
			}
			if scenario == "foreign-org" && len(methods) != 0 {
				t.Fatal("foreign selection reached node")
			}
			if scenario == "no-storage-method" {
				var list struct {
					AccessList []struct {
						StorageKeys []string `json:"storageKeys"`
					} `json:"accessList"`
				}
				if json.Unmarshal(wire.Result, &list) != nil {
					t.Fatal(string(raw))
				}
				for _, entry := range list.AccessList {
					if len(entry.StorageKeys) != 0 {
						t.Fatal("storage method omitted but slot disclosed")
					}
				}
			}
			_ = financial
		})
	}
}

func TestUtilityActualOriginalAppendAndLifetime(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"original-expiry", "original-parent-cancel", "append-failure", "signed-effect-append-failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := utilityFixture()
			var clock atomic.Int64
			clock.Store(now)
			f.clock = &clock
			u := &utilityActivityNode{t: t}
			n := &node{utility: u}
			broadcastHash := ""
			if scenario == "signed-effect-append-failure" {
				n.onSend = func(raw string) string {
					var tx types.Transaction
					if err := tx.UnmarshalBinary(common.FromHex(raw)); err != nil {
						t.Error(err)
						return ""
					}
					broadcastHash = tx.Hash().Hex()
					return broadcastHash
				}
			}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false, creationMountOptions{configure: func(o *rpcengine.RawOptions) { o.Utilities = &rpcengine.ExecutionUtilityOptions{NodeSigning: true} }})
			defer engine.Close()
			net := financial.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			x := setupActivityDatabase(t, network)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			rec := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error {
				close(entered)
				<-release
				if strings.Contains(scenario, "append-failure") {
					return errors.New("owned append failure")
				}
				return nil
			}, "eth_estimateGas", "eth_createAccessList", "eth_sendTransaction")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			method := "eth_createAccessList"
			if scenario == "signed-effect-append-failure" {
				method = "eth_sendTransaction"
			}
			body := `{"id":1,"method":"` + method + `","params":[{"from":"` + signedValue(t, 9).Signer().Hex() + `","to":"` + addressA + `","input":"0x0102","gas":"0x186a0"}]}`
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := requestAsync(t, front.Client(), front.URL, tok, body, ctx)
			await(t, entered)
			if scenario == "original-expiry" {
				clock.Store(now + 1000)
			}
			if scenario == "original-parent-cancel" {
				cancel()
			}
			once.Do(func() { close(release) })
			if scenario == "original-parent-cancel" {
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Fatal("original cancellation did not finish")
				}
				return
			}
			raw := bodyResult(t, done)
			var wire struct {
				Result json.RawMessage
				Error  *rpcengine.RPCError
			}
			if json.Unmarshal(raw, &wire) != nil || wire.Error == nil || wire.Result != nil {
				t.Fatal("expired/failed append disclosed utility success", string(raw))
			}
			if scenario == "signed-effect-append-failure" {
				methods, _ := n.counts()
				count := 0
				for _, m := range methods {
					if m == "eth_sendRawTransaction" {
						count++
					}
				}
				if count != 1 || u.signs != 1 || wire.Error.Code != -32004 {
					t.Fatal("executed send was retried or disguised", count, u.signs, string(raw))
				}
				data, ok := wire.Error.Data.(map[string]any)
				if !ok || len(data) != 1 || broadcastHash == "" || data["transactionHash"] != broadcastHash {
					t.Fatal("recording failure lost the exact verified broadcast hash", string(raw))
				}
			}
		})
	}
}
