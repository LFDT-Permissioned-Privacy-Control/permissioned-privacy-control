package activitylog_test

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
	"net/http/httptest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/walletops"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func traceFixture() fixture {
	f := metadataFixture()
	m := *f.methodCatalog
	m.Assignable = append(m.Assignable, "debug_traceCall", "bank_trace", "eth_getStorageAt")
	aliases := map[string]string{}
	for k, v := range m.Aliases {
		aliases[k] = v
	}
	aliases["bank_trace"] = "debug_traceCall"
	m.Aliases = aliases
	f.methodCatalog = &m
	f.groups[0].AllowedMethods = []string{"debug_traceCall", "bank_trace", "eth_getStorageAt"}
	f.runtime.IntraOrgGrantTracing = false
	for i := range f.contracts {
		f.contracts[i].ReadGrants = []policybundle.ReadGrant{{ID: fmt.Sprintf("aaaaaaaa-aaaa-4aaa-8aaa-%012d", i+1), GroupID: reader, EventRules: policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}}}
	}
	return f
}
func traceBody(method string) string {
	return `{"jsonrpc":"2.0","id":"trace","method":"` + method + `","params":[{"to":"` + addressA + `","data":"0x0102"}]}`
}
func traceObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var wire struct {
		Result map[string]any
		Error  *rpcengine.RPCError
	}
	if json.Unmarshal(raw, &wire) != nil || wire.Error != nil || wire.Result == nil {
		t.Fatalf("trace unavailable: %s", raw)
	}
	return wire.Result
}
func TestClientTraceActualHTTPPostgresRecorderAndMasking(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"plain", "parent-admin", "child-admin", "both-admin", "no-storage-method", "call-only", "target-only-alias", "ungranted-nested", "forbidden-function", "foreign-nested", "delegate-storage", "root-revert", "harmless-config", "unsafe-config", "notification", "original-id"} {
		t.Run(scenario, func(t *testing.T) {
			f := traceFixture()
			body := traceBody("debug_traceCall")
			want := true
			n := &node{}
			n.mutate = func(root map[string]any) {
				root["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressC, "input": "0x11223344", "output": "0xdeadbeef", "value": "0x1", "gas": "0x100", "gasUsed": "0x1", "logs": []any{}}}
			}
			switch scenario {
			case "parent-admin", "child-admin", "both-admin", "no-storage-method":
				f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "values", Name: "Values", AllowedMethods: []string{"eth_getCode"}, Claims: []string{"admin"}})
				f.roles = append(f.roles, second)
				for i := range f.contracts {
					if scenario == "both-admin" || scenario == "no-storage-method" || scenario == "parent-admin" && i == 0 || scenario == "child-admin" && i == 1 {
						f.contracts[i].ReadGrants = append(f.contracts[i].ReadGrants, policybundle.ReadGrant{ID: fmt.Sprintf("bbbbbbbb-bbbb-4bbb-8bbb-%012d", i+1), GroupID: second, EventRules: policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}})
					}
				}
				if scenario == "no-storage-method" {
					f.groups[0].AllowedMethods = []string{"debug_traceCall", "bank_trace"}
				}
			case "call-only":
				f.groups[0].AllowedMethods = []string{"eth_call"}
				want = false
			case "target-only-alias":
				f.groups[0].AllowedMethods = []string{"debug_traceCall"}
				body = traceBody("bank_trace")
				want = false
			case "ungranted-nested":
				f.contracts[1].ReadGrants = []policybundle.ReadGrant{}
				f.groups[0].AllowedMethods = append(f.groups[0].AllowedMethods, "eth_call")
				want = false
			case "forbidden-function":
				f.bindings[0].Allow = f.bindings[0].Allow[:1]
				want = false
			case "foreign-nested":
				n.mutate = func(root map[string]any) {
					root["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressB, "input": "0x", "output": "0xdeadbeef", "value": "0x0", "gas": "0x100", "gasUsed": "0x1"}}
				}
				f.roles = append(f.roles, foreign)
				f.groups[0].AllowedMethods = append(f.groups[0].AllowedMethods, "eth_call")
				f.bBindings = []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{{StorageAddress: addressB, Selector: "*"}}}}
				want = false
			case "delegate-storage":
				f.contracts[1].ReadGrants = []policybundle.ReadGrant{}
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{StorageAddress: addressA, CodeAddress: addressC, Selector: "*", CallTypes: []policycore.CallType{policycore.CallTypeDelegateCall}})
				n.mutate = func(root map[string]any) {
					root["calls"] = []any{map[string]any{"type": "DELEGATECALL", "from": addressA, "to": addressC, "input": "0x11223344", "output": "0xdeadbeef", "value": "0x0", "gas": "0x100", "gasUsed": "0x1"}}
				}
			case "root-revert":
				n.mutate = func(root map[string]any) {
					root["error"] = "execution reverted"
					root["revertReason"] = "root reason"
					root["output"] = "0xdeadbeef"
				}
			case "harmless-config":
				body = strings.TrimSuffix(body, `]}`) + `,"latest",{"tracer":"callTracer","tracerConfig":{"withLog":false,"onlyTopCall":true},"timeout":"100000h","unknown":"ignored"}]}`
			case "unsafe-config":
				body = strings.TrimSuffix(body, `]}`) + `,"latest",{"tracer":"callTracer","tracerConfig":{"withLog":true}}]}`
				want = false
			case "notification":
				body = strings.Replace(body, `"id":"trace",`, "", 1)
			case "original-id":
				body = strings.Replace(body, `"id":"trace"`, `"id":1.2500e+03`, 1)
			}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false)
			defer engine.Close()
			if scenario == "ungranted-nested" || scenario == "foreign-nested" {
				out := engine.Call(t.Context(), tok, orgA, []byte(strings.Replace(traceBody("debug_traceCall"), "debug_traceCall", "eth_call", 1)))
				if out.Result == nil || *out.Result != "0xfeed" {
					t.Fatal("ordinary native baseline did not permit scoped comparison", out)
				}
			}
			net := financial.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			x := setupActivityDatabase(t, network)
			rec := rpcRecorder(t, x, func() time.Time { return time.Unix(now, 0) }, nil, "debug_traceCall", "bank_trace")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			before := metadataRows(t, x)
			raw := bodyResult(t, requestAsync(t, front.Client(), front.URL, tok, body, t.Context()))
			sealed := metadataSealedOne(t, x, before)
			if scenario == "notification" {
				if len(raw) != 0 {
					t.Fatal("notification returned body", string(raw))
				}
				if sealed.Method != "debug_traceCall" {
					t.Fatal(sealed)
				}
				return
			}
			if !want {
				if strings.Contains(string(raw), "deadbeef") || strings.Contains(string(raw), "0xfeed") {
					t.Fatal("denied trace leaked", string(raw))
				}
				var bad struct{ Error *rpcengine.RPCError }
				if json.Unmarshal(raw, &bad) != nil || bad.Error == nil {
					t.Fatal("expected fixed error", string(raw))
				}
				return
			}
			object := traceObject(t, raw)
			if sealed.Method != "debug_traceCall" || sealed.ActorID == "" || sealed.DataOrg != orgA {
				t.Fatal("actual completion", sealed)
			}
			if scenario == "original-id" && !strings.Contains(string(raw), `"id":1.2500e+03`) {
				t.Fatal("raw id changed", string(raw))
			}
			if scenario == "root-revert" {
				if object["error"] != "execution reverted" || object["output"] != "0xdeadbeef" || sealed.Outcome != "evaluation-failed" || sealed.RPCError != nil {
					t.Fatal("root trace error shape", object, sealed)
				}
				return
			}
			child := object["calls"].([]any)[0].(map[string]any)
			parentAdmin := scenario == "parent-admin" || scenario == "both-admin"
			childAdmin := scenario == "child-admin" || scenario == "both-admin"
			if _, yes := child["input"]; yes != parentAdmin {
				t.Fatal("parent storage input", scenario, child)
			}
			if _, yes := child["output"]; yes != childAdmin {
				t.Fatal("own storage output", scenario, child)
			}
			if strings.Contains(string(raw), `"logs"`) || strings.Contains(string(raw), "prestateTracer") {
				t.Fatal("private mux field", string(raw))
			}
			methods, _ := n.counts()
			traces := 0
			for _, m := range methods {
				if m == "debug_traceCall" {
					traces++
				}
			}
			if traces != 1 {
				t.Fatal("second trace", traces)
			}
		})
	}
}
func TestClientTraceActualAppendOriginalSourceAndLifetime(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"positive", "genesis-change", "original-expiry", "append-failure", "wallet-revoke"} {
		t.Run(scenario, func(t *testing.T) {
			f := traceFixture()
			var clock atomic.Int64
			clock.Store(now)
			f.clock = &clock
			n := &node{}
			var wallets *walletops.Service
			if scenario == "wallet-revoke" {
				f.linkSigner = true
			}
			engine, tok, financial, _ := mountedRawEngine(t, f, n, d, false, creationMountOptions{walletService: func(s *walletops.Service) { wallets = s }})
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
				if scenario == "append-failure" {
					return fmt.Errorf("fixture append failure")
				}
				return nil
			}, "debug_traceCall", "bank_trace")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			body := traceBody("debug_traceCall")
			if scenario == "wallet-revoke" {
				body = strings.Replace(body, `"to":`, `"from":"`+signedValue(t, 9).Signer().Hex()+`","to":`, 1)
			}
			done := requestAsync(t, front.Client(), front.URL, tok, body, context.Background())
			await(t, entered)
			switch scenario {
			case "genesis-change":
				n.mu.Lock()
				n.genesisHeader = types.CopyHeader(n.genesisHeader)
				n.genesisHeader.Extra = []byte("new network during append")
				n.mu.Unlock()
			case "original-expiry":
				clock.Store(now + 1000)
			case "wallet-revoke":
				if _, err := wallets.Unlink(t.Context(), tok, signedValue(t, 9).Signer().Hex()); err != nil {
					t.Fatal(err)
				}
			}
			once.Do(func() { close(release) })
			raw := bodyResult(t, done)
			if scenario == "positive" {
				traceObject(t, raw)
			} else if strings.Contains(string(raw), "0xfeed") {
				t.Fatal("trace escaped final fence", scenario, string(raw))
			}
		})
	}
}

// These controls qualify the actual native/node/source gate directly. Audited
// HTTP/Append qualification is supplied separately above, not inferred here.
func TestClientTraceActualNativeScopeAndArguments(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"historical-no-admin", "historical-other-admin", "nested-linked-arg", "nested-unlinked-arg", "alias-positive", "create-positive", "fresh-call-denied", "scope-no-grant", "public9", "public10"} {
		t.Run(scenario, func(t *testing.T) {
			f := traceFixture()
			n := &node{}
			body := traceBody("debug_traceCall")
			want := true
			switch scenario {
			case "historical-no-admin", "historical-other-admin":
				body = strings.TrimSuffix(body, `]}`) + `,"0x1"]}`
				want = scenario == "historical-other-admin"
				if want {
					f.roles = append(f.roles, foreign)
					f.bGroups = []policybundle.Group{{ID: foreign, Slug: "other-admin", Name: "Other admin", IsOrgAdmin: true, AllowedMethods: []string{"eth_call"}, Claims: []string{}}}
				}
			case "alias-positive":
				body = traceBody("bank_trace")
			case "nested-linked-arg", "nested-unlinked-arg":
				abi := json.RawMessage(`[{"type":"function","name":"balanceOf","stateMutability":"view","inputs":[{"name":"who","type":"address"}],"outputs":[{"type":"uint256"}]}]`)
				var abiValue any
				json.Unmarshal(abi, &abiValue)
				canonical := encoded(t, abiValue)
				f.contracts[1].ABI = canonical
				for i, r := range f.bindings[0].Allow {
					if r.StorageAddress == addressC {
						f.bindings[0].Allow[i] = policycore.FrameRule{StorageAddress: addressC, Selector: "0x70a08231", ABIDigest: policycore.ABIDigest(string(canonical)), Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: policycore.AddressSourcePrincipalLinked}}}}
					}
				}
				f.capability(policybundle.CapabilityCalldata)
				f.capability(policybundle.CapabilityLinkedWallets)
				f.linkSigner = true
				who := signedValue(t, 9).Signer().Hex()
				if scenario == "nested-unlinked-arg" {
					who = walletAddress
					want = false
				}
				input := "0x70a08231" + strings.Repeat("0", 24) + strings.ToLower(who[2:])
				n.mutate = func(root map[string]any) {
					root["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressC, "input": input, "output": "0x1122", "value": "0x0", "gas": "0x100", "gasUsed": "0x1"}}
				}
			case "create-positive", "fresh-call-denied":
				n.pre = map[string]any{"0x5555555555555555555555555555555555555555": map[string]any{}}
				n.mutate = func(root map[string]any) {
					calls := []any{map[string]any{"type": "CREATE", "from": addressA, "to": "0x5555555555555555555555555555555555555555", "input": "0x6001", "output": "0x6000", "value": "0x0", "gas": "0x100", "gasUsed": "0x1"}}
					if scenario == "fresh-call-denied" {
						calls = append(calls, map[string]any{"type": "CALL", "from": addressA, "to": "0x5555555555555555555555555555555555555555", "input": "0x", "output": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1"})
					}
					root["calls"] = calls
				}
				want = scenario == "create-positive"
			case "scope-no-grant":
				f.contracts = f.contracts[:1]
				f.contracts[0].ReadGrants = []policybundle.ReadGrant{}
				f.bindings[0].Allow = []policycore.FrameRule{{TargetClass: "org", Selector: "*"}}
				f.runtime.AddressScopes = []policybundle.AddressScope{{Address: addressC, OrganizationID: orgA}}
				f.capability("policy.address-scopes/v1")
				body = strings.Replace(body, addressA, addressC, 1)
				want = false
			case "public9", "public10":
				target := "0x0000000000000000000000000000000000000009"
				if scenario == "public10" {
					target = "0x000000000000000000000000000000000000000a"
					want = false
				}
				body = strings.Replace(body, addressA, target, 1)
				f.bindings[0].Allow = append(f.bindings[0].Allow, policycore.FrameRule{TargetClass: "precompile", Selector: "*"})
			}
			e, tok, _, _ := mountedRawEngine(t, f, n, d, false)
			defer e.Close()
			r := e.TraceCallObserved(t.Context(), tok, orgA, []byte(body))
			raw, err := r.MarshalResponseFor(e)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Result map[string]any
				Error  *rpcengine.RPCError
			}
			if json.Unmarshal(raw, &wire) != nil {
				t.Fatal(string(raw))
			}
			if want {
				if wire.Error != nil || wire.Result == nil || r.RequireDeliverable(t.Context(), e) != nil {
					t.Fatal("actual native positive denied", scenario, string(raw))
				}
			} else if wire.Error == nil || wire.Result != nil {
				t.Fatal("scope/argument negative permitted", scenario, string(raw))
			}
		})
	}
}
