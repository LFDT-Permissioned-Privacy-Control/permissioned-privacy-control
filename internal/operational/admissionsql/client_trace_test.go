package admissionsql_test

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"io"
	"net/http"
	"net/http/httptest"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientTraceActualPublishedRuntimeAndRecorder(t *testing.T) {
	d := setupObserver(t)
	node, _, _, snap, included := newObservedWork(t, d)
	_, qualified := acquireObserved(t, d, snap, included)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal(err)
	}
	binding := f.AddressReadBinding{Network: included.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	reader, err := admissionsql.NewAddressReader(d.facts, binding)
	if err != nil {
		t.Fatal(err)
	}
	network := networkidentity.Binding{Environment: binding.Network.Environment, ChainID: binding.Network.ChainID, GenesisHash: binding.Network.Genesis.Hex(), DeploymentID: binding.Network.Deployment}
	fixture := df.DefaultStateFixture(t)
	for org, groups := range fixture.Groups {
		for i := range groups {
			groups[i].AllowedMethods = []string{"eth_call", "debug_traceCall", "eth_getStorageAt"}
		}
		fixture.Groups[org] = groups
	}
	fixture.Execution = map[string]*policycore.Policy{df.Org: {APIVersion: policycore.NativeV4APIVersion, Kind: policycore.Kind, Org: df.Org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{{Group: df.AdminGroup, Allow: []policycore.FrameRule{{TargetClass: "org", Selector: "*"}}}}}}
	snapshot := df.StateSnapshot(t, fixture)
	var clock atomic.Int64
	clock.Store(df.Now)
	wall := func() time.Time { return time.Unix(clock.Load(), 0) }
	wallet := df.ActualWalletFixture(t, t.Context(), d.db.ownerDSN, snapshot, network, wall)
	// This instance owns NO send lane; global A3 reader still selects the
	// actual nonempty writer source set which published the birth above.
	gate, err := creationcapture.New(creationcapture.Options{Network: binding.Network, State: binding.State, Reference: included.Source(), Sources: []f.Source{}, CaughtUpAssertion: f.CaughtUpAssertion, Store: d.app})
	if err != nil {
		t.Fatal(err)
	}
	if gate.Metadata().SourceSet == binding.SourceSet {
		t.Fatal("read-only control did not distinguish source sets")
	}
	financial, err := a.NewCreationObserved(a.Config{Snapshot: snapshot, Clock: wall, NetworkBinding: a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}, ExpectedState: a.ExpectedState{Generation: binding.State.Generation, Coverage: a.Digest(binding.State.Coverage)}, Store: d.app, ExpectedEvidenceProfile: rpcexecution.LifecycleSignedProfileID, CursorKeyring: a.CursorKeyring{Active: a.CursorKey{ID: "test", Key: []byte(strings.Repeat("x", 32))}}, CaptureGate: gate})
	if err != nil {
		t.Fatal(err)
	}
	type traceHold struct{ entered, release chan struct{} }
	var mu sync.Mutex
	var hold *traceHold
	nativeCode := "0x6000"
	orphans := map[common.Hash]*types.Header{}
	var finalHeaders atomic.Int32
	original := types.CopyHeader(node.header)
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var q struct {
			ID     json.RawMessage
			Method string
			Params []json.RawMessage
		}
		if json.Unmarshal(raw, &q) != nil {
			t.Error("typed request")
			return
		}
		if q.Method == "debug_traceCall" {
			mu.Lock()
			h := hold
			code := nativeCode
			mu.Unlock()
			if h != nil {
				close(h.entered)
				<-h.release
			}
			root := map[string]any{"type": "CALL", "from": common.Address{}.Hex(), "to": node.child.Hex(), "input": "0x", "value": "0x0", "gas": "0x100000", "gasUsed": "0x20", "output": "0xcafe"}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": map[string]any{"callTracer": root, "prestateTracer": map[string]any{node.child.Hex(): map[string]any{"code": code}, common.Address{}.Hex(): map[string]any{"code": "0x"}}}})
			return
		}
		if q.Method == "eth_getCode" && len(q.Params) > 0 && strings.EqualFold(string(q.Params[0]), `"`+node.child.Hex()+`"`) {
			mu.Lock()
			code := nativeCode
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": code})
			return
		}
		if q.Method == "eth_getBlockByHash" && len(q.Params) > 0 {
			var hash string
			_ = json.Unmarshal(q.Params[0], &hash)
			mu.Lock()
			header := orphans[common.HexToHash(hash)]
			mu.Unlock()
			if header != nil {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": header})
				return
			}
		}
		if q.Method == "eth_getBlockByNumber" && len(q.Params) > 0 && string(q.Params[0]) == `"0x0"` {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": node.genesis})
			return
		}
		if q.Method == "eth_getCode" && len(q.Params) > 0 && strings.EqualFold(string(q.Params[0]), `"`+common.Address{}.Hex()+`"`) {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": "0x"})
			return
		}
		if q.Method == "eth_getHeaderByNumber" && len(q.Params) > 0 && string(q.Params[0]) == `"0x1"` {
			finalHeaders.Add(1)
			node.mu.Lock()
			if node.header.Number.Uint64() == 2 && node.header.ParentHash == original.Hash() {
				node.mu.Unlock()
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": original})
				return
			}
			node.mu.Unlock()
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		node.serve(w, r)
	}))
	defer backend.Close()
	clients := map[string]*rpcexecution.Client{}
	for _, org := range []string{df.Org, df.OtherOrg} {
		c, err := rpcexecution.NewClient(backend.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: backend.URL, ChainID: "1", Profile: rpcexecution.SimulationCallProfileID, PragueStartInclusive: 1, PragueEndExclusive: 1 << 63, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		clients[org] = c
	}
	options := rpcengine.RawOptions{CallClients: clients, RawNodes: map[string]rpcengine.RawNodeOptions{}, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, Admission: financial, CaptureGate: gate, Clock: wall, Associations: reader, AssociationBinding: binding}
	engine, err := rpcengine.NewCreationObserved(snapshot, options)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	recorder, _, _ := currentAddressActualRecorder(t, d, network, &clock, []string{"eth_call", "eth_sendRawTransaction", "debug_traceCall"})
	service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(df.Org)
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	token := df.Token(t, snapshot, df.AdminSubject, "Admin")
	request := `{"jsonrpc":"2.0","id":1,"method":"debug_traceCall","params":[{"to":"` + node.child.Hex() + `"}]}`
	for _, scenario := range []string{"positive", "published-code-mismatch", "wrong-selected-org"} {
		t.Run(scenario, func(t *testing.T) {
			mu.Lock()
			nativeCode = "0x6000"
			if scenario == "published-code-mismatch" {
				nativeCode = "0x6001"
			}
			mu.Unlock()
			target := front.URL
			if scenario == "wrong-selected-org" {
				h, _ := service.Handler(df.OtherOrg)
				f := httptest.NewTLSServer(h)
				defer f.Close()
				target = f.URL
			}
			req, _ := http.NewRequest("POST", target, strings.NewReader(request))
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Content-Type", "application/json")
			client := front.Client()
			if scenario == "wrong-selected-org" {
				client = &http.Client{Transport: front.Client().Transport}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if scenario == "positive" {
				var wire struct {
					Result map[string]any
					Error  *rpcengine.RPCError
				}
				if json.Unmarshal(raw, &wire) != nil || wire.Error != nil || wire.Result["output"] != "0xcafe" {
					t.Fatal("genuine published birth not consumed", string(raw))
				}
			} else if strings.Contains(string(raw), "cafe") {
				t.Fatal("unqualified trace escaped", scenario, string(raw))
			}
		})
	}
}
