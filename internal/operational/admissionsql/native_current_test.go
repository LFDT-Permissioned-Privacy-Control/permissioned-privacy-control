package admissionsql_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	log "privacy-proxy/internal/activitylog"
	a "privacy-proxy/internal/admission"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcstatepolicy"
)

// Real covered intent -> included proof -> observer publication -> restricted
// facts role -> original JWT/native evaluator -> TLS/Recorder/Pebble. The node
// is a finite protocol fixture; this does not claim a production-node campaign.
func TestNativeCurrentActualPublishedA2ReadonlyAndPostAppendSQL(t *testing.T) {
	d := setupObserver(t)
	node, originScope, intent, snap, included := newObservedWork(t, d)
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
			groups[i].AllowedMethods = []string{"eth_call"}
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
	bad := options
	bad.AssociationBinding.SourceSet = f.Digest{99}
	if _, err := rpcengine.NewCreationObserved(snapshot, bad); err == nil {
		t.Fatal("foreign independently selected read source accepted")
	}
	token := df.Token(t, snapshot, df.AdminSubject, "Admin")
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + node.child.Hex() + `"}]}`
	if out := engine.Call(t.Context(), token, df.OtherOrg, []byte(body)); out.Result != nil {
		t.Fatal("selected foreign org borrowed dynamic owner", out)
	}
	if out := engine.Call(t.Context(), token, df.Org, []byte(body)); out.Result == nil || *out.Result != "0xcafe" {
		t.Fatal("actual published FACTORY owner not consumed", out)
	}
	t.Run("actual-dynamic-runtime-and-birth-basis", func(t *testing.T) {
		for _, code := range []string{"0x6001", "0x600001"} {
			mu.Lock()
			nativeCode = code
			mu.Unlock()
			if out := engine.Call(t.Context(), token, df.Org, []byte(body)); out.Result != nil || out.Error == nil {
				t.Fatal("unmatched actual runtime inherited current namespace", code, out)
			}
		}
		mu.Lock()
		nativeCode = "0x6000"
		mu.Unlock()
		old := `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + node.child.Hex() + `"},"0x0"]}`
		if out := engine.Call(t.Context(), token, df.Org, []byte(old)); out.Result != nil || out.Error == nil {
			t.Fatal("matching code before published birth qualified", out)
		}
		orphan := types.CopyHeader(original)
		orphan.Extra = []byte("old-same-height-branch")
		mu.Lock()
		orphans[orphan.Hash()] = orphan
		mu.Unlock()
		old = `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + node.child.Hex() + `"},"` + orphan.Hash().Hex() + `"]}`
		if out := engine.Call(t.Context(), token, df.Org, []byte(old)); out.Result != nil || out.Error == nil {
			t.Fatal("same-height wrong birth hash qualified", out)
		}
		canonical2 := &types.Header{Number: big.NewInt(2), ParentHash: original.Hash(), Difficulty: big.NewInt(0), Time: original.Time + 1, GasLimit: 30000000, BaseFee: big.NewInt(1)}
		orphan2 := types.CopyHeader(canonical2)
		orphan2.ParentHash = orphan.Hash()
		orphan2.Extra = []byte("orphan-later-than-birth")
		mu.Lock()
		orphans[orphan2.Hash()] = orphan2
		mu.Unlock()
		node.mu.Lock()
		node.header = canonical2
		node.mu.Unlock()
		old = `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"` + node.child.Hex() + `"},{"blockHash":"` + orphan2.Hash().Hex() + `","requireCanonical":false}]}`
		if out := engine.Call(t.Context(), token, df.Org, []byte(old)); out.Result != nil || out.Error == nil {
			t.Fatal("same-runtime orphan later than birth qualified", out)
		}
		// Explicit current Git authority retains the existing noncanonical
		// historical selector behavior; only derived dynamic authority tightens.
		staticFixture := fixture
		staticFixture.Contracts = map[string][]policybundle.Contract{df.Org: {df.ReadContract(node.child.Hex())}, df.OtherOrg: {}}
		staticSnapshot := df.StateSnapshot(t, staticFixture)
		staticFinancial, err := a.NewCreationObserved(a.Config{Snapshot: staticSnapshot, Clock: wall, NetworkBinding: a.NetworkBinding{Environment: network.Environment, ChainID: network.ChainID, GenesisHash: network.GenesisHash, DeploymentID: network.DeploymentID}, ExpectedState: a.ExpectedState{Generation: binding.State.Generation, Coverage: a.Digest(binding.State.Coverage)}, Store: d.app, ExpectedEvidenceProfile: rpcexecution.LifecycleSignedProfileID, CursorKeyring: a.CursorKeyring{Active: a.CursorKey{ID: "static", Key: []byte(strings.Repeat("y", 32))}}, CaptureGate: gate})
		if err != nil {
			t.Fatal(err)
		}
		staticOptions := options
		staticOptions.Admission = staticFinancial
		counter := &countNativeReader{CurrentAddressReader: reader}
		staticOptions.Associations = counter
		staticEngine, err := rpcengine.NewCreationObserved(staticSnapshot, staticOptions)
		if err != nil {
			t.Fatal(err)
		}
		defer staticEngine.Close()
		out := staticEngine.Call(t.Context(), df.Token(t, staticSnapshot, df.AdminSubject, "Admin"), df.Org, []byte(old))
		if out.Result == nil || *out.Result != "0xcafe" || counter.reads.Load() != 0 {
			t.Fatalf("dynamic basis restriction changed static Git authority: result=%v error=%+v reads=%d", out.Result, out.Error, counter.reads.Load())
		}
		node.mu.Lock()
		node.header = types.CopyHeader(original)
		node.mu.Unlock()
	})
	recorder, scope, activityOwner := currentAddressActualRecorder(t, d, network, &clock, []string{"eth_call", "eth_sendRawTransaction"})
	service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: recorder, Network: network})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(df.Org)
	front := httptest.NewTLSServer(handler)
	defer front.Close()
	for _, mode := range []string{"positive", "node-reorg-during-successful-final-SQL", "expiry-during-successful-final-SQL"} {
		t.Run(mode, func(t *testing.T) {
			var oldRows int
			if err := activityOwner.QueryRow(t.Context(), `SELECT row_count FROM ops_activity_v1.sources WHERE network_key=$1`, scope.NetworkKey[:]).Scan(&oldRows); err != nil {
				t.Fatal(err)
			}
			clock.Store(df.Now)
			node.mu.Lock()
			node.header = types.CopyHeader(original)
			node.mu.Unlock()
			h := &traceHold{make(chan struct{}), make(chan struct{})}
			mu.Lock()
			hold = h
			mu.Unlock()
			var once sync.Once
			defer once.Do(func() { close(h.release) })
			done := make(chan []byte, 1)
			go func() {
				req, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL, strings.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+token)
				resp, err := front.Client().Do(req)
				if err != nil {
					done <- nil
					return
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				done <- b
			}()
			select {
			case <-h.entered:
			case <-time.After(2 * time.Second):
				t.Fatal("dynamic current owner did not reach exact trace")
			}
			lock, err := d.db.owner.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Rollback(context.Background())
			if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_admission_v2.creation_authority_associations IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			numericBefore := finalHeaders.Load()
			once.Do(func() { close(h.release) })
			until := time.Now().Add(200 * time.Millisecond)
			for {
				var waiting bool
				if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='creation_facts' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting {
					break
				}
				if time.Now().After(until) {
					t.Fatal("real final facts SELECT never blocked")
				}
				time.Sleep(time.Millisecond)
			}
			if finalHeaders.Load() != numericBefore+1 {
				t.Fatal("more than the one initial execution-anchor sample preceded final blocking SQL")
			}
			if mode == "node-reorg-during-successful-final-SQL" {
				node.mu.Lock()
				node.header = types.CopyHeader(original)
				node.header.Extra = []byte("actual-backend-reorg-stale-SQL")
				node.mu.Unlock()
			}
			if mode == "expiry-during-successful-final-SQL" {
				clock.Store(df.Now + 300)
			}
			if err := lock.Commit(t.Context()); err != nil {
				t.Fatal(err)
			}
			var wire []byte
			select {
			case wire = <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("actual final query/output did not finish")
			}
			if mode == "positive" {
				if !strings.Contains(string(wire), `"result":"0xcafe"`) {
					t.Fatal("positive failed", string(wire))
				}
			} else if strings.Contains(string(wire), "0xcafe") || !strings.Contains(string(wire), `"code":-32002`) {
				t.Fatal("late source change leaked protected data", string(wire))
			}
			// Final validation follows the actual synchronous append; selected
			// completion remains successful even when its output was withheld.
			until = time.Now().Add(3 * time.Second)
			for {
				var count int
				var encoded []byte
				err := activityOwner.QueryRow(t.Context(), `SELECT s.row_count,l.request_params FROM ops_activity_v1.sources s LEFT JOIN ops_activity_v1.qualified_logs l ON l.chain_name=s.chain_name AND l.id=s.head_id WHERE s.network_key=$1`, scope.NetworkKey[:]).Scan(&count, &encoded)
				if err != nil {
					t.Fatal(err)
				}
				if count == oldRows+1 {
					var env log.Envelope
					if json.Unmarshal(encoded, &env) == nil && env.Outcome == "success" {
						break
					}
				}
				if time.Now().After(until) {
					t.Fatal("selected real completion not sealed", string(encoded))
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
	clock.Store(df.Now)
	node.mu.Lock()
	node.header = types.CopyHeader(original)
	node.mu.Unlock()
	mu.Lock()
	hold = nil
	mu.Unlock()
	t.Run("actual-state-current-scope-isolation", func(t *testing.T) {
		stateClient, err := rpcexecution.NewStateClient(backend.Client().Transport, rpcexecution.StateSource{Network: network, URL: backend.URL, AllowUnauthenticated: true}, rpcexecution.Credential{}, rpcexecution.DefaultStateLimits())
		if err != nil {
			t.Fatal(err)
		}
		stateFixture := df.DefaultStateFixture(t)
		runtime, _ := snapshot.Runtime()
		source, _ := runtime.CreationObservedSource()
		empty := common.HexToAddress("0xdead000000000000000000000000000000000000")
		source.AddressScopes = []policybundle.AddressScope{{Address: node.child.Hex(), OrganizationID: df.OtherOrg}, {Address: empty.Hex(), OrganizationID: df.OtherOrg}}
		stateFixture.Runtime = &source
		makeState := func(fixture df.StateFixture) (*rpcengine.StateEngine, *policybundle.CatalogSnapshot, *countNativeReader) {
			t.Helper()
			snapshot := df.StateSnapshot(t, fixture)
			raw, _ := json.Marshal(rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: []string{}, PreRegisteredAddresses: []rpcstatepolicy.PreRegisteredAddress{}})
			definition, err := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
			if err != nil {
				t.Fatal(err)
			}
			counted := &countNativeReader{CurrentAddressReader: reader}
			engine, err := rpcengine.NewState(rpcengine.StateConfig{Snapshot: snapshot, Policy: definition, Network: network, Default: stateClient, Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{{OrganizationID: df.Org}: stateClient, {OrganizationID: df.OtherOrg}: stateClient}, Associations: counted, AssociationBinding: binding, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: wall})
			if err != nil {
				t.Fatal(err)
			}
			return engine, snapshot, counted
		}
		state, stateSnapshot, _ := makeState(stateFixture)
		adminBoth := df.Token(t, stateSnapshot, df.AdminSubject, "Admin", "Foreign")
		query := func(engine *rpcengine.StateEngine, token, org, address, method string) *rpcengine.StateOperationResult {
			params := `["` + address + `","latest"]`
			if method == "eth_getProof" {
				params = `["` + address + `",[],"latest"]`
			}
			return engine.QueryObserved(t.Context(), rpcengine.MetadataAuthorization([]string{"Bearer " + token}), org, []byte(`{"id":1,"method":"`+method+`","params":`+params+`}`))
		}
		for _, item := range []struct{ name, target, org string }{{"scope-current-owner-blocks-old-org", node.child.Hex(), df.Org}, {"scope-alone-no-registration", empty.Hex(), df.OtherOrg}, {"factory-old-namespace-no-current-admin", node.child.Hex(), df.OtherOrg}} {
			t.Run(item.name, func(t *testing.T) {
				r := query(state, adminBoth, item.org, item.target, "eth_getCode")
				m, err := r.MetadataFor(state)
				if err != nil || m.Class != rpcengine.DeniedCompletion {
					t.Fatal("scope ignored or became registration/association", m, err)
				}
			})
		}
		// Current Git registration/grant wins the old published namespace and
		// performs no A3 read, even with another namespace in the actual reader.
		git := stateFixture
		c := df.ReadContract(node.child.Hex())
		c.ReadGrants[0].GroupID = df.ForeignGroup
		git.Contracts = map[string][]policybundle.Contract{df.Org: {}, df.OtherOrg: {c}}
		gitState, gitSnapshot, counter := makeState(git)
		r := query(gitState, df.Token(t, gitSnapshot, df.AdminSubject, "Admin", "Foreign"), df.OtherOrg, node.child.Hex(), "eth_getCode")
		m, err := r.MetadataFor(gitState)
		if err != nil || m.Class != rpcengine.SuccessfulCompletion || counter.reads.Load() != 0 || r.RequireDeliverable(t.Context(), gitState) != nil {
			t.Fatal("old A3 overrode current Git positive", m, err, counter.reads.Load())
		}
		// Real late WALLET publication supplies only the original actor's plain
		// association under the selected current owner; it does not make scope
		// a registered/admin proof or an unrestricted getProof capability.
		witness := creationWitness(intent, "native-scope-wallet")
		intent.Wallet = &a.CreationWalletAuthority{Actor: originScope.Actor, Organization: originScope.Organization, Witness: witness.ID}
		metadata := creationcapture.Metadata{Network: binding.Network, State: binding.State, SourceSet: binding.SourceSet, Reference: binding.Reference}
		coverage := coverageRecord(metadata, snap, snap.State.Floor)
		_, err = d.app.WithCoveredRawTransaction(t.Context(), originScope, a.CaptureCommitBinding{ObserverEpoch: coverage.ObserverEpoch, CaptureEpoch: coverage.CaptureEpoch, SourceSet: coverage.SourceSet}, func(raw a.RawTx) (a.CommitKind, error) {
			if _, err := raw.PutOrigin(a.Origin{Network: originScope.Network, Hash: originScope.Hash, Actor: originScope.Actor, Organization: originScope.Organization, FirstAdmittedAt: intent.CapturedAt, Primary: witness}); err != nil {
				return 0, err
			}
			_, err := raw.(a.CoveredCreationRawTx).PutCoveredCreationIntent(intent, coverage)
			return a.CommitAllow, err
		})
		if err != nil {
			t.Fatal(err)
		}
		_, q := acquireObserved(t, d, snap, included)
		if err := d.observer.PublishCreationObservation(t.Context(), q); err != nil {
			t.Fatal(err)
		}
		walletToken := df.Token(t, stateSnapshot, df.Subject, "Auditor", "Foreign")
		r = query(state, walletToken, df.OtherOrg, node.child.Hex(), "eth_getCode")
		m, err = r.MetadataFor(state)
		if err != nil || m.Class != rpcengine.SuccessfulCompletion || r.RequireDeliverable(t.Context(), state) != nil {
			t.Fatal("genuine actor plain fallback lost", m, err)
		}
		r = query(state, walletToken, df.OtherOrg, node.child.Hex(), "eth_getProof")
		m, err = r.MetadataFor(state)
		if err != nil || m.Class != rpcengine.DeniedCompletion {
			t.Fatal("WALLET/scope invented current private-storage admin", m, err)
		}
	})
	t.Run("execution-orphaned-after-actual-Append", func(t *testing.T) {
		clock.Store(df.Now)
		canonical := &types.Header{Number: big.NewInt(2), ParentHash: original.Hash(), Difficulty: big.NewInt(0), Time: original.Time + 1, GasLimit: 30000000, BaseFee: big.NewInt(1)}
		node.mu.Lock()
		node.header = canonical
		node.mu.Unlock()
		h := &traceHold{make(chan struct{}), make(chan struct{})}
		mu.Lock()
		hold = h
		mu.Unlock()
		var once sync.Once
		defer once.Do(func() { close(h.release) })
		done := make(chan []byte, 1)
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := front.Client().Do(req)
			if err != nil {
				done <- nil
				return
			}
			wire, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			done <- wire
		}()
		select {
		case <-h.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("dynamic original execution not acquired")
		}
		lock, err := d.db.owner.Begin(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Rollback(context.Background())
		if _, err := lock.Exec(t.Context(), `LOCK TABLE ops_admission_v2.creation_authority_associations IN ACCESS EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		once.Do(func() { close(h.release) })
		until := time.Now().Add(200 * time.Millisecond)
		for {
			var waiting bool
			if err := lock.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE usename='creation_facts' AND wait_event_type='Lock')`).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if time.Now().After(until) {
				t.Fatal("post-Append final facts read never waited")
			}
			time.Sleep(time.Millisecond)
		}
		fork := types.CopyHeader(canonical)
		fork.Extra = []byte("new-canonical-tip-same-original-observer-head")
		node.mu.Lock()
		node.header = fork
		node.mu.Unlock()
		if err := lock.Commit(t.Context()); err != nil {
			t.Fatal(err)
		}
		select {
		case wire := <-done:
			if strings.Contains(string(wire), "0xcafe") || !strings.Contains(string(wire), `"code":-32002`) {
				t.Fatal("orphaned execution leaked despite canonical old observer head", string(wire))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("late execution-anchor fence did not settle")
		}
		node.mu.Lock()
		node.header = types.CopyHeader(original)
		node.mu.Unlock()
		mu.Lock()
		hold = nil
		mu.Unlock()
	})
	t.Run("actual-SQL-observer-advance-retains-original-head", func(t *testing.T) {
		clock.Store(df.Now)
		h := &traceHold{make(chan struct{}), make(chan struct{})}
		mu.Lock()
		hold = h
		mu.Unlock()
		var once sync.Once
		defer once.Do(func() { close(h.release) })
		done := make(chan []byte, 1)
		go func() {
			req, _ := http.NewRequestWithContext(t.Context(), "POST", front.URL, strings.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := front.Client().Do(req)
			if err != nil {
				done <- nil
				return
			}
			wire, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			done <- wire
		}()
		select {
		case <-h.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("original A3 pass never acquired")
		}
		latest, err := d.observer.ReadObserver(t.Context(), snap.Lease)
		if err != nil {
			t.Fatal(err)
		}
		next := &types.Header{Number: big.NewInt(2), ParentHash: original.Hash(), Difficulty: big.NewInt(0), Time: original.Time + 1, GasLimit: 30000000, BaseFee: big.NewInt(1)}
		head := f.Header{Number: 2, Hash: next.Hash(), Parent: next.ParentHash, Timestamp: next.Time}
		if _, err := d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: latest, Common: latest.State.Head, Headers: []f.Header{head}, Tip: head}); err != nil {
			t.Fatal("actual observer prefix advance", err)
		}
		node.mu.Lock()
		node.header = next
		node.mu.Unlock()
		once.Do(func() { close(h.release) })
		select {
		case wire := <-done:
			if !strings.Contains(string(wire), `"result":"0xcafe"`) {
				t.Fatal("normal actual observer progress rejected", string(wire))
			}
		case <-time.After(3 * time.Second):
			t.Fatal("observer progress request did not finish")
		}
	})
}

type countNativeReader struct {
	f.CurrentAddressReader
	reads atomic.Int32
}

func (r *countNativeReader) ReadAddressAssociations(ctx context.Context, target common.Address) (*f.AddressAssociations, error) {
	r.reads.Add(1)
	return r.CurrentAddressReader.ReadAddressAssociations(ctx, target)
}
