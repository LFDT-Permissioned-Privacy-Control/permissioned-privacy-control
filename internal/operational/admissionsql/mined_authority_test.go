package admissionsql_test

import (
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	a "privacy-proxy/internal/admission"
	share "privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/creationcapture"
	f "privacy-proxy/internal/creationfacts"
	df "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
)

// Real covered intent/included qualification/publication and restricted A3 SQL
// are consumed by the mined facade. The controlled node deliberately reports
// before/equal birth points with matching old runtime as negative contradictions;
// this is authority-boundary coverage, not a claim of live-node replay behavior.
func TestMinedActualPublishedBirthOrdinalsRuntimeAndCurrentGit(t *testing.T) {
	d := setupObserver(t)
	node, _, _, snap, included := newObservedWork(t, d, func(n *observedNode) { n.header.GasUsed = 96; n.index = 1 })
	_, qualified := acquireObserved(t, d, snap, included)
	if err := d.observer.PublishCreationObservation(t.Context(), qualified); err != nil {
		t.Fatal(err)
	}
	binding := f.AddressReadBinding{Network: included.Source().Network, State: snap.Lease.State, SourceSet: snap.Lease.SourceSet, Reference: snap.Lease.Reference, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	actual, err := admissionsql.NewAddressReader(d.facts, binding)
	if err != nil {
		t.Fatal(err)
	}
	reader := &countNativeReader{CurrentAddressReader: actual}
	network := networkidentity.Binding{Environment: binding.Network.Environment, ChainID: binding.Network.ChainID, GenesisHash: binding.Network.Genesis.Hex(), DeploymentID: binding.Network.Deployment}
	fixture := df.DefaultStateFixture(t)
	for _, method := range []string{"debug_traceTransaction", "bank_mined"} {
		if !slices.Contains(fixture.Methods.Assignable, method) {
			fixture.Methods.Assignable = append(fixture.Methods.Assignable, method)
		}
	}
	if fixture.Methods.Aliases == nil {
		fixture.Methods.Aliases = map[string]string{}
	}
	fixture.Methods.Aliases["bank_mined"] = "debug_traceTransaction"
	for org, groups := range fixture.Groups {
		for i := range groups {
			groups[i].AllowedMethods = []string{"debug_traceTransaction", "bank_mined", "eth_getStorageAt"}
		}
		fixture.Groups[org] = groups
	}
	fixture.Execution = map[string]*policycore.Policy{}
	for org, group := range map[string]string{df.Org: df.AdminGroup, df.OtherOrg: df.ForeignGroup} {
		fixture.Execution[org] = &policycore.Policy{APIVersion: policycore.NativeV4APIVersion, Kind: policycore.Kind, Org: org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{{Group: group, Allow: []policycore.FrameRule{{TargetClass: "org", Selector: "*"}}}}}
	}
	snapshot := df.StateSnapshot(t, fixture)
	wall := func() time.Time { return time.Unix(df.Now, 0) }
	wallet := df.ActualWalletFixture(t, t.Context(), d.db.ownerDSN, snapshot, network, wall)
	gate, err := creationcapture.New(creationcapture.Options{Network: binding.Network, State: binding.State, Reference: included.Source(), Sources: []f.Source{}, CaughtUpAssertion: f.CaughtUpAssertion, Store: d.app})
	if err != nil {
		t.Fatal(err)
	}
	store, err := admissionsql.OpenReader(t.Context(), d.db.readerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	shareBinding := share.ShareBinding{Network: network, State: a.ExpectedState{Generation: binding.State.Generation, Coverage: a.Digest(binding.State.Coverage)}, SchemaProfile: share.ShareSchemaProfile}
	shares, err := admissionsql.NewShareReader(store, shareBinding)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := crypto.HexToECDSA(strings.Repeat("22", 32))
	tx, err := types.SignNewTx(key, types.LatestSignerForChainID(big.NewInt(1)), &types.LegacyTx{Nonce: 1, To: &node.child, Gas: 500000, GasPrice: big.NewInt(1), Value: new(big.Int), Data: []byte{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	var mu sync.Mutex
	point := uint32(2)
	height := uint64(1)
	code := "0x6000"
	var later *types.Header
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		var q struct {
			ID     json.RawMessage
			Method string
			Params []json.RawMessage
		}
		if json.Unmarshal(raw, &q) != nil {
			t.Error("typed mined request")
			return
		}
		mu.Lock()
		index, number, runtime := point, height, code
		head2 := later
		mu.Unlock()
		h := node.header
		if number == 0 {
			h = node.genesis
		}
		var result any
		handled := true
		switch q.Method {
		case "eth_getTransactionByHash":
			obj := observedObject(t, tx)
			obj["from"], obj["blockHash"], obj["blockNumber"], obj["transactionIndex"] = signer.Hex(), h.Hash().Hex(), fmtHex(number), fmtHex(uint64(index))
			result = obj
		case "eth_getTransactionReceipt":
			result = map[string]any{"transactionHash": tx.Hash().Hex(), "blockHash": h.Hash().Hex(), "blockNumber": fmtHex(number), "transactionIndex": fmtHex(uint64(index)), "from": signer.Hex(), "to": node.child.Hex(), "type": "0x0", "contractAddress": nil, "status": "0x1", "gasUsed": "0x20", "cumulativeGasUsed": "0x20", "effectiveGasPrice": "0x1", "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
			if number == 0 {
				result.(map[string]any)["gasUsed"], result.(map[string]any)["cumulativeGasUsed"] = "0x0", "0x0"
			}
		case "eth_getBlockByHash":
			obj := observedObject(t, h)
			hashes := []any{common.Hash{99}.Hex(), node.tx.Hash().Hex(), common.Hash{100}.Hex()}
			hashes[index] = tx.Hash().Hex()
			obj["transactions"], obj["uncles"], obj["withdrawals"] = hashes, []any{}, []any{}
			result = obj
		case "debug_traceTransaction":
			root := map[string]any{"type": "CALL", "from": signer.Hex(), "to": node.child.Hex(), "input": "0x0102", "value": "0x0", "gas": "0x7a120", "gasUsed": "0x20", "output": "0xcafe"}
			if number == 0 {
				root["gasUsed"] = "0x0"
			}
			result = map[string]any{"callTracer": root, "prestateTracer": map[string]any{signer.Hex(): map[string]any{"nonce": 1}, node.child.Hex(): map[string]any{"code": runtime}}, "flatCallTracer": []any{map[string]any{"blockHash": h.Hash().Hex(), "blockNumber": number, "transactionHash": tx.Hash().Hex(), "transactionPosition": index, "traceAddress": []any{}}}}
		case "eth_getHeaderByNumber":
			if len(q.Params) > 0 && string(q.Params[0]) == `"0x2"` && head2 != nil {
				result = head2
			} else {
				handled = false
			}
		default:
			handled = false
		}
		if handled {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		node.serve(w, r)
	}))
	defer backend.Close()
	makeEngine := func(selected *policybundle.CatalogSnapshot) *rpcengine.Engine {
		t.Helper()
		financial, err := a.NewCreationObserved(a.Config{Snapshot: selected, Clock: wall, NetworkBinding: a.NetworkBinding(network), ExpectedState: shareBinding.State, Store: d.app, ExpectedEvidenceProfile: rpcexecution.LifecycleSignedProfileID, CursorKeyring: a.CursorKeyring{Active: a.CursorKey{ID: "test", Key: []byte(strings.Repeat("x", 32))}}, CaptureGate: gate})
		if err != nil {
			t.Fatal(err)
		}
		clients := map[string]*rpcexecution.Client{}
		for _, org := range []string{df.Org, df.OtherOrg} {
			client, err := rpcexecution.NewClient(backend.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: backend.URL, ChainID: "1", Profile: rpcexecution.SimulationCallProfileID, PragueStartInclusive: 1, PragueEndExclusive: 1 << 63, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			clients[org] = client
		}
		engine, err := rpcengine.NewCreationObservedWithMinedTrace(selected, rpcengine.RawOptions{CallClients: clients, RawNodes: map[string]rpcengine.RawNodeOptions{}, Wallets: wallet.Resolver, WalletBinding: wallet.Binding, WalletState: wallet.State, Admission: financial, CaptureGate: gate, Clock: wall, Associations: reader, AssociationBinding: binding}, rpcengine.MinedTraceOptions{Shares: shares, ShareExpected: shareBinding})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(engine.Close)
		return engine
	}
	engine := makeEngine(snapshot)
	token := df.Token(t, snapshot, df.AdminSubject, "Admin")
	query := func(e *rpcengine.Engine, token, org, method string) []byte {
		t.Helper()
		r := e.TraceTransactionObserved(t.Context(), token, org, []byte(`{"id":1,"method":"`+method+`","params":["`+tx.Hash().Hex()+`"]}`))
		wire, err := r.MarshalResponseFor(e)
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, scenario := range []string{"after", "equal", "before", "runtime-mismatch", "alias", "wrong-org"} {
		t.Run(scenario, func(t *testing.T) {
			mu.Lock()
			point, height, code = 2, 1, "0x6000"
			if scenario == "equal" {
				point = 1
			}
			if scenario == "before" {
				point, height = 0, 1
			}
			if scenario == "runtime-mismatch" {
				code = "0x6001"
			}
			mu.Unlock()
			org, method := df.Org, "debug_traceTransaction"
			if scenario == "wrong-org" {
				org = df.OtherOrg
			}
			if scenario == "alias" {
				method = "bank_mined"
			}
			raw := query(engine, token, org, method)
			want := scenario == "after" || scenario == "alias"
			if strings.Contains(string(raw), "cafe") != want {
				t.Fatal("actual published mined authority", scenario, string(raw))
			}
		})
	}
	mu.Lock()
	point, height, code = 2, 1, "0x6000"
	later = types.CopyHeader(node.header)
	later.Number = big.NewInt(2)
	later.ParentHash = node.header.Hash()
	later.Time++
	head := later
	mu.Unlock()
	first := f.Header{Number: 1, Hash: node.header.Hash(), Parent: node.header.ParentHash, Timestamp: node.header.Time}
	second := f.Header{Number: 2, Hash: head.Hash(), Parent: head.ParentHash, Timestamp: head.Time}
	if _, err = d.observer.PublishObserverHeaders(t.Context(), f.HeaderUpdate{Before: snap, Common: first, Headers: []f.Header{second}, Tip: second}); err != nil {
		t.Fatal("actual observer progress", err)
	}
	if raw := query(engine, token, df.Org, "debug_traceTransaction"); !strings.Contains(string(raw), "cafe") {
		t.Fatal("normal observer progress broke original mined anchor", string(raw))
	}
	if _, err = d.db.owner.Exec(t.Context(), `UPDATE ops_admission_v2.creation_observer_state SET ready=false,capture_ready=false,capture_heartbeat_until=NULL WHERE network_key=$1`, binding.Network.Key[:]); err != nil {
		t.Fatal(err)
	}
	if raw := query(engine, token, df.Org, "debug_traceTransaction"); strings.Contains(string(raw), "cafe") {
		t.Fatal("unready dynamic facts granted mined output")
	}
	git := fixture
	registered := df.ReadContract(node.child.Hex())
	registered.ReadGrants[0].GroupID = df.ForeignGroup
	git.Contracts = map[string][]policybundle.Contract{df.Org: {}, df.OtherOrg: {registered}}
	selected := df.StateSnapshot(t, git)
	current := makeEngine(selected)
	reader.reads.Store(0)
	mu.Lock()
	code = "0x6001"
	mu.Unlock()
	if raw := query(current, df.Token(t, selected, df.AdminSubject, "Foreign"), df.OtherOrg, "debug_traceTransaction"); !strings.Contains(string(raw), "cafe") || reader.reads.Load() != 0 {
		t.Fatal("old/unready A3 overrode current Git registration", string(raw), reader.reads.Load())
	}
}

func fmtHex(n uint64) string { return "0x" + new(big.Int).SetUint64(n).Text(16) }
