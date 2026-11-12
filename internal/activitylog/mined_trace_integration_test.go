package activitylog_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	a "privacy-proxy/internal/admission"
	share "privacy-proxy/internal/admissionsharedata"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/walletops"
)

// Finite honest-protocol fixture. Actual pinned-Reth qualification is separate;
// these tests cross real JWT, SQL roles, wallet proofs and durable Recorder.
type minedActivityNode struct {
	t          *testing.T
	tx         *types.Transaction
	signer     common.Address
	header     *types.Header
	rootChange func(map[string]any)
	orphan     bool
}

func newMinedActivityNode(t *testing.T) *minedActivityNode {
	v := signedValue(t, 9)
	var tx types.Transaction
	if tx.UnmarshalBinary(v.RawBytes()) != nil {
		t.Fatal("signed fixture")
	}
	return &minedActivityNode{t: t, tx: &tx, signer: v.Signer()}
}
func (m *minedActivityNode) respond(n *node, w http.ResponseWriter, id json.RawMessage, method string, params []json.RawMessage) bool {
	if m.header == nil && n.anchorHeader != nil {
		m.header = types.CopyHeader(n.anchorHeader)
		m.header.ParentHash = n.anchorHeader.Hash()
		m.header.Number = big.NewInt(2)
		m.header.Time = 11
		m.header.GasUsed = 21000
	}
	if m.header == nil {
		return false
	}
	h := m.header
	var result any
	switch method {
	case "eth_getHeaderByNumber":
		if len(params) == 0 || string(params[0]) != `"0x2"` {
			return false
		}
		result = h
		if m.orphan {
			other := types.CopyHeader(h)
			other.Extra = []byte("actual different canonical branch")
			result = other
		}
	case "eth_getTransactionByHash":
		result = minedActivityObject(m.t, m.tx)
		obj := result.(map[string]any)
		obj["from"], obj["blockHash"], obj["blockNumber"], obj["transactionIndex"] = m.signer.Hex(), h.Hash().Hex(), "0x2", "0x0"
	case "eth_getBlockByHash":
		result = minedActivityObject(m.t, h)
		obj := result.(map[string]any)
		obj["transactions"], obj["uncles"], obj["withdrawals"] = []any{m.tx.Hash().Hex()}, []any{}, []any{}
	case "eth_getTransactionReceipt":
		status := "0x1"
		root := m.root()
		if root["error"] != nil {
			status = "0x0"
		}
		result = map[string]any{"transactionHash": m.tx.Hash().Hex(), "blockHash": h.Hash().Hex(), "blockNumber": "0x2", "transactionIndex": "0x0", "from": m.signer.Hex(), "to": m.tx.To().Hex(), "type": "0x0", "contractAddress": nil, "status": status, "gasUsed": "0x5208", "cumulativeGasUsed": "0x5208", "effectiveGasPrice": "0x1", "logsBloom": "0x" + strings.Repeat("00", 256), "logs": []any{}}
	case "debug_traceTransaction":
		var config map[string]any
		_ = json.Unmarshal(params[1], &config)
		if config["tracer"] != "muxTracer" {
			m.t.Error("not actual mined mux")
		}
		cfg := config["tracerConfig"].(map[string]any)
		call := cfg["callTracer"].(map[string]any)
		if call["withLog"] != false {
			m.t.Error("mined client requested logs")
		}
		root := m.root()
		if call["onlyTopCall"] == true {
			delete(root, "calls")
		}
		result = map[string]any{"callTracer": root, "prestateTracer": map[string]any{m.signer.Hex(): map[string]any{"nonce": 9}, addressA: map[string]any{"code": "0x6000", "nonce": 1}, addressB: map[string]any{"code": "0x6000", "nonce": 1}, addressC: map[string]any{"code": "0x6000", "nonce": 1}}, "flatCallTracer": []any{map[string]any{"blockHash": h.Hash().Hex(), "blockNumber": h.Number.Uint64(), "transactionHash": m.tx.Hash().Hex(), "transactionPosition": 0, "traceAddress": []any{}}}}
	default:
		return false
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	return true
}
func (m *minedActivityNode) root() map[string]any {
	r := map[string]any{"type": "CALL", "from": m.signer.Hex(), "to": m.tx.To().Hex(), "input": "0x" + common.Bytes2Hex(m.tx.Data()), "value": "0x" + m.tx.Value().Text(16), "gas": "0x186a0", "gasUsed": "0x5208", "output": "0xfeed", "calls": []any{map[string]any{"type": "CALL", "from": addressA, "to": addressC, "input": "0x11223344", "value": "0x1", "gas": "0x100", "gasUsed": "0x1", "output": "0xdeadbeef"}}}
	if m.rootChange != nil {
		m.rootChange(r)
	}
	return r
}
func minedActivityObject(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("typed fixture")
	}
	return out
}

func minedActivityFixture() fixture {
	f := traceFixture()
	f.readOnly = true
	f.linkSigner = true
	m := *f.methodCatalog
	m.Assignable = append(m.Assignable, "debug_traceTransaction", "bank_mined")
	aliases := map[string]string{}
	for k, v := range m.Aliases {
		aliases[k] = v
	}
	aliases["bank_mined"] = "debug_traceTransaction"
	m.Aliases = aliases
	f.methodCatalog = &m
	f.groups[0].AllowedMethods = []string{"debug_traceTransaction", "bank_mined", "eth_getStorageAt"}
	return f
}

func TestMinedTraceActualWalletSQLRecorderAndProfileRules(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"standard-positive", "guard-mode-positive", "strict-participant-no-policy", "strict-outsider", "standard-outsider", "listed-positive", "listed-no-nested-grant", "no-nested-grant", "wrong-function", "foreign-nested", "root-revert", "notification", "raw-id", "public-floor-outsider"} {
		t.Run(scenario, func(t *testing.T) {
			f := minedActivityFixture()
			if scenario == "guard-mode-positive" {
				f.rawMode = policybundle.RawSubmissionGuardV1
			}
			n := &node{mined: newMinedActivityNode(t)}
			want := true
			listed := scenario == "listed-positive" || scenario == "listed-no-nested-grant"
			if strings.HasPrefix(scenario, "strict-") {
				f.runtime.ReadProfile = "strict"
			}
			if scenario == "strict-participant-no-policy" {
				f.bindings = []policycore.Binding{}
				for i := range f.contracts {
					f.contracts[i].ReadGrants = []policybundle.ReadGrant{}
				}
			}
			if scenario == "strict-outsider" || scenario == "standard-outsider" || listed {
				f.linkSigner = false
			}
			switch scenario {
			case "public-floor-outsider":
				f.capability(policybundle.CapabilitySharedCode)
				f.linkSigner = false
				f.contracts = f.contracts[1:]
				f.creationAttribution.Factories = []policybundle.FactoryAttribution{}
				f.bindings = []policycore.Binding{}
				f.runtime.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: addressA}}
				want = false
			case "strict-outsider", "standard-outsider":
				want = false
			case "listed-no-nested-grant", "no-nested-grant":
				f.contracts[1].ReadGrants = []policybundle.ReadGrant{}
				want = false
			case "wrong-function":
				f.bindings[0].Allow = f.bindings[0].Allow[:1]
				want = false
			case "foreign-nested":
				n.mined.rootChange = func(r map[string]any) {
					r["calls"] = []any{map[string]any{"type": "CALL", "from": addressA, "to": addressB, "input": "0x", "value": "0x0", "gas": "0x100", "gasUsed": "0x1", "output": "0xdeadbeef"}}
				}
				want = false
			case "root-revert":
				n.mined.rootChange = func(r map[string]any) { r["error"] = "execution reverted"; r["output"] = "0xbabe" }
			}
			engine, tok, financial, _ := mountedMinedActivityEngine(t, f, n, d, listed, nil)
			defer engine.Close()
			net := financial.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			x := setupActivityDatabase(t, network)
			rec := rpcRecorder(t, x, func() time.Time { return time.Unix(now, 0) }, nil, "debug_traceTransaction", "bank_mined")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			body := `{"jsonrpc":"2.0","id":"mined","method":"debug_traceTransaction","params":["` + n.mined.tx.Hash().Hex() + `"]}`
			if scenario == "notification" {
				body = strings.Replace(body, `"id":"mined",`, "", 1)
			}
			if scenario == "raw-id" {
				body = strings.Replace(body, `"id":"mined"`, `"id":1.2500e+03`, 1)
			}
			before := metadataRows(t, x)
			raw := bodyResult(t, requestAsync(t, front.Client(), front.URL, tok, body, context.Background()))
			sealed := metadataSealedOne(t, x, before)
			if sealed.Method != "debug_traceTransaction" {
				t.Fatal("wrong actual completion", sealed)
			}
			if scenario == "notification" {
				if len(raw) != 0 {
					t.Fatal("notification body", string(raw))
				}
				return
			}
			if !want {
				var wire struct{ Error *rpcengine.RPCError }
				if json.Unmarshal(raw, &wire) != nil || wire.Error == nil || strings.Contains(string(raw), "deadbeef") || strings.Contains(string(raw), "0xfeed") {
					t.Fatal("hidden mined trace escaped", string(raw))
				}
				return
			}
			object := traceObject(t, raw)
			if f.runtime.ReadProfile == "strict" {
				if object["calls"] != nil {
					t.Fatal("strict participant got nested calls")
				}
			} else if scenario != "root-revert" {
				child := object["calls"].([]any)[0].(map[string]any)
				if child["input"] != nil || child["output"] != nil {
					t.Fatal("plain grant got nested private values", child)
				}
			}
			if scenario == "root-revert" && (object["output"] != "0xbabe" || sealed.Outcome != "evaluation-failed" || sealed.RPCError != nil) {
				t.Fatal("revert object changed", object, sealed)
			}
			if scenario == "raw-id" && !strings.Contains(string(raw), `"id":1.2500e+03`) {
				t.Fatal("raw id changed", string(raw))
			}
		})
	}
}

func mountedMinedActivityEngine(t *testing.T, f fixture, n *node, d rawDatabase, listed bool, walletService func(*walletops.Service)) (*rpcengine.Engine, string, *a.Service, *policybundle.CatalogSnapshot) {
	t.Helper()
	var mining rpcengine.MinedTraceOptions
	return mountedRawEngine(t, f, n, d, false, creationMountOptions{walletService: walletService,
		configure: func(options *rpcengine.RawOptions) {
			backend := httptest.NewTLSServer(n)
			t.Cleanup(backend.Close)
			clients := map[string]*rpcexecution.Client{}
			for _, org := range []string{orgA, orgB} {
				c, err := rpcexecution.NewClient(backend.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: backend.URL, ChainID: "1", Profile: rpcexecution.SimulationCallProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				clients[org] = c
			}
			options.CallClients = clients
			u, _ := url.Parse(d.ownerDSN)
			u.User = url.UserPassword("raw_reader", "raw-test-only")
			store, err := admissionsql.OpenReader(t.Context(), u.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(store.Close)
			net := options.Admission.Metadata().Network
			network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
			state := options.AssociationBinding.State
			expected := share.ShareBinding{Network: network, State: a.ExpectedState{Generation: state.Generation, Coverage: a.Digest(state.Coverage)}, SchemaProfile: share.ShareSchemaProfile}
			reader, err := admissionsql.NewShareReader(store, expected)
			if err != nil {
				t.Fatal(err)
			}
			mining = rpcengine.MinedTraceOptions{Shares: reader, ShareExpected: expected}
		},
		constructor: func(snapshot *policybundle.CatalogSnapshot, options rpcengine.RawOptions) (*rpcengine.Engine, error) {
			if listed {
				factory, err := runtimepolicy.NewFactory(snapshot, func() time.Time { return time.Unix(now, 0) })
				if err != nil {
					t.Fatal(err)
				}
				view, err := factory.Build(token(t, snapshot, f.roles))
				if err != nil {
					t.Fatal(err)
				}
				writer, err := admissionsql.Open(t.Context(), d.appDSN)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				key, _ := mining.ShareExpected.Network.Key()
				scope := a.Scope{Network: a.Digest(key), State: mining.ShareExpected.State, Hash: n.mined.tx.Hash(), Actor: view.ActorID(), Organization: orgA}
				recipients, digest, err := a.NormalizeRecipients([]string{view.ActorID()})
				if err != nil {
					t.Fatal(err)
				}
				row := a.Share{Network: scope.Network, Hash: scope.Hash, Actor: scope.Actor, Organization: orgA, Recipients: recipients, RecipientDigest: digest, DeclaredAt: time.Unix(now, 0).UTC(), Witness: a.Witness{AnchorHash: n.anchorHeader.Hash(), AnchorNumber: 1, AnchorTimestamp: 10, ManifestDigest: a.Digest{1}, WalletVersion: a.Digest{2}, WalletEvidenceAt: time.Unix(now, 0).UTC()}}
				receipt, err := writer.WithRawTransaction(t.Context(), scope, func(tx a.RawTx) (a.CommitKind, error) { return a.CommitAllow, tx.PutShare(row) })
				if err != nil || !receipt.Committed {
					t.Fatal("actual admitted share writer", err)
				}
			}
			return rpcengine.NewCreationObservedWithMinedTrace(snapshot, options, mining)
		},
	})
}

func TestMinedTraceActualAppendRevocationAndOriginalNodeFence(t *testing.T) {
	d := rawPostgres(t)
	if _, err := d.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"positive", "wallet-revoke", "share-revoke", "original-expiry", "same-chain-genesis-change", "canonical-node-reorg", "append-failure"} {
		t.Run(scenario, func(t *testing.T) {
			f := minedActivityFixture()
			var clock atomic.Int64
			clock.Store(now)
			f.clock = &clock
			listed := scenario == "share-revoke"
			if listed {
				f.linkSigner = false
			}
			n := &node{mined: newMinedActivityNode(t)}
			var wallets *walletops.Service
			engine, tok, financial, _ := mountedMinedActivityEngine(t, f, n, d, listed, func(s *walletops.Service) { wallets = s })
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
			}, "debug_traceTransaction", "bank_mined")
			service, err := rpcactivity.New(rpcactivity.Config{Engine: engine, Recorder: rec, Network: network})
			if err != nil {
				t.Fatal(err)
			}
			handler, _ := service.Handler(orgA)
			front := httptest.NewTLSServer(handler)
			defer front.Close()
			body := `{"jsonrpc":"2.0","id":"original","method":"debug_traceTransaction","params":["` + n.mined.tx.Hash().Hex() + `"]}`
			done := requestAsync(t, front.Client(), front.URL, tok, body, context.Background())
			await(t, entered)
			switch scenario {
			case "wallet-revoke":
				if _, err := wallets.Unlink(t.Context(), tok, n.mined.signer.Hex()); err != nil {
					t.Fatal(err)
				}
			case "share-revoke":
				key, _ := network.Key()
				if _, err := d.owner.Exec(t.Context(), `DELETE FROM ops_admission_v2.tx_shares WHERE network_key=$1 AND tx_hash=$2`, key[:], n.mined.tx.Hash().Bytes()); err != nil {
					t.Fatal(err)
				}
			case "original-expiry":
				clock.Store(now + 1000)
			case "same-chain-genesis-change":
				n.mu.Lock()
				n.genesisHeader = types.CopyHeader(n.genesisHeader)
				n.genesisHeader.Extra = []byte("different network during real append")
				n.mu.Unlock()
			case "canonical-node-reorg":
				n.mu.Lock()
				n.mined.orphan = true
				n.mu.Unlock()
			}
			once.Do(func() { close(release) })
			raw := bodyResult(t, done)
			if scenario == "positive" {
				traceObject(t, raw)
			} else if strings.Contains(string(raw), "0xfeed") || strings.Contains(string(raw), "deadbeef") {
				t.Fatal("protected mined trace escaped original final fence", scenario, string(raw))
			}
		})
	}
}
