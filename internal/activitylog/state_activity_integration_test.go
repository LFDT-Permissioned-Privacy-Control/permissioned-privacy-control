package activitylog_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
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
	f "privacy-proxy/internal/creationfacts"
	d "privacy-proxy/internal/disclosuretest"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/operational/rpcactivity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcstatepolicy"
)

const stateInfra = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

func stateNode(t *testing.T) *metadataNode {
	n := newMetadataNode(t)
	n.mu.Lock()
	defer n.mu.Unlock()
	n.result["eth_getBalance"] = "0x2a"
	n.result["eth_getCode"] = "0x6000"
	n.result["eth_getStorageAt"] = "0x" + strings.Repeat("00", 32)
	n.result["eth_getTransactionCount"] = "0x7"
	n.result["eth_getProof"] = map[string]any{"address": addressA, "accountProof": []string{"0xc0"}, "balance": "0x0", "nonce": "0x1", "codeHash": "0x" + strings.Repeat("a", 64), "storageHash": types.EmptyRootHash.Hex(), "storageProof": []any{}}
	return n
}
func stateDefinition(t *testing.T, snapshot *policybundle.CatalogSnapshot, anonymous []string, pre []rpcstatepolicy.PreRegisteredAddress) *rpcstatepolicy.Definition {
	t.Helper()
	raw := encoded(t, rpcstatepolicy.Source{APIVersion: rpcstatepolicy.APIVersion, Kind: rpcstatepolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: anonymous, PreRegisteredAddresses: pre})
	p, err := rpcstatepolicy.Compile(raw, rpcstatepolicy.Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func stateClient(t *testing.T, n *metadataNode, ref, value string) *rpcexecution.StateClient {
	return stateClientForNetwork(t, n, n.network(), ref, value)
}
func stateClientForNetwork(t *testing.T, n *metadataNode, network networkidentity.Binding, ref, value string) *rpcexecution.StateClient {
	t.Helper()
	source := rpcexecution.StateSource{Network: network, URL: n.server.URL, CredentialRef: ref, AllowUnauthenticated: ref == ""}
	credential := rpcexecution.Credential{}
	if ref != "" {
		source.CredentialHeader = "Idempotency-Key"
		credential = rpcexecution.Credential{Header: source.CredentialHeader, Value: value}
	}
	c, err := rpcexecution.NewStateClient(n.server.Client().Transport, source, credential, rpcexecution.DefaultStateLimits())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Adding the one-MiB state parser must not move it ahead of native dispatch.
// Both actual services settle the same >one-MiB raw request through Pebble and
// retain the full original ID even though the signed transaction is invalid.
func TestStateActivityPreservesNativeTwoMiBBodyAndExactID(t *testing.T) {
	db := rawPostgres(t)
	if _, err := db.owner.Exec(t.Context(), `CREATE ROLE raw_observer LOGIN PASSWORD 'raw-test-only';CREATE ROLE raw_facts LOGIN PASSWORD 'raw-test-only'`); err != nil {
		t.Fatal(err)
	}
	fixture := metadataFixture()
	for method := rpcexecution.StateBalance; method <= rpcexecution.StateNonce; method++ {
		name := method.String()
		found := false
		for _, present := range fixture.methodCatalog.Assignable {
			found = found || present == name
		}
		if !found {
			fixture.methodCatalog.Assignable = append(fixture.methodCatalog.Assignable, name)
			fixture.groups[0].AllowedMethods = append(fixture.groups[0].AllowedMethods, name)
		}
	}
	var clock atomic.Int64
	clock.Store(now)
	fixture.clock = &clock
	nativeNode := &node{}
	native, tok, financial, snapshot := mountedRawEngine(t, fixture, nativeNode, db, false)
	net := financial.Metadata().Network
	network := networkidentity.Binding{Environment: net.Environment, ChainID: net.ChainID, GenesisHash: net.GenesisHash, DeploymentID: net.DeploymentID}
	n := stateNode(t)
	n.mu.Lock()
	n.genesis = nativeNode.genesisHeader
	n.mu.Unlock()
	config := stateConfig(t, n, snapshot, &clock)
	config.Network = network
	config.Default = stateClientForNetwork(t, n, network, "default", "state-default")
	for key := range config.Clients {
		config.Clients[key] = stateClientForNetwork(t, n, network, key.CredentialRef, "state-selected")
	}
	state := stateEngine(t, config)
	x := setupActivityDatabase(t, network)
	id := strings.Repeat("x", 1200<<10)
	body := `{"jsonrpc":"2.0","id":"` + id + `","method":"eth_sendRawTransaction","params":["0x00"]}`
	var original []byte
	for _, withState := range []bool{false, true} {
		before := metadataRows(t, x)
		recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, nil, state.OperationBinding().Methods...)
		c := rpcactivity.Config{Engine: native, Recorder: recorder, Network: network}
		if withState {
			c.State = state
		}
		service, err := rpcactivity.New(c)
		if err != nil {
			t.Fatal(err)
		}
		handler, err := service.Handler(orgA)
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewTLSServer(handler)
		wire := bodyResult(t, requestAsync(t, server.Client(), server.URL, tok, body, t.Context()))
		server.Close()
		var result struct {
			ID    string
			Error json.RawMessage
		}
		if json.Unmarshal(wire, &result) != nil || result.ID != id || len(result.Error) == 0 {
			t.Fatal("raw two-MiB parser/ID behavior changed", withState, len(wire))
		}
		if !withState {
			original = wire
		} else if string(wire) != string(original) {
			t.Fatal("adding state changed native wire response")
		}
		sealed := metadataSealedOne(t, x, before)
		if sealed.Method != "eth_sendRawTransaction" {
			t.Fatal("raw route normalized into another family", sealed.Method)
		}
	}
	if n.count() != 0 {
		t.Fatal("raw request passed through state parser/client")
	}
}
func stateConfig(t *testing.T, n *metadataNode, snapshot *policybundle.CatalogSnapshot, clock *atomic.Int64) rpcengine.StateConfig {
	t.Helper()
	c := rpcengine.StateConfig{Snapshot: snapshot, Policy: stateDefinition(t, snapshot, []string{}, []rpcstatepolicy.PreRegisteredAddress{}), Network: n.network(), Default: stateClient(t, n, "default", "state-default"), Clients: map[rpcengine.StateBindingKey]*rpcexecution.StateClient{}, QueryLimits: rpcexecution.DefaultStateLimits(), Clock: func() time.Time { return time.Unix(clock.Load(), 0) }}
	for _, org := range snapshot.Organizations() {
		for _, id := range snapshot.GroupIDs(org.ID) {
			g, _ := snapshot.Group(org.ID, id)
			needed := false
			for _, name := range g.AllowedMethods {
				info, known := snapshot.Method(name)
				if !known {
					continue
				}
				for method := rpcexecution.StateBalance; method <= rpcexecution.StateNonce; method++ {
					needed = needed || info.Canonical == method.String()
				}
			}
			if needed {
				ref := ""
				if g.RpcCredential != nil {
					ref = g.RpcCredential.FromEnv
				}
				c.Clients[rpcengine.StateBindingKey{OrganizationID: org.ID, CredentialRef: ref}] = stateClient(t, n, ref, "state-selected")
			}
		}
	}
	return c
}
func stateEngine(t *testing.T, c rpcengine.StateConfig) *rpcengine.StateEngine {
	t.Helper()
	e, err := rpcengine.NewState(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func stateQuery(t *testing.T, e *rpcengine.StateEngine, headers []string, org, method, params string) (*rpcengine.StateOperationResult, []byte) {
	t.Helper()
	r := e.QueryObserved(t.Context(), rpcengine.MetadataAuthorization(headers), org, metadataRequest(method, params))
	if err := r.PreflightFor(e); err != nil {
		t.Fatal("state preflight", err)
	}
	body, err := r.MarshalResponseFor(e)
	if err != nil {
		t.Fatal(err)
	}
	return r, body
}
func stateReadSnapshot(t *testing.T, change func(*d.StateFixture)) *policybundle.CatalogSnapshot {
	t.Helper()
	f := d.DefaultStateFixture(t)
	f.Contracts[d.Org] = []policybundle.Contract{d.ReadContract(addressA)}
	if change != nil {
		change(&f)
	}
	return d.StateSnapshot(t, f)
}

// Pure trusted-adapter fixture for Core decision controls. Actual restricted
// PG/writer/proof/publication/Recheck qualification is tested in admissionsql.
type stateFacts struct {
	meta            f.AddressReaderMetadata
	rows            []f.AddressAssociation
	head            f.Header
	reads, rechecks atomic.Int32
	fail            bool
	recheck         func(context.Context) error
}

func (s *stateFacts) Metadata() f.AddressReaderMetadata { return s.meta }
func (s *stateFacts) ReadAddressAssociations(ctx context.Context, target common.Address) (*f.AddressAssociations, error) {
	s.reads.Add(1)
	if s.fail || ctx.Err() != nil {
		return nil, errors.New("owned source unavailable")
	}
	return f.NewAddressAssociations(s.meta.Identity, s.meta.Binding, target, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", 0, s.head, s.rows)
}
func (s *stateFacts) RecheckAddressAssociations(ctx context.Context, p *f.AddressAssociations) error {
	s.rechecks.Add(1)
	if p.ValidateFor(s.meta.Identity, s.meta.Binding, p.Target()) != nil {
		return f.ErrInvalid
	}
	if s.recheck != nil {
		return s.recheck(ctx)
	}
	return nil
}
func stateFactsFixture(n *metadataNode, target common.Address, namespace, actor string) *stateFacts {
	net := n.network()
	key, _ := net.Key()
	b := f.AddressReadBinding{Network: f.Network{Key: f.Digest(key), Environment: net.Environment, ChainID: net.ChainID, Genesis: common.HexToHash(net.GenesisHash), Deployment: net.DeploymentID}, State: f.State{Generation: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}, SourceSet: f.Digest{1}, Reference: f.Digest{2}, Profile: f.CurrentAddressProfile, Limits: f.DefaultAddressReadLimits()}
	anchor := f.Header{Number: 1, Hash: common.Hash{1}}
	at := time.Unix(100, 0)
	kind := "FACTORY"
	if actor != "" {
		kind = "WALLET"
	}
	coverage := f.CoverageRecord{Version: 1, Policy: f.CaptureProfile, Network: b.Network.Key, State: f.State{Generation: "cccccccc-cccc-cccc-cccc-cccccccccccc"}, ObserverEpoch: "dddddddd-dddd-dddd-dddd-dddddddddddd", CaptureEpoch: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", SourceSet: f.Digest{3}, Reference: f.Digest{4}, Ingress: f.Digest{5}, HighWater: anchor, Latest: anchor, HeaderVersion: 1, LeaseFence: 1, ProbeStarted: at, ProbeFinished: at.Add(time.Millisecond), ValidUntil: at.Add(time.Second)}
	n.mu.Lock()
	head := &types.Header{Number: big.NewInt(2), ParentHash: n.genesis.Hash(), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 3}
	if n.headers == nil {
		n.headers = map[string]*types.Header{}
	}
	n.headers["0x2"] = head
	n.mu.Unlock()
	row := f.AddressAssociation{Namespace: namespace, Kind: kind, WalletActor: actor, Address: target, Creator: common.HexToAddress(addressC), CreationKind: "CREATE", Record: 1, Inclusion: f.Header{Number: 2, Hash: head.Hash()}, TransactionHash: common.Hash{3}, OutputHash: common.Hash{4}, Proof: common.Hash{5}, OutputLength: 2, Seed: f.Digest{6}, Plan: f.Digest{7}, Manifest: f.Digest{8}, Runtime: f.Digest{9}, Qualification: f.Digest{10}, PlannedEntry: 0, Branch: 1, OriginalProfile: "geth-prague-lifecycle-signed/v1", OriginalAnchor: anchor, OriginalCoverage: coverage}
	return &stateFacts{meta: f.AddressReaderMetadata{Binding: b, Identity: f.NewAddressReaderIdentity()}, rows: []f.AddressAssociation{row}, head: f.Header{Number: 2, Hash: head.Hash()}}
}

func TestStateAuthorityActualApprovedJWTAndTLS(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := stateReadSnapshot(t, nil)
	config := stateConfig(t, n, snapshot, &clock)
	e := stateEngine(t, config)
	headers := []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Admin")}
	for method := rpcexecution.StateBalance; method <= rpcexecution.StateNonce; method++ {
		t.Run(method.String(), func(t *testing.T) {
			params := `["` + addressA + `","latest"]`
			if method == rpcexecution.StateStorage {
				params = `["` + addressA + `","` + stateInfra + `","latest"]`
			}
			if method == rpcexecution.StateProof {
				params = `["` + addressA + `",[],"latest"]`
			}
			before := n.count()
			r, wire := stateQuery(t, e, headers, d.Org, method.String(), params)
			m, _ := r.MetadataFor(e)
			if m.Class != rpcengine.SuccessfulCompletion || m.ActorID != d.Actor(d.Subject) || m.OrganizationID != d.Org || n.count()-before != 3 || !strings.Contains(string(wire), `"id":9007199254740993`) {
				t.Fatal(m, string(wire), n.count()-before)
			}
			if err := r.RequireDeliverable(t.Context(), e); err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("plain-reader-infra-and-proof-floor", func(t *testing.T) {
		h := []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}
		_, body := stateQuery(t, e, h, d.Org, "eth_getStorageAt", `["`+addressA+`","`+stateInfra+`"]`)
		if strings.Contains(string(body), `"error"`) {
			t.Fatal(string(body))
		}
		before := n.count()
		_, body = stateQuery(t, e, h, d.Org, "eth_getStorageAt", `["`+addressA+`","0x0"]`)
		requireMetadataCode(t, body, -32001)
		_, body = stateQuery(t, e, h, d.Org, "eth_getProof", `["`+addressA+`",[]]`)
		requireMetadataCode(t, body, -32001)
		if n.count() != before {
			t.Fatal("nonadmin proof/storage queried node")
		}
	})
	t.Run("zero-org-and-readonly-not-target-permission", func(t *testing.T) {
		before := n.count()
		for _, roles := range [][]string{{"Unmapped"}, {"Readonly"}, {"Local"}} {
			_, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, roles...)}, d.Org, "eth_getBalance", `["`+addressA+`"]`)
			requireMetadataCode(t, body, -32001)
		}
		if n.count() != before {
			t.Fatal("unmapped/readonly/globaladmin inferred target grant")
		}
	})
	t.Run("historical-any-org-admin-not-contractadmin", func(t *testing.T) {
		for _, roles := range [][]string{{"Auditor"}, {"Local"}} {
			_, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, roles...)}, d.Org, "eth_getBalance", `["`+addressA+`","0x1"]`)
			requireMetadataCode(t, body, -32001)
		}
		r, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor", "Foreign")}, d.Org, "eth_getBalance", `["`+addressA+`","0x1"]`)
		m, _ := r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion {
			t.Fatal(m, string(body))
		}
	})
	t.Run("genuine-contract-admin-is-not-historical-org-admin", func(t *testing.T) {
		s := stateReadSnapshot(t, func(f *d.StateFixture) { f.Contracts[d.Org][0].ReadGrants[0].GroupID = d.LocalGroup })
		engine := stateEngine(t, stateConfig(t, n, s, &clock))
		h := []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}
		r, body := stateQuery(t, engine, h, d.Org, "eth_getProof", `["`+addressA+`",[],"latest"]`)
		m, _ := r.MetadataFor(engine)
		if m.Class != rpcengine.SuccessfulCompletion {
			t.Fatal("real contract admin not established", m, string(body))
		}
		before := n.count()
		_, body = stateQuery(t, engine, h, d.Org, "eth_getProof", `["`+addressA+`",[],"0x1"]`)
		requireMetadataCode(t, body, -32001)
		if n.count() != before {
			t.Fatal("contract-admin bypassed original historical floor")
		}
	})
	t.Run("readonly-with-actual-readgrant-is-plain-reader", func(t *testing.T) {
		s := stateReadSnapshot(t, func(f *d.StateFixture) { f.Contracts[d.Org][0].ReadGrants[0].GroupID = d.ReadonlyGroup })
		engine := stateEngine(t, stateConfig(t, n, s, &clock))
		h := []string{"Bearer " + d.Token(t, s, d.Subject, "Readonly")}
		r, body := stateQuery(t, engine, h, d.Org, "eth_getCode", `["`+addressA+`"]`)
		m, _ := r.MetadataFor(engine)
		if m.Class != rpcengine.SuccessfulCompletion {
			t.Fatal("genuine readonly readgrant lost", m, string(body))
		}
		_, body = stateQuery(t, engine, h, d.Org, "eth_getProof", `["`+addressA+`",[]]`)
		requireMetadataCode(t, body, -32001)
	})
	t.Run("raw-alias-and-canonical-claim-union", func(t *testing.T) {
		f := d.DefaultStateFixture(t)
		f.Contracts[d.Org] = []policybundle.Contract{d.ReadContract(addressA)}
		f.Methods.Assignable = append(f.Methods.Assignable, "bank_balance")
		f.Methods.Aliases["bank_balance"] = "eth_getBalance"
		f.Methods.RequiredClaims["bank_balance"] = "deploy"
		f.Methods.RequiredClaims["eth_getBalance"] = "upgrade"
		f.Contracts[d.Org][0].ReadGrants[0].GroupID = d.LocalGroup
		for org, groups := range f.Groups {
			for i := range groups {
				groups[i].AllowedMethods = []string{"eth_getCode"}
				if groups[i].ID == d.LocalGroup {
					groups[i].AllowedMethods = []string{"eth_getBalance", "bank_balance"}
					groups[i].Claims = []string{"deploy", "upgrade"}
				}
			}
			f.Groups[org] = groups
		}
		s := d.StateSnapshot(t, f)
		info, _ := s.Method("bank_balance")
		if len(info.RequiredClaims) != 2 || info.RequiredClaims[0] != "deploy" || info.RequiredClaims[1] != "upgrade" {
			t.Fatal("lost actual raw+canonical claim union", info)
		}
		engine := stateEngine(t, stateConfig(t, n, s, &clock))
		r, body := stateQuery(t, engine, []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}, d.Org, "bank_balance", `["`+addressA+`"]`)
		m, _ := r.MetadataFor(engine)
		if m.Class != rpcengine.SuccessfulCompletion || m.Method != "bank_balance" {
			t.Fatal(m, string(body))
		}
		_, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}, d.Org, "BANK_BALANCE", `["`+addressA+`"]`)
		requireMetadataCode(t, body, -32601)
		for i := range f.Groups[d.Org] {
			if f.Groups[d.Org][i].ID == d.LocalGroup {
				f.Groups[d.Org][i].AllowedMethods = []string{"eth_getBalance"}
			}
		}
		s = d.StateSnapshot(t, f)
		engine = stateEngine(t, stateConfig(t, n, s, &clock))
		_, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}, d.Org, "bank_balance", `["`+addressA+`"]`)
		requireMetadataCode(t, body, -32001)
	})
	t.Run("proof-presence-both-backends-and-null", func(t *testing.T) {
		n.mu.Lock()
		original := n.result["eth_getProof"]
		n.mu.Unlock()
		defer func() { n.mu.Lock(); n.result["eth_getProof"] = original; n.mu.Unlock() }()
		for _, mode := range []string{"geth-zero", "reth-empty", "null-proof", "positive-code"} {
			n.mu.Lock()
			proof := map[string]any{"address": addressA, "accountProof": []string{"0xc0"}, "balance": "0x0", "nonce": "0x0", "codeHash": common.Hash{}.Hex(), "storageHash": common.Hash{}.Hex(), "storageProof": []any{}}
			if mode == "reth-empty" {
				proof["codeHash"] = types.EmptyCodeHash.Hex()
				proof["storageHash"] = types.EmptyRootHash.Hex()
			}
			if mode == "null-proof" {
				proof["nonce"] = "0x1"
				proof["accountProof"] = nil
			}
			if mode == "positive-code" {
				proof["codeHash"] = "0x" + strings.Repeat("a", 64)
			}
			n.result["eth_getProof"] = proof
			n.mu.Unlock()
			r, body := stateQuery(t, e, headers, d.Org, "eth_getProof", `["`+addressA+`",[]]`)
			m, _ := r.MetadataFor(e)
			if mode == "positive-code" {
				if m.Class != rpcengine.SuccessfulCompletion {
					t.Fatal(mode, string(body))
				}
			} else {
				requireMetadataCode(t, body, -32002)
			}
		}
	})
}

func TestStateAuthorityGitPriorityActualDeployerAndHeader(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := stateReadSnapshot(t, nil)
	target := common.HexToAddress(addressA)
	facts := stateFactsFixture(n, target, d.OtherOrg, d.Actor(d.Subject))
	facts.fail = true
	c := stateConfig(t, n, snapshot, &clock)
	c.Associations, c.AssociationBinding = facts, facts.meta.Binding
	e := stateEngine(t, c)
	r, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	m, _ := r.MetadataFor(e)
	if m.Class != rpcengine.SuccessfulCompletion || facts.reads.Load() != 0 {
		t.Fatal("current Git positive permission consulted old A2", m, string(body))
	}
	before := n.count()
	_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor", "Foreign")}, d.OtherOrg, "eth_getCode", `["`+addressA+`"]`)
	requireMetadataCode(t, body, -32002)
	if n.count() != before {
		t.Fatal("selected foreign org borrowed Git grant")
	}
	facts.fail = false
	r, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Readonly", "Foreign")}, d.OtherOrg, "eth_getCode", `["`+addressA+`"]`)
	m, _ = r.MetadataFor(e)
	if m.Class != rpcengine.SuccessfulCompletion || m.OrganizationID != d.OtherOrg {
		t.Fatal("genuine WALLET/current Git owner exception lost", m, string(body))
	}
	if err := r.RequireDeliverable(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Readonly", "Foreign")}, d.OtherOrg, "eth_getProof", `["`+addressA+`",[]]`)
	requireMetadataCode(t, body, -32001)
	facts.rows[0].Kind = "FACTORY"
	facts.rows[0].WalletActor = ""
	_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Readonly")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	requireMetadataCode(t, body, -32001)
	c = stateConfig(t, n, snapshot, &clock)
	c.Policy = stateDefinition(t, snapshot, []string{"eth_getCode"}, []rpcstatepolicy.PreRegisteredAddress{})
	e = stateEngine(t, c)
	r, body = stateQuery(t, e, nil, "", "eth_getCode", `["`+addressA+`"]`)
	m, _ = r.MetadataFor(e)
	if m.Class != rpcengine.SuccessfulCompletion || m.ActorID != "" || m.OrganizationID != "" {
		t.Fatal(m, string(body))
	}
	for _, headers := range [][]string{{""}, {"Bearer broken"}, {"Bearer broken", "Bearer broken"}} {
		_, body = stateQuery(t, e, headers, "", "eth_getCode", `["`+addressA+`"]`)
		requireMetadataCode(t, body, -32001)
	}
	_, body = stateQuery(t, e, nil, "", "eth_getCode", `["`+addressA+`","0x1"]`)
	requireMetadataCode(t, body, -32001)
	foreign := stateEngine(t, c)
	if r.PreflightFor(foreign) == nil || r.RequireDeliverable(t.Context(), foreign) == nil {
		t.Fatal("foreign state owner accepted")
	}
}

func TestStateAuthorityDynamicNamespaceAndConflictingPositiveFacts(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := d.StateSnapshot(t, d.DefaultStateFixture(t))
	facts := stateFactsFixture(n, common.HexToAddress(addressA), d.Org, "")
	c := stateConfig(t, n, snapshot, &clock)
	c.Associations, c.AssociationBinding = facts, facts.meta.Binding
	engine := stateEngine(t, c)
	r, body := stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Admin")}, d.Org, "eth_getProof", `["`+addressA+`",[]]`)
	m, _ := r.MetadataFor(engine)
	if m.Class != rpcengine.SuccessfulCompletion || r.RequireDeliverable(t.Context(), engine) != nil {
		t.Fatal("actual owning orgadmin positive FACTORY namespace lost", m, string(body))
	}
	_, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	requireMetadataCode(t, body, -32001)
	other := facts.rows[0]
	other.Namespace = d.OtherOrg
	facts.rows = append(facts.rows, other)
	before := n.count()
	_, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Admin", "Foreign")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	requireMetadataCode(t, body, -32001)
	if n.count() != before {
		t.Fatal("conflicting dynamic owners reached node")
	}
	facts.rows = facts.rows[:1]
	facts.rows[0].Kind = "WALLET"
	facts.rows[0].WalletActor = d.Actor(d.Subject)
	r, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	m, _ = r.MetadataFor(engine)
	if m.Class != rpcengine.SuccessfulCompletion {
		t.Fatal("genuine dynamic WALLET plain read", m, string(body))
	}
	other = facts.rows[0]
	other.WalletActor = d.Actor("other")
	facts.rows = append(facts.rows, other)
	_, body = stateQuery(t, engine, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}, d.Org, "eth_getCode", `["`+addressA+`"]`)
	requireMetadataCode(t, body, -32001)
}

func TestStateAuthorityColdBindingsAndExplicitPreregistration(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := stateReadSnapshot(t, nil)
	base := stateConfig(t, n, snapshot, &clock)
	for _, which := range []string{"missing-client", "extra-client", "network", "limit", "manifest", "association-binding", "association-identity"} {
		t.Run(which, func(t *testing.T) {
			c := base
			c.Clients = map[rpcengine.StateBindingKey]*rpcexecution.StateClient{}
			for k, v := range base.Clients {
				c.Clients[k] = v
			}
			switch which {
			case "missing-client":
				delete(c.Clients, rpcengine.StateBindingKey{OrganizationID: d.Org})
			case "extra-client":
				c.Clients[rpcengine.StateBindingKey{OrganizationID: d.Org, CredentialRef: "unreachable"}] = base.Default
			case "network":
				c.Network.DeploymentID += "-wrong"
			case "limit":
				c.QueryLimits.Timeout = time.Second
			case "manifest":
				c.Snapshot = stateReadSnapshot(t, func(f *d.StateFixture) { f.Contracts[d.Org][0].Name = "changed" })
			case "association-binding":
				facts := stateFactsFixture(n, common.HexToAddress(addressA), d.Org, d.Actor(d.Subject))
				c.Associations = facts
				c.AssociationBinding = facts.meta.Binding
				c.AssociationBinding.Reference = f.Digest{42}
			case "association-identity":
				facts := stateFactsFixture(n, common.HexToAddress(addressA), d.Org, d.Actor(d.Subject))
				facts.meta.Identity = nil
				c.Associations, c.AssociationBinding = facts, facts.meta.Binding
			}
			before := n.count()
			if _, err := rpcengine.NewState(c); err == nil {
				t.Fatal("cold mismatch accepted", which)
			}
			if n.count() != before {
				t.Fatal("cold construction performed node I/O")
			}
		})
	}
	t.Run("explicit-prereg-not-all-unknown-addresses", func(t *testing.T) {
		fixture := d.DefaultStateFixture(t)
		s := d.StateSnapshot(t, fixture)
		c := stateConfig(t, n, s, &clock)
		c.Policy = stateDefinition(t, s, []string{}, []rpcstatepolicy.PreRegisteredAddress{{Address: addressA, OrganizationID: d.Org}})
		e := stateEngine(t, c)
		r, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}, d.Org, "eth_getCode", `["`+addressA+`","pending"]`)
		m, _ := r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion {
			t.Fatal("current explicit prereg+admin claim", m, string(body))
		}
		for _, roles := range [][]string{{"Auditor"}, {"Readonly"}} {
			_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, s, d.Subject, roles...)}, d.Org, "eth_getCode", `["`+addressA+`"]`)
			requireMetadataCode(t, body, -32001)
		}
		_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, s, d.Subject, "Local")}, d.Org, "eth_getCode", `["`+addressB+`"]`)
		requireMetadataCode(t, body, -32001)
		_, body = stateQuery(t, e, []string{"Bearer " + d.Token(t, s, d.Subject, "Admin")}, d.Org, "eth_getProof", `["`+addressA+`",[]]`)
		requireMetadataCode(t, body, -32001)
	})
	t.Run("stage-C-remains-closed", func(t *testing.T) {
		e := stateEngine(t, base)
		for _, name := range []string{"eth_getBalance", "eth_getTransactionCount"} {
			_, body := stateQuery(t, e, []string{"Bearer " + d.Token(t, snapshot, d.Subject, "Auditor")}, d.Org, name, `["`+addressB+`"]`)
			requireMetadataCode(t, body, -32001)
		}
	})
	for _, name := range []string{"eth_fake", "ETH_fake", "admin_addPeer", "ENGINE_x", "ETH_GETCODE"} {
		t.Run("alias-floor-"+name, func(t *testing.T) {
			fixture := d.DefaultStateFixture(t)
			fixture.Methods.Assignable = append(fixture.Methods.Assignable, name)
			fixture.Methods.Aliases[name] = "eth_getCode"
			s := d.StateSnapshot(t, fixture)
			if _, err := rpcengine.NewState(stateConfig(t, n, s, &clock)); err == nil {
				t.Fatal("unsafe state alias accepted", name)
			}
		})
	}
}

func TestStateActivitySharedMetadataGateThroughSocketAndNotification(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	snapshot := stateReadSnapshot(t, nil)
	e := stateEngine(t, stateConfig(t, n, snapshot, &clock))
	metadata := metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{}))
	x := setupActivityDatabase(t, n.network())
	methods := append(e.OperationBinding().Methods, metadata.OperationBinding().Methods...)
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, nil, methods...)
	service, err := rpcactivity.New(rpcactivity.Config{State: e, Metadata: metadata, Recorder: recorder, Network: n.network()})
	if err != nil {
		t.Fatal(err)
	}
	// Equal bytes are insufficient to mix independently selected snapshots.
	copySnapshot := stateReadSnapshot(t, nil)
	if copySnapshot.Metadata().ManifestDigest != snapshot.Metadata().ManifestDigest {
		t.Fatal("fixture changed selected bytes")
	}
	foreignState := stateEngine(t, stateConfig(t, n, copySnapshot, &clock))
	if _, err := rpcactivity.New(rpcactivity.Config{State: foreignState, Metadata: metadata, Recorder: recorder, Network: n.network()}); err == nil {
		t.Fatal("foreign state snapshot accepted with metadata")
	}
	root, _ := service.Handler(d.Org)
	alias, _ := service.Handler("")
	writeEntered, writeRelease := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(writeRelease) }) })
	mux := http.NewServeMux()
	mux.Handle("/alias", alias)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		root.ServeHTTP(&blockedWriter{ResponseWriter: w, entered: writeEntered, release: writeRelease}, r)
	}))
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	beforeRows := metadataRows(t, x)
	tok := d.Token(t, snapshot, d.Subject, "Auditor")
	done := requestAsync(t, server.Client(), server.URL, tok, string(metadataRequest("eth_getCode", `["`+addressA+`"]`)), t.Context())
	await(t, writeEntered)
	beforeRPC := n.count()
	busy := bodyResult(t, requestAsync(t, server.Client(), server.URL+"/alias", tok, string(metadataRequest("eth_chainId", "[]")), t.Context()))
	requireMetadataCode(t, busy, -32002)
	if n.count() != beforeRPC {
		t.Fatal("metadata route bypassed state output-lifetime cap")
	}
	once.Do(func() { close(writeRelease) })
	if body := bodyResult(t, done); !strings.Contains(string(body), "0x6000") {
		t.Fatal(string(body))
	}
	metadataSealedOne(t, x, beforeRows)
	beforeRows = metadataRows(t, x)
	body := bodyResult(t, requestAsync(t, server.Client(), server.URL+"/alias", tok, `{"method":"eth_getCode","params":["`+addressA+`"]}`, t.Context()))
	if len(body) != 0 {
		t.Fatal("state notification emitted response", string(body))
	}
	sealed := metadataSealedOne(t, x, beforeRows)
	if sealed.Method != "eth_getCode" || sealed.Outcome != "success" {
		t.Fatal(sealed)
	}
}

func TestStateActivityActualAppendAndFinalViewAfterRecheck(t *testing.T) {
	n := stateNode(t)
	var clock atomic.Int64
	clock.Store(d.Now)
	fixture := d.DefaultStateFixture(t)
	snapshot := d.StateSnapshot(t, fixture)
	target := common.HexToAddress(addressA)
	facts := stateFactsFixture(n, target, d.Org, d.Actor(d.Subject))
	c := stateConfig(t, n, snapshot, &clock)
	c.Associations, c.AssociationBinding = facts, facts.meta.Binding
	e := stateEngine(t, c)
	x := setupActivityDatabase(t, n.network())
	appendEntered, appendRelease := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(appendRelease) }) })
	recheckEntered, recheckRelease := make(chan struct{}), make(chan struct{})
	var recheckOnce sync.Once
	t.Cleanup(func() { recheckOnce.Do(func() { close(recheckRelease) }) })
	facts.recheck = func(ctx context.Context) error {
		close(recheckEntered)
		select {
		case <-recheckRelease:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	recorder := rpcRecorder(t, x, func() time.Time { return time.Unix(clock.Load(), 0) }, func(uint64) error { close(appendEntered); <-appendRelease; return nil }, e.OperationBinding().Methods...)
	service, err := rpcactivity.New(rpcactivity.Config{State: e, Recorder: recorder, Network: n.network()})
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := service.Handler(d.Org)
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	beforeRows := metadataRows(t, x)
	tok := d.Token(t, snapshot, d.Subject, "Auditor")
	request := string(metadataRequest("eth_getCode", `["`+addressA+`"]`))
	done := requestAsync(t, server.Client(), server.URL, tok, request, t.Context())
	await(t, appendEntered)
	busy := bodyResult(t, requestAsync(t, server.Client(), server.URL, tok, request, t.Context()))
	requireMetadataCode(t, busy, -32002)
	// Expire the SAME original View while the actual Pebble append is held.
	clock.Store(d.Now + 300)
	releaseOnce.Do(func() { close(appendRelease) })
	await(t, recheckEntered)
	recheckOnce.Do(func() { close(recheckRelease) })
	body := bodyResult(t, done)
	requireMetadataCode(t, body, -32002)
	if strings.Contains(string(body), "0x6000") {
		t.Fatal("View expired during recheck leaked observation")
	}
	sealed := metadataSealedOne(t, x, beforeRows)
	if sealed.Method != "eth_getCode" || sealed.ActorID != d.Actor(d.Subject) || sealed.DataOrg != d.Org || sealed.Outcome != "success" {
		t.Fatal("delivery rewrote selected completion", sealed)
	}
}
