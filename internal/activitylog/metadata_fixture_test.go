package activitylog_test

// These finite protocol fixtures use the real immutable bundle, EdDSA token,
// source-qualified runtime View and typed client. The node is an owned TLS
// protocol server; it is not a production-node qualification or benchmark.
import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/rpcmetadatapolicy"
)

type metadataWireCall struct {
	ID     uint64            `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}
type metadataNode struct {
	mu          sync.Mutex
	calls       []metadataWireCall
	credentials []string
	result      map[string]any
	chain       string
	genesis     *types.Header
	headers     map[string]*types.Header // Explicit finite state-consumer ancestor fixtures.
	server      *httptest.Server
}

func newMetadataNode(t *testing.T) *metadataNode {
	t.Helper()
	n := &metadataNode{chain: "0x1", genesis: &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 1, UncleHash: types.EmptyUncleHash, TxHash: types.EmptyTxsHash, ReceiptHash: types.EmptyReceiptsHash, Extra: []byte{}}, result: map[string]any{
		"eth_accounts": []string{addressB}, "eth_blockNumber": "0x1", "eth_gasPrice": "0x2", "eth_maxPriorityFeePerGas": "0x1", "eth_syncing": false, "net_listening": true, "net_peerCount": "0x0", "net_version": "1", "web3_clientVersion": "owned-metadata/1",
		"eth_feeHistory": map[string]any{"oldestBlock": "0x0", "gasUsedRatio": []float64{0.5}, "baseFeePerGas": []string{"0x1", "0x2"}},
	}}
	n.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var c metadataWireCall
		raw, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
		if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, &c) != nil || r.Method != "POST" {
			t.Error("invalid owned metadata request")
			w.WriteHeader(400)
			return
		}
		n.mu.Lock()
		n.calls = append(n.calls, c)
		n.credentials = append(n.credentials, r.Header.Get("Idempotency-Key"))
		result, ok := n.result[c.Method]
		chain, genesis := n.chain, n.genesis
		var selectedHeader *types.Header
		if len(c.Params) == 1 {
			var selector string
			_ = json.Unmarshal(c.Params[0], &selector)
			selectedHeader = n.headers[selector]
		}
		n.mu.Unlock()
		switch c.Method {
		case "eth_chainId":
			result = chain
		case "eth_getHeaderByNumber":
			if len(c.Params) != 1 || string(c.Params[0]) != `"0x0"` && selectedHeader == nil {
				t.Error("metadata genesis selector changed")
			}
			result = genesis
			if selectedHeader != nil {
				result = selectedHeader
			}
		default:
			if !ok {
				t.Error("metadata leaked generic method", c.Method)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": c.ID, "result": result})
	}))
	t.Cleanup(n.server.Close)
	return n
}
func (n *metadataNode) network() networkidentity.Binding {
	return networkidentity.Binding{Environment: "test", ChainID: "1", GenesisHash: n.genesis.Hash().Hex(), DeploymentID: "metadata-handler-test"}
}
func (n *metadataNode) count() int { n.mu.Lock(); defer n.mu.Unlock(); return len(n.calls) }
func (n *metadataNode) client(t *testing.T, ref, value string, limits rpcexecution.MetadataLimits) *rpcexecution.MetadataClient {
	return metadataClientForNetwork(t, n, n.network(), ref, value, limits)
}
func metadataClientForNetwork(t *testing.T, n *metadataNode, network networkidentity.Binding, ref, value string, limits rpcexecution.MetadataLimits) *rpcexecution.MetadataClient {
	t.Helper()
	source := rpcexecution.MetadataSource{Network: network, URL: n.server.URL, CredentialRef: ref, AllowUnauthenticated: ref == ""}
	credential := rpcexecution.Credential{}
	if ref != "" {
		source.CredentialHeader = "Idempotency-Key"
		credential = rpcexecution.Credential{Header: source.CredentialHeader, Value: value}
	}
	c, err := rpcexecution.NewMetadataClient(n.server.Client().Transport, source, credential, limits)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func metadataFixture() fixture {
	f := creationIntentRuntimeFixture()
	f.creationObserved = true
	methods := policybundle.MethodCatalog{Version: "rpc/v1", Assignable: []string{"eth_call", "eth_sendTransaction", "eth_sendRawTransaction", "eth_getCode", "alias_call", "bank_chainId", "bank_accounts"}, Aliases: map[string]string{"alias_call": "eth_call", "bank_chainId": "eth_chainId", "bank_accounts": "eth_accounts"}, Wildcard: []string{"eth_call", "eth_getCode"}, RequiredClaims: map[string]string{}}
	for m := rpcexecution.MetadataAccounts; m <= rpcexecution.MetadataKeccak; m++ {
		methods.Assignable = append(methods.Assignable, m.String())
	}
	f.methodCatalog = &methods
	f.groups[0].AllowedMethods = slices.Clone(methods.Assignable)
	return f
}
func metadataDefinition(t *testing.T, snapshot *policybundle.CatalogSnapshot, anonymous []string) *rpcmetadatapolicy.Definition {
	t.Helper()
	raw := encoded(t, rpcmetadatapolicy.Source{APIVersion: rpcmetadatapolicy.APIVersion, Kind: rpcmetadatapolicy.Kind, BundleManifestDigest: string(snapshot.Metadata().ManifestDigest), AnonymousMethods: anonymous})
	d, err := rpcmetadatapolicy.Compile(raw, rpcmetadatapolicy.Digest(sha256.Sum256(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func metadataConfig(t *testing.T, n *metadataNode, snapshot *policybundle.CatalogSnapshot, clock *atomic.Int64, anonymous []string) rpcengine.MetadataConfig {
	t.Helper()
	l := rpcexecution.DefaultMetadataLimits()
	c := rpcengine.MetadataConfig{Snapshot: snapshot, Policy: metadataDefinition(t, snapshot, anonymous), Network: n.network(), Default: n.client(t, "default", "default-only", l), Clients: map[rpcengine.MetadataBindingKey]*rpcexecution.MetadataClient{}, QueryLimits: l, Clock: func() time.Time { return time.Unix(clock.Load(), 0) }}
	// This fixture explicitly supplies only refs actually selectable by non-free
	// names. Production independently computes and validates the exact set.
	for _, org := range snapshot.Organizations() {
		for _, id := range snapshot.GroupIDs(org.ID) {
			g, _ := snapshot.Group(org.ID, id)
			needed := false
			for _, name := range g.AllowedMethods {
				switch name {
				case "eth_blockNumber", "eth_chainId", "eth_gasPrice", "net_listening", "net_version", "web3_clientVersion":
					continue
				}
				m, ok := snapshot.Method(name)
				if !ok {
					continue
				}
				for method := rpcexecution.MetadataAccounts; method <= rpcexecution.MetadataKeccak; method++ {
					if method.String() == m.Canonical {
						needed = true
					}
				}
			}
			if needed {
				ref := ""
				if g.RpcCredential != nil {
					ref = g.RpcCredential.FromEnv
				}
				c.Clients[rpcengine.MetadataBindingKey{OrganizationID: org.ID, CredentialRef: ref}] = n.client(t, ref, "selected-only", l)
			}
		}
	}
	return c
}
func metadataEngine(t *testing.T, c rpcengine.MetadataConfig) *rpcengine.MetadataEngine {
	t.Helper()
	e, err := rpcengine.NewMetadata(c)
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func metadataRequest(name, params string) []byte {
	if params == "" {
		params = "[]"
	}
	return []byte(`{"id":9007199254740993,"method":"` + name + `","params":` + params + `}`)
}
func metadataQuery(t *testing.T, e *rpcengine.MetadataEngine, headers []string, org string, body []byte) (*rpcengine.MetadataOperationResult, []byte) {
	t.Helper()
	r := e.QueryObserved(context.Background(), rpcengine.MetadataAuthorization(headers), org, body)
	if err := r.PreflightFor(e); err != nil {
		t.Fatal("owned metadata preflight", err)
	}
	wire, err := r.MarshalResponseFor(e)
	if err != nil {
		t.Fatal(err)
	}
	return r, wire
}
func requireMetadataCode(t *testing.T, body []byte, code int32) {
	t.Helper()
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int32           `json:"code"`
			Data json.RawMessage `json:"data"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &out) != nil || out.Error == nil || out.Error.Code != code || len(out.Result) > 0 || len(out.Error.Data) > 0 {
		t.Fatalf("safe metadata error %d: %s", code, body)
	}
}

func TestMetadataHandlerActualJWTAndTLSAllTwelve(t *testing.T) {
	n := newMetadataNode(t)
	f := metadataFixture()
	snapshot := f.load(t)
	var clock atomic.Int64
	clock.Store(now)
	e := metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{}))
	headers := []string{"Bearer " + token(t, snapshot, []string{reader})}
	for method := rpcexecution.MetadataAccounts; method <= rpcexecution.MetadataKeccak; method++ {
		t.Run(method.String(), func(t *testing.T) {
			params := "[]"
			if method == rpcexecution.MetadataFeeHistory {
				params = `[1,"latest",[]]`
			}
			if method == rpcexecution.MetadataKeccak {
				params = `["0x"]`
			}
			before := n.count()
			r, wire := metadataQuery(t, e, headers, orgA, metadataRequest(method.String(), params))
			m, _ := r.MetadataFor(e)
			want := 3
			if method == rpcexecution.MetadataChainID {
				want = 2
			}
			if method == rpcexecution.MetadataKeccak {
				want = 0
			}
			if m.Class != rpcengine.SuccessfulCompletion || m.ActorID == "" || m.Canonical != method || m.Method != method.String() || n.count()-before != want || !strings.Contains(string(wire), `"id":9007199254740993`) {
				t.Fatal("actual typed metadata path", m, string(wire), n.count()-before)
			}
			free := slices.Contains([]rpcexecution.MetadataMethod{rpcexecution.MetadataBlockNumber, rpcexecution.MetadataChainID, rpcexecution.MetadataGasPrice, rpcexecution.MetadataListening, rpcexecution.MetadataNetworkVersion, rpcexecution.MetadataClientVersion}, method)
			if free && m.OrganizationID != "" || !free && m.OrganizationID != orgA {
				t.Fatal("metadata org attribution", m)
			}
			if err := r.RequireDeliverable(t.Context(), e); err != nil {
				t.Fatal(err)
			}
		})
	}
	// Node accounts are node observations, not the subject's operational wallet.
	_, wire := metadataQuery(t, e, headers, orgA, metadataRequest("eth_accounts", "[]"))
	if !strings.Contains(string(wire), addressB) || strings.Contains(string(wire), walletAddress) {
		t.Fatal("node accounts replaced by wallet lookup", string(wire))
	}
}

func TestMetadataHandlerAuthorityAndColdBindings(t *testing.T) {
	n := newMetadataNode(t)
	var clock atomic.Int64
	clock.Store(now)
	t.Run("free-raw-six-default-only-and-alias-explicit", func(t *testing.T) {
		f := metadataFixture()
		f.groups[0].AllowedMethods = []string{"eth_chainId"}
		f.groups[0].RpcCredential = &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_IRRELEVANT"}
		f.capability(policybundle.CapabilityRPCCredential)
		snapshot := f.load(t)
		c := metadataConfig(t, n, snapshot, &clock, []string{})
		if len(c.Clients) != 0 {
			t.Fatal("raw-free group created unreachable client")
		}
		e := metadataEngine(t, c)
		zero := []string{"Bearer " + token(t, snapshot, []string{})}
		before := n.count()
		r, wire := metadataQuery(t, e, zero, orgB, metadataRequest("ETH_CHAINID", "[]"))
		m, _ := r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion || m.OrganizationID != "" || n.count()-before != 2 {
			t.Fatal(m, string(wire))
		}
		n.mu.Lock()
		for _, v := range n.credentials[len(n.credentials)-2:] {
			if v != "default-only" {
				t.Error("raw-free method selected group credential", v)
			}
		}
		n.mu.Unlock()
		_, wire = metadataQuery(t, e, zero, "", metadataRequest("bank_chainId", "[]"))
		requireMetadataCode(t, wire, -32001)
		c.Clients[rpcengine.MetadataBindingKey{OrganizationID: orgA, CredentialRef: f.groups[0].RpcCredential.FromEnv}] = n.client(t, f.groups[0].RpcCredential.FromEnv, "selected-only", c.QueryLimits)
		if _, err := rpcengine.NewMetadata(c); err == nil {
			t.Fatal("unreachable extra binding accepted")
		}
	})
	t.Run("alias-is-exact-raw-grant-and-both-claims", func(t *testing.T) {
		f := metadataFixture()
		f.groups[0].AllowedMethods = []string{"bank_chainId"}
		f.groups[0].Claims = []string{"deploy", "upgrade"}
		f.methodCatalog.RequiredClaims["bank_chainId"] = "deploy"
		f.methodCatalog.RequiredClaims["eth_chainId"] = "upgrade"
		snapshot := f.load(t)
		c := metadataConfig(t, n, snapshot, &clock, []string{})
		if len(c.Clients) != 1 {
			t.Fatal("alias-to-free requires explicit binding")
		}
		e := metadataEngine(t, c)
		headers := []string{"Bearer " + token(t, snapshot, []string{reader})}
		info, _ := snapshot.Method("bank_chainId")
		if !slices.Equal(info.RequiredClaims, []string{"deploy", "upgrade"}) {
			t.Fatal("actual selected alias lost its raw/canonical claim union", info)
		}
		r, wire := metadataQuery(t, e, headers, orgA, metadataRequest("bank_chainId", "[]"))
		m, _ := r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion || m.OrganizationID != orgA || m.Method != "bank_chainId" {
			t.Fatal(m, string(wire))
		}
		n.mu.Lock()
		for _, v := range n.credentials[len(n.credentials)-2:] {
			if v != "" {
				t.Error("explicit emptyref binding replaced by default credential", v)
			}
		}
		n.mu.Unlock()
		_, wire = metadataQuery(t, e, headers, orgA, metadataRequest("BANK_CHAINID", "[]"))
		requireMetadataCode(t, wire, -32601)
		delete(c.Clients, rpcengine.MetadataBindingKey{OrganizationID: orgA})
		if _, err := rpcengine.NewMetadata(c); err == nil {
			t.Fatal("alias's required binding omitted")
		}
		r, wire = metadataQuery(t, e, headers, orgA, metadataRequest("bank_chainId", "[]"))
		m, _ = r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion {
			t.Fatal("caller mutated bound client map", m, string(wire))
		}
	})
	t.Run("org-selection-no-grant-conflicting-ref", func(t *testing.T) {
		f := metadataFixture()
		f.groups[0].AllowedMethods = []string{"eth_accounts"}
		f.bGroups = []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Foreign", AllowedMethods: []string{"eth_accounts"}, Claims: []string{}}}
		snapshot := f.load(t)
		e := metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{}))
		headers := []string{"Bearer " + token(t, snapshot, []string{reader, foreign})}
		before := n.count()
		_, wire := metadataQuery(t, e, headers, "", metadataRequest("eth_accounts", "[]"))
		requireMetadataCode(t, wire, -32001)
		_, wire = metadataQuery(t, e, headers, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", metadataRequest("eth_accounts", "[]"))
		requireMetadataCode(t, wire, -32001)
		if n.count() != before {
			t.Fatal("ambiguous/unknown org queried node")
		}
		r, wire := metadataQuery(t, e, headers, orgB, metadataRequest("eth_accounts", "[]"))
		m, _ := r.MetadataFor(e)
		if m.Class != rpcengine.SuccessfulCompletion || m.OrganizationID != orgB {
			t.Fatal(m, string(wire))
		}
		_, wire = metadataQuery(t, e, []string{"Bearer " + token(t, snapshot, []string{foreign})}, orgA, metadataRequest("eth_accounts", "[]"))
		requireMetadataCode(t, wire, -32001)
		f.groups = append(f.groups, policybundle.Group{ID: second, Slug: "second", Name: "Second", AllowedMethods: []string{"eth_accounts"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_SECOND"}})
		f.groups[0].RpcCredential = &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_FIRST"}
		f.capability(policybundle.CapabilityRPCCredential)
		snapshot = f.load(t)
		e = metadataEngine(t, metadataConfig(t, n, snapshot, &clock, []string{}))
		_, wire = metadataQuery(t, e, []string{"Bearer " + token(t, snapshot, []string{reader, second})}, orgA, metadataRequest("eth_accounts", "[]"))
		requireMetadataCode(t, wire, -32001)
	})
	for _, name := range []string{"admin_addPeer", "AdMiN_addPeer", "personal_unlockAccount", "eth_subscribe", "debug_x", "miner_x", "txpool_x", "engine_x", "ENGINE_x", "eth_fake", "ETH_fake", "net_fake", "NeT_fake", "web3_fake", "Web3_fake", "ETH_CHAINID"} {
		t.Run("reject-alias-"+name, func(t *testing.T) {
			f := metadataFixture()
			f.methodCatalog.Assignable = append(f.methodCatalog.Assignable, name)
			f.methodCatalog.Aliases[name] = "eth_chainId"
			snapshot := f.load(t)
			if _, err := rpcengine.NewMetadata(metadataConfig(t, n, snapshot, &clock, []string{})); err == nil {
				t.Fatal("unsafe metadata alias accepted", name)
			}
		})
	}
	t.Run("limits-network-manifest-exact-client-set", func(t *testing.T) {
		f := metadataFixture()
		snapshot := f.load(t)
		base := metadataConfig(t, n, snapshot, &clock, []string{})
		for _, which := range []string{"network", "manifest", "missing-client", "extra-client", "client-network", "client-timeout"} {
			t.Run(which, func(t *testing.T) {
				c := base
				c.Clients = map[rpcengine.MetadataBindingKey]*rpcexecution.MetadataClient{}
				for k, v := range base.Clients {
					c.Clients[k] = v
				}
				switch which {
				case "network":
					c.Network.DeploymentID += "-other"
				case "manifest":
					f.contracts[0].Name = "changed"
					c.Snapshot = f.load(t)
				case "missing-client":
					delete(c.Clients, rpcengine.MetadataBindingKey{OrganizationID: orgA})
				case "extra-client":
					c.Clients[rpcengine.MetadataBindingKey{OrganizationID: orgB}] = base.Default
				case "client-network":
					c.Network.GenesisHash = "0x" + strings.Repeat("1", 64)
				case "client-timeout":
					c.QueryLimits.Timeout = time.Second
				}
				if _, err := rpcengine.NewMetadata(c); err == nil {
					t.Fatal("cold mismatch accepted", which)
				}
			})
		}
	})
}

func TestMetadataHandlerHeaderPrecedenceOwnerAndOriginalView(t *testing.T) {
	n := newMetadataNode(t)
	f := metadataFixture()
	snapshot := f.load(t)
	var clock atomic.Int64
	clock.Store(now)
	c := metadataConfig(t, n, snapshot, &clock, []string{"eth_chainId"})
	e := metadataEngine(t, c)
	other := metadataEngine(t, c)
	bound := e.OperationBinding()
	bound.Methods[0], bound.OrganizationIDs[0] = "mutated", "mutated"
	if slices.Contains(e.OperationBinding().Methods, "mutated") || slices.Contains(e.OperationBinding().OrganizationIDs, "mutated") {
		t.Fatal("operation binding exposes mutable engine authority")
	}
	valid := "Bearer " + token(t, snapshot, []string{reader})
	for _, headers := range [][]string{{""}, {"Bearer"}, {"Basic x"}, {"Bearer broken"}, {valid, valid}} {
		before := n.count()
		_, wire := metadataQuery(t, e, headers, "", metadataRequest("eth_chainId", "[]"))
		requireMetadataCode(t, wire, -32001)
		if n.count() != before {
			t.Fatal("bad present header fell back to anonymous")
		}
	}
	r, wire := metadataQuery(t, e, nil, orgA, metadataRequest("eth_chainId", "[]"))
	m, _ := r.MetadataFor(e)
	if m.Class != rpcengine.SuccessfulCompletion || m.ActorID != "" || m.OrganizationID != "" {
		t.Fatal(m, string(wire))
	}
	before := n.count()
	_, wire = metadataQuery(t, e, []string{"Bearer broken"}, orgA, metadataRequest("evil_random", "[]"))
	requireMetadataCode(t, wire, -32601)
	_, wire = metadataQuery(t, e, []string{"Bearer broken"}, orgA, metadataRequest("eth_chainId", "[1]"))
	requireMetadataCode(t, wire, -32602)
	if n.count() != before {
		t.Fatal("protocol failure queried node")
	}
	r, wire = metadataQuery(t, e, []string{valid}, orgA, metadataRequest("eth_accounts", "[]"))
	if _, err := r.MarshalResponseFor(other); err == nil {
		t.Fatal("foreign owner marshalled result")
	}
	if r.PreflightFor(other) == nil || r.RequireDeliverable(t.Context(), other) == nil {
		t.Fatal("foreign owner accepted")
	}
	if (&rpcengine.MetadataOperationResult{}).PreflightFor(e) == nil {
		t.Fatal("zero result accepted")
	}
	m, _ = r.MetadataFor(e)
	if m.RPCErrorCode != nil {
		t.Fatal(m)
	}
	clock.Store(now + 300)
	if r.RequireDeliverable(t.Context(), e) == nil {
		t.Fatal("original expired View refreshed/rebuilt")
	}
	_, failed := metadataQuery(t, e, []string{valid}, orgA, metadataRequest("eth_chainId", "[]"))
	requireMetadataCode(t, failed, -32001)
	clock.Store(now)
	n.mu.Lock()
	n.chain = "0x2"
	n.mu.Unlock()
	_, failed = metadataQuery(t, e, []string{valid}, orgA, metadataRequest("eth_accounts", "[]"))
	requireMetadataCode(t, failed, -32002)
	if strings.Contains(string(failed), addressB) {
		t.Fatal("backend mismatch leaked result")
	}
}
