package rpcengine_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/golang-jwt/jwt/v5"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
)

const orgA = "11111111-1111-1111-1111-111111111111"
const orgB = "22222222-2222-2222-2222-222222222222"
const reader = "33333333-3333-3333-3333-333333333333"
const foreign = "44444444-4444-4444-4444-444444444444"
const second = "55555555-5555-5555-5555-555555555555"
const tenant = "66666666-6666-6666-6666-666666666666"
const oid = "77777777-7777-7777-7777-777777777777"
const addressA = "0x1111111111111111111111111111111111111111"
const addressB = "0x2222222222222222222222222222222222222222"
const addressC = "0x3333333333333333333333333333333333333333"
const walletAddress = "0x4444444444444444444444444444444444444444"
const nodeHash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const now = int64(1800000000)

type fixture struct {
	groups       []policybundle.Group
	bindings     []policycore.Binding
	contracts    []policybundle.Contract
	runtime      policybundle.RuntimeSource
	capabilities []string
	roles        []string
}

func encoded(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func signingKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) }
func contract(id, address string) policybundle.Contract {
	return policybundle.Contract{ID: id, Address: address, Name: "contract", ABI: json.RawMessage(`[]`), ReadGrants: []policybundle.ReadGrant{}}
}
func newFixture() fixture {
	return fixture{groups: []policybundle.Group{{ID: reader, Slug: "reader", Name: "Reader", AllowedMethods: []string{"eth_call"}, Claims: []string{}}}, bindings: []policycore.Binding{{Group: reader, Allow: []policycore.FrameRule{{StorageAddress: addressA, Selector: "*"}}}}, contracts: []policybundle.Contract{contract("88888888-8888-8888-8888-888888888888", addressA), contract("99999999-9999-9999-9999-999999999999", addressC)}, runtime: policybundle.RuntimeSource{APIVersion: policybundle.RuntimeAPIVersion, Kind: policybundle.RuntimeKind, ReadProfile: "standard", IntraOrgGrantTracing: true, SharedInfrastructure: []policybundle.SharedInfrastructure{}, AddressScopes: []policybundle.AddressScope{}, NodeEvidenceProfile: policybundle.RuntimeNodeEvidenceProfileID}, capabilities: []string{policybundle.CapabilityNativeValidate, policybundle.CapabilityIdentity, policybundle.CapabilityPrincipal, policybundle.CapabilityRuntimeCall, policybundle.CapabilityFrames, policybundle.CapabilityAnchoredCode, policybundle.CapabilityClassification, policybundle.CapabilityOwnership}, roles: []string{reader}}
}
func (f *fixture) capability(name string) {
	if !slices.Contains(f.capabilities, name) {
		f.capabilities = append(f.capabilities, name)
	}
}
func (f fixture) load(t *testing.T) *policybundle.CatalogSnapshot {
	t.Helper()
	directory := t.TempDir()
	mappings := []identity.Mapping{}
	for i, group := range f.groups {
		mappings = append(mappings, identity.Mapping{ID: fmt.Sprintf("role-%d", i), ProfileID: "azure", OrganizationID: orgA, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: group.ID}, GroupIDs: []string{group.ID}})
	}
	mappings = append(mappings, identity.Mapping{ID: "foreign", ProfileID: "azure", OrganizationID: orgB, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: foreign}, GroupIDs: []string{foreign}})
	source := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "core", Keys: []identity.PublicKey{{Kid: "k1", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(signingKey().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure"}}}, Profiles: []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: tenant, Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0", APIAudience: oid, ClientID: reader, DelegatedScope: "api://bank/access", FactSource: "appRoles"}}, Mappings: mappings}
	docs := map[string][]byte{"identity.json": encoded(t, source), "runtime.json": encoded(t, f.runtime)}
	manifest := policybundle.Manifest{APIVersion: policybundle.BundleAPIVersion, Kind: policybundle.BundleKind, Environment: "test", ChainID: "1", EvaluatorVersion: policybundle.NativeV2EvaluatorVersion, Profile: policybundle.RuntimeCallProfileID, SourceRevision: "selected", Organizations: []policybundle.Organization{{ID: orgA, Slug: "a", Name: "A"}, {ID: orgB, Slug: "b", Name: "B"}}, RequiredCapabilities: f.capabilities, IdentityCatalog: &policybundle.IdentityCatalogRef{Path: "identity.json", SHA256: policybundle.RawDigest(docs["identity.json"])}, RuntimeCatalog: &policybundle.RuntimeCatalogRef{Path: "runtime.json", SHA256: policybundle.RawDigest(docs["runtime.json"])}}
	for _, entry := range []struct {
		org, prefix string
		groups      []policybundle.Group
		contracts   []policybundle.Contract
		bindings    []policycore.Binding
	}{{orgA, "a", f.groups, f.contracts, f.bindings}, {orgB, "b", []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Foreign", AllowedMethods: []string{"eth_call"}, Claims: []string{}}}, []policybundle.Contract{contract("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", addressB)}, []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{}}}}} {
		for kind, spec := range map[policybundle.Kind]any{policybundle.Groups: policybundle.GroupsSpec{Groups: entry.groups}, policybundle.ContractRegistry: policybundle.RegistrySpec{Contracts: entry.contracts}, policybundle.ExecutionRules: policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: entry.org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: entry.bindings}}} {
			path := entry.prefix + "-" + string(kind) + ".json"
			docs[path] = encoded(t, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": kind, "organizationId": entry.org, "spec": spec})
			manifest.Documents = append(manifest.Documents, policybundle.DocumentRef{Kind: kind, OrganizationID: entry.org, Path: path, SHA256: policybundle.RawDigest(docs[path])})
		}
	}
	for path, raw := range docs {
		if e := os.WriteFile(filepath.Join(directory, path), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	raw := encoded(t, manifest)
	if e := os.WriteFile(filepath.Join(directory, "manifest.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: directory, ExpectedManifestDigest: policybundle.RawDigest(raw), ExpectedEnvironment: "test", ExpectedChainID: "1"}, policybundle.Options{Limits: policybundle.DefaultLimits(), Profile: policybundle.RuntimeCallProfile("rpc/v1"), Methods: policybundle.MethodCatalog{Version: "rpc/v1", Assignable: []string{"eth_call", "alias_call", "eth_getCode"}, Aliases: map[string]string{"alias_call": "eth_call"}, Wildcard: []string{"eth_call", "eth_getCode"}, RequiredClaims: map[string]string{}}, IdentityLimits: identity.DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	return snapshot
}
func token(t *testing.T, snapshot *policybundle.CatalogSnapshot, roles []string) string {
	t.Helper()
	catalog, _ := snapshot.Identity()
	digest, _ := catalog.ProfileDigest("azure")
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	h := sha256.New()
	for _, part := range []string{"azure-v2", issuer, tenant, oid, "human"} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	facts := []identity.Fact{}
	for _, role := range roles {
		facts = append(facts, identity.Fact{Kind: "azure.role", Value: role})
	}
	claims := jwt.MapClaims{"iss": "https://ops.test", "aud": "core", "sub": "ops:p1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), "jti": "integration", "iat": now, "nbf": now, "exp": now + 300, "principal_kind": "human", "source_profile": "azure", "source_profile_digest": digest, "identity_authority": issuer, "source_subject": oid, "source_tenant": tenant, "source_verified_at": now, "claims_as_of": now, "source_not_after": now + 3600, "facts": facts}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"], tok.Header["kid"] = "ops-access+jwt", "k1"
	raw, e := tok.SignedString(signingKey())
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

type node struct {
	mu      sync.Mutex
	methods []string
	anchors []string
	mutate  func(map[string]any)
	onTrace func()
	code    string
	codes   map[string]string
}

func (n *node) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	n.mu.Lock()
	defer n.mu.Unlock()
	var req struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		w.WriteHeader(400)
		return
	}
	n.methods = append(n.methods, req.Method)
	var result any
	switch req.Method {
	case "eth_chainId":
		result = "0x1"
	case "eth_getBlockByNumber", "eth_getBlockByHash":
		result = map[string]any{"hash": nodeHash, "number": "0x1", "timestamp": "0xa"}
	case "debug_traceCall":
		var call map[string]any
		json.Unmarshal(req.Params[0], &call)
		var anchor string
		json.Unmarshal(req.Params[1], &anchor)
		n.anchors = append(n.anchors, anchor)
		input := call["input"]
		if input == nil {
			input = call["data"]
		}
		frame := map[string]any{"type": "CALL", "from": call["from"], "to": call["to"], "input": input, "value": call["value"], "gas": "0x10000", "gasUsed": "0x123", "output": "0xfeed"}
		if n.mutate != nil {
			n.mutate(frame)
		}
		code := n.code
		if code == "" {
			code = "0x6000"
		}
		pre := map[string]any{addressA: map[string]any{"code": code}, addressB: map[string]any{"code": "0x6000"}, addressC: map[string]any{"code": "0x6000"}, walletAddress: map[string]any{}}
		if target, ok := call["to"].(string); ok {
			if _, known := pre[target]; !known {
				pre[target] = map[string]any{"code": "0x6000"}
			}
		}
		for address, code := range n.codes {
			if code == "" {
				pre[address] = map[string]any{}
			} else {
				pre[address] = map[string]any{"code": code}
			}
		}
		result = map[string]any{"callTracer": frame, "prestateTracer": pre}
		if n.onTrace != nil {
			n.onTrace()
		}
	case "eth_getCode":
		var block map[string]any
		json.Unmarshal(req.Params[1], &block)
		n.anchors = append(n.anchors, block["blockHash"].(string))
		result = "0x"
	default:
		w.WriteHeader(500)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}
func (n *node) counts() ([]string, []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.methods), slices.Clone(n.anchors)
}

type walletResolver func(context.Context, string) (nativeadmission.WalletSnapshot, error)

func (f walletResolver) Load(ctx context.Context, actor string) (nativeadmission.WalletSnapshot, error) {
	return f(ctx, actor)
}
func linkedWallets() walletResolver {
	return func(_ context.Context, actor string) (nativeadmission.WalletSnapshot, error) {
		return nativeadmission.NewWalletSnapshot(actor, "v1", time.Unix(now, 0), []common.Address{common.HexToAddress(walletAddress)})
	}
}
func engine(t *testing.T, f fixture, n *node, wallets rpcengine.WalletResolver, clock *atomic.Int64) (*rpcengine.Engine, string, *policybundle.CatalogSnapshot) {
	t.Helper()
	snapshot := f.load(t)
	server := httptest.NewServer(n)
	t.Cleanup(server.Close)
	bindings := map[string]*rpcexecution.Client{}
	for _, org := range []string{orgA, orgB} {
		credentials := map[string]rpcexecution.Credential{}
		if org == orgA {
			for _, g := range f.groups {
				if g.RpcCredential != nil {
					credentials[g.RpcCredential.FromEnv] = rpcexecution.Credential{Header: "X-Key", Value: "configured-test-key"}
				}
			}
		}
		client, e := rpcexecution.NewClient(http.DefaultTransport, rpcexecution.NodeBinding{OrganizationID: org, URL: server.URL, ChainID: "1", Profile: rpcexecution.NodeProfileID, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true, Credentials: credentials}, rpcexecution.DefaultLimits())
		if e != nil {
			t.Fatal(e)
		}
		bindings[org] = client
	}
	clock.Store(now)
	e, err := rpcengine.New(snapshot, bindings, wallets, func() time.Time { return time.Unix(clock.Load(), 0) })
	if err != nil {
		t.Fatal(err)
	}
	return e, token(t, snapshot, f.roles), snapshot
}
func request(t *testing.T, e *rpcengine.Engine, token, org string, call map[string]any, block any) (rpcengine.Response, []byte) {
	t.Helper()
	params := []any{call}
	if block != nil {
		params = append(params, block)
	}
	body := encoded(t, map[string]any{"jsonrpc": "2.0", "id": json.Number("123456789012345678901234567890"), "method": "eth_call", "params": params})
	r := httptest.NewRequest(http.MethodPost, "/rpc", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	e.Handler(org).ServeHTTP(w, r)
	var response rpcengine.Response
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response, w.Body.Bytes()
}

func TestHTTPCallReturnsOnlyTheAuthorizedSameExecution(t *testing.T) {
	n := &node{}
	var clock atomic.Int64
	e, token, _ := engine(t, newFixture(), n, nil, &clock)
	response, _ := request(t, e, token, "", map[string]any{"to": addressA}, nil)
	if response.Error != nil || response.Result == nil || *response.Result != "0xfeed" || string(response.ID) != "123456789012345678901234567890" {
		t.Fatalf("response %+v", response)
	}
	methods, anchors := n.counts()
	if !reflect.DeepEqual(methods, []string{"eth_chainId", "eth_getBlockByNumber", "debug_traceCall"}) {
		t.Fatal("extra execution/node method", methods)
	}
	if len(anchors) != 1 || anchors[0] != nodeHash {
		t.Fatal("unanchored acquisition", anchors)
	}
}

func TestHTTPSenderFloorIndependentOfNativePredicates(t *testing.T) {
	for name, from := range map[string]any{"linked": walletAddress, "unlinked": addressB, "explicit zero": common.Address{}.Hex()} {
		t.Run(name, func(t *testing.T) {
			n := &node{}
			var clock atomic.Int64
			e, tok, _ := engine(t, newFixture(), n, linkedWallets(), &clock)
			response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "from": from}, nil)
			methods, _ := n.counts()
			want := name == "linked"
			if (response.Error == nil) != want || (!want && len(methods) != 0) {
				t.Fatalf("%s: %+v calls=%v", name, response, methods)
			}
		})
	}
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, newFixture(), n, nil, &clock)
	if response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA, "from": walletAddress}, nil); response.Error == nil {
		t.Fatal("missing wallet resolver allowed supplied from")
	}
	if methods, _ := n.counts(); len(methods) != 0 {
		t.Fatal("wallet failure reached node")
	}
}

func TestHTTPOutcomeBranchesAreAuthorizedAndSanitized(t *testing.T) {
	for name, tc := range map[string]struct {
		err, reason string
		code        int
		data        bool
	}{"success": {"", "", 0, false}, "revert": {"execution reverted", "private revert reason", 3, true}, "out of gas": {"out of gas", "", -32000, false}, "invalid opcode": {"private invalid opcode details", "", -32000, false}, "inconsistent reason": {"", "private invalid reason", -32002, false}} {
		t.Run(name, func(t *testing.T) {
			n := &node{mutate: func(frame map[string]any) {
				frame["error"], frame["revertReason"], frame["output"] = tc.err, tc.reason, "0xdead"
			}}
			var clock atomic.Int64
			e, tok, _ := engine(t, newFixture(), n, nil, &clock)
			response, body := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
			if tc.code == 0 {
				if response.Error != nil || response.Result == nil || *response.Result != "0xdead" {
					t.Fatal(response)
				}
			} else {
				if response.Error == nil || response.Error.Code != tc.code || (response.Error.Data != nil) != tc.data {
					t.Fatalf("%+v", response)
				}
				if tc.data && response.Error.Data != "0xdead" {
					t.Fatal("revert bytes changed")
				}
			}
			if strings.Contains(string(body), "private") {
				t.Fatal("node reason leaked")
			}
		})
	}
	f := newFixture()
	f.bindings = []policycore.Binding{}
	n := &node{mutate: func(frame map[string]any) {
		frame["error"], frame["revertReason"], frame["output"] = "execution reverted", "private denied reason", "0xdead"
	}}
	var clock atomic.Int64
	e, tok, _ := engine(t, f, n, nil, &clock)
	response, body := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
	if response.Error == nil || response.Error.Data != nil || bytes.Contains(body, []byte("dead")) || bytes.Contains(body, []byte("private")) {
		t.Fatal("denial exposed execution data", string(body))
	}
}

func TestHTTPHistoricalAndExpiryFloors(t *testing.T) {
	for _, role := range []string{"reader", "readonly", "local-admin", "org-admin"} {
		t.Run(role, func(t *testing.T) {
			f := newFixture()
			switch role {
			case "readonly":
				f.groups[0].IsOrgReadonlyAdmin = true
			case "local-admin":
				f.groups[0].Claims = []string{"admin"}
			case "org-admin":
				f.groups[0].IsOrgAdmin = true
			}
			n := &node{}
			var clock atomic.Int64
			e, tok, _ := engine(t, f, n, nil, &clock)
			response, _ := request(t, e, tok, orgA, map[string]any{"to": addressA}, "0x1")
			methods, _ := n.counts()
			if (response.Error == nil) != (role == "org-admin") || (role != "org-admin" && len(methods) != 0) {
				t.Fatalf("%s %+v %v", role, response, methods)
			}
		})
	}
	n := &node{}
	var clock atomic.Int64
	e, tok, _ := engine(t, newFixture(), n, nil, &clock)
	n.onTrace = func() { clock.Store(now + 300) }
	response, body := request(t, e, tok, orgA, map[string]any{"to": addressA}, nil)
	if response.Error == nil || bytes.Contains(body, []byte("feed")) {
		t.Fatal("expired during acquisition exposed output")
	}
}
