package activitylog_test

// Finite owned RPC/SQL fixture derived from the existing rpcengine and activitysql
// qualification helpers. It uses real constructors, native checks, restricted
// SQL and local Pebble; the loopback node is a protocol fixture, not a verdict.
import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/creationcapture"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/networkidentity"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
	s "privacy-proxy/internal/operational/activitysql"
	"privacy-proxy/internal/operational/admissionsql"
	"privacy-proxy/internal/operational/walletsql"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/rpcengine"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/transactioninput"
	"privacy-proxy/internal/walletadapter"
	"privacy-proxy/internal/walletops"
	"privacy-proxy/internal/walletproof"
)

const createdAddress = "0x5555555555555555555555555555555555555555"

func lifecycleRule(class string, kinds ...policycore.CallType) policycore.FrameRule {
	return policycore.FrameRule{TargetClass: class, Selector: "*", CallTypes: kinds}
}

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
	creationObserved    bool
	readOnly            bool
	lifecycle           bool
	creationAttribution *policybundle.CreationAttribution
	simulation          bool
	clock               *atomic.Int64
	linkSigner          bool
	multiOrg            bool
	bGroups             []policybundle.Group
	bContracts          []policybundle.Contract
	bBindings           []policycore.Binding
	bMappedGroups       []string
	rawMode             string
	complianceHook      func(*compliancepolicy.Source)
	groups              []policybundle.Group
	bindings            []policycore.Binding
	contracts           []policybundle.Contract
	runtime             policybundle.RuntimeSource
	capabilities        []string
	roles               []string
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
	foreignIDs := []string{foreign}
	if f.bGroups != nil {
		foreignIDs = make([]string, 0, len(f.bGroups))
		for _, group := range f.bGroups {
			foreignIDs = append(foreignIDs, group.ID)
		}
	}
	if f.bMappedGroups != nil {
		foreignIDs = f.bMappedGroups
	}
	mappings = append(mappings, identity.Mapping{ID: "foreign", ProfileID: "azure", OrganizationID: orgB, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: foreign}, GroupIDs: foreignIDs})
	source := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "core", Keys: []identity.PublicKey{{Kid: "k1", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(signingKey().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure"}}}, Profiles: []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: tenant, Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0", APIAudience: oid, ClientID: reader, DelegatedScope: "api://bank/access", FactSource: "appRoles"}}, Mappings: mappings}
	docs := map[string][]byte{"identity.json": encoded(t, source), "runtime.json": encoded(t, f.runtime)}
	profileID, profile := policybundle.RuntimeCallProfileID, policybundle.RuntimeCallProfile("rpc/v1")
	limits := compliancepolicy.Limits{}
	assignable := []string{"eth_call", "alias_call", "eth_getCode"}
	if f.rawMode != "" {
		profileID, profile = policybundle.RuntimeRawSendProfileID, policybundle.RuntimeRawSendProfile("rpc/v1")
		limits = compliancepolicy.DefaultLimits()
		assignable = append(assignable, "eth_sendTransaction", "eth_sendRawTransaction")
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeRawSource{APIVersion: policybundle.RuntimeRawAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: r.NodeEvidenceProfile, RawSubmissionMode: f.rawMode})
		compliance := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{}, Sanctions: []compliancepolicy.SourceSanction{}}
		for _, org := range []string{orgA, orgB} {
			compliance.Organizations = append(compliance.Organizations, compliancepolicy.OrganizationPolicy{OrganizationID: org, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Currency: "eur", ThresholdFiat: 100, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{}}})
		}
		if f.complianceHook != nil {
			f.complianceHook(&compliance)
		}
		docs["compliance.json"] = encoded(t, compliance)
		for _, capability := range []string{policybundle.CapabilityRuntimeRawSend, policybundle.CapabilitySigner, policybundle.CapabilityAdmission, policybundle.CapabilityWalletProofs, "catalog.compliance-validate/v1"} {
			f.capability(capability)
		}
		if f.rawMode == policybundle.RawSubmissionGuardV1 {
			f.capability(policybundle.CapabilityGuardDelivery)
		} else {
			f.capability(policybundle.CapabilitySignedCall)
		}
	}
	policyVersion, evaluator := policycore.NativeV2APIVersion, policybundle.NativeV2EvaluatorVersion
	if f.multiOrg {
		if f.rawMode == "" {
			t.Fatal("multi-org fixture requires an explicit raw mode")
		}
		profileID, profile = policybundle.RuntimeMultiOrgProfileID, policybundle.RuntimeMultiOrgProfile("rpc/v1")
		policyVersion, evaluator = policycore.NativeV3APIVersion, policybundle.NativeV3EvaluatorVersion
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeMultiOrgSource{APIVersion: policybundle.RuntimeMultiOrgAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: r.NodeEvidenceProfile, RawSubmissionMode: f.rawMode})
		f.capability(policybundle.CapabilityMultiOrg)
	}
	if f.lifecycle || f.simulation || f.creationAttribution != nil {
		if f.rawMode == "" {
			t.Fatal("lifecycle fixture requires an explicit raw mode")
		}
		profileID, profile = policybundle.RuntimeLifecycleProfileID, policybundle.RuntimeLifecycleProfile("rpc/v1")
		policyVersion, evaluator = policycore.NativeV4APIVersion, policybundle.NativeV4EvaluatorVersion
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeLifecycleSource{APIVersion: policybundle.RuntimeLifecycleAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: policybundle.RuntimeLifecycleNodeEvidenceProfileID, RawSubmissionMode: f.rawMode})
		for _, cap := range []string{policybundle.CapabilityMultiOrg, policybundle.CapabilityLifecycle, policybundle.CapabilityTemporalCode, policybundle.CapabilityCreationContext, policybundle.CapabilityLifecycleBeneficiary} {
			f.capability(cap)
		}
	}
	if f.simulation || f.creationAttribution != nil {
		profileID, profile = policybundle.RuntimeSimulationProfileID, policybundle.RuntimeSimulationProfile("rpc/v1")
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeSimulationSource{APIVersion: policybundle.RuntimeSimulationAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: f.rawMode})
		f.capability(policybundle.CapabilityUnsignedSimulation)
	}
	if f.creationAttribution != nil {
		profileID, profile = policybundle.RuntimeCreationIntentProfileID, policybundle.RuntimeCreationIntentProfile("rpc/v1")
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeCreationIntentSource{APIVersion: policybundle.RuntimeCreationIntentAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: f.rawMode, CreationAttribution: *f.creationAttribution})
		f.capability(policybundle.CapabilityCreationIntents)
	}
	if f.creationObserved {
		profileID, profile = policybundle.RuntimeCreationObservedProfileID, policybundle.RuntimeCreationObservedProfile("rpc/v1")
		r := f.runtime
		docs["runtime.json"] = encoded(t, policybundle.RuntimeCreationObservedSource{APIVersion: policybundle.RuntimeCreationObservedAPIVersion, Kind: r.Kind, ReadProfile: r.ReadProfile, IntraOrgGrantTracing: r.IntraOrgGrantTracing, SharedInfrastructure: r.SharedInfrastructure, AddressScopes: r.AddressScopes, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: f.rawMode, CreationAttribution: *f.creationAttribution, CaptureReadinessProfile: "same-node-caught-up/v1"})
		f.capability(policybundle.CapabilityCreationCoverage)
	}
	manifest := policybundle.Manifest{APIVersion: policybundle.BundleAPIVersion, Kind: policybundle.BundleKind, Environment: "test", ChainID: "1", EvaluatorVersion: evaluator, Profile: profileID, SourceRevision: "selected", Organizations: []policybundle.Organization{{ID: orgA, Slug: "a", Name: "A"}, {ID: orgB, Slug: "b", Name: "B"}}, RequiredCapabilities: f.capabilities, IdentityCatalog: &policybundle.IdentityCatalogRef{Path: "identity.json", SHA256: policybundle.RawDigest(docs["identity.json"])}, RuntimeCatalog: &policybundle.RuntimeCatalogRef{Path: "runtime.json", SHA256: policybundle.RawDigest(docs["runtime.json"])}}
	if f.rawMode != "" {
		manifest.ComplianceCatalog = &policybundle.ComplianceCatalogRef{Path: "compliance.json", SHA256: policybundle.RawDigest(docs["compliance.json"])}
	}
	bGroups := []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Foreign", AllowedMethods: []string{"eth_call"}, Claims: []string{}}}
	bContracts := []policybundle.Contract{contract("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", addressB)}
	bBindings := []policycore.Binding{{Group: foreign, Allow: []policycore.FrameRule{}}}
	if f.bGroups != nil {
		bGroups = f.bGroups
	}
	if f.bContracts != nil {
		bContracts = f.bContracts
	}
	if f.bBindings != nil {
		bBindings = f.bBindings
	}
	for _, entry := range []struct {
		org, prefix string
		groups      []policybundle.Group
		contracts   []policybundle.Contract
		bindings    []policycore.Binding
	}{{orgA, "a", f.groups, f.contracts, f.bindings}, {orgB, "b", bGroups, bContracts, bBindings}} {
		for kind, spec := range map[policybundle.Kind]any{policybundle.Groups: policybundle.GroupsSpec{Groups: entry.groups}, policybundle.ContractRegistry: policybundle.RegistrySpec{Contracts: entry.contracts}, policybundle.ExecutionRules: policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policyVersion, Kind: policycore.Kind, Org: entry.org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: entry.bindings}}} {
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
	snapshot, e := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: directory, ExpectedManifestDigest: policybundle.RawDigest(raw), ExpectedEnvironment: "test", ExpectedChainID: "1"}, policybundle.Options{Limits: policybundle.DefaultLimits(), Profile: profile, Methods: policybundle.MethodCatalog{Version: "rpc/v1", Assignable: assignable, Aliases: map[string]string{"alias_call": "eth_call"}, Wildcard: []string{"eth_call", "eth_getCode"}, RequiredClaims: map[string]string{}}, IdentityLimits: identity.DefaultLimits(), ComplianceLimits: limits})
	if e != nil {
		t.Fatal(e)
	}
	return snapshot
}
func token(t *testing.T, snapshot *policybundle.CatalogSnapshot, roles []string) string {
	t.Helper()
	return tokenSubject(t, snapshot, roles, oid)
}

func tokenSubject(t *testing.T, snapshot *policybundle.CatalogSnapshot, roles []string, subject string) string {
	t.Helper()
	catalog, _ := snapshot.Identity()
	digest, _ := catalog.ProfileDigest("azure")
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	h := sha256.New()
	for _, part := range []string{"azure-v2", issuer, tenant, subject, "human"} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	facts := []identity.Fact{}
	for _, role := range roles {
		facts = append(facts, identity.Fact{Kind: "azure.role", Value: role})
	}
	claims := jwt.MapClaims{"iss": "https://ops.test", "aud": "core", "sub": "ops:p1:" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), "jti": "integration", "iat": now, "nbf": now, "exp": now + 300, "principal_kind": "human", "source_profile": "azure", "source_profile_digest": digest, "identity_authority": issuer, "source_subject": subject, "source_tenant": tenant, "source_verified_at": now, "claims_as_of": now, "source_not_after": now + 3600, "facts": facts}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["typ"], tok.Header["kid"] = "ops-access+jwt", "k1"
	raw, e := tok.SignedString(signingKey())
	if e != nil {
		t.Fatal(e)
	}
	return raw
}

type node struct {
	mu                          sync.Mutex
	methods                     []string
	anchors                     []string
	mutate                      func(map[string]any)
	onTrace                     func()
	onNonce                     func()
	onSend                      func(string) string
	code                        string
	codes                       map[string]string
	pre                         map[string]any
	failMethod                  string
	nonce                       string
	captureMined                bool
	captureUnavailable          bool
	genesisHeader, anchorHeader *types.Header
}

// Only the new covered-capture fixture uses complete hash-qualified headers;
// earlier partial-acquisition fixtures retain their exact legacy wire shape.
func (n *node) enableCaptureHeaders() {
	n.genesisHeader = &types.Header{Number: big.NewInt(0), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 9, BaseFee: big.NewInt(1)}
	n.anchorHeader = &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(0), GasLimit: 30000000, Time: 10, BaseFee: big.NewInt(1), ParentHash: n.genesisHeader.Hash()}
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
	if req.Method == n.failMethod {
		w.WriteHeader(503)
		return
	}
	var result any
	switch req.Method {
	case "eth_chainId":
		result = "0x1"
	case "eth_getBlockByNumber", "eth_getBlockByHash", "eth_getHeaderByNumber":
		result = map[string]any{"hash": nodeHash, "number": "0x1", "timestamp": "0xa"}
		if n.anchorHeader != nil {
			result = n.anchorHeader
		}
		if req.Method == "eth_getHeaderByNumber" {
			if n.captureUnavailable {
				w.WriteHeader(503)
				return
			}
			var selector string
			_ = json.Unmarshal(req.Params[0], &selector)
			number := "0x1"
			if selector == "0x0" {
				number = "0x0"
			}
			if n.anchorHeader != nil {
				result = n.anchorHeader
				if selector == "0x0" {
					result = n.genesisHeader
				}
			} else {
				result = map[string]any{"hash": nodeHash, "number": number, "timestamp": "0xa", "parentHash": nodeHash}
			}
		}
	case "eth_syncing":
		result = false
	case "eth_getTransactionReceipt":
		if n.captureMined {
			var hash string
			_ = json.Unmarshal(req.Params[0], &hash)
			result = map[string]any{"transactionHash": hash, "blockHash": nodeHash, "blockNumber": "0x2", "transactionIndex": "0x0", "status": "0x1"}
		}
	case "debug_traceCall":
		var traceConfig map[string]any
		json.Unmarshal(req.Params[2], &traceConfig)
		if traceConfig["tracer"] == "prestateTracer" {
			result = map[string]any{"pre": map[string]any{}, "post": map[string]any{}}
			break
		}
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
		for address, account := range n.pre {
			pre[address] = account
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
	case "eth_getTransactionCount":
		result = "0x0"
		if n.nonce != "" {
			result = n.nonce
		}
		if n.onNonce != nil {
			n.onNonce()
		}
	case "eth_sendRawTransaction":
		var raw string
		if n.onSend == nil || len(req.Params) != 1 || json.Unmarshal(req.Params[0], &raw) != nil {
			w.WriteHeader(500)
			return
		}
		result = n.onSend(raw)
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

type rawDatabase struct {
	ownerDSN, appDSN, walletDSN string
	owner                       *pgx.Conn
}

func rawPostgres(t *testing.T) rawDatabase {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("raw operational qualification requires Docker PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=raw-test-only", "--env", "POSTGRES_DB=raw_test", "--name", "ops-v2-raw-test-"+uuid.NewString()[:8], "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		if out, err := exec.CommandContext(c, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Logf("owned PostgreSQL cleanup %v %s", err, out)
		}
	})
	out, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	d := rawDatabase{ownerDSN: "postgres://postgres:raw-test-only@" + strings.TrimSpace(string(out)) + "/raw_test?sslmode=disable"}
	for ctx.Err() == nil {
		d.owner, err = pgx.Connect(ctx, d.ownerDSN)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		d.owner.Close(c)
	})
	for _, role := range []string{"raw_app", "raw_reader", "raw_retention", "wallet_app", "wallet_reader", "wallet_retention"} {
		if _, err := d.owner.Exec(t.Context(), `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN PASSWORD 'raw-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	if err := admissionsql.Migrate(t.Context(), d.ownerDSN, "raw_app", "raw_reader", "raw_retention"); err != nil {
		t.Fatal(err)
	}
	if err := walletsql.Migrate(t.Context(), d.ownerDSN, "wallet_app", "wallet_reader", "wallet_retention"); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(d.ownerDSN)
	u.User = url.UserPassword("raw_app", "raw-test-only")
	d.appDSN = u.String()
	u.User = url.UserPassword("wallet_app", "raw-test-only")
	d.walletDSN = u.String()
	return d
}

func materialize(t *testing.T, response interface {
	WriteTo(io.Writer) (int64, error)
}) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := response.WriteTo(&b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func signedValue(t *testing.T, nonce uint64) transactioninput.VerifiedTransaction {
	t.Helper()
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	tx, err := types.SignTx(types.NewTransaction(nonce, common.HexToAddress(addressA), new(big.Int).Mul(big.NewInt(2), big.NewInt(1e18)), 100000, big.NewInt(1), []byte{1, 2}), types.LatestSignerForChainID(big.NewInt(1)), key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := tx.MarshalBinary()
	v, err := transactioninput.DecodeRaw("0x"+hex.EncodeToString(raw), "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func operationalLink(t *testing.T, service *walletops.Service, token string, address common.Address) {
	t.Helper()
	response, err := service.Issue(t.Context(), token, walletops.ChallengeRequest{Address: address.Hex()})
	if err != nil {
		t.Fatal(err)
	}
	var challenge walletops.ChallengeResult
	if json.Unmarshal(materialize(t, response), &challenge) != nil || challenge.Message == "" {
		t.Fatal("challenge missing")
	}
	key, _ := crypto.HexToECDSA(strings.Repeat("0", 63) + "1")
	signature, err := crypto.Sign(walletproof.HashMessage(challenge.Message), key)
	if err != nil {
		t.Fatal(err)
	}
	response, err = service.Verify(t.Context(), token, walletops.VerifyRequest{Nonce: challenge.Nonce, Address: address.Hex(), Signature: "0x" + hex.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	materialize(t, response)
}

type creationMountOptions struct {
	limits        *admission.CreationLimits
	wrap          func(*admissionsql.Store) admission.Store
	walletService func(*walletops.Service)
}

func mountedRawEngine(t *testing.T, f fixture, n *node, d rawDatabase, multiOrg bool, creationOptions ...creationMountOptions) (*rpcengine.Engine, string, *admission.Service, *policybundle.CatalogSnapshot) {
	t.Helper()
	f.multiOrg = multiOrg
	if f.rawMode == "" {
		f.rawMode = policybundle.RawSubmissionOPSPreflight
	}
	if !f.readOnly && !slices.Contains(f.groups[0].AllowedMethods, "eth_sendTransaction") {
		f.groups[0].AllowedMethods = append(slices.Clone(f.groups[0].AllowedMethods), "eth_sendTransaction")
	}
	if f.creationAttribution != nil {
		var version int
		if err := d.owner.QueryRow(t.Context(), `SELECT version FROM ops_admission_v2.schema_version WHERE singleton`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if version == 1 {
			if err := admissionsql.MigrateCreationIntents(t.Context(), d.ownerDSN, "raw_app", "raw_reader", "raw_retention"); err != nil {
				t.Fatal(err)
			}
		}
		if f.creationObserved && version != 3 {
			if err := admissionsql.MigrateCreationObserver(t.Context(), d.ownerDSN, "raw_app", "raw_reader", "raw_retention", "raw_observer", "raw_facts"); err != nil {
				t.Fatal(err)
			}
		}
	}
	snapshot := f.load(t)
	clock := func() time.Time { return time.Unix(now, 0) }
	if f.clock != nil {
		clock = func() time.Time { return time.Unix(f.clock.Load(), 0) }
	}
	if _, err := nativeadmission.NewRaw(snapshot, clock); multiOrg && err == nil {
		t.Fatal("old native constructor accepted v3")
	}
	genesisHash := nodeHash
	if f.creationObserved {
		n.enableCaptureHeaders()
		genesisHash = n.genesisHeader.Hash().Hex()
	}
	binding := walletops.ServiceBinding{ServiceOrigin: "https://ops.test", Environment: "test", ChainID: "1", GenesisHash: genesisHash, DeploymentID: "multi-" + uuid.NewString()}
	network := admission.NetworkBinding{Environment: binding.Environment, ChainID: binding.ChainID, GenesisHash: binding.GenesisHash, DeploymentID: binding.DeploymentID}
	gen, walletGen := uuid.NewString(), uuid.NewString()
	if err := admissionsql.BootstrapEmpty(t.Context(), d.ownerDSN, network, gen); err != nil {
		t.Fatal(err)
	}
	if err := walletsql.BootstrapEmpty(t.Context(), d.ownerDSN, binding, walletGen); err != nil {
		t.Fatal(err)
	}
	var store *admissionsql.Store
	var err error
	if len(creationOptions) > 0 && creationOptions[0].limits != nil {
		store, err = admissionsql.OpenCreationWriter(t.Context(), d.appDSN, *creationOptions[0].limits)
	} else {
		store, err = admissionsql.Open(t.Context(), d.appDSN)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	walletStore, err := walletsql.Open(t.Context(), d.walletDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(walletStore.Close)
	namespace, _ := binding.Namespace()
	walletState := walletops.ExpectedState{Generation: walletGen, Coverage: walletsql.EmptyCoverage()}
	if f.linkSigner || len(creationOptions) > 0 && creationOptions[0].walletService != nil {
		service, err := walletops.New(walletops.Config{Snapshot: snapshot, Clock: clock, Binding: binding, State: walletState, Store: walletStore})
		if err != nil {
			t.Fatal(err)
		}
		if f.linkSigner {
			operationalLink(t, service, token(t, snapshot, f.roles), signedValue(t, 9).Signer())
		}
		if len(creationOptions) > 0 && creationOptions[0].walletService != nil {
			creationOptions[0].walletService(service)
		}
	}
	resolver, err := walletadapter.New(walletStore, namespace, walletState, clock)
	if err != nil {
		t.Fatal(err)
	}
	profile := rpcexecution.SignedCallProfileID
	if f.rawMode == policybundle.RawSubmissionGuardV1 {
		profile = rpcexecution.GuardRetainedProfileID
	}
	callProfile := rpcexecution.NodeProfileID
	if f.lifecycle || f.simulation || f.creationAttribution != nil {
		callProfile = rpcexecution.LifecycleCallProfileID
		profile = rpcexecution.LifecycleSignedProfileID
		if f.rawMode == policybundle.RawSubmissionGuardV1 {
			profile = rpcexecution.LifecycleGuardProfileID
		}
		if f.simulation || f.creationAttribution != nil {
			callProfile = rpcexecution.SimulationCallProfileID
		}
	}
	newFinancial := admission.New
	if f.creationAttribution != nil {
		newFinancial = admission.NewCreationIntents
	}
	if f.creationObserved {
		newFinancial = admission.NewCreationObserved
	}
	nodeServer := httptest.NewServer(n)
	t.Cleanup(nodeServer.Close)
	var captureGate *creationcapture.Gate
	if f.creationObserved {
		key, _ := network.Key()
		state := creationfacts.State{Generation: gen, Coverage: creationfacts.Digest(admissionsql.EmptyCoverage())}
		net := creationfacts.Network{Key: creationfacts.Digest(key), Environment: network.Environment, ChainID: network.ChainID, Genesis: common.HexToHash(network.GenesisHash), Deployment: network.DeploymentID}
		ref := creationfacts.Source{Network: net, URL: nodeServer.URL, Profile: "reth-prague-included-creations/v1", PragueStart: 10, PragueEnd: 20}
		sources := []creationfacts.Source{}
		if !f.readOnly {
			source := ref
			source.Organization = orgA
			source.Profile = profile
			sources = append(sources, source)
		}
		captureGate, err = creationcapture.New(creationcapture.Options{Network: net, State: state, Reference: ref, Sources: sources, CaughtUpAssertion: creationfacts.CaughtUpAssertion, Store: store})
		if err != nil {
			t.Fatal(err)
		}
		floor := creationfacts.Header{Number: 1, Hash: n.anchorHeader.Hash(), Parent: n.genesisHeader.Hash(), Timestamp: 10}
		if err := admissionsql.BootstrapCreationObserver(t.Context(), d.ownerDSN, network, admission.ExpectedState{Generation: gen, Coverage: admissionsql.EmptyCoverage()}, captureGate.Metadata(), floor); err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(d.ownerDSN)
		u.User = url.UserPassword("raw_observer", "raw-test-only")
		worker, err := admissionsql.OpenObserver(t.Context(), u.String())
		if err != nil {
			t.Fatal(err)
		}
		defer worker.Close()
		m := captureGate.Metadata()
		lease, err := worker.AcquireObserverLease(t.Context(), net.Key, state, uuid.NewString(), m.SourceSet, m.Reference)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := worker.PublishObserverHeaders(t.Context(), creationfacts.HeaderUpdate{Before: lease, Common: floor, Tip: floor}); err != nil {
			t.Fatal(err)
		}
	}
	var financialStore admission.Store = store
	if len(creationOptions) > 0 && creationOptions[0].wrap != nil {
		financialStore = creationOptions[0].wrap(store)
	}
	financial, err := newFinancial(admission.Config{Snapshot: snapshot, Clock: clock, NetworkBinding: network, ExpectedState: admission.ExpectedState{Generation: gen, Coverage: admissionsql.EmptyCoverage()}, Store: financialStore, ExpectedEvidenceProfile: profile, CursorKeyring: admission.CursorKeyring{Active: admission.CursorKey{ID: "test", Key: bytes.Repeat([]byte{8}, 32)}}, CaptureGate: captureGate})
	if err != nil {
		t.Fatal(err)
	}
	if n.onSend == nil {
		n.onSend = func(raw string) string {
			tx, err := transactioninput.DecodeRaw(raw, "1", transactioninput.ProtectedEVMProfile(), transactioninput.DefaultLimits())
			if err != nil {
				t.Error(err)
				return common.Hash{}.Hex()
			}
			return tx.Hash().Hex()
		}
	}
	clients := map[string]*rpcexecution.Client{}
	for _, org := range []string{orgA, orgB} {
		client, err := rpcexecution.NewClient(nodeServer.Client().Transport, rpcexecution.NodeBinding{OrganizationID: org, URL: nodeServer.URL, ChainID: "1", Profile: callProfile, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, rpcexecution.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		clients[org] = client
	}
	rawNode := rpcengine.RawNodeOptions{Binding: rpcexecution.NodeBinding{OrganizationID: orgA, URL: nodeServer.URL, ChainID: "1", Profile: profile, PragueStartInclusive: 10, PragueEndExclusive: 20, AllowUnauthenticated: true}, Transport: nodeServer.Client().Transport, Limits: rpcexecution.DefaultLimits()}
	if f.rawMode == policybundle.RawSubmissionGuardV1 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		producer := &faultProducer{batches: make(chan []byte, 16)}

		server := grpc.NewServer()
		approvalpb.RegisterApprovalDeliveryServer(server, producer)
		go server.Serve(listener)
		t.Cleanup(server.Stop)
		rawNode.HashMode, rawNode.Seed, rawNode.KeyID, rawNode.MaxBatch = nodeapproval.HashCalls, bytes.Repeat([]byte{7}, 32), "pair-key", 32
		rawNode.Delivery = nodeapproval.DeliveryOptions{Targets: []string{listener.Addr().String()}, Timeout: time.Second, MaxInFlight: 1, RetainMax: 32}
	}
	rawNodes := map[string]rpcengine.RawNodeOptions{orgA: rawNode}
	if f.readOnly {
		rawNodes = map[string]rpcengine.RawNodeOptions{}
	}
	options := rpcengine.RawOptions{CallClients: clients, RawNodes: rawNodes, Wallets: resolver, WalletBinding: binding, WalletState: walletState, Admission: financial, Clock: clock, CaptureGate: captureGate}
	constructor := rpcengine.NewRaw
	if multiOrg {
		if _, err := rpcengine.NewRaw(snapshot, options); err == nil {
			t.Fatal("old RPC constructor accepted v3")
		}
		constructor = rpcengine.NewMultiOrg
	}
	if f.lifecycle {
		if _, err := rpcengine.NewMultiOrg(snapshot, options); err == nil {
			t.Fatal("old RPC constructor accepted native-v4")
		}
		constructor = rpcengine.NewLifecycle
	}
	if f.simulation {
		if _, err := nativeadmission.NewLifecycle(snapshot, clock); err == nil {
			t.Fatal("old native lifecycle constructor accepted v5 simulation")
		}
		if _, err := rpcengine.NewLifecycle(snapshot, options); err == nil {
			t.Fatal("old lifecycle RPC constructor accepted v5 simulation source")
		}
		constructor = rpcengine.NewSimulation
	}
	if f.creationAttribution != nil {
		constructor = rpcengine.NewCreationIntents
	}
	if f.creationObserved {
		constructor = rpcengine.NewCreationObserved
	}
	e, err := constructor(snapshot, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, token(t, snapshot, f.roles), financial, snapshot
}

func lifecycleFixture(mode string) fixture {
	f := newFixture()
	f.lifecycle, f.rawMode = true, mode
	f.groups[0].Claims = []string{"deploy"}
	f.bindings[0].Allow = append(f.bindings[0].Allow,
		policycore.FrameRule{StorageAddress: addressC, Selector: "*"},
		lifecycleRule("create", policycore.CallTypeCreate, policycore.CallTypeCreate2),
		lifecycleRule("deployment-context", policycore.CallTypeCall, policycore.CallTypeStaticCall))
	return f
}

func creationIntentRuntimeFixture() fixture {
	f := lifecycleFixture(policybundle.RawSubmissionOPSPreflight)
	f.creationAttribution = &policybundle.CreationAttribution{Factories: []policybundle.FactoryAttribution{{Address: addressA, OrganizationID: orgA, CodeHash: crypto.Keccak256Hash(common.FromHex("0x6000")).Hex(), Scope: policybundle.FactoryCreationSubtree}}}
	return f
}

type faultProducer struct {
	approvalpb.UnimplementedApprovalDeliveryServer
	deliveries atomic.Int64
	approvals  atomic.Int64
	batches    chan []byte
}

func (p *faultProducer) Status(context.Context, *approvalpb.StatusRequest) (*approvalpb.StatusResponse, error) {
	return &approvalpb.StatusResponse{BootId: "fault-boot", ChainId: 1, TrustedKeyIds: []string{"pair-key"}, MaxTtlMs: uint64(time.Hour.Milliseconds()), Capacity: 10000, WaitMs: 5000}, nil
}
func (p *faultProducer) Deliver(_ context.Context, req *approvalpb.DeliverRequest) (*approvalpb.DeliverResponse, error) {
	p.deliveries.Add(1)
	count := uint32(1)
	offset := len("OPS_APPROVAL_BATCH_V2\x00")
	if len(req.Batch) > offset {
		offset += 1 + int(req.Batch[offset]) + 16
		if len(req.Batch) >= offset+4 {
			count = binary.BigEndian.Uint32(req.Batch[offset:])
		}
	}
	p.approvals.Add(int64(count))
	if p.batches != nil {
		select {
		case p.batches <- bytes.Clone(req.Batch):
		default:
		}
	}
	return &approvalpb.DeliverResponse{BootId: "fault-boot", Stored: count}, nil
}

type database struct {
	owner                          *pgx.Conn
	dsn, writer, reader, retention string
	registration                   s.Registration
	scope                          s.Scope
}

func setupActivityDatabase(t *testing.T, network networkidentity.Binding) *database {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	if raw, err := exec.CommandContext(ctx, "docker", "image", "inspect", "postgres:16-alpine").CombinedOutput(); err != nil {
		t.Fatalf("cached owned PostgreSQL required: %v %s", err, raw)
	}
	name := "ops-v2-activity-test-" + uuid.NewString()[:8]
	raw, err := exec.CommandContext(ctx, "docker", "run", "--rm", "--detach", "--memory", "256m", "--publish", "127.0.0.1::5432", "--env", "POSTGRES_PASSWORD=activity-public-test-only", "--env", "POSTGRES_DB=activity_test", "--name", name, "postgres:16-alpine").CombinedOutput()
	if err != nil {
		t.Fatalf("owned PostgreSQL: %v %s", err, raw)
	}
	id := strings.TrimSpace(string(raw))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if raw, err := exec.CommandContext(ctx, "docker", "rm", "--force", id).CombinedOutput(); err != nil {
			t.Errorf("owned fixture cleanup: %v %s", err, raw)
		}
	})
	raw, err = exec.CommandContext(ctx, "docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatal(err)
	}
	x := &database{dsn: "postgres://postgres:activity-public-test-only@" + strings.TrimSpace(string(raw)) + "/activity_test?sslmode=disable"}
	for ctx.Err() == nil {
		x.owner, err = pgx.Connect(ctx, x.dsn)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("owned PostgreSQL readiness", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = x.owner.Close(ctx)
	})
	for _, role := range []string{"b1_writer", "b1_reader", "b1_retention"} {
		if _, err := x.owner.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` LOGIN NOINHERIT PASSWORD 'activity-public-test-only'`); err != nil {
			t.Fatal(err)
		}
	}
	paths, err := filepath.Glob("../db/migrations_audit/00[1-4]_*.sql")
	if err != nil || len(paths) != 4 {
		t.Fatal("baseline SQL", paths, err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := x.owner.Exec(ctx, "BEGIN;"+string(raw)+";COMMIT"); err != nil {
			t.Fatal("exact baseline", path, err)
		}
	}
	if err := s.Migrate(ctx, x.dsn, "b1_writer", "b1_reader", "b1_retention", true); err != nil {
		t.Fatal("activity005 migrate", err)
	}
	u, _ := url.Parse(x.dsn)
	u.User = url.UserPassword("b1_writer", "activity-public-test-only")
	x.writer = u.String()
	u.User = url.UserPassword("b1_reader", "activity-public-test-only")
	x.reader = u.String()
	u.User = url.UserPassword("b1_retention", "activity-public-test-only")
	x.retention = u.String()
	x.registration = s.Registration{Network: network, SourceID: uuid.NewString(), Configuration: [32]byte{1}, Limits: s.DefaultStorageLimits(), Roles: s.RoleNames{Writer: "b1_writer", Reader: "b1_reader", Retention: "b1_retention"}}
	if err := s.Initialize(ctx, x.dsn, x.registration, true); err != nil {
		t.Fatal("initialize", err)
	}
	key, _ := x.registration.Network.Key()
	status, err := s.Status(ctx, x.dsn, key, x.registration.SourceID)
	if err != nil {
		t.Fatal("status", err)
	}
	x.scope = s.Scope{NetworkKey: key, SourceID: x.registration.SourceID, ExpectedGeneration: status.Metadata.Generation}
	return x
}
