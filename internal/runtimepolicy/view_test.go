package runtimepolicy_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/golang-jwt/jwt/v5"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/runtimepolicy"
)

const orgA = "11111111-1111-1111-1111-111111111111"
const orgB = "22222222-2222-2222-2222-222222222222"
const reader = "33333333-3333-3333-3333-333333333333"
const upgrader = "44444444-4444-4444-4444-444444444444"
const localAdmin = "55555555-5555-5555-5555-555555555555"
const orgAdmin = "66666666-6666-6666-6666-666666666666"
const readonly = "77777777-7777-7777-7777-777777777777"
const foreign = "88888888-8888-8888-8888-888888888888"
const contractA = "0x1111111111111111111111111111111111111111"
const contractB = "0x2222222222222222222222222222222222222222"
const tenant = "99999999-9999-9999-9999-999999999999"
const oid = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
const now = int64(1800000000)
const one = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_ONE"
const two = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_TWO"

type fixture struct {
	groupsA    []policybundle.Group
	mappings   []identity.Mapping
	methods    policybundle.MethodCatalog
	groupGrant policybundle.EventRules
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func key() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)) }
func newFixture() fixture {
	groups := []policybundle.Group{
		{ID: reader, Slug: "reader", Name: "Reader", AllowedMethods: []string{"chain_call", "eth_getCode"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: one}},
		{ID: upgrader, Slug: "upgrader", Name: "Upgrader", AllowedMethods: []string{"eth_sendTransaction"}, Claims: []string{"upgrade"}, RpcCredential: &policybundle.SecretRef{FromEnv: two}},
		{ID: localAdmin, Slug: "local", Name: "Local", AllowedMethods: []string{"eth_getCode"}, Claims: []string{"admin"}, RpcCredential: &policybundle.SecretRef{FromEnv: one}},
		{ID: orgAdmin, Slug: "admin", Name: "Admin", IsOrgAdmin: true, AllowedMethods: []string{"eth_getCode"}, Claims: []string{}},
		{ID: readonly, Slug: "readonly", Name: "Readonly", IsOrgReadonlyAdmin: true, AllowedMethods: []string{"eth_getBalance"}, Claims: []string{}},
	}
	mappings := []identity.Mapping{}
	for i, entry := range []struct{ fact, group, org string }{{"Reader", reader, orgA}, {"Upgrade", upgrader, orgA}, {"Local", localAdmin, orgA}, {"Admin", orgAdmin, orgA}, {"Readonly", readonly, orgA}, {"Foreign", foreign, orgB}} {
		mappings = append(mappings, identity.Mapping{ID: []string{"reader", "upgrade", "local", "admin", "readonly", "foreign"}[i], ProfileID: "azure", OrganizationID: entry.org, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: entry.fact}, GroupIDs: []string{entry.group}})
	}
	return fixture{groups, mappings, policybundle.MethodCatalog{Version: "rpc/v1", Assignable: []string{"eth_call", "chain_call", "eth_getCode", "eth_getBalance", "eth_sendTransaction"}, Aliases: map[string]string{"chain_call": "eth_call"}, Wildcard: []string{"eth_call", "eth_getCode", "eth_getBalance"}, RequiredClaims: map[string]string{}}, policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}}
}

func (f fixture) load(t *testing.T) *policybundle.CatalogSnapshot {
	t.Helper()
	directory := t.TempDir()
	source := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "core", Keys: []identity.PublicKey{{Kid: "k1", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(key().Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure"}}}, Profiles: []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: tenant, Issuer: "https://login.microsoftonline.com/" + tenant + "/v2.0", APIAudience: oid, ClientID: reader, DelegatedScope: "api://bank/access", FactSource: "appRoles"}}, Mappings: f.mappings}
	documents := map[string][]byte{}
	doc := func(kind policybundle.Kind, org string, spec any) []byte {
		return marshal(t, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": kind, "organizationId": org, "spec": spec})
	}
	documents["a-groups.json"] = doc(policybundle.Groups, orgA, policybundle.GroupsSpec{Groups: f.groupsA})
	documents["b-groups.json"] = doc(policybundle.Groups, orgB, policybundle.GroupsSpec{Groups: []policybundle.Group{{ID: foreign, Slug: "foreign", Name: "Foreign", IsOrgAdmin: true, AllowedMethods: []string{"eth_getCode"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: "OPS_RPC_CREDENTIAL_22222222222222222222222222222222_FOREIGN"}}}})
	for _, entry := range []struct{ org, prefix, address, id string }{{orgA, "a", contractA, "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}, {orgB, "b", contractB, "cccccccc-cccc-cccc-cccc-cccccccccccc"}} {
		grants := []policybundle.ReadGrant{}
		if entry.org == orgA {
			for i, id := range []string{reader, localAdmin} {
				grants = append(grants, policybundle.ReadGrant{ID: []string{"dddddddd-dddd-dddd-dddd-dddddddddddd", "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"}[i], GroupID: id, EventRules: f.groupGrant})
			}
		}
		contract := policybundle.Contract{ID: entry.id, Address: entry.address, Name: entry.prefix, ABI: json.RawMessage(`[{"type":"event","name":"Seen","inputs":[{"name":"who","type":"address","indexed":true}],"anonymous":false}]`), ReadGrants: grants}
		documents[entry.prefix+"-registry.json"] = doc(policybundle.ContractRegistry, entry.org, policybundle.RegistrySpec{Contracts: []policybundle.Contract{contract}})
		documents[entry.prefix+"-execution.json"] = doc(policybundle.ExecutionRules, entry.org, policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.APIVersion, Kind: policycore.Kind, Org: entry.org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}})
	}
	identityRaw := marshal(t, source)
	documents["identity.json"] = identityRaw
	manifest := policybundle.Manifest{APIVersion: policybundle.BundleAPIVersion, Kind: policybundle.BundleKind, Environment: "test", ChainID: "1", EvaluatorVersion: policybundle.NativeEvaluatorVersion, Profile: policybundle.IdentityProfileID, SourceRevision: "selected", Organizations: []policybundle.Organization{{ID: orgA, Slug: "a", Name: "A"}, {ID: orgB, Slug: "b", Name: "B"}}, RequiredCapabilities: []string{policybundle.CapabilityNativeValidate, policybundle.CapabilityPrincipal, policybundle.CapabilityRPCCredential, policybundle.CapabilityIdentity}, IdentityCatalog: &policybundle.IdentityCatalogRef{Path: "identity.json", SHA256: policybundle.RawDigest(identityRaw)}}
	for _, entry := range []struct{ org, prefix string }{{orgA, "a"}, {orgB, "b"}} {
		for kind, suffix := range map[policybundle.Kind]string{policybundle.Groups: "groups", policybundle.ContractRegistry: "registry", policybundle.ExecutionRules: "execution"} {
			path := entry.prefix + "-" + suffix + ".json"
			manifest.Documents = append(manifest.Documents, policybundle.DocumentRef{Kind: kind, OrganizationID: entry.org, Path: path, SHA256: policybundle.RawDigest(documents[path])})
		}
	}
	for path, b := range documents {
		if e := os.WriteFile(filepath.Join(directory, path), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	b := marshal(t, manifest)
	if e := os.WriteFile(filepath.Join(directory, "manifest.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: directory, ExpectedManifestDigest: policybundle.RawDigest(b), ExpectedEnvironment: "test", ExpectedChainID: "1"}, policybundle.Options{Limits: policybundle.DefaultLimits(), Profile: policybundle.IdentityProfile("rpc/v1"), Methods: f.methods, IdentityLimits: identity.DefaultLimits()})
	if e != nil {
		t.Fatal(e)
	}
	return snapshot
}

func access(t *testing.T, snapshot *policybundle.CatalogSnapshot, facts ...string) string {
	t.Helper()
	catalog, _ := snapshot.Identity()
	digest, _ := catalog.ProfileDigest("azure")
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	hash := sha256.New()
	for _, s := range []string{"azure-v2", issuer, tenant, oid, "human"} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(s)))
		hash.Write(size[:])
		hash.Write([]byte(s))
	}
	verified := []identity.Fact{}
	for _, value := range facts {
		verified = append(verified, identity.Fact{Kind: "azure.role", Value: value})
	}
	claims := map[string]any{"iss": "https://ops.test", "aud": "core", "sub": "ops:p1:" + base64.RawURLEncoding.EncodeToString(hash.Sum(nil)), "jti": "request", "iat": now, "nbf": now, "exp": now + 300, "principal_kind": "human", "source_profile": "azure", "source_profile_digest": digest, "identity_authority": issuer, "source_subject": oid, "source_tenant": tenant, "source_verified_at": now, "claims_as_of": now, "source_not_after": now + 3600, "facts": verified}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims(claims))
	token.Header["typ"], token.Header["kid"] = "ops-access+jwt", "k1"
	compact, e := token.SignedString(key())
	if e != nil {
		t.Fatal(e)
	}
	return compact
}

func makeFactory(t *testing.T, snapshot *policybundle.CatalogSnapshot, clock identity.Clock) *runtimepolicy.Factory {
	t.Helper()
	f, e := runtimepolicy.NewFactory(snapshot, clock)
	if e != nil {
		t.Fatal(e)
	}
	return f
}

func TestSelectedSnapshotViewPreservesMethodsMasksAndReadScope(t *testing.T) {
	f := newFixture()
	snapshot := f.load(t)
	factory := makeFactory(t, snapshot, func() time.Time { return time.Unix(now, 0) })
	view, e := factory.Build(access(t, snapshot, "Reader", "Upgrade"))
	if e != nil {
		t.Fatal(e)
	}
	org, ok := view.Org(orgA)
	if !ok || !slices.Equal(org.Groups(), []string{reader, upgrader}) {
		t.Fatal("mapped groups missing")
	}
	if !org.GroupAllowsMethod("chain_call") || org.GroupAllowsMethod("eth_call") || org.GroupAllowsMethod("CHAIN_call") || org.GroupAllowsMethod("*") {
		t.Fatal("raw alias grant widened")
	}
	if !slices.Equal(org.GroupMasks(), []runtimepolicy.GroupMask{{GroupID: reader, Claims: 0}, {GroupID: upgrader, Claims: policycore.ClaimUpgrade}}) || org.UnionClaims() != policycore.ClaimUpgrade {
		t.Fatal("source group claim mask leaked across groups")
	}
	contract, ok := view.Contract(common.HexToAddress(contractA))
	if !ok || !contract.Associated() || contract.AdminForRead() || len(contract.ReadGrants()) != 1 || contract.ReadGrants()[0].EventRules.Mode != "none" {
		t.Fatal("read mode none lost its separate association/entitlement meaning")
	}
	other, _ := view.Contract(common.HexToAddress(contractB))
	if other.Associated() || other.AdminForRead() || len(other.ReadGrants()) != 0 {
		t.Fatal("foreign scope inherited local grants")
	}
	if _, ok := view.Contract(common.HexToAddress("0x9999999999999999999999999999999999999999")); ok {
		t.Fatal("unknown address invented registry/EOA facts")
	}
	for _, fact := range []string{"Admin", "Readonly", "Local", "Foreign"} {
		v, e := factory.Build(access(t, snapshot, fact))
		if e != nil {
			t.Fatal(e)
		}
		a, _ := v.Contract(common.HexToAddress(contractA))
		if fact == "Admin" {
			o, _ := v.Org(orgA)
			if !o.IsOrgAdmin() || o.GroupMasks()[0].Claims != 7 || !a.Associated() || !a.AdminForRead() || o.GroupAllowsMethod("eth_sendTransaction") {
				t.Fatal("org admin synthesized methods or lost mask")
			}
			decision := o.NativeProgram().Evaluate(policycore.Context{Org: orgA, Groups: o.Groups()}, []policycore.Frame{{CallType: policycore.CallTypeCall, Calldata: []byte{0, 1, 2, 3}, CodeAddress: common.HexToAddress(contractA), StorageAddress: common.HexToAddress(contractA), CodeOrg: orgA, StorageOrg: orgA, CodeKind: policycore.CodeContract}})
			if decision.Allowed || decision.Code != policycore.DenialNoMatchingRule {
				t.Fatal("admin synthesized native execution", decision)
			}
		}
		if fact == "Readonly" {
			o, _ := v.Org(orgA)
			if !o.IsOrgReadonlyAdmin() || o.IsOrgAdmin() || o.GroupMasks()[0].Claims != 0 || a.Associated() || a.AdminForRead() {
				t.Fatal("readonly became full admin")
			}
		}
		if fact == "Local" {
			o, _ := v.Org(orgA)
			if o.IsOrgAdmin() || !a.AdminForRead() {
				t.Fatal("ordinary admin/read association conflated with true org-admin flag")
			}
		}
		if fact == "Foreign" && a.AdminForRead() {
			t.Fatal("foreign org admin leaked")
		}
	}
}

func TestFactoryReverifiesCurrentMappingAndOriginalExpiry(t *testing.T) {
	first := newFixture().load(t)
	raw := access(t, first, "Reader")
	var seconds atomic.Int64
	seconds.Store(now)
	clock := func() time.Time { return time.Unix(seconds.Load(), 0) }
	factory := makeFactory(t, first, clock)
	old, e := factory.Build(raw)
	if e != nil {
		t.Fatal(e)
	}
	changed := newFixture()
	changed.mappings[0].GroupIDs = []string{readonly}
	second := changed.load(t)
	next, e := makeFactory(t, second, clock).Build(raw)
	if e != nil {
		t.Fatal(e)
	}
	o, _ := old.Org(orgA)
	n, _ := next.Org(orgA)
	if !slices.Equal(o.Groups(), []string{reader}) || !slices.Equal(n.Groups(), []string{readonly}) || o == n {
		t.Fatal("principal/snapshot mappings were mixed")
	}
	policyChange := newFixture()
	policyChange.groupsA[0].AllowedMethods = []string{"eth_getBalance"}
	third := policyChange.load(t)
	if first.Metadata().IdentityCatalog.SemanticDigest != third.Metadata().IdentityCatalog.SemanticDigest {
		t.Fatal("policy-only update changed identity semantics")
	}
	current, e := makeFactory(t, third, clock).Build(raw)
	if e != nil {
		t.Fatal(e)
	}
	co, _ := current.Org(orgA)
	if co.GroupAllowsMethod("chain_call") || !co.GroupAllowsMethod("eth_getBalance") {
		t.Fatal("policy-only new factory reused old method grants")
	}
	unmapped, e := factory.Build(access(t, first, "Unknown"))
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := unmapped.Org(orgA); ok {
		t.Fatal("unmapped identity acquired default membership")
	}
	if c, ok := unmapped.Contract(common.HexToAddress(contractA)); !ok || c.Associated() || c.AdminForRead() || len(c.ReadGrants()) != 0 {
		t.Fatal("unmapped identity acquired registry grants")
	}
	if _, e := factory.Build(""); e == nil {
		t.Fatal("missing bearer created view")
	}
	if _, e := runtimepolicy.NewFactory(nil, clock); e == nil {
		t.Fatal("nil snapshot accepted")
	}
	if _, e := runtimepolicy.NewFactory(first, nil); e == nil {
		t.Fatal("nil clock accepted")
	}
	seconds.Store(now + 300)
	if old.Live() || old.RequireLive() == nil {
		t.Fatal("view extended original access expiry")
	}
	if _, e := factory.Build(raw); e == nil {
		t.Fatal("expired token rebuilt authority")
	}
	if old.Metadata().ManifestDigest == "" || old.ExpiresAt().Unix() != now+300 {
		t.Fatal("expiry removed diagnostic metadata")
	}
}

func TestCredentialsStayInMappedRequestOrgAndRawMethod(t *testing.T) {
	snapshot := newFixture().load(t)
	factory := makeFactory(t, snapshot, func() time.Time { return time.Unix(now, 0) })
	view, e := factory.Build(access(t, snapshot, "Reader", "Local", "Upgrade", "Foreign"))
	if e != nil {
		t.Fatal(e)
	}
	a, _ := view.Org(orgA)
	b, _ := view.Org(orgB)
	if !slices.Equal(a.CredentialRefs("eth_getCode"), []string{one}) {
		t.Fatal("same refs did not coalesce")
	}
	if ref, e := a.SelectCredentialRef("eth_getCode"); e != nil || ref != one {
		t.Fatal(ref, e)
	}
	if !slices.Equal(a.CredentialRefs("eth_sendTransaction"), []string{two}) || len(a.CredentialRefs("eth_call")) != 0 || len(a.CredentialRefs("unknown")) != 0 {
		t.Fatal("credential scope ignored raw method grants")
	}
	if ref, e := a.SelectCredentialRef(""); ref != "" || e == nil {
		t.Fatal("first nonempty conflicting ref selected")
	} else if typed, ok := e.(*runtimepolicy.Error); !ok || typed.Code != runtimepolicy.AmbiguousCredential {
		t.Fatal(e)
	}
	if len(b.CredentialRefs("")) != 1 || strings.Contains(b.CredentialRefs("")[0], "11111111") {
		t.Fatal("foreign request org inherited credential")
	}
	reordered := newFixture()
	slices.Reverse(reordered.groupsA)
	other := reordered.load(t)
	v, e := makeFactory(t, other, func() time.Time { return time.Unix(now, 0) }).Build(access(t, other, "Upgrade", "Reader"))
	if e != nil {
		t.Fatal(e)
	}
	o, _ := v.Org(orgA)
	if !slices.Equal(a.CredentialRefs(""), o.CredentialRefs("")) {
		t.Fatal("credential ambiguity changed by group order")
	}
}

func TestMappedReadModesAndMetadataCannotEscapeGrantPath(t *testing.T) {
	for _, mode := range []string{"none", "all", "allowlist"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture()
			f.groupGrant = policybundle.EventRules{Mode: mode, Rules: []policybundle.EventRule{}}
			if mode == "allowlist" {
				f.groupGrant.Rules = []policybundle.EventRule{{Topic0: crypto.Keccak256Hash([]byte("Seen(address)")).Hex(), Name: "Seen", ParamRules: []policybundle.ParamRule{{Index: 0, MustBe: contractA}}}}
			}
			snapshot := f.load(t)
			factory := makeFactory(t, snapshot, func() time.Time { return time.Unix(now, 0) })
			view, e := factory.Build(access(t, snapshot, "Reader"))
			if e != nil {
				t.Fatal(e)
			}
			c, _ := view.Contract(common.HexToAddress(contractA))
			if !c.Associated() || c.AdminForRead() || len(c.ReadGrants()) != 1 || c.ReadGrants()[0].GroupID != reader || c.ReadGrants()[0].EventRules.Mode != mode {
				t.Fatal("read association/mode/source provenance changed")
			}
			metadata := c.RegistryMetadata()
			fields := []string{}
			typ := reflect.TypeOf(metadata)
			for i := range typ.NumField() {
				fields = append(fields, typ.Field(i).Name)
			}
			if !slices.Equal(fields, []string{"ID", "Address", "Name", "ABI", "AllowVisibleToUnlock", "EventsAllowDynamicPayload"}) {
				t.Fatal("registry metadata contains a grant/claim escape", fields)
			}
			metadata.ABI[0] = '!'
			grants := c.ReadGrants()
			grants[0].GroupID = localAdmin
			if mode == "allowlist" {
				grants[0].EventRules.Rules[0].ParamRules[0].MustBe = "changed"
			}
			if c.RegistryMetadata().ABI[0] != '[' || c.ReadGrants()[0].GroupID != reader || (mode == "allowlist" && c.ReadGrants()[0].EventRules.Rules[0].ParamRules[0].MustBe != contractA) {
				t.Fatal("registry/grant data mutated through getter")
			}
		})
	}
}

func TestMethodSnapshotAndConcurrentViewGettersRemainDetached(t *testing.T) {
	f := newFixture()
	f.methods.RequiredClaims = map[string]string{"chain_call": "deploy", "eth_call": "upgrade"}
	f.groupsA[0].Claims = []string{"admin"}
	snapshot := f.load(t)
	info, ok := snapshot.Method("chain_call")
	if !ok || info.Canonical != "eth_call" || !slices.Equal(info.RequiredClaims, []string{"deploy", "upgrade"}) {
		t.Fatal("raw/canonical required claims lost")
	}
	info.RequiredClaims[0] = "changed"
	f.methods.RequiredClaims["chain_call"] = "admin"
	f.methods.Aliases["chain_call"] = "eth_getCode"
	f.methods.Assignable[0] = "changed"
	current, _ := snapshot.Method("chain_call")
	if current.Canonical != "eth_call" || !slices.Equal(current.RequiredClaims, []string{"deploy", "upgrade"}) {
		t.Fatal("method registry escaped snapshot")
	}
	for _, unknown := range []string{"CHAIN_call", "eth_*", "*", "unknown"} {
		if _, ok := snapshot.Method(unknown); ok {
			t.Fatal("unknown name became registered", unknown)
		}
	}
	view, e := makeFactory(t, snapshot, func() time.Time { return time.Unix(now, 0) }).Build(access(t, snapshot, "Reader"))
	if e != nil {
		t.Fatal(e)
	}
	org, _ := view.Org(orgA)
	org.Groups()[0] = "changed"
	org.GroupMasks()[0].Claims = 0
	org.CredentialRefs("")[0] = "changed"
	metadata := view.Metadata()
	metadata.IdentityCatalog.Path = "changed"
	if org.Groups()[0] != reader || org.GroupMasks()[0].Claims != 7 || org.CredentialRefs("")[0] != one || view.Metadata().IdentityCatalog.Path != "identity.json" {
		t.Fatal("view mutable getter leaked")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 30 {
				view.Metadata()
				view.RequireLive()
				o, _ := view.Org(orgA)
				o.Groups()
				o.GroupMasks()
				o.CredentialRefs("")
				c, _ := view.Contract(common.HexToAddress(contractA))
				c.ReadGrants()
				c.RegistryMetadata()
				snapshot.Method("chain_call")
			}
		})
	}
	wg.Wait()
}
