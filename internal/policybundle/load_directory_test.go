package policybundle_test

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

const (
	orgID       = "11111111-1111-1111-1111-111111111111"
	groupID     = "22222222-2222-2222-2222-222222222222"
	contractID  = "33333333-3333-3333-3333-333333333333"
	grantID     = "44444444-4444-4444-4444-444444444444"
	address     = "0x1111111111111111111111111111111111111111"
	signer      = "0x2222222222222222222222222222222222222222"
	secret      = "OPS_RPC_CREDENTIAL_11111111111111111111111111111111_RPC"
	contractABI = `[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"address"},{"name":"value","type":"uint256"}],"outputs":[]},{"type":"event","name":"Transfer","inputs":[{"name":"to","type":"address","indexed":true}],"anonymous":false}]`
)

type fixture struct {
	manifest policybundle.Manifest
	docs     map[string][]byte
	options  policybundle.Options
}

func encode(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func envelope(t *testing.T, kind policybundle.Kind, org string, spec any) []byte {
	return encode(t, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": kind, "organizationId": org, "spec": spec})
}
func canonicalABI(t *testing.T) string {
	t.Helper()
	var value any
	d := json.NewDecoder(strings.NewReader(contractABI))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return string(encode(t, value))
}
func parsedABI(t *testing.T) abi.ABI {
	t.Helper()
	a, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func baseFixture(t *testing.T) fixture {
	t.Helper()
	a := parsedABI(t)
	max, amount, depth := "100", "10", int64(2)
	group := policybundle.Group{ID: groupID, Slug: "readers", Name: "Readers", AllowedMethods: []string{"eth_call"}, Claims: []string{}, RpcCredential: &policybundle.SecretRef{FromEnv: secret}}
	contract := policybundle.Contract{ID: contractID, Address: address, Name: "Vault", ABI: json.RawMessage(contractABI), ReadGrants: []policybundle.ReadGrant{{ID: grantID, GroupID: groupID, EventRules: policybundle.EventRules{Mode: "allowlist", Rules: []policybundle.EventRule{{Topic0: a.Events["Transfer"].ID.Hex(), Name: "Transfer", ParamRules: []policybundle.ParamRule{{Index: 0, MustBe: "self"}}}}}}}}
	policy := &policycore.Policy{APIVersion: policycore.APIVersion, Kind: policycore.Kind, Org: orgID, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{{Group: groupID, Allow: []policycore.FrameRule{{StorageAddress: address, Selector: "0x" + common.Bytes2Hex(a.Methods["transfer"].ID), ABIDigest: policycore.ABIDigest(canonicalABI(t)), MaxValue: &max, MaxDepth: &depth, CallerAddress: address, Args: []policycore.ArgConstraint{{Index: 0, AddressEquals: &policycore.AddressMatch{Source: policycore.AddressSourceSigner}}, {Index: 1, UintAtMost: &amount}}}}}}}
	docs := map[string][]byte{"groups.json": envelope(t, policybundle.Groups, orgID, policybundle.GroupsSpec{Groups: []policybundle.Group{group}}), "registry.json": envelope(t, policybundle.ContractRegistry, orgID, policybundle.RegistrySpec{Contracts: []policybundle.Contract{contract}}), "execution.json": envelope(t, policybundle.ExecutionRules, orgID, policybundle.ExecutionSpec{Policy: policy})}
	m := policybundle.Manifest{APIVersion: policybundle.BundleAPIVersion, Kind: policybundle.BundleKind, Environment: "test", ChainID: "31337", EvaluatorVersion: policybundle.NativeEvaluatorVersion, Profile: policybundle.FoundationProfileID, SourceRevision: "reviewed-source", Organizations: []policybundle.Organization{{ID: orgID, Slug: "bank", Name: "Bank"}}, RequiredCapabilities: []string{policybundle.CapabilityNativeValidate, policybundle.CapabilityPrincipal, policybundle.CapabilityFrames, policybundle.CapabilityCalldata, policybundle.CapabilitySigner, policybundle.CapabilityLinkedWallets, policybundle.CapabilityCaller, policybundle.CapabilityValue, policybundle.CapabilityDepth, policybundle.CapabilityRPCCredential}, Documents: []policybundle.DocumentRef{{Kind: policybundle.Groups, OrganizationID: orgID, Path: "groups.json"}, {Kind: policybundle.ContractRegistry, OrganizationID: orgID, Path: "registry.json"}, {Kind: policybundle.ExecutionRules, OrganizationID: orgID, Path: "execution.json"}}}
	o := policybundle.Options{Limits: policybundle.DefaultLimits(), Profile: policybundle.FoundationProfile("rpc-test/v1"), Methods: policybundle.MethodCatalog{Version: "rpc-test/v1", Assignable: []string{"eth_call", "eth_getBalance", "chain_call"}, Aliases: map[string]string{"chain_call": "eth_call"}, Wildcard: []string{"eth_call", "eth_getBalance"}, RequiredClaims: map[string]string{}}}
	return fixture{m, docs, o}
}

func (f fixture) write(t *testing.T) policybundle.Selection {
	t.Helper()
	dir := t.TempDir()
	for name, raw := range f.docs {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := range f.manifest.Documents {
		ref := &f.manifest.Documents[i]
		ref.SHA256 = policybundle.RawDigest(f.docs[ref.Path])
	}
	raw := encode(t, f.manifest)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return policybundle.Selection{Directory: dir, ExpectedManifestDigest: policybundle.RawDigest(raw), ExpectedEnvironment: "test", ExpectedChainID: "31337"}
}

func (f *fixture) edit(t *testing.T, name string, edit func(map[string]any)) {
	t.Helper()
	var doc map[string]any
	d := json.NewDecoder(strings.NewReader(string(f.docs[name])))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	f.docs[name] = encode(t, doc)
}
func spec(doc map[string]any) map[string]any  { return doc["spec"].(map[string]any) }
func group(doc map[string]any) map[string]any { return spec(doc)["groups"].([]any)[0].(map[string]any) }
func contract(doc map[string]any) map[string]any {
	return spec(doc)["contracts"].([]any)[0].(map[string]any)
}
func rule(doc map[string]any) map[string]any {
	return spec(doc)["policy"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["allow"].([]any)[0].(map[string]any)
}

func load(t *testing.T, f fixture) *policybundle.CatalogSnapshot {
	t.Helper()
	s, err := policybundle.LoadDirectory(t.Context(), f.write(t), f.options)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func reject(t *testing.T, selection policybundle.Selection, options policybundle.Options, ctx context.Context) *policybundle.Error {
	t.Helper()
	snapshot, err := policybundle.LoadDirectory(ctx, selection, options)
	if snapshot != nil || err == nil {
		t.Fatalf("expected nil snapshot and error, got %v %v", snapshot, err)
	}
	var typed *policybundle.Error
	if !errors.As(err, &typed) {
		t.Fatalf("untyped error: %T", err)
	}
	if len(typed.Error()) > 550 {
		t.Fatal("unbounded diagnostic")
	}
	return typed
}

func TestBundleColdLoadExecutionAndDetachedCatalog(t *testing.T) {
	f := baseFixture(t)
	selection := f.write(t)
	s, err := policybundle.LoadDirectory(t.Context(), selection, f.options)
	if err != nil {
		t.Fatal(err)
	}
	metadata, requirements := s.Metadata(), s.Requirements()
	if metadata.ManifestDigest != selection.ExpectedManifestDigest || metadata.MethodCatalogVersion != "rpc-test/v1" || len(metadata.Documents) != 3 || !slices.Equal(requirements.SecretRefs, []string{secret}) {
		t.Fatal("lost selection identity or inferred secret references")
	}
	for _, doc := range metadata.Documents {
		if doc.SemanticDigest == "" || doc.SHA256 == "" {
			t.Fatal("missing distinct source identities")
		}
	}
	a := parsedABI(t)
	input, err := a.Pack("transfer", common.HexToAddress(signer), big.NewInt(5))
	if err != nil {
		t.Fatal(err)
	}
	ctx := policycore.Context{Org: orgID, Groups: []string{groupID}, Signer: common.HexToAddress(signer)}
	frame := policycore.Frame{StorageAddress: common.HexToAddress(address), CodeAddress: common.HexToAddress(address), CallerAddress: common.HexToAddress(address), CallType: policycore.CallTypeCall, Calldata: input, Value: big.NewInt(1), Depth: 1, CodeKind: policycore.CodeContract, CodeOrg: orgID, StorageOrg: orgID}
	v, ok := s.Execution(orgID)
	if !ok || !v.Evaluate(ctx, []policycore.Frame{frame}).Allowed {
		t.Fatal("selected native catalog did not allow fixture")
	}
	ctx.Signer = common.Address{}
	if v.Evaluate(ctx, []policycore.Frame{frame}).Allowed {
		t.Fatal("loader widened native signer predicate")
	}
	// Mutate all externally available aggregate state and the original inputs.
	f.options.Methods.Assignable[0] = "evil_call"
	f.options.Methods.Aliases["chain_call"] = "evil_call"
	f.options.Methods.Wildcard[0] = "evil_call"
	f.options.Methods.RequiredClaims["eth_call"] = "admin"
	selection.ExpectedChainID = "0"
	metadata.Documents[0].Path = "changed"
	requirements.Capabilities[0] = "changed"
	requirements.SecretRefs[0] = "changed"
	orgs := s.Organizations()
	orgs[0].Name = "changed"
	g, _ := s.Group(orgID, groupID)
	g.AllowedMethods[0] = "changed"
	g.Claims = append(g.Claims, "admin")
	g.RpcCredential.FromEnv = "changed"
	c, _ := s.Contract(orgID, common.HexToAddress(address))
	c.ABI[0] = '!'
	c.ReadGrants[0].EventRules.Rules[0].ParamRules[0].MustBe = "changed"
	native, _ := s.NativeCatalog(orgID)
	delete(native.Groups, groupID)
	native.Contracts[address] = policycore.ContractInfo{ABI: "!"}
	p := v.Policy()
	p.Bindings[0].Allow[0].Selector = "*"
	after, _ := s.Group(orgID, groupID)
	afterContract, _ := s.Contract(orgID, common.HexToAddress(address))
	afterNative, _ := s.NativeCatalog(orgID)
	if after.AllowedMethods[0] != "eth_call" || after.RpcCredential.FromEnv != secret || afterContract.ABI[0] != '[' || afterContract.ReadGrants[0].EventRules.Rules[0].ParamRules[0].MustBe != "self" || len(afterNative.Groups) != 1 || s.Organizations()[0].Name != "Bank" || s.Requirements().SecretRefs[0] != secret {
		t.Fatal("mutable accessor/input reached sealed snapshot")
	}
	second, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: selection.Directory, ExpectedManifestDigest: s.Metadata().ManifestDigest, ExpectedEnvironment: "test", ExpectedChainID: "31337"}, baseFixture(t).options)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(second.Metadata(), s.Metadata()) || !reflect.DeepEqual(second.Requirements(), s.Requirements()) {
		t.Fatal("cold restart changed selected catalog")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				s.Group(orgID, groupID)
				s.Contract(orgID, common.HexToAddress(address))
				s.NativeCatalog(orgID)
				s.Metadata()
				s.Requirements()
				v.Evaluate(ctx, []policycore.Frame{frame})
			}
		})
	}
	wg.Wait()
}
