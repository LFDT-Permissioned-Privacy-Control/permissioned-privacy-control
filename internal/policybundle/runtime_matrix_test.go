package policybundle_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func TestCallProfileRejectsValidDeploymentAndLiveGetterSourceExplicitly(t *testing.T) {
	for _, class := range []string{"create", "deployer", "pending"} {
		f := runtimeFixture(t)
		rule := policycore.FrameRule{TargetClass: class, Selector: "*"}
		if class == "create" {
			rule.CallTypes = []policycore.CallType{policycore.CallTypeCreate}
		}
		p := &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: orgID, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{{Group: groupID, Allow: []policycore.FrameRule{rule}}}}
		f.docs["execution.json"] = envelope(t, policybundle.ExecutionRules, orgID, policybundle.ExecutionSpec{Policy: p})
		if _, err := policycore.ValidateNativeV2(p, policycore.Catalog{Org: orgID, Groups: map[string]struct{}{groupID: {}}, Contracts: map[string]policycore.ContractInfo{}}); err != nil {
			t.Fatal("reference feature unexpectedly removed", err)
		}
		if err := reject(t, f.write(t), f.options, t.Context()); err.Code != policybundle.UnsupportedFeature {
			t.Fatalf("%s was not explicitly unsupported: %v", class, err)
		}
	}
	f := runtimeFixture(t)
	abiText := `[{"type":"function","name":"settle","inputs":[{"type":"uint256","name":"id"}],"outputs":[]},{"type":"function","name":"parties","stateMutability":"view","inputs":[{"type":"uint256","name":"id"}],"outputs":[{"type":"address","name":"party"}]}]`
	var value any
	json.Unmarshal([]byte(abiText), &value)
	canonical := string(encode(t, value))
	parsed, err := abi.JSON(strings.NewReader(canonical))
	if err != nil {
		t.Fatal(err)
	}
	p := &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: orgID, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{{Group: groupID, Allow: []policycore.FrameRule{{StorageAddress: address, Selector: "0x" + common.Bytes2Hex(parsed.Methods["settle"].ID), ABIDigest: policycore.ABIDigest(canonical), Args: []policycore.ArgConstraint{{Index: 0, RecordParty: &policycore.RecordPartyMatch{Getter: "0x" + common.Bytes2Hex(parsed.Methods["parties"].ID), ABIDigest: policycore.ABIDigest(canonical), PartyOutputs: []int{0}}}}}}}}}
	if _, err := policycore.ValidateNativeV2(p, policycore.Catalog{Org: orgID, Groups: map[string]struct{}{groupID: {}}, Contracts: map[string]policycore.ContractInfo{address: {ABI: canonical}}}); err != nil {
		t.Fatal("reference record-party support removed", err)
	}
	f.docs["execution.json"] = envelope(t, policybundle.ExecutionRules, orgID, policybundle.ExecutionSpec{Policy: p})
	f.edit(t, "registry.json", func(d map[string]any) { contract(d)["abi"] = value; contract(d)["readGrants"] = []any{} })
	if err := reject(t, f.write(t), f.options, t.Context()); err.Code != policybundle.UnsupportedFeature {
		t.Fatal("valid live getter did not receive explicit unsupported diagnostic", err)
	}
}

func TestStaticScopesCannotClaimAnotherDeclaredOrganizationsAddress(t *testing.T) {
	const otherOrg = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	const scoped = "0x7777777777777777777777777777777777777777"
	for _, target := range []string{scoped, address} {
		f := runtimeFixture(t)
		f.manifest.Organizations = append(f.manifest.Organizations, policybundle.Organization{ID: otherOrg, Slug: "other", Name: "Other"})
		for kind, spec := range map[policybundle.Kind]any{policybundle.Groups: policybundle.GroupsSpec{Groups: []policybundle.Group{}}, policybundle.ContractRegistry: policybundle.RegistrySpec{Contracts: []policybundle.Contract{}}, policybundle.ExecutionRules: policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.NativeV2APIVersion, Kind: policycore.Kind, Org: otherOrg, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}}} {
			path := "other-" + string(kind) + ".json"
			f.docs[path] = envelope(t, kind, otherOrg, spec)
			f.manifest.Documents = append(f.manifest.Documents, policybundle.DocumentRef{Kind: kind, OrganizationID: otherOrg, Path: path})
		}
		var source policybundle.RuntimeSource
		json.Unmarshal(f.docs["runtime.json"], &source)
		source.AddressScopes = []policybundle.AddressScope{{Address: target, OrganizationID: otherOrg}}
		f.docs["runtime.json"] = encode(t, source)
		f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
		f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityAddressScopes)
		f.edit(t, "registry.json", func(d map[string]any) {
			contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["must_be"] = target
		})
		removeCapability(&f, policybundle.CapabilityLinkedWallets)
		err := reject(t, f.write(t), f.options, t.Context())
		if target == address && err.Code != policybundle.ReferenceFailure {
			t.Fatal("registered owner conflict was not rejected", err)
		}
	}
}
