package policybundle_test

import (
	"encoding/json"
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

const otherOrg = "55555555-5555-5555-5555-555555555555"
const otherGroup = "66666666-6666-6666-6666-666666666666"
const otherContract = "77777777-7777-7777-7777-777777777777"
const otherAddress = "0x3333333333333333333333333333333333333333"

func twoOrganizations(t *testing.T) fixture {
	f := baseFixture(t)
	f.manifest.Organizations = append(f.manifest.Organizations, policybundle.Organization{ID: otherOrg, Slug: "other", Name: "Other"})
	f.docs["other-groups.json"] = envelope(t, policybundle.Groups, otherOrg, policybundle.GroupsSpec{Groups: []policybundle.Group{{ID: otherGroup, Slug: "other", Name: "Other", Claims: []string{}, AllowedMethods: []string{}}}})
	f.docs["other-registry.json"] = envelope(t, policybundle.ContractRegistry, otherOrg, policybundle.RegistrySpec{Contracts: []policybundle.Contract{{ID: otherContract, Address: otherAddress, Name: "Other", ABI: json.RawMessage(contractABI), ReadGrants: []policybundle.ReadGrant{}}}})
	f.docs["other-execution.json"] = envelope(t, policybundle.ExecutionRules, otherOrg, policybundle.ExecutionSpec{Policy: &policycore.Policy{APIVersion: policycore.APIVersion, Kind: policycore.Kind, Org: otherOrg, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}})
	for kind, path := range map[policybundle.Kind]string{policybundle.Groups: "other-groups.json", policybundle.ContractRegistry: "other-registry.json", policybundle.ExecutionRules: "other-execution.json"} {
		f.manifest.Documents = append(f.manifest.Documents, policybundle.DocumentRef{Kind: kind, OrganizationID: otherOrg, Path: path})
	}
	return f
}

func TestCrossOrganizationAmbiguityAndGrantsReject(t *testing.T) {
	if got := load(t, twoOrganizations(t)).Organizations(); len(got) != 2 || got[0].ID != orgID {
		t.Fatal("organization ordering or isolation failed")
	}
	for name, change := range map[string]func(*fixture){
		"group ID ownership": func(f *fixture) { f.edit(t, "other-groups.json", func(d map[string]any) { group(d)["id"] = groupID }) },
		"contract ownership": func(f *fixture) {
			f.edit(t, "other-registry.json", func(d map[string]any) { contract(d)["address"] = address })
		},
		"resource identity": func(f *fixture) {
			f.edit(t, "other-registry.json", func(d map[string]any) { contract(d)["id"] = contractID })
		},
		"foreign grant": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) { contract(d)["readGrants"].([]any)[0].(map[string]any)["groupId"] = otherGroup })
		},
		"foreign event literal": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["must_be"] = otherAddress
			})
		},
		"foreign native target": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { rule(d)["storageAddress"] = otherAddress })
		},
		"organization budget": func(f *fixture) { f.options.Limits.MaxOrganizations = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := twoOrganizations(t)
			change(&f)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
}
