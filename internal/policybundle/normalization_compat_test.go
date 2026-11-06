package policybundle_test

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/rbac"
)

// Legacy dependencies are test-only: the production loader neither imports
// these global registries nor mutates them to normalize source.
func TestGroupNormalizationMatchesExistingExactMethodAndClaimRules(t *testing.T) {
	defer rbac.SnapshotMethodRegistriesForTest()()
	if err := rbac.RegisterExtraNamespaces(map[string][]string{"chain": {"chain_call"}}, map[string]string{"chain_call": "eth_call"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name            string
		methods, claims []string
		admin           bool
	}{
		{"ordinary exact", []string{"eth_call"}, []string{}, false},
		{"admin implications", []string{"eth_call"}, []string{"admin"}, false},
		{"wildcard plus exact alias", []string{"*", "chain_call", "eth_getProof"}, []string{}, false},
		{"org admin", []string{"*"}, []string{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture(t)
			f.options.Methods = policybundle.MethodCatalog{Version: "rpc-test/v1", Assignable: rbac.SupportedMethods(), Aliases: maps.Clone(rbac.MethodAliases), Wildcard: rbac.AllAllowedMethods(), RequiredClaims: map[string]string{}}
			g := policybundle.Group{ID: groupID, Slug: "readers", Name: "Readers", AllowedMethods: tc.methods, Claims: tc.claims, IsOrgAdmin: tc.admin, RpcCredential: &policybundle.SecretRef{FromEnv: secret}}
			f.docs["groups.json"] = envelope(t, policybundle.Groups, orgID, policybundle.GroupsSpec{Groups: []policybundle.Group{g}})
			loaded := load(t, f)
			actual, _ := loaded.Group(orgID, groupID)
			var old configuration.Group
			if err := json.Unmarshal(encode(t, g), &old); err != nil {
				t.Fatal(err)
			}
			doc := configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.Groups, Scope: configuration.Scope{Kind: "organization", ID: orgID}, BaseRevision: 0, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.GroupsSpec{Groups: []configuration.Group{old}}}
			parsed, err := configuration.Parse(encode(t, doc))
			if err != nil {
				t.Fatal(err)
			}
			expected := parsed.Spec.(configuration.GroupsSpec).Groups[0]
			if !slices.Equal(actual.AllowedMethods, expected.AllowedMethods) || !slices.Equal(actual.Claims, expected.Claims) || actual.IsOrgAdmin != expected.IsOrgAdmin {
				t.Fatalf("normalization differs from existing source: %+v %+v", actual, expected)
			}
		})
	}
	for _, method := range []string{"ETH_call", "chain_CALL", "chain_*", "unknown_method"} {
		t.Run(method, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "groups.json", func(d map[string]any) { group(d)["allowedMethods"] = []string{method} })
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	// A supplied required-claim map cannot be evaded by an alias.
	f := baseFixture(t)
	f.options.Methods.RequiredClaims["eth_call"] = "deploy"
	f.edit(t, "groups.json", func(d map[string]any) { group(d)["allowedMethods"] = []string{"chain_call"} })
	reject(t, f.write(t), f.options, t.Context())
	f.edit(t, "groups.json", func(d map[string]any) { group(d)["claims"] = []string{"admin"} })
	load(t, f)
}

func TestRegistryNormalizationMatchesExistingStaticSource(t *testing.T) {
	f := baseFixture(t)
	s := load(t, f)
	actual, _ := s.Contract(orgID, common.HexToAddress(address))
	var wire map[string]any
	d := json.NewDecoder(strings.NewReader(string(f.docs["registry.json"])))
	d.UseNumber()
	if err := d.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	c := contract(wire)
	c["readGrants"].([]any)[0].(map[string]any)["legacyClaims"] = []any{}
	var old configuration.Contract
	if err := json.Unmarshal(encode(t, c), &old); err != nil {
		t.Fatal(err)
	}
	doc := configuration.Document{APIVersion: configuration.APIVersion, Kind: configuration.ContractRegistry, Scope: configuration.Scope{Kind: "organization", ID: orgID}, Dependencies: map[configuration.Kind]string{}, Deletions: []configuration.Deletion{}, Spec: configuration.RegistrySpec{Contracts: []configuration.Contract{old}}}
	parsed, err := configuration.Parse(encode(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	expected := parsed.Spec.(configuration.RegistrySpec).Contracts[0]
	if string(actual.ABI) != string(expected.ABI) || actual.Address != expected.Address || actual.ReadGrants[0].EventRules.Mode != expected.ReadGrants[0].EventRules.Mode || !reflect.DeepEqual(encode(t, actual.ReadGrants[0].EventRules), encode(t, expected.ReadGrants[0].EventRules)) {
		t.Fatal("ABI/event normalization differs from baseline")
	}
}
