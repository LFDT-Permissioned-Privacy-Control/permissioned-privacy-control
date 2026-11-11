package disclosuretest

// StateSnapshot is finite test assembly through the real approved-bundle
// prepare/load path. Production commands do not import this fixture package.
import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
	"privacy-proxy/internal/policyprofiles"
)

type StateFixture struct {
	Groups          map[string][]policybundle.Group
	Contracts       map[string][]policybundle.Contract
	Methods         policybundle.MethodCatalog
	IdentityCatalog *identity.SourceCatalog
	ReadProfile     string
	Execution       map[string]*policycore.Policy
	Runtime         *policybundle.RuntimeCreationObservedSource
	HistoryConsumer bool
}

func DefaultStateFixture(t testing.TB) StateFixture {
	t.Helper()
	base := Snapshot(t, nil)
	options, _, err := policyprofiles.Options(policybundle.RuntimeCreationObservedProfileID)
	if err != nil {
		t.Fatal(err)
	}
	f := StateFixture{Groups: map[string][]policybundle.Group{}, Contracts: map[string][]policybundle.Contract{Org: {}, OtherOrg: {}}, Methods: options.Methods}
	for _, org := range base.Organizations() {
		for _, id := range base.GroupIDs(org.ID) {
			g, _ := base.Group(org.ID, id)
			g.AllowedMethods = append([]string{}, options.Methods.Assignable...)
			f.Groups[org.ID] = append(f.Groups[org.ID], g)
		}
	}
	return f
}
func StateSnapshot(t testing.TB, f StateFixture) *policybundle.CatalogSnapshot {
	t.Helper()
	base := Snapshot(t, nil)
	identityCatalog, _ := base.Identity()
	identitySource := identityCatalog.Source()
	if f.IdentityCatalog != nil {
		identitySource = *f.IdentityCatalog
	}
	options, description, err := policyprofiles.Options(policybundle.RuntimeCreationObservedProfileID)
	if f.HistoryConsumer {
		options, description, err = policyprofiles.HistoryOptions(policybundle.RuntimeCreationObservedProfileID)
	}
	if err != nil {
		t.Fatal(err)
	}
	options.Methods = f.Methods
	draft := policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: "test", ChainID: "1", EvaluatorVersion: description.EvaluatorVersion, Profile: policybundle.RuntimeCreationObservedProfileID, SourceRevision: "state-fixture", Organizations: base.Organizations(), Documents: []policybundle.DraftDocument{}, IdentityCatalog: &policybundle.DraftIdentity{Path: "identity.json"}, RuntimeCatalog: &policybundle.DraftRuntime{Path: "runtime.json"}, ComplianceCatalog: &policybundle.DraftIdentity{Path: "compliance.json"}}
	sourceDir := t.TempDir()
	write := func(name string, v any) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(sourceDir, name), encode(t, v), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i, org := range []string{Org, OtherOrg} {
		execution := &policycore.Policy{APIVersion: policycore.NativeV4APIVersion, Kind: policycore.Kind, Org: org, NestedCalls: policycore.NestedCallsRequireOwnRule, Bindings: []policycore.Binding{}}
		if f.Execution[org] != nil {
			execution = f.Execution[org]
		}
		prefix := []string{"a", "b"}[i]
		for _, item := range []struct {
			kind policybundle.Kind
			name string
			spec any
		}{
			{policybundle.Groups, "groups", policybundle.GroupsSpec{Groups: f.Groups[org]}},
			{policybundle.ContractRegistry, "registry", policybundle.RegistrySpec{Contracts: f.Contracts[org]}},
			{policybundle.ExecutionRules, "execution", policybundle.ExecutionSpec{Policy: execution}},
		} {
			name := prefix + "-" + item.name + ".json"
			draft.Documents = append(draft.Documents, policybundle.DraftDocument{Kind: item.kind, OrganizationID: org, Path: name})
			write(name, map[string]any{"apiVersion": policybundle.DocumentAPIVersion, "kind": item.kind, "organizationId": org, "spec": item.spec})
		}
	}
	write("identity.json", identitySource)
	readProfile := f.ReadProfile
	if readProfile == "" {
		readProfile = "standard"
	}
	runtime := policybundle.RuntimeCreationObservedSource{APIVersion: policybundle.RuntimeCreationObservedAPIVersion, Kind: policybundle.RuntimeKind, ReadProfile: readProfile, IntraOrgGrantTracing: true, SharedInfrastructure: []policybundle.SharedInfrastructure{}, AddressScopes: []policybundle.AddressScope{}, NodeEvidenceProfile: policybundle.RuntimeSimulationNodeEvidenceProfileID, RawSubmissionMode: policybundle.RawSubmissionOPSPreflight, CreationAttribution: policybundle.CreationAttribution{Factories: []policybundle.FactoryAttribution{}}, CaptureReadinessProfile: "same-node-caught-up/v1"}
	if f.Runtime != nil {
		runtime = *f.Runtime
	}
	write("runtime.json", runtime)
	compliance := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{}, Sanctions: []compliancepolicy.SourceSanction{}}
	for _, org := range []string{Org, OtherOrg} {
		compliance.Organizations = append(compliance.Organizations, compliancepolicy.OrganizationPolicy{OrganizationID: org, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Currency: "usd", ThresholdFiat: 100, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{}}})
	}
	write("compliance.json", compliance)
	write("draft.json", draft)
	artifact, err := policybundle.PrepareDirectory(context.Background(), policybundle.DraftSelection{Directory: sourceDir}, options)
	if err != nil {
		t.Fatal("state approved prepare", err)
	}
	output := t.TempDir()
	for _, file := range artifact.Files() {
		if err := os.WriteFile(filepath.Join(output, file.Path), file.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(output, "manifest.json"), artifact.ManifestBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := policybundle.LoadDirectory(context.Background(), policybundle.Selection{Directory: output, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "1"}, options)
	if err != nil {
		t.Fatal("state approved load", err)
	}
	return snapshot
}

// ReadContract associates the existing auditor group without operational admin.
func ReadContract(address string) policybundle.Contract {
	return policybundle.Contract{ID: "99999999-9999-9999-9999-999999999999", Address: address, Name: "State target", ABI: json.RawMessage(`[]`), ReadGrants: []policybundle.ReadGrant{{ID: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee", GroupID: AuditorGroup, EventRules: policybundle.EventRules{Mode: "none", Rules: []policybundle.EventRule{}}}}}
}
