package policybundle_test

import (
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/policybundle"
)

func complianceFixture(t *testing.T) fixture {
	f := nativeV2Fixture(t)
	f.options.Profile = policybundle.ComplianceProfile("rpc-test/v1")
	f.options.ComplianceLimits = compliancepolicy.DefaultLimits()
	f.manifest.Profile = policybundle.ComplianceProfileID
	s := compliancepolicy.Source{APIVersion: compliancepolicy.APIVersion, Kind: compliancepolicy.Kind, Organizations: []compliancepolicy.OrganizationPolicy{}, Sanctions: []compliancepolicy.SourceSanction{}}
	for _, o := range f.manifest.Organizations {
		s.Organizations = append(s.Organizations, compliancepolicy.OrganizationPolicy{OrganizationID: o.ID, RecordMaxSeconds: 86400, PriceMaxAgeSeconds: 600, Spec: compliancepolicy.SourceSpec{Settings: compliancepolicy.SourceSettings{Currency: "eur", ThresholdFiat: 100, UnknownPricePolicy: "forbidden", EnforcementMode: "enforce"}, AddressThresholds: []compliancepolicy.SourceThreshold{}, TokenPrices: []compliancepolicy.SourceTokenPrice{}}})
	}
	f.docs["compliance.json"] = encode(t, s)
	f.manifest.ComplianceCatalog = &policybundle.ComplianceCatalogRef{Path: "compliance.json", SHA256: policybundle.RawDigest(f.docs["compliance.json"])}
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, "catalog.compliance-validate/v1")
	return f
}
func TestComplianceGlobalUsesSharedCompilerAndColdLoader(t *testing.T) {
	f := complianceFixture(t)
	snapshot := load(t, f)
	catalog, ok := snapshot.Compliance()
	if !ok || snapshot.Metadata().ComplianceCatalog.SemanticDigest != policybundle.Digest(catalog.Digest()) {
		t.Fatal("compliance source missing")
	}
	m := snapshot.Metadata()
	m.ComplianceCatalog.Path = "changed"
	if snapshot.Metadata().ComplianceCatalog.Path != "compliance.json" {
		t.Fatal("metadata escaped")
	}
	a, e := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if e != nil {
		t.Fatal(e)
	}
	s, e := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if e != nil {
		t.Fatal(e)
	}
	got, ok := s.Compliance()
	if !ok || got.Digest() != catalog.Digest() {
		t.Fatal("prepare changed selected compliance semantics")
	}
	selection := f.write(t)
	raw, e := os.ReadFile(filepath.Join(selection.Directory, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	total := int64(len(raw))
	for _, raw := range f.docs {
		total += int64(len(raw))
	}
	f.options.Limits.MaxBundleBytes = total
	if _, e := policybundle.LoadDirectory(t.Context(), selection, f.options); e != nil {
		t.Fatal("combined globals charged twice", e)
	}
	f.options.Limits.MaxBundleBytes--
	reject(t, selection, f.options, t.Context())
}
func TestComplianceProfileRejectsMissingTamperedAndMixedSources(t *testing.T) {
	for name, change := range map[string]func(*fixture){"no source": func(f *fixture) { f.manifest.ComplianceCatalog = nil; delete(f.docs, "compliance.json") }, "missing capability": func(f *fixture) { removeCapability(f, "catalog.compliance-validate/v1") }, "old profile": func(f *fixture) {
		f.options.Profile = policybundle.NativeV2Profile("rpc-test/v1")
		f.manifest.Profile = policybundle.NativeV2ProfileID
	}, "collision": func(f *fixture) { f.manifest.ComplianceCatalog.Path = f.manifest.IdentityCatalog.Path }, "tamper": func(f *fixture) { f.docs["compliance.json"] = append(f.docs["compliance.json"], ' ') }, "total files": func(f *fixture) { f.options.Limits.MaxDocuments = len(f.manifest.Documents) + 1 }, "limits required": func(f *fixture) { f.options.ComplianceLimits = compliancepolicy.Limits{} }, "runtime global": func(f *fixture) {
		other := runtimeFixture(t)
		f.manifest.RuntimeCatalog = other.manifest.RuntimeCatalog
		f.docs["runtime.json"] = other.docs["runtime.json"]
	}, "disclosure global": func(f *fixture) {
		other := disclosureFixture(t)
		f.manifest.DisclosureCatalog = other.manifest.DisclosureCatalog
		f.docs["disclosure.json"] = other.docs["disclosure.json"]
	}} {
		t.Run(name, func(t *testing.T) {
			f := complianceFixture(t)
			change(&f)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := complianceFixture(t)
	f.edit(t, "compliance.json", func(m map[string]any) {
		o := m["organizations"].([]any)[0].(map[string]any)
		o["spec"].(map[string]any)["settings"].(map[string]any)["enabled"] = true
	})
	f.manifest.ComplianceCatalog.SHA256 = policybundle.RawDigest(f.docs["compliance.json"])
	for _, missing := range []string{"operational.travel-rule/v1", "inputs.price-quotes/v1"} {
		g := f
		g.manifest.RequiredCapabilities = append(append([]string{}, f.manifest.RequiredCapabilities...), "operational.travel-rule/v1", "inputs.price-quotes/v1")
		removeCapability(&g, missing)
		if e := reject(t, g.write(t), g.options, t.Context()); e.Code != policybundle.CapabilityMismatch {
			t.Fatal("omission failed for another reason", e)
		}
	}
}
