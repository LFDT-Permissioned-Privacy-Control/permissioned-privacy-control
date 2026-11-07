package policybundle_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/policybundle"
)

func disclosureFixture(t *testing.T) fixture {
	f := nativeV2Fixture(t)
	f.options.Profile = policybundle.DisclosureProfile("rpc-test/v1")
	f.options.DisclosureLimits = disclosurepolicy.DefaultLimits()
	f.manifest.Profile = policybundle.DisclosureProfileID
	f.docs["disclosure.json"] = []byte(`{"apiVersion":"ops.disclosure-policy/v1alpha1","kind":"DisclosurePolicy","rules":[]}`)
	f.manifest.DisclosureCatalog = &policybundle.DisclosureCatalogRef{Path: "disclosure.json", SHA256: policybundle.RawDigest(f.docs["disclosure.json"])}
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, "disclosure.rules/v1", "disclosure.case-state/v1", "secrets.disclosure-cursor/v1")
	if !slices.Contains(f.manifest.RequiredCapabilities, policybundle.CapabilityPrincipal) {
		f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityPrincipal)
	}
	return f
}
func TestDisclosureSelectedCatalogIsGlobalPinnedAndProfileExplicit(t *testing.T) {
	f := disclosureFixture(t)
	s := load(t, f)
	catalog, ok := s.Disclosure()
	if !ok || len(catalog.RuleIDs()) != 0 || s.Metadata().DisclosureCatalog.SemanticDigest != policybundle.Digest(catalog.Digest()) {
		t.Fatal("global source lost")
	}
	m := s.Metadata()
	m.DisclosureCatalog.Path = "changed"
	if s.Metadata().DisclosureCatalog.Path != "disclosure.json" {
		t.Fatal("metadata mutable")
	}
	for name, mutate := range map[string]func(*fixture){"wrong hash": func(f *fixture) { f.manifest.DisclosureCatalog.SHA256 = policybundle.RawDigest(nil) }, "missing": func(f *fixture) { delete(f.docs, "disclosure.json") }, "required": func(f *fixture) { f.manifest.DisclosureCatalog = nil; delete(f.docs, "disclosure.json") }, "old profile": func(f *fixture) {
		f.options.Profile = policybundle.NativeV2Profile("rpc-test/v1")
		f.manifest.Profile = policybundle.NativeV2ProfileID
	}, "global collision": func(f *fixture) { f.manifest.DisclosureCatalog.Path = f.manifest.IdentityCatalog.Path }, "all files counted": func(f *fixture) { f.options.Limits.MaxDocuments = len(f.manifest.Documents) + 1 }, "limits required": func(f *fixture) { f.options.DisclosureLimits = disclosurepolicy.Limits{} }} {
		t.Run(name, func(t *testing.T) {
			f := disclosureFixture(t)
			mutate(&f)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
}
func TestCombinedGlobalFileBytesCountedInPinnedLoaderAndPrepare(t *testing.T) {
	f := disclosureFixture(t)
	sel := f.write(t)
	// f.write intentionally receives a value; use actual manifest bytes for the
	// exact runtime boundary, including both independently hashed global files.
	var total int64
	for _, bytes := range f.docs {
		total += int64(len(bytes))
	}
	manifestBytes, err := os.ReadFile(filepath.Join(sel.Directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	total += int64(len(manifestBytes))
	f.options.Limits.MaxBundleBytes = total
	if _, err := policybundle.LoadDirectory(t.Context(), sel, f.options); err != nil {
		t.Fatal("exact combined boundary rejected", err)
	}
	f.options.Limits.MaxBundleBytes = total - 1
	reject(t, sel, f.options, t.Context())
	d := draftFor(f)
	d.DisclosureCatalog = &policybundle.DraftIdentity{Path: "disclosure.json"}
	draft := writeDraft(t, f, d)
	if a, err := policybundle.PrepareDirectory(t.Context(), draft, f.options); err == nil || a != nil {
		t.Fatal("prepare exceeded combined/final budget")
	}
}
func TestDisclosurePreparationUsesSameCompilerAndMetadata(t *testing.T) {
	f := disclosureFixture(t)
	d := draftFor(f)
	d.DisclosureCatalog = &policybundle.DraftIdentity{Path: "disclosure.json"}
	a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, d), f.options)
	if err != nil {
		t.Fatal(err)
	}
	s, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Disclosure(); !ok {
		t.Fatal("checker lost disclosure source")
	}
}
