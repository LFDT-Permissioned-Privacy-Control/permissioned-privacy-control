package policybundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	"privacy-proxy/internal/policybundle"
)

func brokerFixture(t *testing.T) fixture {
	f := nativeV2Fixture(t)
	f.options.Profile = policybundle.BrokerProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.BrokerProfileID
	source := brokerpolicy.Source{APIVersion: brokerpolicy.APIVersion, Kind: brokerpolicy.Kind, IssuerID: "ops", AccessKeyID: "k1", WebOrigin: "https://ops.test", CompletionURI: "https://ops.test/auth/complete", AzureProfiles: []brokerpolicy.AzureBinding{{ProfileID: "azure", RedirectURI: "https://ops.test/callback", ClientSecret: &brokerpolicy.SecretRef{FromEnv: "OPS_BROKER_AZURE_TEST"}}}, RenewalKeys: []brokerpolicy.KeyRef{{ID: "mac", FromEnv: "OPS_BROKER_REFRESH_TEST", Active: true}}, EncryptionKeys: []brokerpolicy.KeyRef{{ID: "aes", FromEnv: "OPS_BROKER_ENCRYPTION_TEST", Active: true}}}
	f.docs["auth.json"] = encode(t, source)
	f.manifest.AuthCatalog = &policybundle.AuthCatalogRef{Path: "auth.json", SHA256: policybundle.RawDigest(f.docs["auth.json"])}
	// The authoring compiler derives capabilities and references; use its exact
	// manifest to exercise independently pinned loading below.
	artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(artifact.ManifestBytes(), &f.manifest); err != nil {
		t.Fatal(err)
	}
	return f
}
func TestStandaloneBrokerPreparationAndPinnedLoadShareImmutableCatalog(t *testing.T) {
	f := brokerFixture(t)
	s := load(t, f)
	catalog, ok := s.AuthBroker()
	if !ok || catalog.Digest() == "" || s.Metadata().AuthCatalog.SemanticDigest != policybundle.Digest(catalog.Digest()) {
		t.Fatal("broker metadata not paired")
	}
	meta := s.Metadata()
	meta.AuthCatalog.Path = "other"
	if s.Metadata().AuthCatalog.Path != "auth.json" {
		t.Fatal("mutable auth metadata")
	}
	source := catalog.Source()
	source.WebOrigin = "https://other.test"
	if catalog.Source().WebOrigin != "https://ops.test" {
		t.Fatal("mutable source")
	}
	artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, artifact), ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil || loaded.Metadata().AuthCatalog.SemanticDigest != s.Metadata().AuthCatalog.SemanticDigest {
		t.Fatal("prepare/load drift", err)
	}
}
func TestBrokerExtensionCannotWaiveClosedProfilesOrSourceBudgets(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"old native profile": func(f *fixture) {
			f.options.Profile = policybundle.NativeV2Profile("rpc-test/v1")
			f.manifest.Profile = policybundle.NativeV2ProfileID
		},
		"missing auth": func(f *fixture) { f.manifest.AuthCatalog = nil; delete(f.docs, "auth.json") }, "missing identity": func(f *fixture) { f.manifest.IdentityCatalog = nil; delete(f.docs, "identity.json") },
		"document count": func(f *fixture) { f.options.Limits.MaxDocuments = 4 }, "byte bound": func(f *fixture) { f.options.Limits.MaxDocumentBytes = 64 }, "total bytes": func(f *fixture) { f.options.Limits.MaxBundleBytes = 128 },
		"same path": func(f *fixture) { f.manifest.AuthCatalog.Path = "identity.json" }, "manifest path": func(f *fixture) { f.manifest.AuthCatalog.Path = "manifest.json" }, "escape": func(f *fixture) { f.manifest.AuthCatalog.Path = "../auth.json" },
		"raw digest": func(f *fixture) { f.manifest.AuthCatalog.SHA256 = policybundle.RawDigest(nil) }, "missing requirement": func(f *fixture) { removeCapability(f, "provider.azure-grant/v1") },
	} {
		t.Run(name, func(t *testing.T) { f := brokerFixture(t); change(&f); reject(t, f.write(t), f.options, t.Context()) })
	}
	f := brokerFixture(t)
	selection := f.write(t)
	if err := os.WriteFile(filepath.Join(selection.Directory, "auth.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	reject(t, selection, f.options, t.Context())
}
