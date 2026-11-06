package policybundle_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

func identityFixture(t *testing.T) fixture {
	f := baseFixture(t)
	f.options.Profile = policybundle.IdentityProfile("rpc-test/v1")
	f.options.IdentityLimits = identity.DefaultLimits()
	f.manifest.Profile = policybundle.IdentityProfileID
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityIdentity)
	s := identity.SourceCatalog{APIVersion: identity.APIVersion, Kind: identity.CatalogKind, Issuers: []identity.Issuer{{ID: "ops", Issuer: "https://ops.test", Audience: "ops-core", Keys: []identity.PublicKey{{Kid: "k1", Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey))}}, AllowedProfiles: []string{"azure"}}}, Profiles: []identity.Profile{{ID: "azure", Kind: identity.AzureHuman, TenantID: orgID, Issuer: "https://login.microsoftonline.com/" + orgID + "/v2.0", APIAudience: groupID, ClientID: contractID, DelegatedScope: "api://bank/access", FactSource: "appRoles"}}, Mappings: []identity.Mapping{{ID: "reader", ProfileID: "azure", OrganizationID: orgID, PrincipalKind: identity.Human, Fact: identity.Fact{Kind: "azure.role", Value: "Reader"}, GroupIDs: []string{groupID}}}}
	f.docs["identity.json"] = encode(t, s)
	f.manifest.IdentityCatalog = &policybundle.IdentityCatalogRef{Path: "identity.json", SHA256: policybundle.RawDigest(f.docs["identity.json"])}
	return f
}

func TestExplicitIdentityProfileLoadsOneGlobalPinnedCatalog(t *testing.T) {
	f := identityFixture(t)
	s := load(t, f)
	catalog, ok := s.Identity()
	if !ok || !catalog.HasMappings() {
		t.Fatal("identity catalog missing")
	}
	metadata := s.Metadata()
	if metadata.IdentityCatalog == nil || metadata.IdentityCatalog.SemanticDigest != policybundle.Digest(catalog.Digest()) || len(metadata.Documents) != 3 {
		t.Fatal("identity/raw/native identity spaces mixed")
	}
	metadata.IdentityCatalog.Path = "changed"
	if s.Metadata().IdentityCatalog.Path != "identity.json" {
		t.Fatal("metadata pointer escaped snapshot")
	}
	source := catalog.Source()
	source.Mappings[0].GroupIDs[0] = grantID
	if catalog.Source().Mappings[0].GroupIDs[0] != groupID {
		t.Fatal("identity graph escaped snapshot")
	}
	// Formatting changes raw provenance; normalization remains independently stable.
	var decoded any
	if err := json.Unmarshal(f.docs["identity.json"], &decoded); err != nil {
		t.Fatal(err)
	}
	pretty, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.docs["identity.json"] = pretty
	f.manifest.IdentityCatalog.SHA256 = policybundle.RawDigest(pretty)
	second := load(t, f)
	if second.Metadata().IdentityCatalog.SHA256 == s.Metadata().IdentityCatalog.SHA256 || second.Metadata().IdentityCatalog.SemanticDigest != s.Metadata().IdentityCatalog.SemanticDigest {
		t.Fatal("identity raw and semantic digests collapsed")
	}
}

func TestIdentityExtensionCannotWaiveFoundationOrBundleGuards(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"foundation rejects identity": func(f *fixture) {
			f.options.Profile = policybundle.FoundationProfile("rpc-test/v1")
			f.manifest.Profile = policybundle.FoundationProfileID
		},
		"identity required":     func(f *fixture) { delete(f.docs, "identity.json"); f.manifest.IdentityCatalog = nil },
		"limits required":       func(f *fixture) { f.options.IdentityLimits = identity.Limits{} },
		"capability required":   func(f *fixture) { removeCapability(f, policybundle.CapabilityIdentity) },
		"file count":            func(f *fixture) { f.options.Limits.MaxDocuments = 3 },
		"identity bytes":        func(f *fixture) { f.options.IdentityLimits.MaxIdentityDocumentBytes = 16 },
		"path collision":        func(f *fixture) { f.manifest.IdentityCatalog.Path = "groups.json" },
		"manifest collision":    func(f *fixture) { f.manifest.IdentityCatalog.Path = "manifest.json" },
		"escape":                func(f *fixture) { f.manifest.IdentityCatalog.Path = "../identity.json" },
		"wrong identity digest": func(f *fixture) { f.manifest.IdentityCatalog.SHA256 = policybundle.RawDigest(nil) },
		"unknown group": func(f *fixture) {
			var source identity.SourceCatalog
			if err := json.Unmarshal(f.docs["identity.json"], &source); err != nil {
				t.Fatal(err)
			}
			source.Mappings[0].GroupIDs = []string{grantID}
			f.docs["identity.json"] = encode(t, source)
			f.manifest.IdentityCatalog.SHA256 = policybundle.RawDigest(f.docs["identity.json"])
		},
		"existing native ABI fence": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { rule(d)["abiDigest"] = "wrong" })
		},
		"existing unsupported history": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) { contract(d)["allowVisibleToUnlock"] = true })
		},
	} {
		t.Run(name, func(t *testing.T) { f := identityFixture(t); change(&f); reject(t, f.write(t), f.options, t.Context()) })
	}
	f := identityFixture(t)
	selection := f.write(t)
	if err := os.WriteFile(filepath.Join(selection.Directory, "identity.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	reject(t, selection, f.options, t.Context())
	f = identityFixture(t)
	selection = f.write(t)
	raw, err := os.ReadFile(filepath.Join(selection.Directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["identityCatalog"] = nil
	raw = encode(t, manifest)
	if err := os.WriteFile(filepath.Join(selection.Directory, "manifest.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	selection.ExpectedManifestDigest = policybundle.RawDigest(raw)
	reject(t, selection, f.options, t.Context())
}
