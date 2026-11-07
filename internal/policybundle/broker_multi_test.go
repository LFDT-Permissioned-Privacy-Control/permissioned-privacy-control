package policybundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/brokerpolicy"
	bf "privacy-proxy/internal/brokertest"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

func multiBrokerFixture(t *testing.T) fixture {
	t.Helper()
	f := nativeV2Fixture(t)
	f.options.Profile = policybundle.BrokerMultiProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.BrokerMultiProfileID
	ids := bf.MultiIdentitySource(t)
	ids.Mappings = []identity.Mapping{}
	f.docs["identity.json"] = encode(t, ids)
	f.manifest.IdentityCatalog.SHA256 = policybundle.RawDigest(f.docs["identity.json"])
	f.docs["auth.json"] = encode(t, bf.MultiBrokerSource())
	f.docs["role-context.json"] = append([]byte(nil), bf.PrivadoContext...)
	f.manifest.AuthCatalog = &policybundle.AuthCatalogRef{Path: "auth.json", SHA256: policybundle.RawDigest(f.docs["auth.json"])}
	artifact, e := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(artifact.ManifestBytes(), &f.manifest); e != nil {
		t.Fatal(e)
	}
	return f
}
func TestMultiBrokerPinsDocumentsInTheSharedPrepareLoadCompiler(t *testing.T) {
	f := multiBrokerFixture(t)
	s := load(t, f)
	c, ok := s.AuthBroker()
	if !ok {
		t.Fatal("missing broker")
	}
	if _, ok = c.MultiSource(); !ok {
		t.Fatal("wrong broker variant")
	}
	if _, ok = c.SourceV1(); ok {
		t.Fatal("projected v1")
	}
	documents := c.PinnedDocuments()
	if len(documents) != 1 || documents[0].URL != bf.PrivadoContextURL {
		t.Fatal("document missing")
	}
	documents[0].RawBytes[0] = 'x'
	if c.PinnedDocuments()[0].RawBytes[0] != '{' {
		t.Fatal("document escaped")
	}
	artifact, e := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, file := range artifact.Files() {
		if file.Path == "role-context.json" {
			found = true
		}
	}
	if !found {
		t.Fatal("prepared artifact lost nested reference")
	}
	selection := f.write(t)
	if e = os.WriteFile(filepath.Join(selection.Directory, "role-context.json"), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	reject(t, selection, f.options, t.Context())
}
func TestMultiBrokerCannotBypassPinnedResolverOrClosedProfiles(t *testing.T) {
	for name, change := range map[string]func(*fixture){"legacy profile": func(f *fixture) {
		f.options.Profile = policybundle.BrokerProfile("rpc-test/v1")
		f.manifest.Profile = policybundle.BrokerProfileID
	}, "file count includes context": func(f *fixture) { f.options.Limits.MaxDocuments = 5 }, "small total": func(f *fixture) { f.options.Limits.MaxBundleBytes = 128 }, "duplicate existing path": func(f *fixture) {
		var s brokerpolicy.SourceV2
		_ = json.Unmarshal(f.docs["auth.json"], &s)
		s.PinnedDocuments[0].Path = "identity.json"
		f.docs["auth.json"] = encode(t, s)
		f.manifest.AuthCatalog.SHA256 = policybundle.RawDigest(f.docs["auth.json"])
	}, "escape": func(f *fixture) {
		var s brokerpolicy.SourceV2
		_ = json.Unmarshal(f.docs["auth.json"], &s)
		s.PinnedDocuments[0].Path = "../role-context.json"
		f.docs["auth.json"] = encode(t, s)
		f.manifest.AuthCatalog.SHA256 = policybundle.RawDigest(f.docs["auth.json"])
	}} {
		t.Run(name, func(t *testing.T) {
			f := multiBrokerFixture(t)
			change(&f)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := multiBrokerFixture(t)
	selection := f.write(t)
	if e := os.Remove(filepath.Join(selection.Directory, "role-context.json")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("identity.json", filepath.Join(selection.Directory, "role-context.json")); e != nil {
		t.Fatal(e)
	}
	reject(t, selection, f.options, t.Context())
}
