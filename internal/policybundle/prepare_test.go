package policybundle_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/policybundle"
)

func draftFor(f fixture) policybundle.Draft {
	d := policybundle.Draft{APIVersion: policybundle.DraftAPIVersion, Kind: policybundle.DraftKind, Environment: f.manifest.Environment, ChainID: f.manifest.ChainID, EvaluatorVersion: f.manifest.EvaluatorVersion, Profile: f.manifest.Profile, SourceRevision: f.manifest.SourceRevision, Organizations: f.manifest.Organizations, Documents: []policybundle.DraftDocument{}}
	for _, r := range f.manifest.Documents {
		d.Documents = append(d.Documents, policybundle.DraftDocument{Kind: r.Kind, OrganizationID: r.OrganizationID, Path: r.Path})
	}
	if f.manifest.IdentityCatalog != nil {
		d.IdentityCatalog = &policybundle.DraftIdentity{Path: f.manifest.IdentityCatalog.Path}
	}
	return d
}

func writeDraft(t *testing.T, f fixture, d policybundle.Draft) policybundle.DraftSelection {
	t.Helper()
	dir := t.TempDir()
	for name, raw := range f.docs {
		if err := os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "draft.json"), encode(t, d), 0600); err != nil {
		t.Fatal(err)
	}
	return policybundle.DraftSelection{Directory: dir}
}

func writePrepared(t *testing.T, artifact *policybundle.PreparedArtifact) string {
	t.Helper()
	dir := t.TempDir()
	for _, file := range artifact.Files() {
		if err := os.WriteFile(filepath.Join(dir, file.Path), file.Bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), artifact.ManifestBytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestPrepareDerivesExactHashesRequirementsAndReloads(t *testing.T) {
	f := baseFixture(t)
	// Formatting and line endings remain authored bytes, not normalized source.
	f.docs["groups.json"] = append([]byte(" \r\n"), f.docs["groups.json"]...)
	selection := writeDraft(t, f, draftFor(f))
	a, err := policybundle.PrepareDirectory(t.Context(), selection, f.options)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policybundle.PrepareDirectory(t.Context(), selection, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.ManifestBytes(), b.ManifestBytes()) || a.ManifestDigest() != b.ManifestDigest() || !reflect.DeepEqual(a.Files(), b.Files()) {
		t.Fatal("unchanged inputs produced different artifacts")
	}
	var manifest policybundle.Manifest
	if err := json.Unmarshal(a.ManifestBytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	for i, ref := range manifest.Documents {
		if ref.SHA256 != policybundle.RawDigest(f.docs[ref.Path]) || (i > 0 && manifest.Documents[i-1].Path >= ref.Path) {
			t.Fatal("exact hashes or deterministic file order lost")
		}
	}
	for _, file := range a.Files() {
		if !bytes.Equal(file.Bytes, f.docs[file.Path]) {
			t.Fatal("prepare rewrote source bytes")
		}
	}
	if !reflect.DeepEqual(manifest.RequiredCapabilities, a.Requirements().Capabilities) {
		t.Fatal("requirements not inferred from compiled source")
	}
	loaded, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil || !reflect.DeepEqual(loaded.Requirements(), a.Requirements()) {
		t.Fatalf("prepared artifact fails actual pinned loader: %v", err)
	}
	copy := a.Files()
	copy[0].Bytes[0] = 0
	copy[0].Path = "other"
	raw := a.ManifestBytes()
	raw[0] = 0
	required := a.Requirements()
	required.Capabilities[0] = "other"
	if !bytes.Equal(a.ManifestBytes(), b.ManifestBytes()) || !reflect.DeepEqual(a.Files(), b.Files()) || !reflect.DeepEqual(a.Requirements(), b.Requirements()) {
		t.Fatal("prepared getters expose mutable internals")
	}
}

func TestPrepareIdentityUsesTheSameGlobalFileCompiler(t *testing.T) {
	f := baseFixture(t)
	f.manifest.Profile = policybundle.IdentityProfileID
	f.options.Profile = policybundle.IdentityProfile(f.options.Methods.Version)
	f.options.IdentityLimits = identity.DefaultLimits()
	f.docs["identity.json"] = []byte(`{"apiVersion":"ops.identity-catalog/v1alpha1","kind":"IdentityCatalog","issuers":[],"profiles":[],"mappings":[]}`)
	f.manifest.IdentityCatalog = &policybundle.IdentityCatalogRef{Path: "identity.json"}
	a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	var m policybundle.Manifest
	if err := json.Unmarshal(a.ManifestBytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m.IdentityCatalog == nil || m.IdentityCatalog.SHA256 != policybundle.RawDigest(f.docs["identity.json"]) {
		t.Fatal("identity file not hashed")
	}
	loaded, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Identity(); !ok {
		t.Fatal("identity profile disappeared")
	}
}

func TestPreparedNativeV2RetainsVersionedBoundsAndMethodSnapshot(t *testing.T) {
	f := nativeV2Fixture(t)
	a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	s, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	v, ok := s.Execution(orgID)
	if !ok || *v.Policy().Bindings[0].Allow[0].MinDepth != 1 || s.Metadata().EvaluatorVersion != policybundle.NativeV2EvaluatorVersion {
		t.Fatal("shared preparation lost versioned native semantics")
	}
	method, ok := s.Method("chain_call")
	if !ok || method.Canonical != "eth_call" {
		t.Fatal("shared compiler discarded the trusted method snapshot")
	}
}

func TestPrepareCannotBypassSourceOrFilesystemGuards(t *testing.T) {
	for name, change := range map[string]func(*fixture, *policybundle.Draft){
		"draft collision": func(f *fixture, d *policybundle.Draft) { d.Documents[0].Path = "draft.json" },
		"escape":          func(f *fixture, d *policybundle.Draft) { d.Documents[0].Path = "../groups.json" },
		"wrong profile":   func(f *fixture, d *policybundle.Draft) { d.Profile = "invented" },
		"missing group": func(f *fixture, d *policybundle.Draft) {
			f.edit(t, "groups.json", func(m map[string]any) { spec(m)["groups"] = []any{} })
		},
		"malformed source": func(f *fixture, d *policybundle.Draft) { f.docs["groups.json"] = []byte(`{"invalid":`) },
		"duplicate source": func(f *fixture, d *policybundle.Draft) {
			f.docs["groups.json"] = bytes.Replace(f.docs["groups.json"], []byte(`"groups":`), []byte(`"groups":[],"groups":`), 1)
		},
		"missing doc": func(f *fixture, d *policybundle.Draft) { delete(f.docs, "groups.json") },
		"extra doc":   func(f *fixture, d *policybundle.Draft) { f.docs["extra.json"] = []byte(`{}`) },
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			d := draftFor(f)
			change(&f, &d)
			a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, d), f.options)
			if a != nil || err == nil {
				t.Fatal("invalid draft yielded proposal")
			}
		})
	}
	f := baseFixture(t)
	selection := writeDraft(t, f, draftFor(f))
	if err := os.Remove(filepath.Join(selection.Directory, "groups.json")); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "groups.json")
	if err := os.WriteFile(outside, f.docs["groups.json"], 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(selection.Directory, "groups.json")); err != nil {
		t.Fatal(err)
	}
	if a, err := policybundle.PrepareDirectory(t.Context(), selection, f.options); a != nil || err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestGeneratedManifestAndTotalBudgetsAreRechecked(t *testing.T) {
	f := baseFixture(t)
	d := draftFor(f)
	selection := writeDraft(t, f, d)
	artifact, err := policybundle.PrepareDirectory(t.Context(), selection, f.options)
	if err != nil {
		t.Fatal(err)
	}
	draftBytes, err := os.ReadFile(filepath.Join(selection.Directory, "draft.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.ManifestBytes()) <= len(draftBytes) {
		t.Fatal("fixture does not exercise generated growth")
	}
	for _, kind := range []string{"manifest", "total"} {
		t.Run(kind, func(t *testing.T) {
			o := f.options
			if kind == "manifest" {
				o.Limits.MaxManifestBytes = int64(len(artifact.ManifestBytes()) - 1)
			} else {
				n := int64(len(artifact.ManifestBytes()) - 1)
				for _, raw := range f.docs {
					n += int64(len(raw))
				}
				o.Limits.MaxBundleBytes = n
			}
			a, err := policybundle.PrepareDirectory(t.Context(), selection, o)
			var detail *policybundle.Error
			if a != nil || !errors.As(err, &detail) || detail.Code != policybundle.LimitExceeded {
				t.Fatalf("generated %s budget not checked: %v", kind, err)
			}
		})
	}
}
