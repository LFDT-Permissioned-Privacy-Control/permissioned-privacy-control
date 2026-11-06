package policybundle_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func TestPinnedArtifactRejectsMixedMissingAndUnexpectedFiles(t *testing.T) {
	for name, change := range map[string]func(*testing.T, policybundle.Selection){
		"changed document": func(t *testing.T, s policybundle.Selection) {
			p := filepath.Join(s.Directory, "groups.json")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(raw, ' '), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"changed manifest": func(t *testing.T, s policybundle.Selection) {
			p := filepath.Join(s.Directory, "manifest.json")
			raw, _ := os.ReadFile(p)
			if err := os.WriteFile(p, append(raw, ' '), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"missing document": func(t *testing.T, s policybundle.Selection) {
			if err := os.Remove(filepath.Join(s.Directory, "groups.json")); err != nil {
				t.Fatal(err)
			}
		},
		"unexpected file": func(t *testing.T, s policybundle.Selection) {
			if err := os.WriteFile(filepath.Join(s.Directory, "extra.json"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"subdirectory": func(t *testing.T, s policybundle.Selection) {
			if err := os.Mkdir(filepath.Join(s.Directory, "nested"), 0700); err != nil {
				t.Fatal(err)
			}
		},
		"symlink document": func(t *testing.T, s policybundle.Selection) {
			p := filepath.Join(s.Directory, "groups.json")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		},
		"symlink manifest": func(t *testing.T, s policybundle.Selection) {
			p := filepath.Join(s.Directory, "manifest.json")
			if err := os.Rename(p, p+".old"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(p+".old", p); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, s policybundle.Selection) {
			p := filepath.Join(s.Directory, "groups.json")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(p, 0600); err != nil {
				t.Fatal(err)
			}
		},
		"many unexpected entries": func(t *testing.T, s policybundle.Selection) {
			for i := range 200 {
				if err := os.WriteFile(filepath.Join(s.Directory, fmt.Sprintf("unexpected-%03d.json", i)), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			s := f.write(t)
			change(t, s)
			reject(t, s, f.options, t.Context())
		})
	}
}

func TestTrustedSelectionAndResourceBudgets(t *testing.T) {
	for name, change := range map[string]func(*fixture, *policybundle.Selection){
		"absent hash": func(_ *fixture, s *policybundle.Selection) { s.ExpectedManifestDigest = "" },
		"wrong hash":  func(_ *fixture, s *policybundle.Selection) { s.ExpectedManifestDigest = policybundle.RawDigest(nil) },
		"uppercase hash": func(_ *fixture, s *policybundle.Selection) {
			s.ExpectedManifestDigest = policybundle.Digest(strings.ToUpper(string(s.ExpectedManifestDigest)))
		},
		"environment":        func(_ *fixture, s *policybundle.Selection) { s.ExpectedEnvironment = "another" },
		"chain":              func(_ *fixture, s *policybundle.Selection) { s.ExpectedChainID = "1" },
		"chain leading zero": func(_ *fixture, s *policybundle.Selection) { s.ExpectedChainID = "031337" },
		"chain overflow":     func(_ *fixture, s *policybundle.Selection) { s.ExpectedChainID = strings.Repeat("9", 78) },
		"evaluator":          func(f *fixture, _ *policybundle.Selection) { f.options.Profile = policybundle.ValidationProfile{} },
		"method version":     func(f *fixture, _ *policybundle.Selection) { f.options.Methods.Version = "different" },
		"manifest bytes":     func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxManifestBytes = 20 },
		"document bytes":     func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxDocumentBytes = 20 },
		"aggregate bytes":    func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxBundleBytes = 2000 },
		"documents":          func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxDocuments = 2 },
		"zero budget":        func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxJSONDepth = 0 },
		"depth":              func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxJSONDepth = 3 },
		"ABI entries":        func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxABIEntries = 1 },
		"ABI head":           func(f *fixture, _ *policybundle.Selection) { f.options.Limits.MaxExpandedABIHeadSlots = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			s := f.write(t)
			change(&f, &s)
			reject(t, s, f.options, t.Context())
		})
	}
	f := baseFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := reject(t, f.write(t), f.options, ctx)
	if err.Code != policybundle.Canceled || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation identity lost")
	}
}

func TestManifestPathsAndClosedIdentities(t *testing.T) {
	for _, path := range []string{"../escape.json", "/absolute.json", "nested/path.json", "Groups.json", "a..json", "manifest.json", "a.json\x00", "x.yaml", strings.Repeat("a", 124) + ".json"} {
		t.Run(path, func(t *testing.T) {
			f := baseFixture(t)
			f.manifest.Documents[0].Path = path
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	for name, change := range map[string]func(*fixture){
		"duplicate path":            func(f *fixture) { f.manifest.Documents[1].Path = f.manifest.Documents[0].Path },
		"duplicate source":          func(f *fixture) { f.manifest.Documents[1].Kind = policybundle.Groups },
		"missing execution":         func(f *fixture) { f.manifest.Documents = f.manifest.Documents[:2] },
		"undeclared organization":   func(f *fixture) { f.manifest.Documents[0].OrganizationID = groupID },
		"noncanonical organization": func(f *fixture) { f.manifest.Organizations[0].ID = "{11111111-1111-1111-1111-111111111111}" },
		"duplicate organization": func(f *fixture) {
			f.manifest.Organizations = append(f.manifest.Organizations, f.manifest.Organizations[0])
		},
		"unknown kind":    func(f *fixture) { f.manifest.Documents[0].Kind = "identity" },
		"wrong schema":    func(f *fixture) { f.manifest.APIVersion = "ops.configuration/v1" },
		"wrong profile":   func(f *fixture) { f.manifest.Profile = "runtime-unchecked/v1" },
		"wrong evaluator": func(f *fixture) { f.manifest.EvaluatorVersion = "evm" },
	} {
		t.Run(name, func(t *testing.T) { f := baseFixture(t); change(&f); reject(t, f.write(t), f.options, t.Context()) })
	}
}
