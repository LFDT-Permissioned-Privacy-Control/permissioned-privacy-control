package policybundle_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func TestRuntimeAndDisclosureProfilesRemainSeparate(t *testing.T) {
	for _, runtimeSelected := range []bool{true, false} {
		name := "disclosure rejects runtime"
		if runtimeSelected {
			name = "runtime rejects disclosure"
		}
		t.Run(name, func(t *testing.T) {
			f, other := disclosureFixture(t), runtimeFixture(t)
			if runtimeSelected {
				f, other = other, f
				f.manifest.DisclosureCatalog = other.manifest.DisclosureCatalog
				f.docs["disclosure.json"] = other.docs["disclosure.json"]
			} else {
				f.manifest.RuntimeCatalog = other.manifest.RuntimeCatalog
				f.docs["runtime.json"] = other.docs["runtime.json"]
			}
			if err := reject(t, f.write(t), f.options, t.Context()); err.Code != policybundle.UnsupportedFeature {
				t.Fatal("cross-profile source did not reject explicitly", err)
			}
			a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
			var typed *policybundle.Error
			if a != nil || !errors.As(err, &typed) || typed.Code != policybundle.UnsupportedFeature {
				t.Fatal("preparation combined separately selected profiles", err)
			}
		})
	}
}

func TestRuntimeIdentityBytesCountOnceAtExactBundleBoundary(t *testing.T) {
	f := runtimeFixture(t)
	selection := f.write(t)
	raw, err := os.ReadFile(filepath.Join(selection.Directory, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	total := int64(len(raw))
	for _, raw := range f.docs {
		total += int64(len(raw))
	}
	f.options.Limits.MaxBundleBytes = total
	if _, err := policybundle.LoadDirectory(t.Context(), selection, f.options); err != nil {
		t.Fatal("identity/runtime bytes charged more than once", err)
	}
	f.options.Limits.MaxBundleBytes--
	if err := reject(t, selection, f.options, t.Context()); err.Code != policybundle.LimitExceeded {
		t.Fatal("identity/runtime bytes omitted from aggregate budget", err)
	}
}
