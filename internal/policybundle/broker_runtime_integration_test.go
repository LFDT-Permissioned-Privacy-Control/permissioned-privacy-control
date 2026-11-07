package policybundle_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func TestBrokerRuntimeIntegrationKeepsSourceProfilesClosed(t *testing.T) {
	auth := brokerFixture(t)
	for name, makeFixture := range map[string]func(*testing.T) fixture{
		"native":            nativeV2Fixture,
		"call":              runtimeFixture,
		"lifecycle":         lifecycleFixture,
		"simulation":        simulationFixture,
		"creation-intent":   creationIntentFixture,
		"creation-observed": creationObservedFixture,
		"raw": func(t *testing.T) fixture {
			return rawRuntimeFixture(t, policybundle.RawSubmissionOPSPreflight)
		},
		"multi-org-with-feed": func(t *testing.T) fixture {
			f := multiOrgFixture(t)
			withFeed(t, &f)
			return f
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := makeFixture(t)
			// Each independently supported profile still loads without auth.
			load(t, f)
			f.docs["auth.json"] = auth.docs["auth.json"]
			f.manifest.AuthCatalog = &policybundle.AuthCatalogRef{Path: "auth.json", SHA256: policybundle.RawDigest(f.docs["auth.json"])}
			selection := f.write(t)
			_, err := policybundle.LoadDirectory(t.Context(), selection, f.options)
			var typed *policybundle.Error
			if !errors.As(err, &typed) || typed.Code != policybundle.UnsupportedFeature || typed.Field != "authCatalog" {
				t.Fatal("auth must not silently compose with another profile", err)
			}
			if _, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options); !errors.As(err, &typed) || typed.Code != policybundle.UnsupportedFeature || typed.Field != "authCatalog" {
				t.Fatal("preparation must enforce the same closed profile", err)
			}
		})
	}
	for name, f := range map[string]fixture{"runtime": runtimeFixture(t), "compliance": complianceFixture(t)} {
		t.Run("broker-rejects-"+name, func(t *testing.T) {
			b := brokerFixture(t)
			field := "runtimeCatalog"
			if name == "runtime" {
				b.manifest.RuntimeCatalog = f.manifest.RuntimeCatalog
				b.docs["runtime.json"] = f.docs["runtime.json"]
			} else {
				field = "complianceCatalog"
				b.manifest.ComplianceCatalog = f.manifest.ComplianceCatalog
				b.docs["compliance.json"] = f.docs["compliance.json"]
			}
			_, err := policybundle.LoadDirectory(t.Context(), b.write(t), b.options)
			var typed *policybundle.Error
			if !errors.As(err, &typed) || typed.Code != policybundle.UnsupportedFeature || typed.Field != field {
				t.Fatal("standalone broker profile must remain closed", err)
			}
		})
	}
}

func TestBrokerIdentityAndAuthConsumeOneExactBundleBudget(t *testing.T) {
	f := brokerFixture(t)
	selection := f.write(t)
	var total int64
	entries, err := os.ReadDir(selection.Directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		info, err := os.Stat(filepath.Join(selection.Directory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		total += info.Size()
	}
	f.options.Limits.MaxBundleBytes = total
	if _, err := policybundle.LoadDirectory(t.Context(), selection, f.options); err != nil {
		t.Fatal("exact approved bundle budget rejected", err)
	}
	f.options.Limits.MaxBundleBytes--
	_, err = policybundle.LoadDirectory(t.Context(), selection, f.options)
	var typed *policybundle.Error
	if !errors.As(err, &typed) || typed.Code != policybundle.LimitExceeded {
		t.Fatal("identity and auth must share the total byte budget", err)
	}
}
