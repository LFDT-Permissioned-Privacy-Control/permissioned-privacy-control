package policybundle_test

import (
	"slices"
	"testing"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/policybundle"
)

func creationObservedFixture(t *testing.T) fixture {
	t.Helper()
	f := creationIntentFixture(t)
	f.options.Profile = policybundle.RuntimeCreationObservedProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.RuntimeCreationObservedProfileID
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityCreationCoverage)
	f.edit(t, "runtime.json", func(d map[string]any) {
		d["apiVersion"] = policybundle.RuntimeCreationObservedAPIVersion
		d["captureReadinessProfile"] = creationfacts.CaptureProfile
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func TestObservedCreationSourceIsClosedAndDetached(t *testing.T) {
	f := creationObservedFixture(t)
	withFeed(t, &f)
	s := load(t, f)
	r, _ := s.Runtime()
	source, ok := r.CreationObservedSource()
	if !ok || source.CaptureReadinessProfile != creationfacts.CaptureProfile || !slices.Contains(s.Requirements().Capabilities, policybundle.CapabilityCreationCoverage) {
		t.Fatal("missing explicit capture requirement")
	}
	if _, old := r.CreationIntentSource(); old {
		t.Fatal("covered source projected as journal-only")
	}
	if _, old := r.SimulationSource(); old {
		t.Fatal("covered source projected as simulation")
	}
	source.CreationAttribution.Factories[0].OrganizationID = "changed"
	source.PriceFeed.URI = "changed"
	again, _ := r.CreationObservedSource()
	if again.CreationAttribution.Factories[0].OrganizationID != orgID || again.PriceFeed.URI == "changed" {
		t.Fatal("mutable approved source escaped")
	}
	prepared, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, prepared), ExpectedManifestDigest: prepared.ManifestDigest(), ExpectedEnvironment: f.manifest.Environment, ExpectedChainID: f.manifest.ChainID}, f.options)
	if err != nil || cold.Metadata().RuntimeCatalog.SemanticDigest != r.Digest() {
		t.Fatal("authoring/runtime compiler diverged", err)
	}
}
func TestObservedCaptureRequirementCannotActivateOlderProfiles(t *testing.T) {
	for _, bad := range []string{"missing", "null", "unknown", "wrong-case", "older-profile", "omitted-capability"} {
		t.Run(bad, func(t *testing.T) {
			f := creationObservedFixture(t)
			switch bad {
			case "older-profile":
				f.options.Profile = policybundle.RuntimeCreationIntentProfile("rpc-test/v1")
				f.manifest.Profile = policybundle.RuntimeCreationIntentProfileID
			case "omitted-capability":
				f.manifest.RequiredCapabilities = slices.DeleteFunc(f.manifest.RequiredCapabilities, func(s string) bool { return s == policybundle.CapabilityCreationCoverage })
			default:
				f.edit(t, "runtime.json", func(d map[string]any) {
					switch bad {
					case "missing":
						delete(d, "captureReadinessProfile")
					case "null":
						d["captureReadinessProfile"] = nil
					case "unknown":
						d["captureReadinessProfile"] = "globally-proved/v1"
					case "wrong-case":
						delete(d, "captureReadinessProfile")
						d["CaptureReadinessProfile"] = creationfacts.CaptureProfile
					}
				})
				f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
			}
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	legacy := creationIntentFixture(t)
	legacy.edit(t, "runtime.json", func(d map[string]any) { d["captureReadinessProfile"] = creationfacts.CaptureProfile })
	legacy.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(legacy.docs["runtime.json"])
	reject(t, legacy.write(t), legacy.options, t.Context())
}
