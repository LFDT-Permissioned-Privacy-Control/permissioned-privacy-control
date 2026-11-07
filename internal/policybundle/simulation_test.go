package policybundle_test

import (
	"slices"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func simulationFixture(t *testing.T) fixture {
	t.Helper()
	f := lifecycleFixture(t)
	f.options.Profile = policybundle.RuntimeSimulationProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.RuntimeSimulationProfileID
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityUnsignedSimulation)
	f.edit(t, "runtime.json", func(d map[string]any) {
		d["apiVersion"], d["nodeEvidenceProfile"] = policybundle.RuntimeSimulationAPIVersion, policybundle.RuntimeSimulationNodeEvidenceProfileID
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func TestSimulationSourceIsExplicitDetachedAndUsesOneCompiler(t *testing.T) {
	f := simulationFixture(t)
	withFeed(t, &f)
	s := load(t, f)
	runtime, _ := s.Runtime()
	view, ok := runtime.SimulationSource()
	if !ok || view.APIVersion != policybundle.RuntimeSimulationAPIVersion || runtime.NodeEvidenceProfile() != policybundle.RuntimeSimulationNodeEvidenceProfileID || s.Metadata().EvaluatorVersion != policybundle.NativeV4EvaluatorVersion {
		t.Fatal("simulation source not honestly tagged")
	}
	if _, ok := runtime.LifecycleSource(); ok {
		t.Fatal("v5 projected as lifecycle-v4")
	}
	if _, ok := runtime.MultiOrgSource(); ok {
		t.Fatal("v5 projected as multi-org-v3")
	}
	if _, ok := runtime.RawSource(); ok || runtime.Source().APIVersion != "" {
		t.Fatal("v5 projected as older source")
	}
	view.PriceFeed.URI = "changed"
	view.AddressScopes = nil
	again, _ := runtime.SimulationSource()
	if again.PriceFeed.URI == "changed" {
		t.Fatal("source copy leaked")
	}
	artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, artifact), ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil || loaded.Metadata().RuntimeCatalog.SemanticDigest != s.Metadata().RuntimeCatalog.SemanticDigest || !slices.Contains(loaded.Requirements().Capabilities, policybundle.CapabilityUnsignedSimulation) {
		t.Fatal("prepare/load simulation semantics drift", err)
	}
	for _, change := range []func(*fixture){
		func(f *fixture) {
			f.options.Profile = policybundle.RuntimeLifecycleProfile("rpc-test/v1")
			f.manifest.Profile = policybundle.RuntimeLifecycleProfileID
		},
		func(f *fixture) { removeCapability(f, policybundle.CapabilityUnsignedSimulation) },
		func(f *fixture) {
			f.edit(t, "runtime.json", func(d map[string]any) { d["nodeEvidenceProfile"] = policybundle.RuntimeLifecycleNodeEvidenceProfileID })
			f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
		},
	} {
		bad := simulationFixture(t)
		change(&bad)
		reject(t, bad.write(t), bad.options, t.Context())
	}
}
