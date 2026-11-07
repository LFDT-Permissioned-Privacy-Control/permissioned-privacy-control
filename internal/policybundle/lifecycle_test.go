package policybundle_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func lifecycleFixture(t *testing.T) fixture {
	t.Helper()
	f := multiOrgFixture(t)
	f.options.Profile = policybundle.RuntimeLifecycleProfile("rpc-test/v1")
	f.manifest.Profile, f.manifest.EvaluatorVersion = policybundle.RuntimeLifecycleProfileID, policybundle.NativeV4EvaluatorVersion
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityLifecycle, policybundle.CapabilityTemporalCode, policybundle.CapabilityCreationContext, policybundle.CapabilityLifecycleBeneficiary)
	f.edit(t, "execution.json", func(d map[string]any) {
		spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.NativeV4APIVersion
	})
	f.edit(t, "runtime.json", func(d map[string]any) {
		d["apiVersion"], d["nodeEvidenceProfile"] = policybundle.RuntimeLifecycleAPIVersion, policybundle.RuntimeLifecycleNodeEvidenceProfileID
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func TestLifecycleSourceStaysTaggedAndSharesOnePreparationCompiler(t *testing.T) {
	f := lifecycleFixture(t)
	withFeed(t, &f)
	snapshot := load(t, f)
	runtime, _ := snapshot.Runtime()
	source, ok := runtime.LifecycleSource()
	if !ok || source.APIVersion != policybundle.RuntimeLifecycleAPIVersion || runtime.NodeEvidenceProfile() != policybundle.RuntimeLifecycleNodeEvidenceProfileID {
		t.Fatal("lifecycle source not tagged")
	}
	if _, ok := runtime.MultiOrgSource(); ok {
		t.Fatal("v4 projected as v3")
	}
	if _, ok := runtime.RawSource(); ok || runtime.Source().APIVersion != "" {
		t.Fatal("v4 projected as older source")
	}
	source.AddressScopes = nil
	source.PriceFeed.URI = "changed"
	again, _ := runtime.LifecycleSource()
	if again.PriceFeed.URI == "changed" {
		t.Fatal("source metadata escaped mutably")
	}
	artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, artifact), ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: "test", ExpectedChainID: "31337"}, f.options)
	if err != nil || loaded.Metadata().RuntimeCatalog.SemanticDigest != snapshot.Metadata().RuntimeCatalog.SemanticDigest {
		t.Fatal("prepare/load lifecycle digest drift", err)
	}
	for _, capability := range []string{policybundle.CapabilityLifecycle, policybundle.CapabilityTemporalCode, policybundle.CapabilityCreationContext, policybundle.CapabilityLifecycleBeneficiary, policybundle.CapabilityMultiOrg} {
		if !slices.Contains(loaded.Requirements().Capabilities, capability) {
			t.Fatal("missing lifecycle requirement", capability)
		}
	}
}

func TestLifecycleSourceExplicitlyAcceptsOnlyItsReviewedClasses(t *testing.T) {
	for _, class := range []string{"create", "deployment-context", "deployer", "pending"} {
		t.Run(class, func(t *testing.T) {
			f := lifecycleFixture(t)
			kind := policycore.CallTypeCall
			if class == "create" {
				kind = policycore.CallTypeCreate
			}
			f.edit(t, "execution.json", func(d map[string]any) {
				p := spec(d)["policy"].(map[string]any)
				p["bindings"].([]any)[0].(map[string]any)["allow"] = []any{map[string]any{"storageAddress": "", "abiDigest": "", "targetClass": class, "selector": "*", "callTypes": []string{string(kind)}}}
			})
			artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
			if class == "deployer" || class == "pending" {
				var typed *policybundle.Error
				if !errors.As(err, &typed) || typed.Code != policybundle.UnsupportedFeature || artifact != nil {
					t.Fatal("durable operational class enabled without observer")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var manifest policybundle.Manifest
			if err := json.Unmarshal(artifact.ManifestBytes(), &manifest); err != nil {
				t.Fatal(err)
			}
			if manifest.EvaluatorVersion != policybundle.NativeV4EvaluatorVersion {
				t.Fatal("wrong native evaluator")
			}
		})
	}
	for _, change := range []func(*fixture){
		func(f *fixture) {
			f.manifest.Profile = policybundle.RuntimeMultiOrgProfileID
			f.options.Profile = policybundle.RuntimeMultiOrgProfile("rpc-test/v1")
			f.manifest.EvaluatorVersion = policybundle.NativeV3EvaluatorVersion
		},
		func(f *fixture) { removeCapability(f, policybundle.CapabilityCreationContext) },
		func(f *fixture) {
			f.edit(t, "runtime.json", func(d map[string]any) { d["nodeEvidenceProfile"] = policybundle.RuntimeNodeEvidenceProfileID })
			f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
		},
	} {
		f := lifecycleFixture(t)
		change(&f)
		reject(t, f.write(t), f.options, t.Context())
	}
}
