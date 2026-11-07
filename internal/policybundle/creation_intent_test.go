package policybundle_test

import (
	"slices"
	"strings"
	"testing"

	"privacy-proxy/internal/policybundle"
)

func creationIntentFixture(t *testing.T) fixture {
	t.Helper()
	f := simulationFixture(t)
	f.options.Profile = policybundle.RuntimeCreationIntentProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.RuntimeCreationIntentProfileID
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityCreationIntents)
	f.edit(t, "runtime.json", func(d map[string]any) {
		d["apiVersion"] = policybundle.RuntimeCreationIntentAPIVersion
		d["creationAttribution"] = map[string]any{"factories": []any{map[string]any{
			"address": address, "organizationId": orgID, "codeHash": "0x" + strings.Repeat("12", 32), "scope": policybundle.FactoryCreationSubtree,
		}}}
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func TestCreationIntentSourceIsClosedDetachedAndPreparedBySameCompiler(t *testing.T) {
	f := creationIntentFixture(t)
	withFeed(t, &f)
	s := load(t, f)
	r, _ := s.Runtime()
	x, ok := r.CreationIntentSource()
	if !ok || len(x.CreationAttribution.Factories) != 1 || x.CreationAttribution.Factories[0].OrganizationID != orgID || s.Metadata().EvaluatorVersion != policybundle.NativeV4EvaluatorVersion {
		t.Fatal("missing explicitly approved attribution")
	}
	if _, ok := r.SimulationSource(); ok {
		t.Fatal("new source projected as older simulation")
	}
	if _, ok := r.LifecycleSource(); ok {
		t.Fatal("new source projected as older lifecycle")
	}
	if _, ok := r.MultiOrgSource(); ok {
		t.Fatal("new source projected as older multi-org")
	}
	if _, ok := r.RawSource(); ok || r.Source().APIVersion != "" {
		t.Fatal("new source projected as older source")
	}
	x.CreationAttribution.Factories[0].OrganizationID = "changed"
	x.PriceFeed.URI = "changed"
	again, _ := r.CreationIntentSource()
	if again.CreationAttribution.Factories[0].OrganizationID != orgID || again.PriceFeed.URI == "changed" {
		t.Fatal("mutable approved attribution escaped")
	}
	a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: f.manifest.Environment, ExpectedChainID: f.manifest.ChainID}, f.options)
	if err != nil || cold.Metadata().RuntimeCatalog.SemanticDigest != r.Digest() || !slices.Contains(cold.Requirements().Capabilities, policybundle.CapabilityCreationIntents) {
		t.Fatal("different preparation/loader semantics", err)
	}
}

func TestCreationIntentFactoryNeedsExplicitOwnedOrdinaryDeclaration(t *testing.T) {
	for name, change := range map[string]func(map[string]any){
		"missing":        func(d map[string]any) { delete(d, "creationAttribution") },
		"null":           func(d map[string]any) { d["creationAttribution"] = nil },
		"null factories": func(d map[string]any) { d["creationAttribution"].(map[string]any)["factories"] = nil },
		"unknown field":  func(d map[string]any) { d["creationAttribution"].(map[string]any)["allowAll"] = true },
		"not registered": func(d map[string]any) { factoryEntry(d)["address"] = "0x9999999999999999999999999999999999999999" },
		"unregistered empty owner": func(d map[string]any) {
			factoryEntry(d)["address"] = "0x9999999999999999999999999999999999999999"
			factoryEntry(d)["organizationId"] = ""
		},
		"precompile":     func(d map[string]any) { factoryEntry(d)["address"] = "0x0000000000000000000000000000000000000001" },
		"wrong owner":    func(d map[string]any) { factoryEntry(d)["organizationId"] = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb" },
		"zero pin":       func(d map[string]any) { factoryEntry(d)["codeHash"] = "0x" + strings.Repeat("00", 32) },
		"invalid pin":    func(d map[string]any) { factoryEntry(d)["codeHash"] = "0x" + strings.Repeat("gg", 32) },
		"unknown scope":  func(d map[string]any) { factoryEntry(d)["scope"] = "all-orgs" },
		"shared factory": func(d map[string]any) { d["sharedInfrastructure"] = []any{map[string]any{"address": address}} },
		"duplicate": func(d map[string]any) {
			d["creationAttribution"].(map[string]any)["factories"] = []any{factoryEntry(d), factoryEntry(d)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := creationIntentFixture(t)
			f.edit(t, "runtime.json", change)
			f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := creationIntentFixture(t)
	f.edit(t, "runtime.json", func(d map[string]any) { d["creationAttribution"].(map[string]any)["factories"] = []any{} })
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	load(t, f)
}

func factoryEntry(d map[string]any) map[string]any {
	return d["creationAttribution"].(map[string]any)["factories"].([]any)[0].(map[string]any)
}
