package policybundle_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func runtimeFixture(t *testing.T) fixture {
	f := identityFixture(t)
	f.options.Profile = policybundle.RuntimeCallProfile("rpc-test/v1")
	f.manifest.Profile = policybundle.RuntimeCallProfileID
	f.manifest.EvaluatorVersion = policybundle.NativeV2EvaluatorVersion
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityRuntimeCall, policybundle.CapabilityAnchoredCode, policybundle.CapabilityClassification, policybundle.CapabilityOwnership)
	f.edit(t, "execution.json", func(d map[string]any) {
		spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.NativeV2APIVersion
	})
	runtime := policybundle.RuntimeSource{APIVersion: policybundle.RuntimeAPIVersion, Kind: policybundle.RuntimeKind, ReadProfile: "standard", IntraOrgGrantTracing: true, SharedInfrastructure: []policybundle.SharedInfrastructure{}, AddressScopes: []policybundle.AddressScope{}, NodeEvidenceProfile: policybundle.RuntimeNodeEvidenceProfileID}
	f.docs["runtime.json"] = encode(t, runtime)
	f.manifest.RuntimeCatalog = &policybundle.RuntimeCatalogRef{Path: "runtime.json", SHA256: policybundle.RawDigest(f.docs["runtime.json"])}
	return f
}

func TestRuntimeSourceIsExplicitClosedAndBudgetedAcrossGlobalFiles(t *testing.T) {
	load(t, runtimeFixture(t))
	for name, change := range map[string]func(*fixture){
		"old profile": func(f *fixture) {
			f.options.Profile = policybundle.NativeV2Profile("rpc-test/v1")
			f.manifest.Profile = policybundle.NativeV2ProfileID
		},
		"missing runtime":                   func(f *fixture) { f.manifest.RuntimeCatalog = nil; delete(f.docs, "runtime.json") },
		"identity collision":                func(f *fixture) { f.manifest.RuntimeCatalog.Path = "identity.json" },
		"combined document budget":          func(f *fixture) { f.options.Limits.MaxDocuments = 4 },
		"missing anchored code declaration": func(f *fixture) { removeCapability(f, policybundle.CapabilityAnchoredCode) },
		"tampered exact bytes":              func(f *fixture) { f.docs["runtime.json"] = append(f.docs["runtime.json"], byte(' ')) },
	} {
		t.Run(name, func(t *testing.T) { f := runtimeFixture(t); change(&f); reject(t, f.write(t), f.options, t.Context()) })
	}
	for _, change := range []func(map[string]any){func(m map[string]any) { delete(m, "intraOrgGrantTracing") }, func(m map[string]any) { m["addressScopes"] = nil }, func(m map[string]any) { m["unknown"] = true }, func(m map[string]any) { m["ReadProfile"] = m["readProfile"]; delete(m, "readProfile") }, func(m map[string]any) { m["nodeEvidenceProfile"] = "geth-future/v1" }} {
		f := runtimeFixture(t)
		var m map[string]any
		json.Unmarshal(f.docs["runtime.json"], &m)
		change(m)
		f.docs["runtime.json"] = encode(t, m)
		f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
		reject(t, f.write(t), f.options, t.Context())
	}
	f := runtimeFixture(t)
	selection := f.write(t)
	total := len(encode(t, f.manifest))
	for _, raw := range f.docs {
		total += len(raw)
	}
	f.options.Limits.MaxBundleBytes = int64(total - 1)
	err := reject(t, selection, f.options, t.Context())
	if err.Code != policybundle.LimitExceeded {
		t.Fatal("combined identity/runtime byte budget", err)
	}
}

func TestRuntimePreparationUsesTheSameCompilerAndExactGlobals(t *testing.T) {
	f := runtimeFixture(t)
	draft := draftFor(f)
	artifact, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draft), f.options)
	if err != nil {
		t.Fatal(err)
	}
	directory := writePrepared(t, artifact)
	snapshot, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: directory, ExpectedManifestDigest: artifact.ManifestDigest(), ExpectedEnvironment: f.manifest.Environment, ExpectedChainID: f.manifest.ChainID}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if runtime, ok := snapshot.Runtime(); !ok || runtime.NodeEvidenceProfile() != policybundle.RuntimeNodeEvidenceProfileID {
		t.Fatal("prepared runtime source missing")
	}
	for _, file := range artifact.Files() {
		if file.Path == "runtime.json" && string(file.Bytes) != string(f.docs["runtime.json"]) {
			t.Fatal("preparation changed approved runtime bytes")
		}
	}
	// Preparation infers requirements; the pinned loader independently rejects
	// a manifest that conceals a required code-provenance input.
	removeCapability(&f, policybundle.CapabilityAnchoredCode)
	reject(t, f.write(t), f.options, t.Context())
}

func TestRuntimeSourceCopiesAndStaticScopesDoNotBecomeContracts(t *testing.T) {
	const scoped = "0x7777777777777777777777777777777777777777"
	f := runtimeFixture(t)
	var source policybundle.RuntimeSource
	json.Unmarshal(f.docs["runtime.json"], &source)
	pin := "0x" + strings.Repeat("1", 64)
	source.SharedInfrastructure = []policybundle.SharedInfrastructure{{Address: address, CodeHash: &pin}}
	source.AddressScopes = []policybundle.AddressScope{{Address: scoped, OrganizationID: orgID}}
	f.docs["runtime.json"] = encode(t, source)
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilitySharedCode, policybundle.CapabilityAddressScopes)
	f.edit(t, "registry.json", func(d map[string]any) {
		contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["must_be"] = scoped
	})
	removeCapability(&f, policybundle.CapabilityLinkedWallets)
	snapshot := load(t, f)
	catalog, ok := snapshot.Runtime()
	if !ok {
		t.Fatal("runtime catalog absent")
	}
	native, _ := snapshot.NativeCatalog(orgID)
	if _, exists := native.Contracts[scoped]; exists {
		t.Fatal("static scope became native contract")
	}
	if _, exists := snapshot.Contract(orgID, common.HexToAddress(scoped)); exists {
		t.Fatal("static scope became registry/read association")
	}
	copy := catalog.Source()
	copy.AddressScopes[0].OrganizationID = "foreign"
	*copy.SharedInfrastructure[0].CodeHash = "changed"
	if catalog.Source().AddressScopes[0].OrganizationID != orgID || *catalog.Source().SharedInfrastructure[0].CodeHash != pin {
		t.Fatal("runtime source escaped")
	}
	metadata := snapshot.Metadata()
	metadata.RuntimeCatalog.Path = "changed"
	if snapshot.Metadata().RuntimeCatalog.Path != "runtime.json" {
		t.Fatal("runtime metadata escaped")
	}
	oldSemantic := catalog.Digest()
	oldRaw := snapshot.Metadata().RuntimeCatalog.SHA256
	f.docs["runtime.json"] = append([]byte(" \n"), f.docs["runtime.json"]...)
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	again := load(t, f)
	runtime, _ := again.Runtime()
	if runtime.Digest() != oldSemantic || again.Metadata().RuntimeCatalog.SHA256 == oldRaw {
		t.Fatal("raw/runtime semantic identities mixed")
	}
	for _, org := range []string{groupID, "ffffffff-ffff-ffff-ffff-ffffffffffff"} {
		source.AddressScopes[0].OrganizationID = org
		f.docs["runtime.json"] = encode(t, source)
		f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
		reject(t, f.write(t), f.options, t.Context())
	}
}
