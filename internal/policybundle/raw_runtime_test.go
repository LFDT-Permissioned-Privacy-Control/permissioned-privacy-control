package policybundle_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/policybundle"
)

func rawRuntimeFixture(t *testing.T, mode string) fixture {
	t.Helper()
	f := runtimeFixture(t)
	c := complianceFixture(t)
	f.options.Profile = policybundle.RuntimeRawSendProfile("rpc-test/v1")
	f.options.ComplianceLimits = compliancepolicy.DefaultLimits()
	f.manifest.Profile = policybundle.RuntimeRawSendProfileID
	f.docs["compliance.json"] = c.docs["compliance.json"]
	f.manifest.ComplianceCatalog = c.manifest.ComplianceCatalog
	for _, capability := range []string{"catalog.compliance-validate/v1", policybundle.CapabilityRuntimeRawSend, policybundle.CapabilitySigner, policybundle.CapabilityAdmission, policybundle.CapabilityWalletProofs} {
		if !slices.Contains(f.manifest.RequiredCapabilities, capability) {
			f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, capability)
		}
	}
	capability := policybundle.CapabilitySignedCall
	if mode == policybundle.RawSubmissionGuardV1 {
		capability = policybundle.CapabilityGuardDelivery
	}
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, capability)
	f.edit(t, "runtime.json", func(m map[string]any) {
		m["apiVersion"] = policybundle.RuntimeRawAPIVersion
		m["rawSubmissionMode"] = mode
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func TestRawRuntimeModeAndGlobalsUseOnePinnedCompiler(t *testing.T) {
	for _, mode := range []string{policybundle.RawSubmissionGuardV1, policybundle.RawSubmissionOPSPreflight} {
		t.Run(mode, func(t *testing.T) {
			f := rawRuntimeFixture(t, mode)
			snapshot := load(t, f)
			runtime, _ := snapshot.Runtime()
			if runtime.Source().APIVersion != "" || runtime.RawSubmissionMode() != mode {
				t.Fatal("v2 projected as v1 or mode lost")
			}
			source, ok := runtime.RawSource()
			if !ok || source.APIVersion != policybundle.RuntimeRawAPIVersion || source.RawSubmissionMode != mode {
				t.Fatal("tag lost")
			}
			a, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, a), ExpectedManifestDigest: a.ManifestDigest(), ExpectedEnvironment: f.manifest.Environment, ExpectedChainID: f.manifest.ChainID}, f.options)
			if err != nil {
				t.Fatal(err)
			}
			got, _ := prepared.Runtime()
			if got.Digest() != runtime.Digest() {
				t.Fatal("prepare and load diverged")
			}
			selection := f.write(t)
			manifest, err := os.ReadFile(filepath.Join(selection.Directory, "manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			total := int64(len(manifest))
			for _, raw := range f.docs {
				total += int64(len(raw))
			}
			f.options.Limits.MaxBundleBytes = total
			if _, err := policybundle.LoadDirectory(t.Context(), selection, f.options); err != nil {
				t.Fatal("global bytes charged twice", err)
			}
			f.options.Limits.MaxBundleBytes--
			reject(t, selection, f.options, t.Context())
		})
	}
}

func TestRawRuntimeClosedVersionProfileCapabilitiesAndChain(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"old profile": func(f *fixture) {
			f.options.Profile = policybundle.RuntimeCallProfile("rpc-test/v1")
			f.manifest.Profile = policybundle.RuntimeCallProfileID
		},
		"old version": func(f *fixture) {
			f.edit(t, "runtime.json", func(m map[string]any) { m["apiVersion"] = policybundle.RuntimeAPIVersion })
		},
		"missing mode": func(f *fixture) { f.edit(t, "runtime.json", func(m map[string]any) { delete(m, "rawSubmissionMode") }) },
		"null mode":    func(f *fixture) { f.edit(t, "runtime.json", func(m map[string]any) { m["rawSubmissionMode"] = nil }) },
		"bad mode": func(f *fixture) {
			f.edit(t, "runtime.json", func(m map[string]any) { m["rawSubmissionMode"] = "fallback" })
		},
		"missing compliance":        func(f *fixture) { f.manifest.ComplianceCatalog = nil; delete(f.docs, "compliance.json") },
		"compliance limits":         func(f *fixture) { f.options.ComplianceLimits = compliancepolicy.Limits{} },
		"missing mode capability":   func(f *fixture) { removeCapability(f, policybundle.CapabilityGuardDelivery) },
		"missing wallet capability": func(f *fixture) { removeCapability(f, policybundle.CapabilityWalletProofs) },
		"wrong mode capability": func(f *fixture) {
			f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilitySignedCall)
		},
		"zero chain":  func(f *fixture) { f.manifest.ChainID = "0" },
		"large chain": func(f *fixture) { f.manifest.ChainID = "18446744073709551616" },
		"disclosure global": func(f *fixture) {
			d := disclosureFixture(t)
			f.manifest.DisclosureCatalog = d.manifest.DisclosureCatalog
			f.docs["disclosure.json"] = d.docs["disclosure.json"]
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := rawRuntimeFixture(t, policybundle.RawSubmissionGuardV1)
			change(&f)
			if f.manifest.RuntimeCatalog != nil {
				f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
			}
			selection := f.write(t)
			selection.ExpectedChainID = f.manifest.ChainID
			err := reject(t, selection, f.options, t.Context())
			if (name == "zero chain" || name == "large chain") && (err.Code != policybundle.UnsupportedFeature || err.Field != "chainId") {
				t.Fatal("chain bound failed for unrelated selection", err)
			}
		})
	}
	f := runtimeFixture(t)
	f.edit(t, "runtime.json", func(m map[string]any) { m["rawSubmissionMode"] = policybundle.RawSubmissionGuardV1 })
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	reject(t, f.write(t), f.options, t.Context())
	maximum := rawRuntimeFixture(t, policybundle.RawSubmissionGuardV1)
	maximum.manifest.ChainID = "18446744073709551615"
	selection := maximum.write(t)
	selection.ExpectedChainID = maximum.manifest.ChainID
	if _, err := policybundle.LoadDirectory(t.Context(), selection, maximum.options); err != nil {
		t.Fatal("maximum accepting chain rejected", err)
	}
	validationOnly := complianceFixture(t)
	validationOnly.manifest.ChainID = "18446744073709551616"
	selection = validationOnly.write(t)
	selection.ExpectedChainID = validationOnly.manifest.ChainID
	if _, err := policybundle.LoadDirectory(t.Context(), selection, validationOnly.options); err != nil {
		t.Fatal("validation-only range narrowed", err)
	}
}

func TestRawRuntimeDetachesBothVersionAndCommonAccessors(t *testing.T) {
	f := rawRuntimeFixture(t, policybundle.RawSubmissionGuardV1)
	f.edit(t, "runtime.json", func(m map[string]any) {
		m["sharedInfrastructure"] = []any{map[string]any{"address": address, "codeHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}
		m["addressScopes"] = []any{map[string]any{"address": address, "organizationId": orgID}}
	})
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilitySharedCode, policybundle.CapabilityAddressScopes)
	runtime, _ := load(t, f).Runtime()
	s, _ := runtime.RawSource()
	s.RawSubmissionMode = "changed"
	*s.SharedInfrastructure[0].CodeHash = "changed"
	s.AddressScopes[0].OrganizationID = "changed"
	shared := runtime.SharedInfrastructure()
	*shared[0].CodeHash = "changed"
	s, _ = runtime.RawSource()
	if s.RawSubmissionMode != policybundle.RawSubmissionGuardV1 || *s.SharedInfrastructure[0].CodeHash == "changed" || s.AddressScopes[0].OrganizationID != orgID {
		t.Fatal("source aliases caller")
	}
	var ordinary policybundle.RuntimeSource
	json.Unmarshal(encode(t, runtime.Source()), &ordinary)
	if ordinary.APIVersion != "" {
		t.Fatal("apparent v1 source exposed")
	}
}
