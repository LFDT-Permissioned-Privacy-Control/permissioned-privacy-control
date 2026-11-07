package policybundle_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/compliancepolicy"
	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func multiOrgFixture(t *testing.T) fixture {
	f := rawRuntimeFixture(t, policybundle.RawSubmissionOPSPreflight)
	f.options.Profile = policybundle.RuntimeMultiOrgProfile("rpc-test/v1")
	f.manifest.Profile, f.manifest.EvaluatorVersion = policybundle.RuntimeMultiOrgProfileID, policybundle.NativeV3EvaluatorVersion
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityMultiOrg)
	f.edit(t, "execution.json", func(d map[string]any) {
		spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.NativeV3APIVersion
	})
	f.edit(t, "runtime.json", func(d map[string]any) { d["apiVersion"] = policybundle.RuntimeMultiOrgAPIVersion })
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
	return f
}

func withFeed(t *testing.T, f *fixture) {
	f.edit(t, "runtime.json", func(d map[string]any) {
		d["priceFeed"] = map[string]any{"uri": "https://prices.test/simple?z=2&a=1", "format": "coingecko-simple", "refreshIntervalSeconds": 60, "credential": map[string]any{"fromEnv": "OPS_PRICE_FEED_TOKEN"}}
	})
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityPriceFeed)
	f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
}

func TestMultiOrgFirstSourceCompilesImmutableFeedWithSameCompliance(t *testing.T) {
	f := multiOrgFixture(t)
	snapshot := load(t, f)
	runtime, _ := snapshot.Runtime()
	if _, _, ok := runtime.PriceFeed(); ok {
		t.Fatal("absent source fabricated a feed")
	}
	withFeed(t, &f)
	snapshot = load(t, f)
	runtime, _ = snapshot.Runtime()
	def, plan, ok := runtime.PriceFeed()
	compliance, _ := snapshot.Compliance()
	if !ok || plan.SourceDigest() != def.Digest() || plan.CatalogDigest() != compliance.Digest() || !slices.Equal(plan.IDs(), []string{"ethereum"}) || !slices.Equal(plan.Currencies(), []string{"eur"}) {
		t.Fatal("feed plan was not compiled from selected source/catalog")
	}
	if runtime.Source().APIVersion != "" {
		t.Fatal("v3 projected as v1")
	}
	if _, ok := runtime.RawSource(); ok {
		t.Fatal("v3 projected as v2")
	}
	source, ok := runtime.MultiOrgSource()
	if !ok || source.PriceFeed == nil || source.PriceFeed.URI != "https://prices.test/simple?a=1&z=2" {
		t.Fatal(source)
	}
	source.PriceFeed.URI = "changed"
	source.PriceFeed.Credential.FromEnv = "changed"
	metadata := snapshot.Metadata()
	identity := metadata.RuntimeCatalog.PriceFeed
	if identity == nil || identity.SourceDigest != def.Digest() || identity.PlanDigest != plan.Digest() || identity.ComplianceDigest != compliance.Digest() || !slices.Contains(snapshot.Requirements().SecretRefs, "OPS_PRICE_FEED_TOKEN") {
		t.Fatal("feed identity/dependencies missing")
	}
	identity.SourceDigest = "changed"
	if snapshot.Metadata().RuntimeCatalog.PriceFeed.SourceDigest != def.Digest() {
		t.Fatal("mutable metadata escaped")
	}
	refs := snapshot.NativeCodeReferences()
	delete(refs, address)
	if snapshot.NativeCodeReferences()[address].OwnerOrg != orgID {
		t.Fatal("global ABI index escaped")
	}
	own, _ := snapshot.NativeCatalog(orgID)
	if _, ok := own.Contracts[address]; !ok {
		t.Fatal("owned catalog changed")
	}
	registry, _ := snapshot.Contract(orgID, common.HexToAddress(address))
	if snapshot.NativeCodeReferences()[address].ABI != string(registry.ABI) {
		t.Fatal("reference ABI diverged")
	}
	prepared, err := policybundle.PrepareDirectory(t.Context(), writeDraft(t, f, draftFor(f)), f.options)
	if err != nil {
		t.Fatal(err)
	}
	cold, err := policybundle.LoadDirectory(t.Context(), policybundle.Selection{Directory: writePrepared(t, prepared), ExpectedManifestDigest: prepared.ManifestDigest(), ExpectedEnvironment: f.manifest.Environment, ExpectedChainID: f.manifest.ChainID}, f.options)
	if err != nil {
		t.Fatal(err)
	}
	coldRuntime, _ := cold.Runtime()
	_, coldPlan, _ := coldRuntime.PriceFeed()
	if coldRuntime.Digest() != runtime.Digest() || coldPlan.Digest() != plan.Digest() {
		t.Fatal("prepare/load use different compilers")
	}
}

func TestMultiOrgFeedIsClosedVersionedAndUsageInferred(t *testing.T) {
	for name, edit := range map[string]func(*fixture){
		"null feed": func(f *fixture) { f.edit(t, "runtime.json", func(d map[string]any) { d["priceFeed"] = nil }) },
		"unknown feed field": func(f *fixture) {
			f.edit(t, "runtime.json", func(d map[string]any) { d["priceFeed"].(map[string]any)["fallback"] = true })
		},
		"feed capability missing":  func(f *fixture) { removeCapability(f, policybundle.CapabilityPriceFeed) },
		"multi capability missing": func(f *fixture) { removeCapability(f, policybundle.CapabilityMultiOrg) },
		"foreign capability without use": func(f *fixture) {
			f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityForeignCode)
		},
		"old native source": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) {
				spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.NativeV2APIVersion
			})
		},
		"old source version": func(f *fixture) {
			f.edit(t, "runtime.json", func(d map[string]any) { d["apiVersion"] = policybundle.RuntimeRawAPIVersion })
		},
		"unused plan": func(f *fixture) {
			var source compliancepolicy.Source
			if err := json.Unmarshal(f.docs["compliance.json"], &source); err != nil {
				t.Fatal(err)
			}
			source.Organizations[0].Spec.TokenPrices = []compliancepolicy.SourceTokenPrice{{ID: "dddddddd-dddd-dddd-dddd-dddddddddddd", TokenAddress: "native", Symbol: "ETH", Decimals: 18, PricesByCurrency: map[string]float64{}}}
			f.docs["compliance.json"] = encode(t, source)
			f.manifest.ComplianceCatalog.SHA256 = policybundle.RawDigest(f.docs["compliance.json"])
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := multiOrgFixture(t)
			withFeed(t, &f)
			edit(&f)
			f.manifest.RuntimeCatalog.SHA256 = policybundle.RawDigest(f.docs["runtime.json"])
			err := reject(t, f.write(t), f.options, t.Context())
			if name == "unused plan" && err.Field != "priceFeed" {
				t.Fatal("not rejected by feed-plan validation", err)
			}
		})
	}
	for _, f := range []fixture{runtimeFixture(t), rawRuntimeFixture(t, policybundle.RawSubmissionOPSPreflight)} {
		withFeed(t, &f)
		reject(t, f.write(t), f.options, t.Context())
	}
}

func multiForeignFixture(t *testing.T) fixture {
	f := multiOrgFixture(t)
	other := twoOrganizations(t)
	f.manifest.Organizations = append(f.manifest.Organizations, other.manifest.Organizations[1])
	for _, ref := range other.manifest.Documents {
		if ref.OrganizationID == otherOrg {
			f.manifest.Documents = append(f.manifest.Documents, ref)
			f.docs[ref.Path] = other.docs[ref.Path]
		}
	}
	f.edit(t, "other-execution.json", func(d map[string]any) {
		spec(d)["policy"].(map[string]any)["apiVersion"] = policycore.NativeV3APIVersion
	})
	f.edit(t, "execution.json", func(d map[string]any) {
		rule(d)["codeAddress"] = otherAddress
		rule(d)["callTypes"] = []any{"delegatecall"}
	})
	var compliance compliancepolicy.Source
	if err := json.Unmarshal(f.docs["compliance.json"], &compliance); err != nil {
		t.Fatal(err)
	}
	copy := compliance.Organizations[0]
	copy.OrganizationID = otherOrg
	compliance.Organizations = append(compliance.Organizations, copy)
	f.docs["compliance.json"] = encode(t, compliance)
	f.manifest.ComplianceCatalog.SHA256 = policybundle.RawDigest(f.docs["compliance.json"])
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityForeignCode)
	return f
}

func TestMultiOrgForeignCodeReferencesStaySeparateAndUsageBound(t *testing.T) {
	f := multiForeignFixture(t)
	snapshot := load(t, f)
	own, _ := snapshot.NativeCatalog(orgID)
	if _, imported := own.Contracts[otherAddress]; imported {
		t.Fatal("foreign contract imported as owned")
	}
	refs := snapshot.NativeCodeReferences()
	if refs[otherAddress].OwnerOrg != otherOrg {
		t.Fatal("foreign reference owner changed")
	}
	for name, edit := range map[string]func(*fixture){
		"missing required input": func(f *fixture) { removeCapability(f, policybundle.CapabilityForeignCode) },
		"changed ABI pin": func(f *fixture) {
			f.edit(t, "other-registry.json", func(d map[string]any) { contract(d)["abi"] = []any{} })
		},
		"foreign storage": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { rule(d)["storageAddress"] = otherAddress })
		},
		"source asserted access": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { rule(d)["codeAccessible"] = true })
		},
		"owner ambiguity": func(f *fixture) {
			f.edit(t, "other-registry.json", func(d map[string]any) { contract(d)["address"] = address })
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := multiForeignFixture(t)
			edit(&f)
			err := reject(t, f.write(t), f.options, t.Context())
			if name == "missing required input" && err.Code != policybundle.CapabilityMismatch {
				t.Fatal("wrong rejection", err)
			}
		})
	}
}
