package policybundle_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
	"privacy-proxy/internal/policycore"
)

func removeCapability(f *fixture, name string) {
	f.manifest.RequiredCapabilities = slices.DeleteFunc(f.manifest.RequiredCapabilities, func(s string) bool { return s == name })
}

func TestRequirementsAreInferredAndDeclarationsCannotHideUsage(t *testing.T) {
	for _, name := range baseFixture(t).manifest.RequiredCapabilities {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			removeCapability(&f, name)
			err := reject(t, f.write(t), f.options, t.Context())
			if err.Code != policybundle.CapabilityMismatch {
				t.Fatal(err)
			}
		})
	}
	for _, extra := range []string{"unused.unknown", policybundle.CapabilityDynamicPayload} {
		t.Run(extra, func(t *testing.T) {
			f := baseFixture(t)
			f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, extra)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := baseFixture(t)
	f.edit(t, "registry.json", func(doc map[string]any) { contract(doc)["eventsAllowDynamicPayload"] = true })
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, policybundle.CapabilityDynamicPayload)
	if !slices.Contains(load(t, f).Requirements().Capabilities, policybundle.CapabilityDynamicPayload) {
		t.Fatal("dynamic payload flag requirement lost")
	}
	f = baseFixture(t)
	f.edit(t, "registry.json", func(doc map[string]any) { contract(doc)["allowVisibleToUnlock"] = true })
	f.manifest.RequiredCapabilities = append(f.manifest.RequiredCapabilities, "privacy.visible-to-history")
	err := reject(t, f.write(t), f.options, t.Context())
	if err.Code != policybundle.UnsupportedFeature {
		t.Fatal("self declaration enabled unresolved history", err)
	}
}

func TestClosedNativeFoundationMatrix(t *testing.T) {
	for _, selector := range []string{"*", "0x"} {
		t.Run("literal "+selector, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) {
				r := rule(doc)
				r["selector"], r["abiDigest"] = selector, ""
				delete(r, "args")
			})
			removeCapability(&f, policybundle.CapabilitySigner)
			if selector == "*" {
				removeCapability(&f, policybundle.CapabilityCalldata)
			}
			load(t, f)
		})
	}
	for _, kind := range []string{"call", "staticcall"} {
		t.Run(kind, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) { rule(doc)["callTypes"] = []string{kind} })
			load(t, f)
		})
	}
	for _, source := range []string{"literal", "principal.linked"} {
		t.Run(source, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) {
				match := rule(doc)["args"].([]any)[0].(map[string]any)["addressEquals"].(map[string]any)
				match["source"] = source
				if source == "literal" {
					match["value"] = signer
				}
			})
			removeCapability(&f, policybundle.CapabilitySigner)
			load(t, f)
		})
	}
	for _, class := range []string{"org", "shared", "eoa", "precompile", "create", "deployer", "pending", "unknown"} {
		t.Run("class "+class, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) {
				r := rule(doc)
				r["targetClass"], r["storageAddress"], r["selector"], r["abiDigest"] = class, "", "*", ""
				delete(r, "args")
				if class == "eoa" {
					r["selector"] = "0x"
				}
				if class == "create" {
					r["callTypes"] = []string{"create"}
				}
				if class == "deployer" {
					r["except"] = []any{map[string]any{"storageAddress": address, "groups": []string{groupID}}}
				}
			})
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	for _, kind := range []string{"delegatecall", "callcode", "create", "create2", "unknown"} {
		t.Run("opcode "+kind, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) { r := rule(doc); r["callTypes"], r["codeAddress"] = []string{kind}, address })
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	for name, edit := range map[string]func(map[string]any){
		"upgrade":                 func(r map[string]any) { r["allowUpgrade"] = true },
		"wildcard args":           func(r map[string]any) { r["selector"], r["abiDigest"] = "*", "" },
		"unknown selector":        func(r map[string]any) { r["selector"] = "0x00000000" },
		"ABI mismatch":            func(r map[string]any) { r["abiDigest"] = strings.Repeat("0", 64) },
		"conflicting constraints": func(r map[string]any) { r["args"].([]any)[0].(map[string]any)["uintAtMost"] = "1" },
		"negative depth":          func(r map[string]any) { r["maxDepth"] = -1 },
		"overflow value":          func(r map[string]any) { r["maxValue"] = strings.Repeat("9", 79) },
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) { edit(rule(doc)) })
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	// A valid native record getter still requires a later live-input profile.
	f := baseFixture(t)
	getterABI := strings.TrimSuffix(contractABI, "]") + `,{"type":"function","name":"parties","stateMutability":"view","inputs":[{"name":"id","type":"uint256"}],"outputs":[{"name":"party","type":"address"}]}]`
	var value any
	if err := json.Unmarshal([]byte(getterABI), &value); err != nil {
		t.Fatal(err)
	}
	canonical := string(encode(t, value))
	getter, err := abi.JSON(strings.NewReader(getterABI))
	if err != nil {
		t.Fatal(err)
	}
	f.edit(t, "registry.json", func(doc map[string]any) { contract(doc)["abi"] = value })
	f.edit(t, "execution.json", func(doc map[string]any) {
		r := rule(doc)
		r["abiDigest"] = policycore.ABIDigest(canonical)
		r["args"].([]any)[1] = map[string]any{"index": 1, "recordParty": map[string]any{"getter": "0x" + common.Bytes2Hex(getter.Methods["parties"].ID), "abiDigest": policycore.ABIDigest(canonical), "partyOutputs": []int{0}}}
	})
	if err := reject(t, f.write(t), f.options, t.Context()); err.Code != policybundle.UnsupportedFeature {
		t.Fatal("recordParty did not identify deferred live input", err)
	}
}

func TestNewEnvelopeRequiresExplicitDenyAllWithoutChangingNativeParser(t *testing.T) {
	for _, field := range []string{"bindings", "allow"} {
		t.Run(field, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "execution.json", func(doc map[string]any) {
				p := spec(doc)["policy"].(map[string]any)
				if field == "bindings" {
					delete(p, "bindings")
				} else {
					delete(p["bindings"].([]any)[0].(map[string]any), "allow")
				}
				native, err := policycore.Parse(encode(t, p))
				if err != nil {
					t.Fatal("standalone native omission changed", err)
				}
				catalog := policycore.Catalog{Org: orgID, Groups: map[string]struct{}{groupID: {}}, Contracts: map[string]policycore.ContractInfo{address: {ABI: canonicalABI(t)}}}
				if _, err := policycore.Validate(native, catalog); err != nil {
					t.Fatal("native omission no longer deny-all", err)
				}
			})
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := baseFixture(t)
	f.edit(t, "groups.json", func(doc map[string]any) { spec(doc)["groups"] = []any{} })
	f.edit(t, "registry.json", func(doc map[string]any) { spec(doc)["contracts"] = []any{} })
	f.edit(t, "execution.json", func(doc map[string]any) { spec(doc)["policy"].(map[string]any)["bindings"] = []any{} })
	f.manifest.RequiredCapabilities = []string{policybundle.CapabilityNativeValidate}
	s := load(t, f)
	v, _ := s.Execution(orgID)
	if v.Evaluate(policycore.Context{Org: orgID}, nil).Allowed {
		t.Fatal("explicit empty policy allows execution")
	}
}

func TestMetadataOnlyDenyAllCatalogInfersNoPrincipalOrFrameProvider(t *testing.T) {
	f := baseFixture(t)
	f.edit(t, "groups.json", func(d map[string]any) { g := group(d); g["allowedMethods"] = []any{}; delete(g, "rpcCredential") })
	f.edit(t, "registry.json", func(d map[string]any) {
		e := contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)
		e["mode"], e["rules"] = "none", []any{}
	})
	f.edit(t, "execution.json", func(d map[string]any) { spec(d)["policy"].(map[string]any)["bindings"] = []any{} })
	f.manifest.RequiredCapabilities = []string{policybundle.CapabilityNativeValidate}
	s := load(t, f)
	if !slices.Equal(s.Requirements().Capabilities, f.manifest.RequiredCapabilities) || len(s.Requirements().SecretRefs) != 0 {
		t.Fatal("metadata-only source inferred unused runtime authority")
	}
}
