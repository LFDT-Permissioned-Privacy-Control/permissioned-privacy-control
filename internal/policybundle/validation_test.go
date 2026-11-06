package policybundle_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/policybundle"
)

func TestAmbiguousABISelectorsAndEventLayoutsCannotChooseByMapOrder(t *testing.T) {
	collision := `[{"type":"function","name":"burn","inputs":[{"name":"n","type":"uint256"}],"outputs":[]},{"type":"function","name":"collate_propagate_storage","inputs":[{"name":"b","type":"bytes16"}],"outputs":[]}]`
	parsed, err := abi.JSON(strings.NewReader(collision))
	if err != nil {
		t.Fatal(err)
	}
	if common.Bytes2Hex(parsed.Methods["burn"].ID) != common.Bytes2Hex(parsed.Methods["collate_propagate_storage"].ID) {
		t.Fatal("fixture is not a real selector collision")
	}
	for name, text := range map[string]string{
		"selector collision":   collision,
		"indexed event layout": `[{"type":"event","name":"Changed","inputs":[{"name":"x","type":"uint256","indexed":true}],"anonymous":false},{"type":"event","name":"Changed","inputs":[{"name":"x","type":"uint256","indexed":false}],"anonymous":false}]`,
		"equivalent duplicate": `[{"type":"function","name":"same","inputs":[],"outputs":[]},{"type":"function","name":"same","inputs":[],"outputs":[]}]`,
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			var value any
			if err := json.Unmarshal([]byte(text), &value); err != nil {
				t.Fatal(err)
			}
			f.edit(t, "registry.json", func(d map[string]any) { contract(d)["abi"] = value })
			selection := f.write(t)
			for range 4 {
				failure := reject(t, selection, f.options, t.Context())
				if failure.Code != policybundle.InvalidSchema || !strings.Contains(failure.Error(), "ABI") {
					t.Fatal("ambiguity did not fail deterministically before native indexing", failure)
				}
			}
		})
	}
}

func TestDynamicABITypeExpansionIsBoundedBeforeLibraryConstruction(t *testing.T) {
	for name, input := range map[string]map[string]any{
		"dynamic scalar fixed arrays":   {"name": "outer", "type": "tuple", "components": []any{map[string]any{"name": "value", "type": "bytes[4096][4096][4096][4096][4096][4096]"}}},
		"nested tuple fixed arrays":     {"name": "outer", "type": "tuple[16][16]", "components": []any{map[string]any{"name": "inner", "type": "tuple[16]", "components": []any{map[string]any{"name": "value", "type": "bytes[16]"}}}}},
		"large element hidden by slice": {"name": "outer", "type": "tuple", "components": []any{map[string]any{"name": "value", "type": "bytes[4096][4096][]"}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["abi"] = []any{map[string]any{"type": "function", "name": "bounded", "inputs": []any{input}, "outputs": []any{}}}
			})
			err := reject(t, f.write(t), f.options, t.Context())
			if err.Code != policybundle.LimitExceeded {
				t.Fatal("unbounded reflected type reached ABI construction", err)
			}
		})
	}
	for _, typ := range []string{"bytes[4][4]", "bytes[4096][][2]"} {
		t.Run("allowed "+typ, func(t *testing.T) {
			f := baseFixture(t)
			var canonical []byte
			f.edit(t, "registry.json", func(d map[string]any) {
				c := contract(d)
				c["abi"] = append(c["abi"].([]any), map[string]any{"type": "function", "name": "bounded", "inputs": []any{map[string]any{"name": "outer", "type": "tuple", "components": []any{map[string]any{"name": "value", "type": typ}}}}, "outputs": []any{}})
				canonical = encode(t, c["abi"])
			})
			f.edit(t, "execution.json", func(d map[string]any) {
				rule(d)["abiDigest"] = strings.TrimPrefix(string(policybundle.RawDigest(canonical)), "sha256:")
			})
			load(t, f)
		})
	}
}

func TestABITypeDepthIncludesTupleAndEnclosingArrayDimensions(t *testing.T) {
	for _, depth := range []int{3, 4} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			f := baseFixture(t)
			f.options.Limits.MaxABITypeDepth = depth
			var canonical []byte
			f.edit(t, "registry.json", func(d map[string]any) {
				c := contract(d)
				c["abi"] = append(c["abi"].([]any), map[string]any{"type": "function", "name": "depth", "inputs": []any{map[string]any{"name": "outer", "type": "tuple[1]", "components": []any{map[string]any{"name": "value", "type": "uint256[1]"}}}}, "outputs": []any{}})
				canonical = encode(t, c["abi"])
			})
			f.edit(t, "execution.json", func(d map[string]any) {
				rule(d)["abiDigest"] = strings.TrimPrefix(string(policybundle.RawDigest(canonical)), "sha256:")
			})
			if depth == 3 {
				err := reject(t, f.write(t), f.options, t.Context())
				if err.Code != policybundle.LimitExceeded {
					t.Fatal("combined type path escaped the depth budget", err)
				}
			} else {
				load(t, f)
			}
		})
	}
}

func TestReadModesPreserveExplicitNoneAllAndAllowlistMeaning(t *testing.T) {
	for _, mode := range []string{"none", "all"} {
		t.Run(mode, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "registry.json", func(d map[string]any) {
				eventRules := contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)
				eventRules["mode"], eventRules["rules"] = mode, []any{}
			})
			removeCapability(&f, policybundle.CapabilityLinkedWallets)
			load(t, f)
		})
	}
	for _, mode := range []string{"none", "all", "unknown"} {
		t.Run("invalid "+mode, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["mode"] = mode
			})
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	f := baseFixture(t)
	f.edit(t, "registry.json", func(d map[string]any) {
		contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"] = nil
	})
	reject(t, f.write(t), f.options, t.Context())
}

func TestStrictBundleSourceRejectsAmbiguousOrLegacyAuthority(t *testing.T) {
	for _, tc := range []struct {
		name, document string
		change         func(map[string]any)
	}{
		{"document case", "groups.json", func(d map[string]any) { d["Kind"] = d["kind"]; delete(d, "kind") }},
		{"null groups", "groups.json", func(d map[string]any) { spec(d)["groups"] = nil }},
		{"missing methods", "groups.json", func(d map[string]any) { delete(group(d), "allowedMethods") }},
		{"null optional secret", "groups.json", func(d map[string]any) { group(d)["rpcCredential"] = nil }},
		{"secret value", "groups.json", func(d map[string]any) { group(d)["rpcCredential"].(map[string]any)["value"] = "never accepted" }},
		{"foreign secret", "groups.json", func(d map[string]any) { group(d)["rpcCredential"].(map[string]any)["fromEnv"] = "JWT_SECRET" }},
		{"user records", "groups.json", func(d map[string]any) { spec(d)["users"] = []any{} }},
		{"legacy revision", "groups.json", func(d map[string]any) { d["baseRevision"] = 0 }},
		{"legacy claims", "registry.json", func(d map[string]any) {
			contract(d)["readGrants"].([]any)[0].(map[string]any)["legacyClaims"] = []any{}
		}},
		{"param spelling", "registry.json", func(d map[string]any) {
			param := contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)
			param["mustBe"] = param["must_be"]
			delete(param, "must_be")
		}},
		{"policy case", "execution.json", func(d map[string]any) { p := spec(d)["policy"].(map[string]any); p["Org"] = p["org"]; delete(p, "org") }},
		{"null args", "execution.json", func(d map[string]any) { rule(d)["args"] = nil }},
		{"null bound", "execution.json", func(d map[string]any) { rule(d)["maxValue"] = nil }},
		{"missing index", "execution.json", func(d map[string]any) { delete(rule(d)["args"].([]any)[0].(map[string]any), "index") }},
		{"unknown constraint", "execution.json", func(d map[string]any) { rule(d)["requiresOwner"] = true }},
		{"legacy restrictions", "execution.json", func(d map[string]any) { spec(d)["legacyRestrictionDigest"] = strings.Repeat("0", 64) }},
		{"migration proxy pairs", "execution.json", func(d map[string]any) { spec(d)["proxyPairs"] = []any{} }},
		{"bytecode", "execution.json", func(d map[string]any) { spec(d)["artifact"] = map[string]any{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, tc.document, tc.change)
			reject(t, f.write(t), f.options, t.Context())
		})
	}
	for _, tc := range []struct {
		name, document string
		change         func(string) string
	}{
		{"duplicate envelope", "groups.json", func(s string) string {
			return strings.Replace(s, `"kind":"groups"`, `"kind":"groups","kind":"groups"`, 1)
		}},
		{"duplicate ABI metadata", "registry.json", func(s string) string {
			return strings.Replace(s, `"name":"transfer"`, `"name":"transfer","name":"different"`, 1)
		}},
		{"trailing value", "execution.json", func(s string) string { return s + ` {}` }},
		{"malformed", "groups.json", func(s string) string { return s[:len(s)-1] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := baseFixture(t)
			f.docs[tc.document] = []byte(tc.change(string(f.docs[tc.document])))
			reject(t, f.write(t), f.options, t.Context())
		})
	}
}

func TestSameBundleReferencesAndABIComplexity(t *testing.T) {
	for name, change := range map[string]func(*fixture){
		"missing grant group": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) { contract(d)["readGrants"].([]any)[0].(map[string]any)["groupId"] = grantID })
		},
		"wrong policy org": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { spec(d)["policy"].(map[string]any)["org"] = groupID })
		},
		"wrong document org": func(f *fixture) { f.edit(t, "groups.json", func(d map[string]any) { d["organizationId"] = groupID }) },
		"unknown execution group": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) {
				spec(d)["policy"].(map[string]any)["bindings"].([]any)[0].(map[string]any)["group"] = grantID
			})
		},
		"unregistered execution target": func(f *fixture) {
			f.edit(t, "execution.json", func(d map[string]any) { rule(d)["storageAddress"] = signer })
		},
		"unresolved EOA event": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["must_be"] = signer
			})
		},
		"event name": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["name"] = "Different"
			})
		},
		"event index": func(f *fixture) {
			f.edit(t, "registry.json", func(d map[string]any) {
				contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["index"] = 3
			})
		},
		"group budget": func(f *fixture) {
			f.options.Limits.MaxGroupsPerOrg = 1
			f.edit(t, "groups.json", func(d map[string]any) {
				g := group(d)
				copy := map[string]any{}
				for k, v := range g {
					copy[k] = v
				}
				copy["id"], copy["slug"], copy["name"] = grantID, "other", "Other"
				spec(d)["groups"] = append(spec(d)["groups"].([]any), copy)
			})
		},
		"contract budget": func(f *fixture) {
			f.options.Limits.MaxContractsPerOrg = 1
			f.edit(t, "registry.json", func(d map[string]any) { spec(d)["contracts"] = append(spec(d)["contracts"].([]any), contract(d)) })
		},
		"native budget": func(f *fixture) {
			f.options.Limits.MaxNativeRulesPerOrg = 1
			f.edit(t, "execution.json", func(d map[string]any) {
				b := spec(d)["policy"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
				b["allow"] = append(b["allow"].([]any), rule(d))
			})
		},
	} {
		t.Run(name, func(t *testing.T) { f := baseFixture(t); change(&f); reject(t, f.write(t), f.options, t.Context()) })
	}
	for _, typ := range []string{"uint256[9999999999999999999999999999]", "uint256[4096][4096]", "uint256" + strings.Repeat("[]", 20), "tuple"} {
		t.Run(typ, func(t *testing.T) {
			f := baseFixture(t)
			f.edit(t, "registry.json", func(d map[string]any) {
				c := contract(d)
				c["abi"] = []any{map[string]any{"type": "function", "name": "huge", "inputs": []any{map[string]any{"name": "x", "type": typ}}, "outputs": []any{}}}
			})
			err := reject(t, f.write(t), f.options, t.Context())
			if err.Code != policybundle.LimitExceeded {
				t.Fatal("ABI failed after structural guard", err)
			}
		})
	}
	// Static same-organization contract literals need no operational directory.
	f := baseFixture(t)
	f.edit(t, "registry.json", func(d map[string]any) {
		contract(d)["readGrants"].([]any)[0].(map[string]any)["eventRules"].(map[string]any)["rules"].([]any)[0].(map[string]any)["paramRules"].([]any)[0].(map[string]any)["must_be"] = address
	})
	removeCapability(&f, policybundle.CapabilityLinkedWallets)
	load(t, f)
}

func TestRawFileIdentityDiffersFromCanonicalABIAndPolicyIdentity(t *testing.T) {
	f := baseFixture(t)
	first := load(t, f)
	var pretty any
	if err := json.Unmarshal(f.docs["registry.json"], &pretty); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	f.docs["registry.json"] = raw
	second := load(t, f)
	if first.Metadata().ManifestDigest == second.Metadata().ManifestDigest {
		t.Fatal("raw source identity ignored whitespace")
	}
	firstContract, _ := first.Contract(orgID, common.HexToAddress(address))
	secondContract, _ := second.Contract(orgID, common.HexToAddress(address))
	if string(firstContract.ABI) != string(secondContract.ABI) {
		t.Fatal("ABI whitespace changed canonical identity")
	}
	for _, a := range first.Metadata().Documents {
		for _, b := range second.Metadata().Documents {
			if a.Kind == b.Kind {
				if a.SemanticDigest != b.SemanticDigest || a.PolicyDigest != b.PolicyDigest {
					t.Fatal("normalized identity changed with whitespace")
				}
				if a.Kind == policybundle.ContractRegistry && a.SHA256 == b.SHA256 {
					t.Fatal("file-byte identity reused canonical digest")
				}
			}
		}
	}
	f.edit(t, "registry.json", func(d map[string]any) {
		contract(d)["abi"].([]any)[0].(map[string]any)["x-annotation"] = json.Number("9007199254740993")
	})
	reject(t, f.write(t), f.options, t.Context()) // metadata participates in ABI pin.
	var doc map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(f.docs["registry.json"])))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	rawABI := encode(t, contract(doc)["abi"])
	f.edit(t, "execution.json", func(d map[string]any) {
		rule(d)["abiDigest"] = strings.TrimPrefix(string(policybundle.RawDigest(rawABI)), "sha256:")
	})
	third := load(t, f)
	c, _ := third.Contract(orgID, common.HexToAddress(address))
	if !strings.Contains(string(c.ABI), "9007199254740993") {
		t.Fatal("ABI metadata number rounded or silently dropped")
	}
	if slices.Equal(first.Requirements().Capabilities, nil) {
		t.Fatal("requirements unexpectedly empty")
	}
}
