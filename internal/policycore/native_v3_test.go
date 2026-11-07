package policycore

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestNativeV3ForeignCodeAuthorityIsLiteralAndVersioned(t *testing.T) {
	const foreign = "0x7777777777777777777777777777777777777777"
	const foreignABI = `[{"inputs":[{"name":"recipient","type":"address"}],"name":"run","outputs":[],"stateMutability":"nonpayable","type":"function"}]`
	selector := "0x" + hex.EncodeToString(crypto.Keccak256([]byte("run(address)"))[:4])
	for _, selection := range []string{selector, "*", "0x"} {
		for _, kind := range []CallType{CallTypeDelegateCall, CallTypeCallCode} {
			t.Run(selection+"/"+string(kind), func(t *testing.T) {
				rule := FrameRule{StorageAddress: vaultAddr, CodeAddress: foreign, Selector: selection, CallTypes: []CallType{kind}}
				if selection == selector {
					rule.ABIDigest = ABIDigest(foreignABI)
				}
				p := nativeV2Policy(rule)
				p.APIVersion = NativeV3APIVersion
				cat := testCatalog(t)
				refs := CodeReferenceCatalog{foreign: {OwnerOrg: "org-b", ABI: foreignABI}}
				v, err := ValidateNativeV3(p, cat, refs)
				if err != nil {
					t.Fatal(err)
				}
				var input []byte
				if selection == selector {
					input, _ = hex.DecodeString(strings.TrimPrefix(selector, "0x") + strings.Repeat("0", 64))
				}
				f := Frame{CallType: kind, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(foreign), StorageOrg: orgID, CodeOrg: "org-b", CodeKind: CodeContract, CodeAccessible: true, Calldata: input}
				ctx := Context{Org: orgID, Groups: []string{groupID}}
				if d := v.Evaluate(ctx, []Frame{f}); !d.Allowed {
					t.Fatal(d)
				}
				narrowed := v.ForGroup(groupID)
				if narrowed.Policy().APIVersion != NativeV3APIVersion || !narrowed.Evaluate(ctx, []Frame{f}).Allowed {
					t.Fatal("group projection lost native-v3 provenance/foreign authority")
				}
				for name, mutate := range map[string]func(*Frame){
					"missing access":        func(f *Frame) { f.CodeAccessible = false },
					"different code owner":  func(f *Frame) { f.CodeOrg = "org-c" },
					"relabel as own":        func(f *Frame) { f.CodeOrg = orgID },
					"foreign storage":       func(f *Frame) { f.StorageOrg = "org-b" },
					"shared implementation": func(f *Frame) { f.CodeShared = true },
					"missing runtime code":  func(f *Frame) { f.CodeKind = CodeEOA },
					"ordinary call":         func(f *Frame) { f.CallType = CallTypeCall },
				} {
					bad := f
					mutate(&bad)
					if v.Evaluate(ctx, []Frame{bad}).Allowed {
						t.Fatal("allowed", name)
					}
				}
				encoded, _ := json.Marshal(p)
				if _, err := ParseNativeV3(encoded); err != nil {
					t.Fatal(err)
				}
				if _, err := ParseNativeV2(encoded); err == nil {
					t.Fatal("old native parser accepted v3")
				}
				if _, err := ValidateNativeV2(p, cat); err == nil {
					t.Fatal("old native validator accepted v3")
				}
				if _, err := Validate(p, cat); err == nil {
					t.Fatal("legacy validator accepted v3")
				}
				refs[foreign] = CodeReferenceInfo{OwnerOrg: orgID, ABI: "[]"}
				delete(cat.Contracts, vaultAddr)
				p.Bindings = nil
				if !v.Evaluate(ctx, []Frame{f}).Allowed {
					t.Fatal("compiled program retained mutable source/catalog")
				}
			})
		}
	}
}

func TestNativeV3RejectsUnqualifiedOrAmbiguousCodeReferences(t *testing.T) {
	const foreign = "0x7777777777777777777777777777777777777777"
	p := nativeV2Policy(FrameRule{StorageAddress: vaultAddr, CodeAddress: foreign, Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}})
	p.APIVersion = NativeV3APIVersion
	for name, refs := range map[string]CodeReferenceCatalog{
		"missing":                   {},
		"empty owner":               {foreign: {ABI: "[]"}},
		"manufactured ownership":    {foreign: {OwnerOrg: orgID, ABI: "[]"}},
		"malformed ABI":             {foreign: {OwnerOrg: "org-b", ABI: "bad"}},
		"noncanonical ABI":          {foreign: {OwnerOrg: "org-b", ABI: " [] "}},
		"conflicting owned address": {foreign: {OwnerOrg: "org-b", ABI: "[]"}, vaultAddr: {OwnerOrg: "org-b", ABI: "[]"}},
	} {
		if _, err := ValidateNativeV3(p, testCatalog(t), refs); err == nil {
			t.Fatal("accepted", name)
		}
	}
	refs := CodeReferenceCatalog{foreign: {OwnerOrg: "org-b", ABI: "[]"}}
	p.Bindings[0].Allow[0].CallTypes = []CallType{CallTypeCall}
	if _, err := ValidateNativeV3(p, testCatalog(t), refs); err == nil {
		t.Fatal("foreign ordinary CALL literal accepted")
	}
	p.Bindings[0].Allow[0] = FrameRule{TargetClass: "org", Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}}
	v, err := ValidateNativeV3(p, testCatalog(t), refs)
	if err != nil {
		t.Fatal(err)
	}
	if v.Evaluate(Context{Org: orgID, Groups: []string{groupID}}, []Frame{{CallType: CallTypeDelegateCall, CodeAddress: common.HexToAddress(foreign), StorageAddress: common.HexToAddress(vaultAddr), CodeOrg: "org-b", StorageOrg: orgID, CodeKind: CodeContract, CodeAccessible: true}}).Allowed {
		t.Fatal("code access widened generic org wildcard")
	}
}
