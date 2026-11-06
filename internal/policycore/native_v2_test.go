package policycore

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func nativeV2Policy(rule FrameRule) *Policy {
	return &Policy{APIVersion: NativeV2APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: []FrameRule{rule}}}}
}

func TestNativeV2ParserDoesNotWidenLegacyGrammar(t *testing.T) {
	for _, key := range []string{"minDepth", "MinDepth", "MINDEPTH"} {
		for _, value := range []string{"0", "null", "1"} {
			// The first bindings object is discarded by the legacy JSON decoder;
			// the field must still be rejected before that can happen.
			raw := []byte(`{"apiVersion":"` + APIVersion + `","bindings":[{"group":"g","allow":[{"` + key + `":` + value + `}]}],"bindings":[]}`)
			if _, err := Parse(raw); err == nil {
				t.Fatalf("legacy accepted shadowed %s:%s", key, value)
			}
		}
	}
	// These are existing encoding/json behaviors outside the custom rule
	// decoder. This extension must not turn them into a stricter legacy API.
	for _, raw := range []string{
		`{"apiVersion":"old","apiVersion":"` + APIVersion + `","bindings":[]}`,
		`{"APIVERSION":"` + APIVersion + `"}`,
		`{"apiVersion":"unknown-version"}`,
		`{"org":"minDepth"}`,
		`{}`,
	} {
		if _, err := Parse([]byte(raw)); err != nil {
			t.Fatalf("legacy decode behavior changed for %s: %v", raw, err)
		}
	}
	for _, malformed := range []string{"", strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001)} {
		if _, err := Parse([]byte(malformed)); err == nil || !strings.Contains(err.Error(), "policy: malformed document:") {
			t.Fatalf("original malformed/depth error behavior changed: %v", err)
		}
	}
	p := nativeV2Policy(FrameRule{StorageAddress: vaultAddr, Selector: "*"})
	encoded, _ := json.Marshal(p)
	if _, err := ParseNativeV2(encoded); err != nil {
		t.Fatal(err)
	}
	p.APIVersion = APIVersion
	encoded, _ = json.Marshal(p)
	if _, err := ParseNativeV2(encoded); err == nil {
		t.Fatal("native parser accepted legacy source")
	}
	minimum := 0
	p.Bindings[0].Allow[0].MinDepth = &minimum
	if _, err := Validate(p, testCatalog(t)); err == nil {
		t.Fatal("legacy structured validation accepted native field")
	}
}

func TestNativeV2DepthBoundsAreExactAndPortable(t *testing.T) {
	for _, field := range []string{"minDepth", "maxDepth"} {
		for _, value := range []string{"null", "-1", "2147483648", "1.0", "1e0", `"1"`, "9223372036854775808"} {
			raw := `{"apiVersion":"` + NativeV2APIVersion + `","kind":"` + Kind + `","org":"` + orgID + `","nestedCalls":"requireOwnRule","bindings":[{"group":"` + groupID + `","allow":[{"storageAddress":"` + vaultAddr + `","selector":"*","` + field + `":` + value + `}]}]}`
			p, err := ParseNativeV2([]byte(raw))
			if err == nil {
				_, err = ValidateNativeV2(p, testCatalog(t))
			}
			if err == nil {
				t.Fatalf("accepted %s:%s", field, value)
			}
		}
	}
	minimum, maximum := 2, int64(1)
	p := nativeV2Policy(FrameRule{StorageAddress: vaultAddr, Selector: "*", MinDepth: &minimum, MaxDepth: &maximum})
	if _, err := ValidateNativeV2(p, testCatalog(t)); err == nil {
		t.Fatal("accepted inverted interval")
	}
	minimum, maximum = 2147483647, 2147483647
	if _, err := ValidateNativeV2(p, testCatalog(t)); err != nil {
		t.Fatal(err)
	}
	// Legacy maxDepth deliberately retains its previous wider int64 range.
	p.APIVersion, p.Bindings[0].Allow[0].MinDepth, maximum = APIVersion, nil, 1<<40
	if _, err := Validate(p, testCatalog(t)); err != nil {
		t.Fatalf("legacy maxDepth range changed: %v", err)
	}
}

func TestNativeV2InclusiveDepthAppliesToEveryTargetKind(t *testing.T) {
	for _, class := range []string{"", "org", "shared", "eoa", "precompile", "deployer", "pending", "create"} {
		t.Run(class, func(t *testing.T) {
			minimum, maximum := 1, int64(2)
			rule := FrameRule{TargetClass: class, Selector: "*", MinDepth: &minimum, MaxDepth: &maximum}
			frame := vaultCall([]byte{1, 2, 3, 4})
			frame.CodeKind, frame.CodeShared, frame.StorageShared = CodeContract, true, true
			frame.StorageDeployer, frame.StoragePending = true, true
			frame.CallerOrg = orgID
			frame.GroupClaims = map[string]uint8{groupID: ClaimDeploy}
			switch class {
			case "":
				rule = plainRule(t, selTransfer)
				rule.MinDepth, rule.MaxDepth = &minimum, &maximum
				frame = vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))
			case "eoa":
				rule.Selector, frame.Calldata = "0x", nil
				frame.CodeKind, frame.CodeOrg, frame.StorageOrg = CodeEOA, "", ""
			case "precompile":
				frame.CodeKind = CodePrecompile
			case "create":
				rule.CallTypes, frame.CallType = []CallType{CallTypeCreate}, CallTypeCreate
			}
			v, err := ValidateNativeV2(nativeV2Policy(rule), testCatalog(t))
			if err != nil {
				t.Fatal(err)
			}
			for _, depth := range []uint64{0, 1, 2, 3} {
				frame.Depth = depth
				decision := v.Evaluate(memberCtx(), []Frame{frame})
				want := depth == 1 || depth == 2
				if decision.Allowed != want || (!want && decision.Code != DenialDepth) {
					t.Fatalf("depth %d: %+v", depth, decision)
				}
			}
		})
	}
	zero := 0
	v, err := ValidateNativeV2(nativeV2Policy(FrameRule{StorageAddress: vaultAddr, Selector: "*", MinDepth: &zero}), testCatalog(t))
	if err != nil || !v.Evaluate(memberCtx(), []Frame{vaultCall(nil)}).Allowed {
		t.Fatalf("explicit zero must allow root: %v", err)
	}
}

func TestNativeV2DepthCopiesAndWholeDocumentDigest(t *testing.T) {
	minimum := 1
	p := nativeV2Policy(FrameRule{StorageAddress: vaultAddr, Selector: "*", MinDepth: &minimum})
	p.Bindings = append(p.Bindings, Binding{Group: "deny-all", Allow: []FrameRule{}})
	cat := testCatalog(t)
	cat.Groups["deny-all"] = struct{}{}
	v, err := ValidateNativeV2(p, cat)
	if err != nil {
		t.Fatal(err)
	}
	originalDigest, _ := CanonicalDigest(v.Policy())
	minimum = 0
	*v.Policy().Bindings[0].Allow[0].MinDepth = 0
	selected := v.ForGroup(groupID)
	view, err := selected.CodegenView()
	if err != nil {
		t.Fatal(err)
	}
	if *view.Bindings[0].Rules[0].MinDepth != 1 || view.Policy.APIVersion != NativeV2APIVersion || !view.PerGroup || len(view.Policy.Bindings) != 2 || len(view.Bindings) != 1 {
		t.Fatal("prepared view lost native source/bound")
	}
	*view.Bindings[0].Rules[0].MinDepth = 0
	*view.Policy.Bindings[0].Allow[0].MinDepth = 0
	if selected.Evaluate(memberCtx(), []Frame{vaultCall(nil)}).Allowed || v.Evaluate(memberCtx(), []Frame{vaultCall(nil)}).Allowed {
		t.Fatal("a copied minimum mutated the compiled program")
	}
	if got, _ := CanonicalDigest(selected.Policy()); got != originalDigest {
		t.Fatal("per-group provenance differs from the complete document")
	}
	for _, changed := range []*Policy{p.clone(), v.Policy()} {
		if changed == nil {
			t.Fatal("missing policy")
		}
		changed.APIVersion = APIVersion
		if digest, _ := CanonicalDigest(changed); digest == originalDigest {
			t.Fatal("digest did not include source version")
		}
	}
	if digest, _ := CanonicalDigest(p); digest == originalDigest {
		t.Fatal("digest did not include minimum bound")
	}
}

func TestNativeV2LegacyConverterSeparatesEntryAndNestedAuthority(t *testing.T) {
	cat := testCatalog(t)
	snapshot := LegacySnapshot{Groups: []LegacyGroup{{ID: groupID, Grants: []LegacyGrant{{Address: vaultAddr, Functions: []LegacyFunction{}}}}}}
	if p, _, err := ImportLegacyNativeV2(snapshot, cat, LegacyAdmissionProfile{}); err == nil || p != nil {
		t.Fatal("zero profile selected conversion semantics")
	}
	for _, scoped := range []bool{false, true} {
		p, report, err := ImportLegacyNativeV2(snapshot, cat, NewLegacyAdmissionProfile(scoped))
		if err != nil || len(report.Limitations) == 0 {
			t.Fatalf("conversion/report: %v", err)
		}
		v, err := ValidateNativeV2(p, cat)
		if err != nil {
			t.Fatal(err)
		}
		shared := vaultCall([]byte{1, 2, 3, 4})
		shared.CodeKind, shared.CodeShared, shared.StorageShared = CodeContract, true, true
		shared.CodeOrg, shared.StorageOrg = "foreign", "foreign"
		if v.Evaluate(memberCtx(), []Frame{shared}).Allowed {
			t.Fatal("events-only shared grant widened root entry")
		}
		shared.Depth = 1
		if !v.Evaluate(memberCtx(), []Frame{shared}).Allowed {
			t.Fatal("qualified nested shared default lost")
		}
		for _, kind := range []CallType{CallTypeCall, CallTypeStaticCall, CallTypeDelegateCall, CallTypeCallCode} {
			frame := vaultCall([]byte{1, 2, 3, 4})
			frame.Depth, frame.CallType = 1, kind
			if kind == CallTypeDelegateCall || kind == CallTypeCallCode {
				frame.CodeAddress = libraryAddr
			}
			if got := v.Evaluate(memberCtx(), []Frame{frame}); got.Allowed == scoped {
				t.Fatalf("scoped=%v kind=%s: %+v", scoped, kind, got)
			}
			frame.Depth = 0
			if v.Evaluate(memberCtx(), []Frame{frame}).Allowed {
				t.Fatal("nested org rule widened root")
			}
		}
		for _, owner := range []string{"", "foreign"} {
			f := vaultCall([]byte{1, 2, 3, 4})
			f.Depth, f.CodeOrg, f.StorageOrg, f.CodeKind = 1, owner, owner, CodeContract
			if v.Evaluate(memberCtx(), []Frame{f}).Allowed {
				t.Fatal("unknown/foreign unshared frame allowed")
			}
		}
	}
	noGrant, _, err := ImportLegacyNativeV2(LegacySnapshot{Groups: []LegacyGroup{{ID: groupID}}}, cat, NewLegacyAdmissionProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	noGrantProgram, err := ValidateNativeV2(noGrant, cat)
	if err != nil {
		t.Fatal(err)
	}
	noGrantShared := vaultCall([]byte{1, 2, 3, 4})
	noGrantShared.CodeKind, noGrantShared.CodeShared, noGrantShared.StorageShared = CodeContract, true, true
	if noGrantProgram.Evaluate(memberCtx(), []Frame{noGrantShared}).Allowed {
		t.Fatal("no-grant shared root allowed")
	}
	// Explicit root selector/argument restrictions are still carried, not
	// replaced by the nested default or a read association.
	snapshot.Groups[0].Grants[0].Functions = []LegacyFunction{{Selector: selTransfer, ParamRules: []LegacyParamRule{{Index: 0, MustBe: "self"}}}}
	p, _, err := ImportLegacyNativeV2(snapshot, cat, NewLegacyAdmissionProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	v, _ := ValidateNativeV2(p, cat)
	if !v.Evaluate(memberCtx(), []Frame{vaultCall(transferCalldata(t, linkedAddr, big.NewInt(1)))}).Allowed || v.Evaluate(memberCtx(), []Frame{vaultCall(transferCalldata(t, libraryAddr, big.NewInt(1)))}).Allowed {
		t.Fatal("explicit root argument restrictions changed")
	}
	// Neither a separately claimed group nor the unscoped nested org fallback
	// can lend upgrade authority to an explicit rule in another group.
	cat.Groups["operators"] = struct{}{}
	snapshot.Groups = []LegacyGroup{{ID: groupID, Claims: []string{"upgrade"}, Grants: []LegacyGrant{{Address: vaultAddr}}}, {ID: "operators", Claims: []string{"upgrade"}}}
	p, _, err = ImportLegacyNativeV2(snapshot, cat, NewLegacyAdmissionProfile(false))
	if err != nil {
		t.Fatal(err)
	}
	v, _ = ValidateNativeV2(p, cat)
	upgrade := vaultCall(append(common.FromHex("0x3659cfe6"), common.LeftPadBytes(libraryAddr.Bytes(), 32)...))
	upgrade.Depth, upgrade.UpgradeTargetOrg = 1, orgID
	ctx := memberCtx()
	ctx.Groups = append(ctx.Groups, "operators")
	upgrade.GroupClaims = map[string]uint8{"operators": ClaimUpgrade}
	if v.Evaluate(ctx, []Frame{upgrade}).Allowed {
		t.Fatal("upgrade authority leaked across groups")
	}
	upgrade.GroupClaims[groupID] = ClaimUpgrade
	if !v.Evaluate(ctx, []Frame{upgrade}).Allowed {
		t.Fatal("explicit target rule and its own upgrade claim denied")
	}
	upgrade.StorageAddress, upgrade.CodeAddress = libraryAddr, libraryAddr
	if v.Evaluate(ctx, []Frame{upgrade}).Allowed {
		t.Fatal("generic nested org fallback authorized upgrade")
	}
	snapshot.Groups = []LegacyGroup{{ID: groupID, OrgAdmin: true}}
	p, _, err = ImportLegacyNativeV2(snapshot, cat, NewLegacyAdmissionProfile(true))
	if err != nil {
		t.Fatal(err)
	}
	v, _ = ValidateNativeV2(p, cat)
	if !v.Evaluate(memberCtx(), []Frame{vaultCall([]byte{1, 2, 3, 4})}).Allowed {
		t.Fatal("true org admin lost root authority")
	}
	// Stable source translation; importantly this still uses the old importer.
	old, err := ImportLegacy(snapshot, cat)
	if err != nil || old.APIVersion != APIVersion {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(old)
	if strings.Contains(string(encoded), "minDepth") {
		t.Fatal("legacy importer emitted new source")
	}
}

func TestLegacyImportSourceDigestsRemainExact(t *testing.T) {
	// Captured by running the original importer from the archived a0555d37
	// tree before this native-v2 extension. These pin the complete JSON bytes,
	// including absent optional fields and original generated rule order.
	for name, fixture := range map[string]struct {
		group  LegacyGroup
		digest string
	}{
		"empty":                    {LegacyGroup{ID: groupID}, "85b6555447e34c5706df13239279b69eca8009438cce947c330d76b28af26301"},
		"events-only":              {LegacyGroup{ID: groupID, Grants: []LegacyGrant{{Address: vaultAddr, Functions: []LegacyFunction{}}}}, "5660cb06f1069df5213710b7bcbc7e5847e5a6cc50101d89d6006f3b8572f2bf"},
		"explicit-self-and-deploy": {LegacyGroup{ID: groupID, Claims: []string{"deploy"}, Grants: []LegacyGrant{{Address: vaultAddr, Functions: []LegacyFunction{{Selector: selTransfer, ParamRules: []LegacyParamRule{{Index: 0, MustBe: "self"}}}}}}}, "dd91f0e76032c12768a20c77426c397008300e7c89c1f2cd589d78257e901bae"},
		"true-admin":               {LegacyGroup{ID: groupID, OrgAdmin: true}, "3ed2cbe49ab2b53eb0a62606e5a78fff25f4bc345e104728bd30ba17438ccfff"},
	} {
		p, err := ImportLegacy(LegacySnapshot{Groups: []LegacyGroup{fixture.group}}, testCatalog(t))
		if err != nil {
			t.Fatal(err)
		}
		if digest, err := CanonicalDigest(p); err != nil || digest != fixture.digest {
			t.Errorf("%s: got %s (%v), want %s", name, digest, err, fixture.digest)
		}
	}
}
