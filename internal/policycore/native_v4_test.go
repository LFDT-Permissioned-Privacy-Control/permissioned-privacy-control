package policycore

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func lifecycleProgram(t *testing.T, rule FrameRule, refs CodeReferenceCatalog) *Validated {
	t.Helper()
	p := &Policy{APIVersion: NativeV4APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: []FrameRule{rule}}}}
	v, err := ValidateNativeV4(p, testCatalog(t), refs)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestV4CreateAttemptUsesOnlyItsBindingSourceClaim(t *testing.T) {
	v := lifecycleProgram(t, FrameRule{TargetClass: "create", Selector: "*", CallTypes: []CallType{CallTypeCreate, CallTypeCreate2}}, nil)
	f := Frame{CallType: CallTypeCreate, CreationUnresolved: true, CreationNamespace: orgID, CallerOrg: "another-org", Depth: 2, GroupClaims: map[string]uint8{groupID: ClaimAdmin}}
	ctx := Context{Org: orgID, Groups: []string{groupID}, GroupSourceClaims: map[string]uint8{"other-group": ClaimDeploy}, Claims: ClaimAdmin}
	if v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("union, target or another group's claim authorized creation")
	}
	ctx.GroupSourceClaims[groupID] = ClaimDeploy
	if !v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("explicit empty-initcode unresolved attempt was denied")
	}
	f.CreationNamespace = "another-org"
	if v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("known foreign creation was relabelled")
	}
}

func TestV4DeploymentContextBorrowingIsExplicitAndBound(t *testing.T) {
	storage := common.HexToAddress("0x7777777777777777777777777777777777777777")
	code := common.HexToAddress("0x8888888888888888888888888888888888888888")
	ctx := Context{Org: orgID, Groups: []string{groupID}, GroupSourceClaims: map[string]uint8{groupID: ClaimDeploy}}
	f := Frame{CallType: CallTypeDelegateCall, StorageAddress: storage, CodeAddress: code, CodeKind: CodeContract, StorageDeploymentNamespace: orgID, CodeDeploymentNamespace: orgID}
	omitted := lifecycleProgram(t, FrameRule{TargetClass: "deployment-context", Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}}, nil)
	if omitted.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("omitted codeAddress became a borrowing wildcard")
	}
	exact := lifecycleProgram(t, FrameRule{TargetClass: "deployment-context", CodeAddress: code.Hex(), Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}}, nil)
	if !exact.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("qualified same-namespace exact code denied")
	}
	f.CodeDeploymentNamespace = "foreign"
	if exact.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("foreign created code borrowed without access")
	}
	f.CodeAccessible = true
	if !exact.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("qualified foreign namespace exact code denied")
	}
	f.CodeDeploymentNamespace = ""
	if exact.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("unrelated unregistered runtime gained context authority")
	}
	refs := CodeReferenceCatalog{code.Hex(): {OwnerOrg: "foreign", ABI: "[]"}}
	registered := lifecycleProgram(t, FrameRule{TargetClass: "deployment-context", CodeAddress: code.Hex(), Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}}, refs)
	f.CodeOrg = "foreign"
	if !registered.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("approved registered foreign code access denied")
	}
	f.CodeShared = true
	if registered.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("shared delegation bypassed M6")
	}
}

func TestV4PrecompileDelegationDoesNotInspectBinaryAsUpgrade(t *testing.T) {
	precompile := common.HexToAddress("0x1")
	ctx := Context{Org: orgID, Groups: []string{groupID}}
	f := Frame{CallType: CallTypeDelegateCall, CodeAddress: precompile, StorageAddress: common.HexToAddress(vaultAddr), CodeKind: CodePrecompile, StorageOrg: orgID, Calldata: common.FromHex("0x3659cfe6")}
	v := lifecycleProgram(t, FrameRule{TargetClass: "precompile", Selector: "*", CallTypes: []CallType{CallTypeDelegateCall, CallTypeCallCode}}, nil)
	if !v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("raw precompile bytes were treated as malformed upgrade ABI")
	}
	f.StorageOrg, f.StorageDeploymentNamespace = "", orgID
	if v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("transient storage precompile borrowed a deploy claim")
	}
	ctx.GroupSourceClaims = map[string]uint8{groupID: ClaimDeploy}
	if !v.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("explicit transient precompile with same-group deploy denied")
	}
	for _, rule := range []FrameRule{
		{TargetClass: "precompile", Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}, AllowUpgrade: true},
		{TargetClass: "deployment-context", CodeAddress: precompile.Hex(), Selector: "*", CallTypes: []CallType{CallTypeDelegateCall}, AllowUpgrade: true},
	} {
		p := &Policy{APIVersion: NativeV4APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{{Group: groupID, Allow: []FrameRule{rule}}}}
		if _, err := ValidateNativeV4(p, testCatalog(t), nil); err == nil {
			t.Fatal("meaningless precompile upgrade capability accepted")
		}
	}
}

func TestV4EmptyStorageCannotUseOrdinaryRulesAndOldFactsStayUnchanged(t *testing.T) {
	rule := FrameRule{StorageAddress: vaultAddr, Selector: "*"}
	v4 := lifecycleProgram(t, rule, nil)
	f := Frame{CallType: CallTypeCall, StorageAddress: common.HexToAddress(vaultAddr), CodeAddress: common.HexToAddress(vaultAddr), CodeKind: CodeContract, CodeOrg: orgID, StorageOrg: orgID}
	ctx := Context{Org: orgID, Groups: []string{groupID}}
	if v4.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("registered label replaced positive storage runtime")
	}
	f.StorageRuntimeHasCode = true
	if !v4.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("ordinary positive runtime denied")
	}
	p := v4.Policy()
	p.APIVersion = NativeV3APIVersion
	v3, err := ValidateNativeV3(p, testCatalog(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.CreationUnresolved, f.StorageRuntimeHasCode = true, false
	if !v3.Evaluate(ctx, []Frame{f}).Allowed {
		t.Fatal("v4-only facts changed v3 matcher")
	}
}

func TestPraguePrecompileClassifierIsExact(t *testing.T) {
	for i := 0; i < 256; i++ {
		var a common.Address
		a[19] = byte(i)
		if IsPraguePrecompile(a) != (i >= 1 && i <= 17) {
			t.Fatalf("classification %d", i)
		}
		a[0] = 1
		if IsPraguePrecompile(a) {
			t.Fatal("high prefix ignored")
		}
	}
}
