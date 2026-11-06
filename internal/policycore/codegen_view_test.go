package policycore

import (
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

const viewRecordGroup = "record-readers"

func codegenFixture(t *testing.T) (*Validated, Context, []Frame) {
	t.Helper()
	text := strings.TrimSuffix(vaultABI, "]") + `,
 {"type":"function","name":"settle","inputs":[{"name":"id","type":"uint256"}],"outputs":[]},
 {"type":"function","name":"parties","stateMutability":"view","inputs":[{"name":"id","type":"uint256"}],"outputs":[{"type":"address"},{"type":"bool"},{"type":"uint64"}]}]`
	abiSpec, err := abi.JSON(strings.NewReader(text))
	if err != nil {
		t.Fatal(err)
	}
	maximum, amount := "10", "100"
	depth := int64(2)
	policy := &Policy{APIVersion: APIVersion, Kind: Kind, Org: orgID, NestedCalls: NestedCallsRequireOwnRule, Bindings: []Binding{
		{Group: groupID, Allow: []FrameRule{
			{StorageAddress: vaultAddr, Selector: selTransfer, ABIDigest: ABIDigest(text), MaxValue: &maximum, MaxDepth: &depth, CallerAddress: libraryAddr.Hex(), Args: []ArgConstraint{
				{Index: 0, AddressEquals: &AddressMatch{Source: AddressSourceSigner}}, {Index: 1, UintAtMost: &amount},
			}},
			{TargetClass: "deployer", Selector: "*", Except: []DeployerException{{StorageAddress: vaultAddr, Groups: []string{viewRecordGroup}}}},
		}},
		{Group: viewRecordGroup, Allow: []FrameRule{{StorageAddress: vaultAddr, Selector: "0x" + common.Bytes2Hex(abiSpec.Methods["settle"].ID), ABIDigest: ABIDigest(text), Args: []ArgConstraint{{Index: 0, RecordParty: &RecordPartyMatch{Getter: "0x" + common.Bytes2Hex(abiSpec.Methods["parties"].ID), ABIDigest: ABIDigest(text), PartyOutputs: []int{0}}}}}}},
	}}
	catalog := testCatalog(t)
	catalog.Groups[viewRecordGroup] = struct{}{}
	catalog.Contracts[vaultAddr] = ContractInfo{ABI: text}
	v, err := Validate(policy, catalog)
	if err != nil {
		t.Fatal(err)
	}
	ctx := memberCtx()
	ctx.Groups = append(ctx.Groups, viewRecordGroup)
	ctx.ReadRecord = func(common.Address, []byte, uint64) ([]byte, error) {
		result := make([]byte, 96)
		copy(result[12:32], linkedAddr.Bytes())
		result[63], result[95] = 1, 7
		return result, nil
	}
	transfer := vaultCall(transferCalldata(t, signerAddr, big.NewInt(1)))
	transfer.CallerAddress, transfer.Value, transfer.Depth = libraryAddr, big.NewInt(1), 1
	record := vaultCall(packCalldata(t, text, "settle", big.NewInt(7)))
	return v, ctx, []Frame{transfer, record}
}

func TestCodegenViewCannotMutateNativeProgram(t *testing.T) {
	v, ctx, frames := codegenFixture(t)
	want := v.Evaluate(ctx, frames)
	if !want.Allowed {
		t.Fatalf("fixture must permit both rules: %+v", want)
	}
	original, err := v.CodegenView()
	if err != nil {
		t.Fatal(err)
	}
	view, err := v.CodegenView()
	if err != nil {
		t.Fatal(err)
	}
	view.Policy.Org = "altered"
	*view.Policy.Bindings[0].Allow[0].MaxValue = "0"
	for i := range view.Bindings {
		binding := &view.Bindings[i]
		binding.Group = "altered"
		for j := range binding.Rules {
			rule := &binding.Rules[j]
			rule.Target.Storage, rule.Target.Code = strangerAddr, strangerAddr
			rule.Target.Selector[0] ^= 0xff
			rule.Signature, rule.HeadLen = "altered", 0
			if rule.MaxValue != nil {
				rule.MaxValue.SetInt64(0)
			}
			if rule.MaxDepth != nil {
				*rule.MaxDepth = 0
			}
			if rule.Caller != nil {
				*rule.Caller = strangerAddr
			}
			if len(rule.CallTypes) > 0 {
				rule.CallTypes[0] = "unknown"
			}
			for k := range rule.Exceptions {
				rule.Exceptions[k].Groups[0] = "altered"
			}
			for k := range rule.Args {
				arg := &rule.Args[k]
				arg.Index, arg.Offset = 100, 100
				if arg.Max != nil {
					arg.Max.SetInt64(0)
				}
				if arg.Record != nil {
					arg.Record.Selector[0] ^= 0xff
					arg.Record.OutputBits[0] = 1
					arg.Record.PartyOutputs[0] = 2
				}
			}
		}
	}
	if got := v.Evaluate(ctx, frames); got != want {
		t.Fatalf("view changed native decision: %+v", got)
	}
	after, err := v.CodegenView()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, original) {
		t.Fatal("view mutation reached native program or another view")
	}
}

func TestCodegenViewPreservesWholeDocumentAndSelectedGroupFlags(t *testing.T) {
	v, _, _ := codegenFixture(t)
	want, err := CanonicalDigest(v.Policy())
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{groupID, viewRecordGroup} {
		selected := v.ForGroup(group)
		view, err := selected.CodegenView()
		if err != nil {
			t.Fatal(err)
		}
		got, err := CanonicalDigest(view.Policy)
		if err != nil {
			t.Fatal(err)
		}
		if got != want || len(view.Policy.Bindings) != 2 {
			t.Fatal("ForGroup lost complete approved document provenance")
		}
		if !view.PerGroup || len(view.Bindings) != 1 || view.Bindings[0].Group != group {
			t.Fatalf("wrong group view: %+v", view)
		}
		if view.HasRecordReads != (group == viewRecordGroup) {
			t.Fatal("record-read mutability is not selected-rule specific")
		}
	}
	if v.ForGroup("missing") != nil {
		t.Fatal("unknown group invented a program")
	}
}

func TestCodegenViewRejectsUnvalidatedValues(t *testing.T) {
	for _, v := range []*Validated{nil, {}} {
		if _, err := v.CodegenView(); err == nil {
			t.Fatal("unvalidated program produced a codegen view")
		}
	}
}
