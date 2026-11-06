package policycore

import (
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// CodegenProgram is a detached view of already validated, prepared rules for
// the optional code generator. It is not a policy input or executable artifact.
// Backend entrypoints must receive a Validated, never accept this view from an
// untrusted caller. Every mutable value below is copied from the live program.
type CodegenProgram struct {
	Policy         *Policy
	PerGroup       bool
	HasRecordReads bool
	Bindings       []CodegenBinding
}

type CodegenBinding struct {
	Group string
	Rules []CodegenRule
}

type CodegenSelectorMode uint8

const (
	CodegenSelectorExact CodegenSelectorMode = iota
	CodegenSelectorAny
	CodegenSelectorEmpty
)

type CodegenTarget struct {
	Class        string
	SelectorMode CodegenSelectorMode
	Storage      common.Address
	Code         common.Address
	Selector     [4]byte
}

type CodegenRule struct {
	Target        CodegenTarget
	AllowUpgrade  bool
	Signature     string
	HeadLen       int
	ExactLen      bool
	CallTypes     []CallType
	Args          []CodegenArgument
	MaxValue      *big.Int
	MaxDepth      *int64
	MinDepth      *int
	Caller        *common.Address
	Exceptions    []DeployerException
	HasRecordRead bool
}

type CodegenArgumentKind uint8

const (
	CodegenArgumentAddress CodegenArgumentKind = iota + 1
	CodegenArgumentUint
	CodegenArgumentRecordParty
)

type CodegenArgument struct {
	Index   int
	Offset  int
	Kind    CodegenArgumentKind
	Bits    int
	Source  AddressSource
	Literal common.Address
	Max     *big.Int
	Record  *CodegenRecord
}

type CodegenRecordInput uint8

const (
	CodegenRecordUint CodegenRecordInput = iota + 1
	CodegenRecordString
	CodegenRecordBytes
	CodegenRecordBytes32
)

// CodegenRecord contains prepared scalar facts, not a mutable ABI type graph.
type CodegenRecord struct {
	Selector     [4]byte
	InputKind    CodegenRecordInput
	InputBits    int
	OutputBits   []int
	PartyOutputs []int
}

// CodegenView copies the prepared program in the evaluator's deterministic
// order. A ForGroup view retains the full document and its digest/provenance,
// while Bindings contains only the selected group's prepared rules.
func (v *Validated) CodegenView() (CodegenProgram, error) {
	if v == nil || v.policy == nil || v.byGroup == nil {
		return CodegenProgram{}, fmt.Errorf("policydsl: no validated policy to generate from")
	}
	view := CodegenProgram{Policy: v.Policy(), PerGroup: v.perGroup, HasRecordReads: v.hasRecordReads()}
	for _, group := range v.Groups() {
		binding := CodegenBinding{Group: group}
		index := v.byGroup[group]
		for _, key := range sortedFrameKeys(index) {
			var selectorMode CodegenSelectorMode
			switch key.selectorMode {
			case selectorExact:
				selectorMode = CodegenSelectorExact
			case selectorAny:
				selectorMode = CodegenSelectorAny
			case selectorEmpty:
				selectorMode = CodegenSelectorEmpty
			default:
				return CodegenProgram{}, fmt.Errorf("policydsl: unsupported prepared selector mode")
			}
			for _, rule := range index[key] {
				item := CodegenRule{
					Target:       CodegenTarget{Class: key.targetClass, SelectorMode: selectorMode, Storage: key.storage, Code: key.code, Selector: key.selector},
					AllowUpgrade: rule.allowUpgrade, Signature: rule.sig, HeadLen: rule.headLen(), ExactLen: rule.exactLen,
					Exceptions: cloneDeployerExceptions(rule.exceptions), HasRecordRead: rule.hasRecordRead(),
				}
				for kind := range rule.callTypes {
					item.CallTypes = append(item.CallTypes, kind)
				}
				sort.Slice(item.CallTypes, func(i, j int) bool { return item.CallTypes[i] < item.CallTypes[j] })
				if rule.maxValue != nil {
					item.MaxValue = new(big.Int).Set(rule.maxValue)
				}
				if rule.maxDepth != nil {
					value := *rule.maxDepth
					item.MaxDepth = &value
				}
				if rule.minDepth != nil {
					value := *rule.minDepth
					item.MinDepth = &value
				}
				if rule.caller != nil {
					value := *rule.caller
					item.Caller = &value
				}
				for _, arg := range rule.args {
					var kind CodegenArgumentKind
					switch arg.kind {
					case argAddress:
						kind = CodegenArgumentAddress
					case argUint:
						kind = CodegenArgumentUint
					case argRecordParty:
						kind = CodegenArgumentRecordParty
					default:
						return CodegenProgram{}, fmt.Errorf("policydsl: unsupported prepared argument kind")
					}
					out := CodegenArgument{Index: arg.index, Offset: arg.offset, Kind: kind, Bits: arg.bits, Source: arg.source, Literal: arg.literal}
					if arg.max != nil {
						out.Max = new(big.Int).Set(arg.max)
					}
					if arg.record != nil {
						getter := arg.record
						record := &CodegenRecord{Selector: getter.selector, InputBits: getter.input.Size, PartyOutputs: append([]int(nil), getter.parties...)}
						switch getter.input.T {
						case abi.UintTy:
							record.InputKind = CodegenRecordUint
						case abi.StringTy:
							record.InputKind = CodegenRecordString
						case abi.BytesTy:
							record.InputKind = CodegenRecordBytes
						case abi.FixedBytesTy:
							record.InputKind = CodegenRecordBytes32
						default:
							return CodegenProgram{}, fmt.Errorf("policydsl: unsupported prepared record input")
						}
						for _, output := range getter.outputs {
							record.OutputBits = append(record.OutputBits, recordOutputBits(output))
						}
						out.Record = record
					}
					item.Args = append(item.Args, out)
				}
				binding.Rules = append(binding.Rules, item)
			}
		}
		view.Bindings = append(view.Bindings, binding)
	}
	return view, nil
}
