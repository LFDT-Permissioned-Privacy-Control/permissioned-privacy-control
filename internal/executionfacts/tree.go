package executionfacts

import (
	"math/big"
	"slices"

	"github.com/ethereum/go-ethereum/common"
)

// Address distinguishes an unknown context from a known zero address.
type Address struct {
	Value common.Address
	Known bool
}

// ExpectedRoot comes from the normalized, verified request, independently of
// the trace. Value must be supplied, including for zero. CreatedAddress may be
// set only when the runtime independently derives a creation destination.
type ExpectedRoot struct {
	Kind           Kind
	From           common.Address
	To             Address
	Input          []byte
	Value          *big.Int
	CreatedAddress Address
}

// Record preserves one reported operation, including failed/caught operations.
// ParentIndex is -1 for the root. SELFDESTRUCT is a lifecycle effect, not an
// executed call or a synthetic native policy opcode.
type Record struct {
	Kind                Kind
	ParentIndex         int
	Depth               int
	From                common.Address // Raw tracer From; not delegated msg.sender.
	To                  Address        // Raw reported destination, possibly absent.
	NominalCodeAddress  Address        // Requires trusted executed-code resolution.
	StorageAddress      Address
	CallerAddress       Address  // Effective EVM msg.sender for execution frames.
	Value               *big.Int // SELFDESTRUCT: reported source balance, not msg.value or proof of transfer.
	Input               []byte
	Output              []byte
	Gas                 uint64
	GasUsed             uint64
	Error               string
	RevertReason        string
	Static              bool
	AncestorFailed      bool
	ContextFromExpected bool
	Logs                []Log // Non-native-authority metadata, in source order.
}

type Log struct {
	Address  common.Address
	Topics   []common.Hash
	Data     []byte
	Position uint64
	Index    *uint64 // Older qualified geth output omits this field.
}

func (r Record) Failed() bool { return r.Error != "" }

// EvidenceRequirements names work for the runtime resolver. It is never a
// readiness assertion. Even a fully known storage/caller tree still requires
// code provenance, policy ownership, principal and other trusted facts.
type EvidenceRequirements struct {
	UnresolvedExecutionContext bool
	CodeProvenance             bool
	Creation                   bool
	Lifecycle                  bool
}

type Tree struct {
	profile      string
	records      []Record
	requirements EvidenceRequirements
}

// Outcome is the root execution result from this same checked trace. A runtime
// may disclose it only after every applicable authorization/privacy check.
type Outcome struct {
	Output       []byte
	Error        string
	RevertReason string
}

func (t *Tree) Outcome() (Outcome, bool) {
	if t == nil || t.profile == "" || len(t.records) == 0 {
		return Outcome{}, false
	}
	root := t.records[0]
	return Outcome{Output: slices.Clone(root.Output), Error: root.Error, RevertReason: root.RevertReason}, true
}

func (t *Tree) Profile() string {
	if t == nil {
		return ""
	}
	return t.profile
}

func (t *Tree) Records() []Record {
	if t == nil {
		return nil
	}
	result := slices.Clone(t.records)
	for i := range result {
		result[i].Input = slices.Clone(result[i].Input)
		result[i].Output = slices.Clone(result[i].Output)
		result[i].Value = new(big.Int).Set(result[i].Value)
		result[i].Logs = slices.Clone(result[i].Logs)
		for j := range result[i].Logs {
			log := &result[i].Logs[j]
			log.Topics = slices.Clone(log.Topics)
			log.Data = slices.Clone(log.Data)
			if log.Index != nil {
				index := *log.Index
				log.Index = &index
			}
		}
	}
	return result
}

func (t *Tree) Requirements() EvidenceRequirements {
	if t == nil || t.profile == "" {
		return EvidenceRequirements{UnresolvedExecutionContext: true, CodeProvenance: true}
	}
	return t.requirements
}
