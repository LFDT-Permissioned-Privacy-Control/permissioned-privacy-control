package rpcexecution

import (
	"bytes"
	"context"
	"math"
	"math/bits"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policycore"
)

type CreationKind string

const (
	UnresolvedAttempt CreationKind = "unresolved-attempt"
	KnownAttempt      CreationKind = "known-attempt"
	FreshConstructor  CreationKind = "fresh-constructor"
)

type CreationContext struct {
	Address executionfacts.Address
	Creator common.Address
	Kind    CreationKind
}

type accountState struct {
	code      CodeInfo
	destroyed bool // Finalization marker, never an intra-tx code/nonce clear.
}
type codeTransition struct {
	ordinal uint32
	state   accountState
}
type codeTimeline struct {
	entry      []uint32
	frames     []CodeInfo
	frameKnown []bool
	creations  []CreationContext
	changes    map[common.Address][]codeTransition
	survivors  map[int]bool // Immutable final annotation, never owner authority.
	work       uint64
}

func (e *CallExecution) FrameCode(index int) (CodeInfo, bool) {
	if e == nil || e.timeline == nil || index < 0 || index >= len(e.timeline.frames) {
		return CodeInfo{}, false
	}
	return e.timeline.frames[index], e.timeline.frameKnown[index]
}
func (e *CallExecution) RuntimeCodeAt(index int, address common.Address) (CodeInfo, bool) {
	if e == nil || e.timeline == nil || index < 0 || index >= len(e.timeline.entry) {
		return CodeInfo{}, false
	}
	changes := e.timeline.changes[address]
	i := sort.Search(len(changes), func(i int) bool { return changes[i].ordinal > e.timeline.entry[index] })
	if i > 0 {
		return changes[i-1].state.code, true
	}
	code, known := e.codes[address]
	return code, known
}
func (e *CallExecution) CreationContext(index int) (CreationContext, bool) {
	if e == nil || e.timeline == nil || index < 0 || index >= len(e.timeline.creations) {
		return CreationContext{}, false
	}
	c := e.timeline.creations[index]
	return c, c.Kind != ""
}
func (e *CallExecution) QualificationWork() uint64 {
	if e == nil || e.timeline == nil {
		return 0
	}
	return e.timeline.work
}

// All native passes together may issue at most16 indexed queries per original
// record, never per rule. Compute the complete bound before publication.
func qualificationWork(records, transitions int) (uint64, bool) {
	if records < 0 || transitions < 0 {
		return 0, false
	}
	n, t := uint64(records), uint64(transitions)
	factor := uint64(16) * uint64(1+bits.Len64(t)) // ceilLog2(1+T) == bitlen(T).
	if n > math.MaxUint64/factor || n > math.MaxUint64-t {
		return 0, false
	}
	base, queries := n+t, n*factor
	if queries > math.MaxUint64-base {
		return 0, false
	}
	return base + queries, true
}

type timelineUndo struct {
	address common.Address
	prior   accountState
}
type timelineScope struct{ index, mark int }

// buildTimeline owns sparse forward/undo transitions. ensure supplies bounded
// same-execution account facts; the shared retained-byte budget includes later
// supplements too. Neither function assigns an organisation or grant.
func buildTimeline(ctx context.Context, records []executionfacts.Record, retainedBytes *int, limits Limits, ensure func(common.Address, bool) (CodeInfo, error)) (*codeTimeline, error) {
	n := len(records)
	if n == 0 || n > limits.Trace.MaxRecords || retainedBytes == nil || *retainedBytes < 0 || *retainedBytes > limits.MaxTotalCodeBytes {
		return nil, failure(InvalidEvidence)
	}
	t := &codeTimeline{entry: make([]uint32, n), frames: make([]CodeInfo, n), frameKnown: make([]bool, n), creations: make([]CreationContext, n), changes: make(map[common.Address][]codeTransition), survivors: make(map[int]bool)}
	current := make(map[common.Address]accountState)
	journal := []timelineUndo{}
	stack := []timelineScope{}
	var ordinal uint32
	transitions, outputBytes := 0, 0
	stateAt := func(a common.Address, needNonce bool) (accountState, error) {
		if state, known := current[a]; known {
			return state, nil
		}
		code, err := ensure(a, needNonce)
		return accountState{code: code}, err
	}
	appendChange := func(a common.Address, state accountState) error {
		if transitions >= 8*n {
			return failure(EvidenceLimit)
		}
		transitions++
		t.changes[a] = append(t.changes[a], codeTransition{ordinal, state})
		current[a] = state
		return nil
	}
	change := func(a common.Address, prior, next accountState) error {
		journal = append(journal, timelineUndo{a, prior})
		return appendChange(a, next)
	}
	exit := func(scope timelineScope) error {
		if ctx.Err() != nil {
			return failure(NodeFailure)
		}
		ordinal++
		r := records[scope.index]
		if r.Failed() {
			for len(journal) > scope.mark {
				last := journal[len(journal)-1]
				journal = journal[:len(journal)-1]
				if err := appendChange(last.address, last.prior); err != nil {
					return err
				}
			}
		} else if c := t.creations[scope.index]; c.Kind == FreshConstructor {
			if len(r.Output) > limits.MaxCodeBytesPerAccount || len(r.Output) > limits.MaxTotalCodeBytes-*retainedBytes {
				return failure(EvidenceLimit)
			}
			code := bytes.Clone(r.Output) // One owned blob per runtime version.
			if delegation(code) {
				return failure(UnsupportedEvidence)
			}
			*retainedBytes += len(code)
			prior := current[c.Address.Value]
			next := prior
			next.code = CodeInfo{code: code, hash: crypto.Keccak256Hash(code), precompile: precompile(c.Address.Value), origin: CreatedRuntime, creation: scope.index, nonce: 1, nonceKnown: true}
			if err := change(c.Address.Value, prior, next); err != nil {
				return err
			}
		}
		return nil
	}
	for i, r := range records {
		if ctx.Err() != nil {
			return nil, failure(NodeFailure)
		}
		for len(stack) > 0 && records[stack[len(stack)-1].index].Depth >= r.Depth {
			scope := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if err := exit(scope); err != nil {
				return nil, err
			}
		}
		ordinal++
		t.entry[i] = ordinal
		stack = append(stack, timelineScope{i, len(journal)})
		switch r.Kind {
		case executionfacts.Create, executionfacts.Create2:
			if _, err := stateAt(r.From, false); err != nil {
				return nil, err
			}
			if len(r.Output) > 8<<20-outputBytes {
				return nil, failure(EvidenceLimit)
			}
			outputBytes += len(r.Output) // Failed output is bounded, never installed.
			c := CreationContext{r.StorageAddress, r.From, KnownAttempt}
			if !c.Address.Known {
				c.Kind = UnresolvedAttempt
			}
			children := i+1 < n && records[i+1].ParentIndex == i
			if !r.Failed() || children {
				if !c.Address.Known {
					return nil, failure(InvalidEvidence)
				}
				prior, err := stateAt(c.Address.Value, true)
				if err != nil {
					return nil, err
				}
				if !prior.code.nonceKnown || prior.code.nonce != 0 || prior.code.HasCode() {
					return nil, failure(InvalidEvidence)
				}
				c.Kind = FreshConstructor
				next := accountState{code: CodeInfo{hash: crypto.Keccak256Hash(nil), precompile: precompile(c.Address.Value), origin: CreatedRuntime, creation: i, nonce: 1, nonceKnown: true}}
				if err := change(c.Address.Value, prior, next); err != nil {
					return nil, err
				}
			}
			t.creations[i] = c
			t.frames[i] = CodeInfo{code: r.Input, hash: crypto.Keccak256Hash(r.Input), origin: ConstructorAttempt, creation: i}
			t.frameKnown[i] = true
		case executionfacts.SelfDestruct:
			state, err := stateAt(r.From, false)
			if err != nil {
				return nil, err
			}
			if !r.To.Known {
				return nil, failure(InvalidEvidence)
			}
			if _, err := stateAt(r.To.Value, false); err != nil {
				return nil, err
			}
			if _, created := state.code.CreationRecordIndex(); created {
				next := state
				next.destroyed = true
				if err := change(r.From, state, next); err != nil {
					return nil, err
				}
			}
		default:
			if !r.NominalCodeAddress.Known || !r.StorageAddress.Known || !r.CallerAddress.Known {
				return nil, failure(InvalidEvidence)
			}
			for _, a := range []common.Address{r.NominalCodeAddress.Value, r.StorageAddress.Value, r.CallerAddress.Value} {
				if _, err := stateAt(a, false); err != nil {
					return nil, err
				}
			}
			state, err := stateAt(r.NominalCodeAddress.Value, false)
			if err != nil {
				return nil, err
			}
			t.frames[i], t.frameKnown[i] = state.code, true
			if state.code.HasCode() && !state.code.Precompile() {
				if target, recognized, err := policycore.InspectUpgradeTarget(r.Input); recognized {
					if err != nil {
						return nil, failure(InvalidEvidence)
					}
					if _, err := stateAt(target, false); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	for len(stack) > 0 {
		scope := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if err := exit(scope); err != nil {
			return nil, err
		}
	}
	if ordinal > uint32(2*n+1) {
		return nil, failure(EvidenceLimit)
	}
	for _, state := range current {
		if index, created := state.code.CreationRecordIndex(); created && !state.destroyed {
			t.survivors[index] = true
		}
	}
	var valid bool
	t.work, valid = qualificationWork(n, transitions)
	if !valid {
		return nil, failure(EvidenceLimit)
	}
	return t, nil
}
