package historynamespace

import (
	"bytes"
	"math"
	"math/bits"
	"slices"
)

// RangeLimits bound one namespace-predicate operation, independently of the
// number of transactions a later retained source may contain. They do not
// change the existing point-reader limits or establish source completeness.
type RangeLimits struct {
	Read                       ReadLimits
	MaxAddresses, MaxIntervals int
}

func DefaultRangeLimits() RangeLimits {
	return RangeLimits{Read: DefaultReadLimits(), MaxAddresses: 4096, MaxIntervals: 16384}
}

func (l RangeLimits) Valid() bool {
	m := DefaultRangeLimits()
	return l.Read.Valid() && l.MaxAddresses > 0 && l.MaxAddresses <= m.MaxAddresses &&
		l.MaxIntervals > 0 && l.MaxIntervals <= m.MaxIntervals
}

// Position is an ordinal boundary before Index in Number. An exclusive end may
// name the next block without claiming that block exists or has a known hash.
// Actual birth/checkpoint/transfer cuts still require qualified canonical data.
type Position struct {
	Number uint64
	Index  uint32
}

func comparePositions(a, b Position) int {
	return CompareCuts(Cut{Number: a.Number, Index: a.Index}, Cut{Number: b.Number, Index: b.Index})
}

type TrustedRangeScope struct {
	Network                   Digest
	Era                       ModelEra
	CanonicalViewID           Digest
	Head                      CanonicalBlock
	FromNumber, ThroughNumber uint64
	Addresses                 []Address
}

// RangeScope owns shape/pairing only. It is not an included ROOT, a permission,
// a source cut or a report-clear capability, including for an empty selection.
type RangeScope struct {
	data      TrustedRangeScope
	selection *RootScope // private candidate selection; never exposed as ROOT proof
}

func PrepareRangeScope(input TrustedRangeScope, limits RangeLimits) (*RangeScope, error) {
	if !limits.Valid() || input.Network == (Digest{}) || input.CanonicalViewID == (Digest{}) ||
		!input.Era.Valid() || !input.Head.valid() || input.FromNumber > input.ThroughNumber ||
		input.ThroughNumber > input.Head.Number || input.ThroughNumber >= math.MaxInt64 ||
		input.Head.Number < input.Era.EntryNumber || input.Head.Timestamp < input.Era.EntryTimestamp ||
		input.Head.Timestamp >= input.Era.EndTimestampExclusive {
		return nil, ErrInvalid
	}
	if len(input.Addresses) > limits.MaxAddresses || 256+len(input.Addresses)*20 > limits.Read.MaxInputBytes {
		return nil, ErrTooBroad
	}
	for i, a := range input.Addresses {
		if i > 0 && bytes.Compare(input.Addresses[i-1][:], a[:]) >= 0 {
			return nil, ErrInvalid
		}
	}
	work := 4 * len(input.Addresses) * (1 + bits.Len(uint(len(input.Addresses))))
	if work > limits.Read.MaxWork {
		return nil, ErrTooBroad
	}
	digest, encoded, err := boundedReadDigest("ops-history-range-scope/v1", struct {
		Model string
		Scope TrustedRangeScope
	}{ModelID, input}, limits.Read.MaxInputBytes, nil)
	if err != nil {
		return nil, err
	}
	work += 1 + (encoded+31)/32
	if work > limits.Read.MaxWork {
		return nil, ErrTooBroad
	}
	data := input
	data.Head = input.Head.detached()
	data.Addresses = slices.Clone(input.Addresses)
	selection := &RootScope{
		data:   TrustedRootScope{Network: input.Network, Era: input.Era, CanonicalViewID: input.CanonicalViewID, Head: data.Head},
		digest: digest, addresses: data.Addresses, inputBytes: encoded, inputWork: work,
	}
	return &RangeScope{data: data, selection: selection}, nil
}

func (s *RangeScope) Data() TrustedRangeScope {
	if s == nil {
		return TrustedRangeScope{}
	}
	d := s.data
	d.Head = d.Head.detached()
	d.Addresses = slices.Clone(d.Addresses)
	return d
}
func (s *RangeScope) Digest() Digest {
	if s == nil || s.selection == nil {
		return Digest{}
	}
	return s.selection.digest
}
func (s *RangeScope) Network() Digest {
	if s == nil {
		return Digest{}
	}
	return s.data.Network
}
func (s *RangeScope) Era() ModelEra {
	if s == nil {
		return ModelEra{}
	}
	return s.data.Era
}
func (s *RangeScope) Addresses() []Address {
	if s == nil {
		return nil
	}
	return slices.Clone(s.data.Addresses)
}

type TrustedRangePass struct {
	Scope                                           TrustedRangeScope
	CanonicalBlocks                                 []CanonicalBlock
	ExpectedScopeDigest, ExpectedRequirementsDigest Digest
}

type RangePass struct {
	scope *RangeScope
	pass  *RootPass // private canonical/candidate machinery, not a point pass API
}

func (p *RangePass) Scope() *RangeScope {
	if p == nil {
		return nil
	}
	return p.scope
}

func PrepareRangePass(input TrustedRangePass, limits RangeLimits) (*RangePass, error) {
	scope, err := PrepareRangeScope(input.Scope, limits)
	if err != nil {
		return nil, err
	}
	if len(input.CanonicalBlocks) > limits.Read.MaxBlocks || scope.selection.inputBytes+len(input.CanonicalBlocks)*85 > limits.Read.MaxInputBytes {
		return nil, ErrTooBroad
	}
	if input.ExpectedScopeDigest != scope.Digest() || input.ExpectedRequirementsDigest == (Digest{}) {
		return nil, ErrUnavailable
	}
	_, encoded, err := boundedReadDigest("ops-history-range-canonical-input/v1", input, limits.Read.MaxInputBytes, nil)
	if err != nil {
		return nil, err
	}
	work := scope.selection.inputWork + 1 + (encoded+31)/32
	if work > limits.Read.MaxWork {
		return nil, ErrTooBroad
	}
	p := &RootPass{scope: scope.selection, expected: input.ExpectedRequirementsDigest, inputBytes: encoded, inputWork: work, blocks: make(map[uint64]CanonicalBlock, len(input.CanonicalBlocks))}
	for i, b := range input.CanonicalBlocks {
		if !b.valid() || b.Number > input.Scope.Head.Number || b.Timestamp > input.Scope.Head.Timestamp ||
			i > 0 && (input.CanonicalBlocks[i-1].Number >= b.Number || input.CanonicalBlocks[i-1].Timestamp >= b.Timestamp) ||
			b.Number < input.Scope.Era.EntryNumber && b.Timestamp >= input.Scope.Era.EntryTimestamp ||
			b.Number >= input.Scope.Era.EntryNumber && b.Timestamp < input.Scope.Era.EntryTimestamp {
			return nil, ErrInvalid
		}
		p.blocks[b.Number] = b.detached()
	}
	return &RangePass{scope, p}, nil
}

// IntervalResolution labels an ordinal cell, never an authenticated indexer
// row. Unknown/conflicting/public cells grant no organization-positive access.
type IntervalResolution struct {
	Address                       Address
	From, Before                  Position
	Kind                          ResolutionKind
	OrganizationID                *string
	BasisDigests, TransferDigests []Digest
}

func (r IntervalResolution) detached() IntervalResolution {
	if r.OrganizationID != nil {
		id := *r.OrganizationID
		r.OrganizationID = &id
	}
	r.BasisDigests = slices.Clone(r.BasisDigests)
	r.TransferDigests = slices.Clone(r.TransferDigests)
	return r
}

type NamespaceRangePass struct {
	scope, requirements, authority, canonical Digest
	generation                                string
	intervals                                 []IntervalResolution
	creations                                 []Resolution
}

func (p *NamespaceRangePass) ScopeDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.scope
}
func (p *NamespaceRangePass) RequirementsDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.requirements
}
func (p *NamespaceRangePass) AuthorityDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.authority
}
func (p *NamespaceRangePass) CanonicalContextDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.canonical
}
func (p *NamespaceRangePass) Generation() string {
	if p == nil {
		return ""
	}
	return p.generation
}
func (p *NamespaceRangePass) Intervals() []IntervalResolution {
	if p == nil {
		return nil
	}
	out := make([]IntervalResolution, len(p.intervals))
	for i, r := range p.intervals {
		out[i] = r.detached()
	}
	return out
}

// CreationCoordinates come from qualified original record0 metadata. The real
// source must still match actual included ROOT/hash/index/address before use.
func (p *NamespaceRangePass) CreationCoordinates() []Resolution {
	if p == nil {
		return nil
	}
	out := make([]Resolution, len(p.creations))
	for i, r := range p.creations {
		out[i] = r.detached()
	}
	return out
}
