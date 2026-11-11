package historynamespace

import (
	"bytes"
	"context"
	"math"
	"math/bits"
	"slices"
	"time"
)

// ReadLimits bound one whole scope, never one independently reusable chunk.
// Callers may lower ceilings; a maximum row count does not promise every shape
// also fits the independent byte, work and deadline ceilings.
type ReadLimits struct {
	Timeout                                                                time.Duration
	MaxRoots, MaxBlocks, MaxCandidates, MaxQueries, MaxWork                int
	MaxInputBytes, MaxCandidateBytes, MaxRequirementsBytes, MaxOutputBytes int
}

func DefaultReadLimits() ReadLimits {
	return ReadLimits{5 * time.Second, 10000, 32768, 32768, 512, 2000000, 4 << 20, 8 << 20, 4 << 20, 2 << 20}
}

func (l ReadLimits) Valid() bool {
	m := DefaultReadLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout &&
		l.MaxRoots > 0 && l.MaxRoots <= m.MaxRoots && l.MaxBlocks > 0 && l.MaxBlocks <= m.MaxBlocks &&
		l.MaxCandidates > 0 && l.MaxCandidates <= m.MaxCandidates && l.MaxQueries > 0 && l.MaxQueries <= m.MaxQueries &&
		l.MaxWork > 0 && l.MaxWork <= m.MaxWork &&
		l.MaxInputBytes > 0 && l.MaxInputBytes <= m.MaxInputBytes &&
		l.MaxCandidateBytes > 0 && l.MaxCandidateBytes <= m.MaxCandidateBytes &&
		l.MaxRequirementsBytes > 0 && l.MaxRequirementsBytes <= m.MaxRequirementsBytes &&
		l.MaxOutputBytes > 0 && l.MaxOutputBytes <= m.MaxOutputBytes
}

// CanonicalBlock is a trusted C-B acquisition DTO, not a canonicality proof.
// TxCount is optional, and must come from an actual qualified hash-list lookup
// where required. A header by itself cannot supply that count.
type CanonicalBlock struct {
	Number           uint64
	Hash, ParentHash Hash
	Timestamp        uint64
	TxCount          *uint32
}

func (b CanonicalBlock) valid() bool { return b.Number <= math.MaxInt64 && b.Hash != (Hash{}) }
func (b CanonicalBlock) detached() CanonicalBlock {
	if b.TxCount != nil {
		n := *b.TxCount
		b.TxCount = &n
	}
	return b
}
func sameHeader(a, b CanonicalBlock) bool {
	return a.Number == b.Number && a.Hash == b.Hash && a.ParentHash == b.ParentHash && a.Timestamp == b.Timestamp
}

// Root is the actual included ROOT request coordinate. To=nil may represent a
// creation, with CreatedAddress only when separately acquired as such. A factory
// CALL must keep its own To and cannot borrow a child creation's namespace.
type Root struct {
	Hash, BlockHash    Hash
	Number             uint64
	Index              uint32
	Timestamp          uint64
	To, CreatedAddress *Address
}

func (r Root) detached() Root {
	if r.To != nil {
		a := *r.To
		r.To = &a
	}
	if r.CreatedAddress != nil {
		a := *r.CreatedAddress
		r.CreatedAddress = &a
	}
	return r
}
func (r Root) address() (Address, bool) {
	if r.To != nil {
		return *r.To, true
	}
	if r.CreatedAddress != nil {
		return *r.CreatedAddress, true
	}
	return Address{}, false
}
func (r Root) cut() Cut { return Cut{r.Number, r.BlockHash, r.Index} }

type TrustedRootScope struct {
	Network         Digest
	Era             ModelEra
	CanonicalViewID Digest
	Head            CanonicalBlock
	Roots           []Root
}

// RootScope owns a bounded, validated request description. Its construction
// proves shape and pairing only, never actual ROOT inclusion or authorization.
type RootScope struct {
	data       TrustedRootScope
	digest     Digest
	addresses  []Address
	inputBytes int
	inputWork  int
}

func PrepareRootScope(input TrustedRootScope, limits ReadLimits) (*RootScope, error) {
	if !limits.Valid() || input.Network == (Digest{}) || !input.Era.Valid() || input.CanonicalViewID == (Digest{}) || !input.Head.valid() {
		return nil, ErrInvalid
	}
	if len(input.Roots) > limits.MaxRoots {
		return nil, ErrTooBroad
	}
	// Cheap fixed-field floor rejects obviously over-budget input before
	// copies. Exact canonical JSON bytes are checked below, not called RSS.
	size := 32 + 32 + 64 + 85 + len(input.Roots)*126
	if size > limits.MaxInputBytes {
		return nil, ErrTooBroad
	}
	data := input
	seen := make(map[Hash]bool, len(input.Roots))
	addresses := make(map[Address]bool, len(input.Roots))
	for i, r := range input.Roots {
		if r.Hash == (Hash{}) || r.BlockHash == (Hash{}) || r.Number > input.Head.Number || r.Timestamp > input.Head.Timestamp ||
			r.To != nil && r.CreatedAddress != nil || seen[r.Hash] ||
			i > 0 && (input.Roots[i-1].Number > r.Number || input.Roots[i-1].Number == r.Number && input.Roots[i-1].Index >= r.Index) {
			return nil, ErrInvalid
		}
		seen[r.Hash] = true
		if a, ok := r.address(); ok {
			addresses[a] = true
		}
	}
	work := 4 * len(addresses) * (1 + bits.Len(uint(len(addresses))))
	if work > limits.MaxWork {
		return nil, ErrTooBroad
	}
	digest, encoded, err := boundedReadDigest("ops-history-root-scope/v1", struct {
		Model string
		Scope TrustedRootScope
	}{ModelID, data}, limits.MaxInputBytes, nil)
	if err != nil {
		return nil, err
	}
	work += 1 + (encoded+31)/32
	if work > limits.MaxWork {
		return nil, ErrTooBroad
	}
	data.Head = input.Head.detached()
	data.Roots = make([]Root, len(input.Roots))
	for i, r := range input.Roots {
		data.Roots[i] = r.detached()
	}
	s := &RootScope{data: data, inputBytes: encoded, inputWork: work, addresses: make([]Address, 0, len(addresses))}
	for a := range addresses {
		s.addresses = append(s.addresses, a)
	}
	slices.SortFunc(s.addresses, func(a, b Address) int { return bytes.Compare(a[:], b[:]) })
	s.digest = digest
	s.inputBytes = encoded
	return s, nil
}
func (s *RootScope) Data() TrustedRootScope {
	if s == nil {
		return TrustedRootScope{}
	}
	d := s.data
	d.Head = d.Head.detached()
	d.Roots = make([]Root, len(s.data.Roots))
	for i, r := range s.data.Roots {
		d.Roots[i] = r.detached()
	}
	return d
}
func (s *RootScope) Digest() Digest {
	if s == nil {
		return Digest{}
	}
	return s.digest
}
func (s *RootScope) Network() Digest {
	if s == nil {
		return Digest{}
	}
	return s.data.Network
}
func (s *RootScope) Era() ModelEra {
	if s == nil {
		return ModelEra{}
	}
	return s.data.Era
}
func (s *RootScope) Addresses() []Address {
	if s == nil {
		return nil
	}
	return slices.Clone(s.addresses)
}

type TrustedRootPass struct {
	Scope                                           TrustedRootScope
	CanonicalBlocks                                 []CanonicalBlock
	ExpectedScopeDigest, ExpectedRequirementsDigest Digest
}
type RootPass struct {
	scope      *RootScope
	blocks     map[uint64]CanonicalBlock
	expected   Digest
	inputBytes int
	inputWork  int
}

func PrepareRootPass(input TrustedRootPass, limits ReadLimits) (*RootPass, error) {
	scope, err := PrepareRootScope(input.Scope, limits)
	if err != nil {
		return nil, err
	}
	if len(input.CanonicalBlocks) > limits.MaxBlocks || scope.inputBytes+len(input.CanonicalBlocks)*85 > limits.MaxInputBytes {
		return nil, ErrTooBroad
	}
	if input.ExpectedScopeDigest != scope.digest || input.ExpectedRequirementsDigest == (Digest{}) {
		return nil, ErrUnavailable
	}
	_, encoded, err := boundedReadDigest("ops-history-canonical-input/v1", input, limits.MaxInputBytes, nil)
	if err != nil {
		return nil, err
	}
	work := scope.inputWork + 1 + (encoded+31)/32
	if work > limits.MaxWork {
		return nil, ErrTooBroad
	}
	p := &RootPass{scope: scope, expected: input.ExpectedRequirementsDigest, inputBytes: encoded, inputWork: work, blocks: make(map[uint64]CanonicalBlock, len(input.CanonicalBlocks))}
	for i, b := range input.CanonicalBlocks {
		if !b.valid() || b.Number > input.Scope.Head.Number || i > 0 && input.CanonicalBlocks[i-1].Number >= b.Number {
			return nil, ErrInvalid
		}
		p.blocks[b.Number] = b.detached()
	}
	return p, nil
}
func (p *RootPass) Scope() *RootScope {
	if p == nil {
		return nil
	}
	return p.scope
}

// Stored facts are trusted adapter output, not unforgeable Go capabilities.
// The adapter rechecks typed row digests, original coverage and stored-prefix
// binding inside the SAME RR snapshot. The pure pass rechecks canonical context.
type LifetimeFact struct {
	ID           Digest
	CohortID     string
	CohortDigest Digest
	Revoked      bool
	Lifetime     Lifetime
}
type TransferFact struct {
	ID           Digest
	CohortID     string
	CohortDigest Digest
	Revoked      bool
	Transfer     Transfer
}
type AutomaticFact struct {
	Plan, Manifest, Runtime                     Digest
	Branch                                      uint8
	Address                                     Address
	RuntimeHash                                 Hash
	RuntimeLength                               uint32
	Namespace                                   string
	Birth                                       BirthCoordinate
	Anchor                                      CanonicalBlock
	Seed, Coverage, Qualification               Digest
	Proof                                       Hash
	OriginalProfile                             string
	OriginalGeneration                          string
	OriginalStateCoverage                       Digest
	PlannedEntry                                uint16
	Kind                                        string
	Revoked                                     bool
	StoredAnchorCanonical, StoredBirthCanonical bool
}

func (a AutomaticFact) ID() (Digest, error) {
	return semanticDigest("ops-history-automatic-basis/v1", struct {
		Model string
		Fact  AutomaticFact
	}{ModelID, a})
}

type ObserverTrust struct {
	Epoch                string
	Ready                bool
	Quarantine           string
	Floor, Head          CanonicalBlock
	ReorgEpoch           int64
	SourceSet, Reference Digest
}
type Snapshot struct {
	Network                         Digest
	Era                             ModelEra
	Generation                      string
	NamespaceRevision               int64
	Completeness, AdmissionCoverage Digest
	Ready                           bool
	Observer                        *ObserverTrust
	Lifetimes                       []LifetimeFact
	Transfers                       []TransferFact
	Automatic                       []AutomaticFact
}

type workBudget struct {
	ctx    context.Context
	limits ReadLimits
	work   int
}

func (b *workBudget) use(n int) error {
	if n < 0 || b.work > b.limits.MaxWork-n {
		return ErrTooBroad
	}
	b.work += n
	if b.ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}

type ResolutionKind uint8

const (
	Unknown ResolutionKind = iota
	KnownOrg
	KnownPublic
	Conflict
)

type Resolution struct {
	Root                          Root
	Kind                          ResolutionKind
	OrganizationID                *string
	BasisDigests, TransferDigests []Digest
}

func (r Resolution) detached() Resolution {
	r.Root = r.Root.detached()
	if r.OrganizationID != nil {
		id := *r.OrganizationID
		r.OrganizationID = &id
	}
	r.BasisDigests = slices.Clone(r.BasisDigests)
	r.TransferDigests = slices.Clone(r.TransferDigests)
	return r
}

type NamespacePass struct {
	scope, requirements, authority Digest
	canonical                      Digest
	generation                     string
	results                        []Resolution
}

func (p *NamespacePass) CanonicalContextDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.canonical
}

func (p *NamespacePass) ScopeDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.scope
}
func (p *NamespacePass) RequirementsDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.requirements
}
func (p *NamespacePass) AuthorityDigest() Digest {
	if p == nil {
		return Digest{}
	}
	return p.authority
}
func (p *NamespacePass) Generation() string {
	if p == nil {
		return ""
	}
	return p.generation
}
func (p *NamespacePass) Results() []Resolution {
	if p == nil {
		return nil
	}
	out := make([]Resolution, len(p.results))
	for i, r := range p.results {
		out[i] = r.detached()
	}
	return out
}
