package historynamespace

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"math/bits"
	"slices"
)

// BlockRequirement identifies a NUMBER whose actual canonical hash must be
// acquired outside SQL. ClaimedHashes are conflicting/orphan metadata, not a
// direction to fetch or bless those hashes.
type BlockRequirement struct {
	Number        uint64
	NeedTxCount   bool
	ClaimedHashes []Hash
}
type Requirements struct {
	scope, digest Digest
	blocks        []BlockRequirement
}

func (r *Requirements) ScopeDigest() Digest {
	if r == nil {
		return Digest{}
	}
	return r.scope
}
func (r *Requirements) Digest() Digest {
	if r == nil {
		return Digest{}
	}
	return r.digest
}
func (r *Requirements) Blocks() []BlockRequirement {
	if r == nil {
		return nil
	}
	out := make([]BlockRequirement, len(r.blocks))
	for i, b := range r.blocks {
		out[i] = b
		out[i].ClaimedHashes = slices.Clone(b.ClaimedHashes)
	}
	return out
}

type preparedFacts struct {
	snapshot     Snapshot
	requirements *Requirements
	budget       *workBudget
	automaticIDs []Digest
}

// DiscoverRequirements is a bounded metadata pass. It returns no namespace
// labels, permission, Complete flag or persisted query capability.
func DiscoverRequirements(ctx context.Context, scope *RootScope, snapshot Snapshot, limits ReadLimits) (*Requirements, error) {
	p, err := prepareFacts(ctx, scope, snapshot, limits, 0)
	if err != nil {
		return nil, err
	}
	return p.requirements, nil
}

func prepareFacts(ctx context.Context, scope *RootScope, input Snapshot, limits ReadLimits, extraWork int) (*preparedFacts, error) {
	return prepareFactsForPurpose(ctx, scope, input, limits, extraWork, nil, "ops-history-requirements/v1")
}

// extraNumbers are real canonical-number lookup requirements, not claimed
// hashes, included ROOTs or authority. Only the separate range purpose uses
// them; the existing point path retains its exact digest and required set.
func prepareFactsForPurpose(ctx context.Context, scope *RootScope, input Snapshot, limits ReadLimits, extraWork int, extraNumbers []uint64, domain string) (*preparedFacts, error) {
	if ctx == nil || scope == nil || !limits.Valid() || input.Network != scope.data.Network || input.Era != scope.data.Era ||
		!UUID(input.Generation) || input.NamespaceRevision < 1 || input.Completeness == (Digest{}) || input.AdmissionCoverage == (Digest{}) || !input.Ready {
		return nil, ErrUnavailable
	}
	if len(scope.data.Roots) > limits.MaxRoots || scope.inputBytes > limits.MaxInputBytes {
		return nil, ErrTooBroad
	}
	if len(input.Lifetimes) > limits.MaxCandidates || len(input.Transfers) > limits.MaxCandidates-len(input.Lifetimes) ||
		len(input.Automatic) > limits.MaxCandidates-len(input.Lifetimes)-len(input.Transfers) {
		return nil, ErrTooBroad
	}
	p := &preparedFacts{snapshot: input, budget: &workBudget{ctx: ctx, limits: limits}}
	if extraWork < 0 || scope.inputWork > limits.MaxWork-extraWork {
		return nil, ErrTooBroad
	}
	if err := p.budget.use(scope.inputWork + extraWork); err != nil {
		return nil, err
	}
	p.snapshot.Lifetimes = make([]LifetimeFact, 0, len(input.Lifetimes))
	p.snapshot.Transfers = make([]TransferFact, 0, len(input.Transfers))
	p.snapshot.Automatic = make([]AutomaticFact, 0, len(input.Automatic))
	addresses := make(map[Address]bool, len(scope.addresses))
	for _, a := range scope.addresses {
		addresses[a] = true
	}
	required := map[uint64]*BlockRequirement{}
	add := func(number uint64, hash Hash, count bool) error {
		if err := p.budget.use(1); err != nil {
			return err
		}
		if hash == (Hash{}) {
			return ErrUnavailable
		}
		r := required[number]
		if r == nil {
			if len(required) >= limits.MaxBlocks {
				return ErrTooBroad
			}
			r = &BlockRequirement{Number: number}
			required[number] = r
		}
		r.NeedTxCount = r.NeedTxCount || count
		// Append followed by bounded sort/dedup avoids quadratic scans over
		// adversarial same-height alternatives.
		r.ClaimedHashes = append(r.ClaimedHashes, hash)
		return nil
	}
	if err := add(scope.data.Head.Number, scope.data.Head.Hash, false); err != nil {
		return nil, err
	}
	if err := add(scope.data.Era.EntryNumber, scope.data.Era.EntryHash, false); err != nil {
		return nil, err
	}
	for _, number := range extraNumbers {
		if err := p.budget.use(1); err != nil {
			return nil, err
		}
		if number > scope.data.Head.Number {
			return nil, ErrUnavailable
		}
		if required[number] == nil {
			if len(required) >= limits.MaxBlocks {
				return nil, ErrTooBroad
			}
			required[number] = &BlockRequirement{Number: number}
		}
	}
	for _, root := range scope.data.Roots {
		if err := add(root.Number, root.BlockHash, true); err != nil {
			return nil, err
		}
	}
	digest := sha256.New()
	digest.Write([]byte("ops-history-relevant-candidates/v1\x00"))
	encodedBytes := 0
	charge := func(value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return ErrUnavailable
		}
		if len(raw) > limits.MaxCandidateBytes-encodedBytes {
			return ErrTooBroad
		}
		encodedBytes += len(raw)
		if err := p.budget.use(1 + 2*((len(raw)+31)/32)); err != nil {
			return err
		}
		return nil
	}
	feed := func(value any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			return ErrUnavailable
		}
		if err := p.budget.use(1 + (len(raw)+31)/32); err != nil {
			return err
		}
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
		digest.Write(length[:])
		digest.Write(raw)
		return nil
	}
	for _, f := range input.Lifetimes {
		id, err := LifetimeDigest(input.Network, input.Era, f.Lifetime)
		if err != nil || id != f.ID || !UUID(f.CohortID) || f.CohortDigest == (Digest{}) || !addresses[f.Lifetime.Address] {
			return nil, ErrUnavailable
		}
		if err := charge(f); err != nil {
			return nil, err
		}
		f.Lifetime = f.Lifetime.Detached()
		p.snapshot.Lifetimes = append(p.snapshot.Lifetimes, f)
	}
	for _, f := range input.Transfers {
		id, err := TransferDigest(input.Network, input.Era, f.Transfer)
		if err != nil || id != f.ID || !UUID(f.CohortID) || f.CohortDigest == (Digest{}) || !addresses[f.Transfer.Address] {
			return nil, ErrUnavailable
		}
		if err := charge(f); err != nil {
			return nil, err
		}
		f.Transfer = f.Transfer.Detached()
		p.snapshot.Transfers = append(p.snapshot.Transfers, f)
	}
	if len(input.Automatic) > 0 {
		o := input.Observer
		if o == nil || !o.Ready || o.Quarantine != "none" || !UUID(o.Epoch) || !o.Floor.valid() || !o.Head.valid() ||
			o.Head.Number < o.Floor.Number || o.ReorgEpoch < 0 || o.SourceSet == (Digest{}) || o.Reference == (Digest{}) {
			return nil, ErrUnavailable
		}
		copy := *o
		copy.Floor = o.Floor.detached()
		copy.Head = o.Head.detached()
		p.snapshot.Observer = &copy
		if err := add(o.Floor.Number, o.Floor.Hash, false); err != nil {
			return nil, err
		}
	}
	automatic := make(map[Digest]AutomaticFact, len(input.Automatic))
	for _, f := range input.Automatic {
		if !addresses[f.Address] || f.RuntimeHash == (Hash{}) || f.RuntimeLength == 0 || f.RuntimeLength > MaxRuntimeBytes || !UUID(f.Namespace) ||
			!f.Birth.Valid() || !f.Anchor.valid() || f.Seed == (Digest{}) || f.Coverage == (Digest{}) || f.Qualification == (Digest{}) || f.Proof == (Hash{}) ||
			f.Plan == (Digest{}) || f.Manifest == (Digest{}) || f.Runtime == (Digest{}) || f.Branch < 1 || f.Branch > 8 ||
			!UUID(f.OriginalGeneration) || f.OriginalStateCoverage == (Digest{}) || f.PlannedEntry >= 128 ||
			(f.OriginalProfile != "geth-prague-lifecycle-signed/v1" && f.OriginalProfile != "geth-prague-lifecycle-guard/v1") ||
			(f.Kind != "WALLET" && f.Kind != "FACTORY") {
			return nil, ErrUnavailable
		}
		if err := charge(f); err != nil {
			return nil, err
		}
		f.Anchor = f.Anchor.detached()
		id, err := f.ID()
		if err != nil {
			return nil, err
		}
		if _, duplicate := automatic[id]; duplicate {
			return nil, ErrUnavailable
		}
		automatic[id] = f
		p.automaticIDs = append(p.automaticIDs, id)
	}
	sortCharge := func(n int) error {
		// Conservative comparison/work allowance, checked BEFORE sorting.
		// All limits are conjunctive; broad alternatives may be TooBroad.
		return p.budget.use(4 * n * (1 + bits.Len(uint(n))))
	}
	for _, n := range []int{len(p.snapshot.Lifetimes), len(p.snapshot.Transfers), len(p.automaticIDs)} {
		if err := sortCharge(n); err != nil {
			return nil, err
		}
	}
	slices.SortFunc(p.snapshot.Lifetimes, func(a, b LifetimeFact) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	slices.SortFunc(p.snapshot.Transfers, func(a, b TransferFact) int { return bytes.Compare(a.ID[:], b.ID[:]) })
	slices.SortFunc(p.automaticIDs, func(a, b Digest) int { return bytes.Compare(a[:], b[:]) })
	for _, id := range p.automaticIDs {
		p.snapshot.Automatic = append(p.snapshot.Automatic, automatic[id])
	}
	for i, f := range p.snapshot.Lifetimes {
		if i > 0 && p.snapshot.Lifetimes[i-1].ID == f.ID {
			return nil, ErrUnavailable
		}
		if err := feed(struct {
			ID       Digest
			Cohort   string
			Semantic Digest
			Revoked  bool
		}{f.ID, f.CohortID, f.CohortDigest, f.Revoked}); err != nil {
			return nil, err
		}
		l := f.Lifetime
		for _, cut := range []*Cut{l.Start, l.End} {
			if cut != nil {
				if err := add(cut.Number, cut.Hash, true); err != nil {
					return nil, err
				}
			}
		}
		if l.Checkpoint != nil {
			if err := add(l.Checkpoint.Number, l.Checkpoint.Hash, true); err != nil {
				return nil, err
			}
		}
		if l.Physical != nil && l.Physical.Birth != nil {
			b := l.Physical.Birth
			if err := add(b.Number, b.Hash, true); err != nil {
				return nil, err
			}
		}
	}
	for i, f := range p.snapshot.Transfers {
		if i > 0 && p.snapshot.Transfers[i-1].ID == f.ID {
			return nil, ErrUnavailable
		}
		if err := feed(struct {
			ID       Digest
			Cohort   string
			Semantic Digest
			Revoked  bool
		}{f.ID, f.CohortID, f.CohortDigest, f.Revoked}); err != nil {
			return nil, err
		}
		cut := f.Transfer.EffectiveFrom
		if err := add(cut.Number, cut.Hash, true); err != nil {
			return nil, err
		}
	}
	var previous Digest
	for i, f := range p.snapshot.Automatic {
		id := p.automaticIDs[i]
		if i > 0 && id == previous {
			return nil, ErrUnavailable
		}
		previous = id
		if err := feed(id); err != nil {
			return nil, err
		}
		if err := add(f.Anchor.Number, f.Anchor.Hash, false); err != nil {
			return nil, err
		}
		if err := add(f.Birth.Number, f.Birth.Hash, true); err != nil {
			return nil, err
		}
	}
	r := &Requirements{scope: scope.digest, blocks: make([]BlockRequirement, 0, len(required))}
	outputBytes := 64
	for _, b := range required {
		if err := sortCharge(len(b.ClaimedHashes)); err != nil {
			return nil, err
		}
		slices.SortFunc(b.ClaimedHashes, func(a, b Hash) int { return bytes.Compare(a[:], b[:]) })
		b.ClaimedHashes = slices.Compact(b.ClaimedHashes)
		outputBytes += 9 + 32*len(b.ClaimedHashes)
		if outputBytes > limits.MaxRequirementsBytes {
			return nil, ErrTooBroad
		}
		r.blocks = append(r.blocks, *b)
	}
	if err := sortCharge(len(r.blocks)); err != nil {
		return nil, err
	}
	slices.SortFunc(r.blocks, func(a, b BlockRequirement) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	var candidates Digest
	copy(candidates[:], digest.Sum(nil))
	// Moving lease, capture liveness and ordinary prefix-head progress are
	// excluded. Durable trust/source/reorg changes and each relevant original
	// candidate/deny remain bound. The whole pass uses one SQL snapshot.
	type observerIdentity struct {
		Epoch                string
		Floor                CanonicalBlock
		ReorgEpoch           int64
		SourceSet, Reference Digest
	}
	var observer *observerIdentity
	if len(input.Automatic) > 0 {
		o := input.Observer
		observer = &observerIdentity{o.Epoch, o.Floor, o.ReorgEpoch, o.SourceSet, o.Reference}
	}
	var err error
	if err := p.budget.use(1 + (outputBytes+15)/16); err != nil {
		return nil, err
	}
	r.digest, _, err = boundedReadDigest(domain, struct {
		Scope                           Digest
		Generation                      string
		Revision                        int64
		Completeness, State, Candidates Digest
		Observer                        *observerIdentity
		Blocks                          []BlockRequirement
	}{scope.digest, input.Generation, input.NamespaceRevision, input.Completeness, input.AdmissionCoverage, candidates, observer, r.blocks}, limits.MaxRequirementsBytes, p.budget)
	if err != nil {
		return nil, err
	}
	p.requirements = r
	return p, nil
}
