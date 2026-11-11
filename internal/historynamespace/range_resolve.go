package historynamespace

import (
	"bytes"
	"context"
	"encoding/json"
	"math/bits"
	"slices"
)

func prepareRangeFacts(ctx context.Context, scope *RangeScope, snapshot Snapshot, limits RangeLimits, extraWork int) (*preparedFacts, error) {
	if scope == nil || scope.selection == nil || !limits.Valid() {
		return nil, ErrInvalid
	}
	if len(scope.data.Addresses) > limits.MaxAddresses {
		return nil, ErrTooBroad
	}
	return prepareFactsForPurpose(ctx, scope.selection, snapshot, limits.Read, extraWork,
		[]uint64{scope.data.FromNumber, scope.data.ThroughNumber}, "ops-history-range-requirements/v1")
}

// DiscoverRangeRequirements returns metadata requirements only. Canonical
// numbers must be acquired by the actual source outside any SQL transaction.
func DiscoverRangeRequirements(ctx context.Context, scope *RangeScope, snapshot Snapshot, limits RangeLimits) (*Requirements, error) {
	if ctx == nil || !limits.Valid() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Read.Timeout)
	defer cancel()
	p, err := prepareRangeFacts(ctx, scope, snapshot, limits, 0)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return p.requirements, nil
}

// ResolveRangePass reuses the actual C2 candidate, support, barrier and transfer
// classifier. Its sparse boundary positions are not included transaction ROOTs.
// Any missing retained support fails the whole pass; no partial positives escape.
func ResolveRangePass(ctx context.Context, pass *RangePass, snapshot Snapshot, limits RangeLimits) (*NamespaceRangePass, error) {
	if ctx == nil || pass == nil || pass.scope == nil || pass.pass == nil || !limits.Valid() {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, limits.Read.Timeout)
	defer cancel()
	p := pass.pass
	if len(p.blocks) > limits.Read.MaxBlocks || p.inputBytes > limits.Read.MaxInputBytes {
		return nil, ErrTooBroad
	}
	facts, err := prepareRangeFacts(ctx, pass.scope, snapshot, limits, p.inputWork-p.scope.inputWork)
	if err != nil {
		return nil, err
	}
	if p.expected != facts.requirements.digest {
		return nil, ErrUnavailable
	}
	r := &resolver{pass: p, rangeScope: pass.scope, facts: facts, addresses: map[Address]*addressIndex{},
		edges: map[Digest]TransferFact{}, edgeStatus: map[Digest]error{}, edgeBasis: map[Digest]Digest{}, creationRoots: map[Hash][]qualifiedBasis{}}
	if err := r.validateContext(); err != nil {
		return nil, err
	}
	r.canonical, _, err = boundedReadDigest("ops-history-range-canonical-context/v1", struct{ Scope, Canonical Digest }{
		pass.scope.Digest(), r.canonical}, limits.Read.MaxInputBytes, facts.budget)
	if err != nil {
		return nil, err
	}
	if err := r.index(); err != nil {
		return nil, err
	}
	out := &NamespaceRangePass{scope: pass.scope.Digest(), requirements: facts.requirements.digest,
		canonical: r.canonical, generation: snapshot.Generation}
	// This conservative framing allowance includes whole-result metadata. It is
	// a canonical-payload bound, not heap/RSS. Each bounded item is charged before
	// retaining it, followed by the exact whole-result encoder before hashing.
	outputBytes := 1024
	charge := func(item any) error {
		if len(out.intervals)+len(out.creations) >= limits.MaxIntervals {
			return ErrTooBroad
		}
		raw, err := json.Marshal(item)
		if err != nil {
			return ErrInvalid
		}
		if len(raw)+1 > limits.Read.MaxOutputBytes-outputBytes {
			return ErrTooBroad
		}
		outputBytes += len(raw) + 1
		return facts.budget.use(1 + (len(raw)+15)/16)
	}
	lo := Position{Number: pass.scope.data.FromNumber}
	hi := Position{Number: pass.scope.data.ThroughNumber + 1}
	for _, address := range pass.scope.data.Addresses {
		cuts := []Position{lo, hi}
		add := func(number uint64, index uint32) {
			p := Position{number, index}
			if comparePositions(lo, p) < 0 && comparePositions(p, hi) < 0 {
				cuts = append(cuts, p)
			}
		}
		add(pass.scope.data.Era.EntryNumber, 0)
		if index := r.addresses[address]; index != nil {
			for _, segment := range index.segments {
				for _, basis := range segment.bases {
					if err := facts.budget.use(1); err != nil {
						return nil, err
					}
					add(basis.start.Number, basis.start.Index)
					if basis.end != nil {
						add(basis.end.Number, basis.end.Index)
					}
				}
				for _, edge := range segment.edges {
					if err := facts.budget.use(1); err != nil {
						return nil, err
					}
					add(edge.Transfer.EffectiveFrom.Number, edge.Transfer.EffectiveFrom.Index)
				}
			}
		}
		if err := facts.budget.use(len(cuts) * (1 + bits.Len(uint(len(cuts))))); err != nil {
			return nil, err
		}
		slices.SortFunc(cuts, comparePositions)
		cuts = slices.Compact(cuts)
		for i := 0; i+1 < len(cuts); i++ {
			if err := facts.budget.use(1); err != nil {
				return nil, err
			}
			// Only the private positional classifier sees this ordinal. Its
			// synthetic Root fields are discarded; no point pass or included
			// ROOT metadata is constructed or exposed by the range API.
			classified, err := r.root(Root{Number: cuts[i].Number, Index: cuts[i].Index, To: &address})
			if err != nil {
				return nil, err
			}
			item := IntervalResolution{Address: address, From: cuts[i], Before: cuts[i+1], Kind: classified.Kind,
				OrganizationID: classified.OrganizationID, BasisDigests: classified.BasisDigests, TransferDigests: classified.TransferDigests}
			if err := charge(item); err != nil {
				return nil, err
			}
			out.intervals = append(out.intervals, item.detached())
		}
	}
	// Root creation is an exact coordinate, never the call interval at birth.
	// Multiple equivalent originals collapse only on the full coordinate.
	type creationKey struct {
		Hash, BlockHash Hash
		Number          uint64
		Index           uint32
		Address         Address
	}
	seen := map[creationKey]bool{}
	var roots []Root
	for hash, bases := range r.creationRoots {
		for _, basis := range bases {
			if err := facts.budget.use(1); err != nil {
				return nil, err
			}
			birth := basis.automatic.Birth
			if birth.Number < pass.scope.data.FromNumber || birth.Number > pass.scope.data.ThroughNumber {
				continue
			}
			key := creationKey{hash, birth.Hash, birth.Number, birth.Index, basis.address}
			if seen[key] {
				continue
			}
			seen[key] = true
			a := basis.address
			roots = append(roots, Root{Hash: hash, BlockHash: birth.Hash, Number: birth.Number, Index: birth.Index,
				Timestamp: p.blocks[birth.Number].Timestamp, CreatedAddress: &a})
		}
	}
	if err := facts.budget.use(len(roots) * (1 + bits.Len(uint(len(roots))))); err != nil {
		return nil, err
	}
	slices.SortFunc(roots, func(a, b Root) int {
		if c := comparePositions(Position{a.Number, a.Index}, Position{b.Number, b.Index}); c != 0 {
			return c
		}
		if c := bytes.Compare(a.Hash[:], b.Hash[:]); c != 0 {
			return c
		}
		return bytes.Compare(a.CreatedAddress[:], b.CreatedAddress[:])
	})
	for _, root := range roots {
		if err := facts.budget.use(1); err != nil {
			return nil, err
		}
		item, err := r.root(root)
		if err != nil {
			return nil, err
		}
		if err := charge(item); err != nil {
			return nil, err
		}
		out.creations = append(out.creations, item.detached())
	}
	out.authority, _, err = boundedReadDigest("ops-history-namespace-range-pass/v1", struct {
		Scope, Requirements, Canonical Digest
		Generation                     string
		Intervals                      []IntervalResolution
		Creations                      []Resolution
	}{out.scope, out.requirements, out.canonical, out.generation, out.intervals, out.creations}, limits.Read.MaxOutputBytes, facts.budget)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return out, nil
}
