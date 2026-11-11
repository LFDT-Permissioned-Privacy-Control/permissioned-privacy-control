package historynamespace

import (
	"bytes"
	"context"
	"slices"
)

type qualifiedBasis struct {
	id, segment Digest
	address     Address
	kind        string
	runtime     Hash
	length      uint32
	initial     Label
	physical    *PhysicalStart
	start       Cut
	end         *Cut
	automatic   *AutomaticFact
}
type segmentIndex struct {
	key          Digest
	kind         string
	bases        []qualifiedBasis
	edges        []TransferFact
	inconsistent bool
}
type addressIndex struct {
	segments        map[Digest]*segmentIndex
	pragueConflict  bool
	pragueReference *qualifiedBasis
}
type resolver struct {
	pass          *RootPass
	facts         *preparedFacts
	addresses     map[Address]*addressIndex
	edges         map[Digest]TransferFact
	edgeStatus    map[Digest]error
	edgeBasis     map[Digest]Digest
	creationRoots map[Hash][]qualifiedBasis
	canonical     Digest
}

// ResolvePass independently rediscovers the complete relevant candidate set.
// It consumes trusted canonical-view metadata, not a request's claim to be
// canonical. It performs no I/O, policy replay, wallet lookup or current-owner
// fallback and exposes no complete-history/permission capability.
func ResolvePass(ctx context.Context, pass *RootPass, snapshot Snapshot, limits ReadLimits) (*NamespacePass, error) {
	if pass == nil {
		return nil, ErrInvalid
	}
	if !limits.Valid() || len(pass.blocks) > limits.MaxBlocks || pass.inputBytes > limits.MaxInputBytes {
		return nil, ErrTooBroad
	}
	facts, err := prepareFacts(ctx, pass.scope, snapshot, limits, pass.inputWork-pass.scope.inputWork)
	if err != nil {
		return nil, err
	}
	if pass.expected != facts.requirements.digest {
		return nil, ErrUnavailable
	}
	r := &resolver{pass: pass, facts: facts, addresses: map[Address]*addressIndex{}, edges: map[Digest]TransferFact{}, edgeStatus: map[Digest]error{}, edgeBasis: map[Digest]Digest{}, creationRoots: map[Hash][]qualifiedBasis{}}
	if err := r.validateContext(); err != nil {
		return nil, err
	}
	if err := r.index(); err != nil {
		return nil, err
	}
	out := &NamespacePass{scope: pass.scope.digest, requirements: facts.requirements.digest, canonical: r.canonical, generation: snapshot.Generation, results: make([]Resolution, 0, len(pass.scope.data.Roots))}
	outputBytes := 128
	for _, root := range pass.scope.data.Roots {
		if err := facts.budget.use(1); err != nil {
			return nil, err
		}
		result, err := r.root(root)
		if err != nil {
			return nil, err
		}
		size := 126 + 1 + 37 + 32*(len(result.BasisDigests)+len(result.TransferDigests))
		if size > limits.MaxOutputBytes-outputBytes {
			return nil, ErrTooBroad
		}
		outputBytes += size
		out.results = append(out.results, result)
	}
	if err := facts.budget.use(1 + (outputBytes+15)/16); err != nil {
		return nil, err
	}
	out.authority, _, err = boundedReadDigest("ops-history-namespace-pass/v1", struct {
		Scope, Requirements, Canonical Digest
		Generation                     string
		Results                        []Resolution
	}{out.scope, out.requirements, out.canonical, out.generation, out.results}, limits.MaxOutputBytes, facts.budget)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *resolver) validateContext() error {
	scope := r.pass.scope.data
	canonical := make([]CanonicalBlock, 0, len(r.facts.requirements.blocks))
	for _, needed := range r.facts.requirements.blocks {
		if err := r.facts.budget.use(1); err != nil {
			return err
		}
		b, ok := r.pass.blocks[needed.Number]
		if !ok || needed.NeedTxCount && b.TxCount == nil {
			return ErrUnavailable
		}
		if previous, ok := r.pass.blocks[b.Number-1]; b.Number > 0 && ok && (b.ParentHash != previous.Hash || b.Timestamp <= previous.Timestamp) {
			return ErrUnavailable
		}
		canonical = append(canonical, b)
	}
	head, ok := r.pass.blocks[scope.Head.Number]
	if !ok || !sameHeader(head, scope.Head) {
		return ErrUnavailable
	}
	entry, ok := r.pass.blocks[scope.Era.EntryNumber]
	if !ok || entry.Hash != scope.Era.EntryHash || entry.Timestamp != scope.Era.EntryTimestamp {
		return ErrUnavailable
	}
	for _, root := range scope.Roots {
		if err := r.facts.budget.use(1); err != nil {
			return err
		}
		b, ok := r.pass.blocks[root.Number]
		if !ok || b.Hash != root.BlockHash || b.Timestamp != root.Timestamp || b.TxCount == nil || root.Index >= *b.TxCount {
			return ErrUnavailable
		}
	}
	var err error
	r.canonical, _, err = boundedReadDigest("ops-history-canonical-context/v1", struct {
		View   Digest
		Blocks []CanonicalBlock
	}{scope.CanonicalViewID, canonical}, r.facts.budget.limits.MaxInputBytes, r.facts.budget)
	if err != nil {
		return err
	}
	if len(r.facts.snapshot.Automatic) > 0 {
		o := r.facts.snapshot.Observer
		floor, ok := r.pass.blocks[o.Floor.Number]
		if !ok || !sameHeader(floor, o.Floor) {
			return ErrUnavailable
		}
	}
	return nil
}
func (r *resolver) canonicalCut(c Cut) (bool, error) {
	b, ok := r.pass.blocks[c.Number]
	if !ok || b.TxCount == nil {
		return false, ErrUnavailable
	}
	if b.Hash != c.Hash {
		return false, nil
	}
	if c.Index > *b.TxCount {
		return false, ErrUnavailable
	}
	return true, nil
}
func (r *resolver) inEra(number uint64) bool {
	b, ok := r.pass.blocks[number]
	e := r.pass.scope.data.Era
	return ok && number >= e.EntryNumber && b.Timestamp >= e.EntryTimestamp && b.Timestamp < e.EndTimestampExclusive
}
func (r *resolver) physicalValid(p *PhysicalStart) (bool, error) {
	if p == nil {
		return false, ErrUnavailable
	}
	if p.Kind == "preexisting" {
		return true, nil
	}
	if p.Birth == nil {
		return false, ErrUnavailable
	}
	b, ok := r.pass.blocks[p.Birth.Number]
	if !ok || b.TxCount == nil {
		return false, ErrUnavailable
	}
	if b.Hash != p.Birth.Hash {
		return false, nil
	}
	if p.Birth.Index >= *b.TxCount {
		return false, ErrUnavailable
	}
	return r.inEra(b.Number), nil
}
func physicalEqual(a, b *PhysicalStart) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind {
		return false
	}
	if a.Birth == nil || b.Birth == nil {
		return a.Birth == b.Birth
	}
	return *a.Birth == *b.Birth
}
func (r *resolver) addBasis(b qualifiedBasis) error {
	if err := r.facts.budget.use(1); err != nil {
		return err
	}
	address := r.addresses[b.address]
	if address == nil {
		address = &addressIndex{segments: map[Digest]*segmentIndex{}}
		r.addresses[b.address] = address
	}
	segment := address.segments[b.segment]
	if segment == nil {
		segment = &segmentIndex{key: b.segment, kind: b.kind}
		address.segments[b.segment] = segment
	}
	if b.kind == "prague" {
		previous := address.pragueReference
		if previous == nil {
			copy := b
			address.pragueReference = &copy
		} else if previous.runtime != b.runtime || previous.length != b.length || !previous.initial.Equal(b.initial) || !physicalEqual(previous.physical, b.physical) {
			address.pragueConflict = true
		}
	} else if len(segment.bases) > 0 {
		previous := segment.bases[0]
		segment.inconsistent = segment.inconsistent || previous.runtime != b.runtime || previous.length != b.length || !previous.initial.Equal(b.initial)
	}
	// Equivalent automatic sources share one actual birth/start and physical
	// assertion. Keep the smallest basis ID for that identical support interval;
	// every original candidate/deny remains in the whole requirements digest.
	for i, old := range segment.bases {
		if err := r.facts.budget.use(1); err != nil {
			return err
		}
		if old.start == b.start && (old.end == nil && b.end == nil || old.end != nil && b.end != nil && *old.end == *b.end) {
			if bytes.Compare(b.id[:], old.id[:]) < 0 {
				segment.bases[i] = b
			}
			return nil
		}
	}
	segment.bases = append(segment.bases, b)
	return nil
}
func (r *resolver) index() error {
	legacyPerAddress := map[Address]int{}
	for _, fact := range r.facts.snapshot.Lifetimes {
		l := fact.Lifetime
		legacyPerAddress[l.Address]++
		if legacyPerAddress[l.Address] > 32 {
			return ErrTooBroad
		}
		if fact.Revoked {
			continue
		}
		b := qualifiedBasis{id: fact.ID, segment: l.Segment, address: l.Address, runtime: l.RuntimeHash, length: l.RuntimeLength, initial: l.Initial, physical: l.Physical, kind: "prague"}
		if l.Start != nil {
			ok, err := r.canonicalCut(*l.Start)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			ok, err = r.canonicalCut(*l.End)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			b.start = *l.Start
			b.end = l.End
			if l.Kind == "pre-era-finite" {
				b.kind = "legacy"
			} else {
				ok, err := r.physicalValid(l.Physical)
				if err != nil {
					return err
				}
				if !ok || !r.inEra(l.Start.Number) {
					continue
				}
			}
		} else {
			block, ok := r.pass.blocks[l.Checkpoint.Number]
			if !ok || block.TxCount == nil {
				return ErrUnavailable
			}
			if block.Hash != l.Checkpoint.Hash || !r.inEra(block.Number) {
				continue
			}
			ok, err := r.physicalValid(l.Physical)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			b.start = Cut{block.Number, block.Hash, *block.TxCount}
			if l.Physical.Birth != nil && CompareCuts(Cut{l.Physical.Birth.Number, l.Physical.Birth.Hash, l.Physical.Birth.Index}, b.start) >= 0 {
				continue
			}
		}
		if err := r.addBasis(b); err != nil {
			return err
		}
	}
	for i, fact := range r.facts.snapshot.Automatic {
		o := r.facts.snapshot.Observer
		if fact.Revoked || !fact.StoredAnchorCanonical || !fact.StoredBirthCanonical {
			continue
		}
		a, aok := r.pass.blocks[fact.Anchor.Number]
		birth, bok := r.pass.blocks[fact.Birth.Number]
		if !aok || !bok || birth.TxCount == nil {
			return ErrUnavailable
		}
		if !sameHeader(a, fact.Anchor) || birth.Hash != fact.Birth.Hash || fact.Anchor.Number < o.Floor.Number ||
			fact.Anchor.Number >= fact.Birth.Number || fact.Birth.Number > o.Head.Number || fact.Birth.Number > r.pass.scope.data.Head.Number ||
			!r.inEra(fact.Birth.Number) {
			continue
		}
		if fact.Birth.Index >= *birth.TxCount {
			return ErrUnavailable
		}
		segment, err := PragueSegmentKey(r.facts.snapshot.Network, fact.Address, fact.RuntimeHash, fact.RuntimeLength)
		if err != nil {
			return err
		}
		physical := &PhysicalStart{Kind: "born", Birth: &fact.Birth}
		organization := fact.Namespace
		b := qualifiedBasis{id: r.facts.automaticIDs[i], segment: segment, address: fact.Address, kind: "prague", runtime: fact.RuntimeHash, length: fact.RuntimeLength, initial: Label{Kind: "org", OrganizationID: &organization}, physical: physical, start: Cut{birth.Number, birth.Hash, fact.Birth.Index + 1}, automatic: &fact}
		if fact.Birth.Record == 0 {
			r.creationRoots[fact.Birth.TransactionHash] = append(r.creationRoots[fact.Birth.TransactionHash], b)
		}
		if err := r.addBasis(b); err != nil {
			return err
		}
	}
	for _, edge := range r.facts.snapshot.Transfers {
		if err := r.facts.budget.use(1); err != nil {
			return err
		}
		t := edge.Transfer
		address := r.addresses[t.Address]
		if address == nil {
			address = &addressIndex{segments: map[Digest]*segmentIndex{}}
			r.addresses[t.Address] = address
		}
		segment := address.segments[t.Segment]
		if segment == nil {
			segment = &segmentIndex{key: t.Segment, kind: t.SegmentKind}
			address.segments[t.Segment] = segment
		}
		if segment.kind != t.SegmentKind || len(segment.edges) >= 64 {
			return ErrTooBroad
		}
		segment.edges = append(segment.edges, edge)
		r.edges[edge.ID] = edge
	}
	for _, address := range r.addresses {
		for _, segment := range address.segments {
			slices.SortFunc(segment.edges, func(a, b TransferFact) int {
				if c := CompareCuts(a.Transfer.EffectiveFrom, b.Transfer.EffectiveFrom); c != 0 {
					return c
				}
				return bytes.Compare(a.ID[:], b.ID[:])
			})
		}
	}
	return nil
}

func (r *resolver) support(segment *segmentIndex, cut Cut, initial *Label, exact *Digest) (*qualifiedBasis, error) {
	var chosen *qualifiedBasis
	for i := range segment.bases {
		if err := r.facts.budget.use(1); err != nil {
			return nil, err
		}
		b := &segment.bases[i]
		if CompareCuts(cut, b.start) < 0 || b.end != nil && CompareCuts(cut, *b.end) >= 0 || initial != nil && !b.initial.Equal(*initial) || exact != nil && b.id != *exact {
			continue
		}
		if b.kind == "prague" && !r.inEra(cut.Number) {
			continue
		}
		if chosen == nil || bytes.Compare(b.id[:], chosen.id[:]) < 0 {
			chosen = b
		}
	}
	return chosen, nil
}

// qualifyEdge memoizes the chain once per segment. It never borrows a later
// checkpoint as support at an earlier edge and never erases a retained deny.
func (r *resolver) qualifyEdge(edge TransferFact, depth int) error {
	if known, ok := r.edgeStatus[edge.ID]; ok {
		return known
	}
	if depth >= 64 {
		return ErrTooBroad
	}
	t := edge.Transfer
	segment := r.addresses[t.Address].segments[t.Segment]
	if edge.Revoked {
		r.edgeStatus[edge.ID] = ErrUnavailable
		return ErrUnavailable
	}
	basis, err := r.support(segment, t.EffectiveFrom, &t.Initial, t.LegacyBasis)
	if err != nil {
		return err
	}
	if basis == nil {
		r.edgeStatus[edge.ID] = ErrUnavailable
		return ErrUnavailable
	}
	if t.Parent == nil {
		if !t.Previous.Equal(t.Initial) {
			return ErrUnavailable
		}
	} else {
		parent, ok := r.edges[*t.Parent]
		if !ok || parent.Transfer.Address != t.Address || parent.Transfer.Segment != t.Segment || parent.Transfer.SegmentKind != t.SegmentKind ||
			!parent.Transfer.Initial.Equal(t.Initial) || !parent.Transfer.New.Equal(t.Previous) || CompareCuts(parent.Transfer.EffectiveFrom, t.EffectiveFrom) >= 0 {
			return ErrUnavailable
		}
		canonical, err := r.canonicalCut(parent.Transfer.EffectiveFrom)
		if err != nil {
			return err
		}
		if !canonical {
			return ErrUnavailable
		}
		if err := r.qualifyEdge(parent, depth+1); err != nil {
			return err
		}
	}
	r.edgeBasis[edge.ID] = basis.id
	r.edgeStatus[edge.ID] = nil
	return nil
}

func (r *resolver) root(root Root) (Resolution, error) {
	out := Resolution{Root: root.detached(), Kind: Unknown}
	address, hasAddress := root.address()
	if !hasAddress {
		return out, nil
	}
	index := r.addresses[address]
	if index == nil {
		return out, nil
	}
	inEra := r.inEra(root.Number)
	if inEra && index.pragueConflict {
		out.Kind = Conflict
		return out, nil
	}
	var selected *segmentIndex
	var support *qualifiedBasis
	for _, segment := range index.segments {
		if err := r.facts.budget.use(1); err != nil {
			return out, err
		}
		if inEra != (segment.kind == "prague") {
			continue
		}
		basis, err := r.support(segment, root.cut(), nil, nil)
		if err != nil {
			return out, err
		}
		if root.To == nil && root.CreatedAddress != nil {
			// Creation's ROOT namespace is its exact surviving record0,
			// rather than an ordinary call made strictly after its birth.
			basis = nil
			for i := range r.creationRoots[root.Hash] {
				if err := r.facts.budget.use(1); err != nil {
					return out, err
				}
				b := &r.creationRoots[root.Hash][i]
				if b.address == address && b.segment == segment.key && b.automatic.Birth.Number == root.Number && b.automatic.Birth.Index == root.Index {
					basis = b
					break
				}
			}
		}
		if basis == nil {
			continue
		}
		if segment.inconsistent || selected != nil {
			out.Kind = Conflict
			return out, nil
		}
		selected, support = segment, basis
	}
	// Prague barriers are address/model-first, even when their now-revoked
	// original basis used a different normalized code key from the selected
	// positive. Pre-era physical lifetimes remain explicitly separate.
	if inEra {
		for _, segment := range index.segments {
			if err := r.facts.budget.use(1); err != nil {
				return out, err
			}
			if segment.kind != "prague" {
				continue
			}
			for _, edge := range segment.edges {
				if err := r.facts.budget.use(1); err != nil {
					return out, err
				}
				if CompareCuts(edge.Transfer.EffectiveFrom, root.cut()) > 0 {
					continue
				}
				ok, err := r.canonicalCut(edge.Transfer.EffectiveFrom)
				if err != nil {
					return out, err
				}
				if !ok {
					continue
				}
				if !r.inEra(edge.Transfer.EffectiveFrom.Number) {
					continue
				}
				if err := r.qualifyEdge(edge, 0); err != nil {
					return out, err
				}
				if selected == nil || segment != selected {
					return out, ErrUnavailable
				}
			}
		}
	}
	if selected == nil {
		return out, nil
	}
	label := support.initial
	out.BasisDigests = []Digest{support.id}
	active := map[Digest]TransferFact{}
	parents := map[Digest]bool{}
	for _, edge := range selected.edges {
		if err := r.facts.budget.use(1); err != nil {
			return out, err
		}
		if CompareCuts(edge.Transfer.EffectiveFrom, root.cut()) > 0 {
			continue
		}
		ok, err := r.canonicalCut(edge.Transfer.EffectiveFrom)
		if err != nil {
			return out, err
		}
		if !ok {
			continue
		}
		if selected.kind == "prague" && !r.inEra(edge.Transfer.EffectiveFrom.Number) {
			continue
		}
		if err := r.qualifyEdge(edge, 0); err != nil {
			return out, err
		}
		active[edge.ID] = edge
		if edge.Transfer.Parent != nil {
			parents[*edge.Transfer.Parent] = true
		}
	}
	var leaf *TransferFact
	for id, edge := range active {
		if parents[id] {
			continue
		}
		if leaf != nil {
			out.Kind = Conflict
			out.BasisDigests = nil
			return out, nil
		}
		copy := edge
		leaf = &copy
	}
	if leaf != nil {
		label = leaf.Transfer.New
		for edge := *leaf; ; {
			out.TransferDigests = append(out.TransferDigests, edge.ID)
			out.BasisDigests = append(out.BasisDigests, r.edgeBasis[edge.ID])
			if edge.Transfer.Parent == nil {
				break
			}
			var ok bool
			edge, ok = active[*edge.Transfer.Parent]
			if !ok {
				return out, ErrUnavailable
			}
		}
		slices.Reverse(out.TransferDigests)
	}
	slices.SortFunc(out.BasisDigests, func(a, b Digest) int { return bytes.Compare(a[:], b[:]) })
	out.BasisDigests = slices.Compact(out.BasisDigests)
	if label.Kind == "org" {
		out.Kind = KnownOrg
		organization := *label.OrganizationID
		out.OrganizationID = &organization
	} else {
		out.Kind = KnownPublic
	}
	return out, nil
}
