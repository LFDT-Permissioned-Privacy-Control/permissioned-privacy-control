package protectedsource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"

	d "privacy-proxy/internal/disclosuredata"
	x "privacy-proxy/internal/explorerquery"
	h "privacy-proxy/internal/historynamespace"
	a "privacy-proxy/internal/operational/admissionsql"
)

type namespaceRead struct {
	reader     *a.NamespaceReader
	metadata   a.NamespaceMetadata
	node       *nodeRead
	rangeInput h.TrustedRangeScope
	rangePass  *h.NamespaceRangePass
	pointInput *h.TrustedRootScope
	pointPass  *h.NamespacePass
}

func namespaceError(err error) error {
	if errors.Is(err, h.ErrTooBroad) {
		return d.ErrTooBroad
	}
	if errors.Is(err, h.ErrConflict) {
		return d.ErrConflict
	}
	return d.ErrUnavailable
}

func viewDigest(n *nodeRead, upper h.CanonicalBlock) h.Digest {
	raw, _ := json.Marshal(struct {
		Source string
		Upper  h.CanonicalBlock
	}{n.config.Source.Digest().String(), upper})
	return h.Digest(sha256.Sum256(append([]byte("ops.disclosure.retained-canonical-selection/v1\x00"), raw...)))
}

func newNamespaceRead(ctx context.Context, reader *a.NamespaceReader, node *nodeRead, upper h.CanonicalBlock, destinations x.ProtectedDestinations) (*namespaceRead, error) {
	if reader == nil || node == nil || len(destinations.Addresses) > 4096 {
		return nil, d.ErrInvalid
	}
	metadata, err := reader.Metadata(ctx)
	if err != nil {
		return nil, namespaceError(err)
	}
	if !metadata.Ready || metadata.Network != h.Digest(node.config.Source.Network.Key) || upper.Number < metadata.Era.EntryNumber || upper.Timestamp < metadata.Era.EntryTimestamp || upper.Timestamp >= metadata.Era.EndTimestampExclusive {
		return nil, d.ErrUnavailable
	}
	addresses := make([]h.Address, len(destinations.Addresses))
	for i, address := range destinations.Addresses {
		addresses[i] = h.Address(address)
	}
	from, through := metadata.Era.EntryNumber, upper.Number
	if destinations.First != nil {
		from, through = *destinations.First, *destinations.Last
	}
	input := h.TrustedRangeScope{Network: metadata.Network, Era: metadata.Era, CanonicalViewID: viewDigest(node, upper), Head: upper, FromNumber: from, ThroughNumber: through, Addresses: addresses}
	read := &namespaceRead{reader: reader, metadata: metadata, node: node, rangeInput: input}
	pass, err := read.resolveRange(ctx)
	if err != nil {
		return nil, err
	}
	read.rangePass = pass
	return read, nil
}

func (n *namespaceRead) resolveRange(ctx context.Context) (*h.NamespaceRangePass, error) {
	requirements, err := n.reader.DiscoverRangeRequirements(ctx, n.rangeInput)
	if err != nil {
		return nil, namespaceError(err)
	}
	blocks, err := n.node.supports(ctx, requirements)
	if err != nil {
		return nil, err
	}
	pass, err := n.reader.ResolveRangePass(ctx, h.TrustedRangePass{Scope: n.rangeInput, CanonicalBlocks: blocks, ExpectedScopeDigest: requirements.ScopeDigest(), ExpectedRequirementsDigest: requirements.Digest()})
	if err != nil {
		return nil, namespaceError(err)
	}
	if pass == nil {
		return nil, d.ErrUnavailable
	}
	return pass, nil
}

func (n *namespaceRead) predicate(organization string) (x.ProtectedPredicate, error) {
	out := x.ProtectedPredicate{Intervals: []x.ProtectedInterval{}, Creations: []x.ProtectedCreation{}}
	if n == nil || n.rangePass == nil {
		return out, d.ErrUnavailable
	}
	intervals, creations := n.rangePass.Intervals(), n.rangePass.CreationCoordinates()
	if len(intervals) > 16384 || len(creations) > 16384-len(intervals) {
		return out, d.ErrTooBroad
	}
	for _, cell := range intervals {
		if cell.Kind == h.KnownOrg && cell.OrganizationID != nil && *cell.OrganizationID == organization {
			out.Intervals = append(out.Intervals, x.ProtectedInterval{Address: [20]byte(cell.Address), FromNumber: cell.From.Number, FromIndex: cell.From.Index, BeforeNumber: cell.Before.Number, BeforeIndex: cell.Before.Index})
		}
	}
	for _, creation := range creations {
		if creation.Kind == h.KnownOrg && creation.OrganizationID != nil && *creation.OrganizationID == organization {
			root := creation.Root
			if root.To != nil || root.CreatedAddress == nil {
				return out, d.ErrUnavailable
			}
			out.Creations = append(out.Creations, x.ProtectedCreation{Address: [20]byte(*root.CreatedAddress), Position: x.ProtectedPosition{Number: root.Number, Index: root.Index, Hash: [32]byte(root.Hash)}})
		}
	}
	return out, nil
}

func compareRoots(a, b h.Root) int {
	if a.Number != b.Number {
		if a.Number < b.Number {
			return -1
		}
		return 1
	}
	if a.Index != b.Index {
		if a.Index < b.Index {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.Hash[:], b.Hash[:])
}

// Included ROOTs come only from actual CB1 acquisitions. A positive range is
// merely an indexed query predicate; this point resolution is still required.
func pointScope(n *namespaceRead, roots []qualifiedRoot) h.TrustedRootScope {
	selected := make([]h.Root, len(roots))
	for i, root := range roots {
		selected[i] = root.root
	}
	slices.SortFunc(selected, compareRoots)
	selected = slices.CompactFunc(selected, func(a, b h.Root) bool { return compareRoots(a, b) == 0 })
	return h.TrustedRootScope{Network: n.rangeInput.Network, Era: n.rangeInput.Era, CanonicalViewID: n.rangeInput.CanonicalViewID, Head: n.rangeInput.Head, Roots: selected}
}

func (n *namespaceRead) qualify(ctx context.Context, roots []qualifiedRoot, organization string) error {
	_, err := n.qualifyPrefix(ctx, roots, 0, organization, false)
	return err
}

// Discover point support without fetching it. At most eight metadata planning
// passes halve an ordered transaction prefix. No monotonicity/maximality claim
// is made; only the chosen fitting prefix acquires its support body/header set.
func (n *namespaceRead) qualifyPrefix(ctx context.Context, roots []qualifiedRoot, witnesses int, organization string, prefix bool) ([]qualifiedRoot, error) {
	if n == nil || n.pointInput != nil || len(roots) > 4096 || witnesses < 0 || witnesses > len(roots) {
		return nil, d.ErrInvalid
	}
	selectedCount, requirements, err := fitPointPrefix(len(roots), witnesses, prefix, func(count int) (*h.Requirements, error) {
		input := pointScope(n, roots[:count])
		requirements, err := n.reader.DiscoverRequirements(ctx, input)
		if err != nil {
			return nil, namespaceError(err)
		}
		return requirements, nil
	}, n.node.canSupport)
	if err != nil {
		return nil, err
	}
	input := pointScope(n, roots[:selectedCount])
	n.pointInput = &input
	pass, err := n.resolvePointsRequirements(ctx, requirements, true)
	if err != nil {
		return nil, err
	}
	results := pass.Results()
	if len(results) != len(input.Roots) {
		return nil, d.ErrUnavailable
	}
	for i, result := range results {
		if compareRoots(result.Root, input.Roots[i]) != 0 || result.Kind != h.KnownOrg || result.OrganizationID == nil || *result.OrganizationID != organization {
			return nil, d.ErrUnavailable
		}
	}
	n.pointPass = pass
	return roots[:selectedCount], nil
}

// This planner grants no namespace authority and performs no node acquisition.
// Its opaque requirement is still checked by the actual ResolvePass afterward.
func fitPointPrefix(total, witnesses int, prefix bool, discover func(int) (*h.Requirements, error), fits func(*h.Requirements) bool) (int, *h.Requirements, error) {
	if total < 0 || witnesses < 0 || witnesses > total || prefix && total-witnesses > 100 {
		return 0, nil, d.ErrInvalid
	}
	count := total
	for attempt := 0; attempt < 8; attempt++ {
		requirements, err := discover(count)
		if err != nil {
			return 0, nil, err
		}
		if requirements == nil {
			return 0, nil, d.ErrUnavailable
		}
		if fits(requirements) {
			return count, requirements, nil
		}
		if !prefix || count-witnesses <= 1 {
			return 0, nil, d.ErrTooBroad
		}
		count = witnesses + (count-witnesses)/2
	}
	return 0, nil, d.ErrTooBroad
}

func (n *namespaceRead) resolvePointsRequirements(ctx context.Context, requirements *h.Requirements, acquire bool) (*h.NamespacePass, error) {
	if n.pointInput == nil {
		return nil, d.ErrInvalid
	}
	var blocks []h.CanonicalBlock
	var err error
	if acquire {
		blocks, err = n.node.supports(ctx, requirements)
	} else {
		blocks, err = n.node.knownSupport(requirements)
	}
	if err != nil {
		return nil, err
	}
	pass, err := n.reader.ResolvePass(ctx, h.TrustedRootPass{Scope: *n.pointInput, CanonicalBlocks: blocks, ExpectedScopeDigest: requirements.ScopeDigest(), ExpectedRequirementsDigest: requirements.Digest()})
	if err != nil {
		return nil, namespaceError(err)
	}
	if pass == nil {
		return nil, d.ErrUnavailable
	}
	return pass, nil
}

func (n *namespaceRead) check(ctx context.Context) error {
	metadata, err := n.reader.Metadata(ctx)
	if err != nil {
		return namespaceError(err)
	}
	if metadata != n.metadata {
		return d.ErrConflict
	}
	rangeRequirements, err := n.reader.DiscoverRangeRequirements(ctx, n.rangeInput)
	if err != nil {
		return namespaceError(err)
	}
	if rangeRequirements.ScopeDigest() != n.rangePass.ScopeDigest() || rangeRequirements.Digest() != n.rangePass.RequirementsDigest() {
		return d.ErrConflict
	}
	blocks, err := n.node.knownSupport(rangeRequirements)
	if err != nil {
		return err
	}
	ranges, err := n.reader.ResolveRangePass(ctx, h.TrustedRangePass{Scope: n.rangeInput, CanonicalBlocks: blocks, ExpectedScopeDigest: rangeRequirements.ScopeDigest(), ExpectedRequirementsDigest: rangeRequirements.Digest()})
	if err != nil {
		return namespaceError(err)
	}
	if ranges == nil {
		return d.ErrUnavailable
	}
	if ranges.ScopeDigest() != n.rangePass.ScopeDigest() || ranges.RequirementsDigest() != n.rangePass.RequirementsDigest() || ranges.AuthorityDigest() != n.rangePass.AuthorityDigest() || ranges.CanonicalContextDigest() != n.rangePass.CanonicalContextDigest() || ranges.Generation() != n.rangePass.Generation() {
		return d.ErrConflict
	}
	if n.pointPass != nil {
		requirements, err := n.reader.DiscoverRequirements(ctx, *n.pointInput)
		if err != nil {
			return namespaceError(err)
		}
		if requirements.ScopeDigest() != n.pointPass.ScopeDigest() || requirements.Digest() != n.pointPass.RequirementsDigest() {
			return d.ErrConflict
		}
		points, err := n.resolvePointsRequirements(ctx, requirements, false)
		if err != nil {
			return err
		}
		if points.ScopeDigest() != n.pointPass.ScopeDigest() || points.RequirementsDigest() != n.pointPass.RequirementsDigest() || points.AuthorityDigest() != n.pointPass.AuthorityDigest() || points.CanonicalContextDigest() != n.pointPass.CanonicalContextDigest() || points.Generation() != n.pointPass.Generation() {
			return d.ErrConflict
		}
	}
	return nil
}
