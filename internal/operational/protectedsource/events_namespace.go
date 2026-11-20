package protectedsource

import (
	"bytes"
	"context"
	"slices"

	d "privacy-proxy/internal/disclosuredata"
	h "privacy-proxy/internal/historynamespace"
)

// This plan merges acquisition work only. The point and emitter resolvers each
// receive their original opaque requirements and independently checked scope.
type eventNamespacePlan struct {
	points              h.TrustedRootScope
	pointRequirements   *h.Requirements
	emitters            h.TrustedRangeScope
	emitterRequirements *h.Requirements
}

type eventCell struct {
	from, before h.Cut
	organization string
	known        bool
}

func (n *namespaceRead) planEvents(ctx context.Context, roots []qualifiedRoot, emitters []h.Address) (*eventNamespacePlan, error) {
	if n == nil || n.pointInput != nil || len(roots) == 0 || len(roots) > 100 || len(emitters) > 128 {
		return nil, d.ErrInvalid
	}
	metadata, err := n.reader.Metadata(ctx)
	if err != nil {
		return nil, namespaceError(err)
	}
	if metadata != n.metadata {
		return nil, d.ErrConflict
	}
	points := pointScope(n, roots)
	pointRequirements, err := n.reader.DiscoverRequirements(ctx, points)
	if err != nil {
		return nil, namespaceError(err)
	}
	addresses := slices.Clone(emitters)
	slices.SortFunc(addresses, func(a, b h.Address) int { return bytes.Compare(a[:], b[:]) })
	addresses = slices.Compact(addresses)
	emitterScope := h.TrustedRangeScope{Network: n.rangeInput.Network, Era: n.rangeInput.Era, CanonicalViewID: n.rangeInput.CanonicalViewID, Head: n.rangeInput.Head, FromNumber: points.Roots[0].Number, ThroughNumber: points.Roots[len(points.Roots)-1].Number, Addresses: addresses}
	emitterRequirements, err := n.reader.DiscoverRangeRequirements(ctx, emitterScope)
	if err != nil {
		return nil, namespaceError(err)
	}
	return &eventNamespacePlan{points, pointRequirements, emitterScope, emitterRequirements}, nil
}

func (n *namespaceRead) acceptEvents(ctx context.Context, plan *eventNamespacePlan, organization string) error {
	if plan == nil || n.pointInput != nil || n.eventInput != nil {
		return d.ErrInvalid
	}
	if err := n.node.supportsMany(ctx, plan.pointRequirements, plan.emitterRequirements); err != nil {
		return err
	}
	n.pointInput = &plan.points
	pass, err := n.resolvePointsRequirements(ctx, plan.pointRequirements, false)
	if err != nil {
		return err
	}
	results := pass.Results()
	if len(results) != len(plan.points.Roots) {
		return d.ErrUnavailable
	}
	for i, result := range results {
		if compareRoots(result.Root, plan.points.Roots[i]) != 0 || result.Kind != h.KnownOrg || result.OrganizationID == nil || *result.OrganizationID != organization {
			return d.ErrUnavailable
		}
	}
	n.pointPass = pass
	n.eventInput = &plan.emitters
	n.eventPass, err = n.resolveEvents(ctx, plan.emitterRequirements)
	if err != nil {
		return err
	}
	intervals := n.eventPass.Intervals()
	if len(intervals) > 16384 {
		return d.ErrTooBroad
	}
	if err = n.node.retain(80*len(intervals) + 4096); err != nil {
		return err
	}
	n.eventCells = make(map[h.Address][]eventCell, len(plan.emitters.Addresses))
	for _, cell := range intervals {
		entry := eventCell{from: h.Cut{Number: cell.From.Number, Index: cell.From.Index}, before: h.Cut{Number: cell.Before.Number, Index: cell.Before.Index}}
		if cell.Kind == h.KnownOrg && cell.OrganizationID != nil {
			entry.known = true
			entry.organization = *cell.OrganizationID
		}
		n.eventCells[cell.Address] = append(n.eventCells[cell.Address], entry)
	}
	return nil
}

func (n *namespaceRead) resolveEvents(ctx context.Context, requirements *h.Requirements) (*h.NamespaceRangePass, error) {
	if n.eventInput == nil || requirements == nil {
		return nil, d.ErrUnavailable
	}
	blocks, err := n.node.knownSupport(requirements)
	if err != nil {
		return nil, err
	}
	pass, err := n.reader.ResolveRangePass(ctx, h.TrustedRangePass{Scope: *n.eventInput, CanonicalBlocks: blocks, ExpectedScopeDigest: requirements.ScopeDigest(), ExpectedRequirementsDigest: requirements.Digest()})
	if err != nil {
		return nil, namespaceError(err)
	}
	if pass == nil {
		return nil, d.ErrUnavailable
	}
	return pass, nil
}

func (n *namespaceRead) checkEvents(ctx context.Context) error {
	if n.eventInput == nil && n.eventPass == nil {
		return nil
	}
	if n.eventInput == nil || n.eventPass == nil {
		return d.ErrUnavailable
	}
	requirements, err := n.reader.DiscoverRangeRequirements(ctx, *n.eventInput)
	if err != nil {
		return namespaceError(err)
	}
	if requirements.ScopeDigest() != n.eventPass.ScopeDigest() || requirements.Digest() != n.eventPass.RequirementsDigest() {
		return d.ErrConflict
	}
	pass, err := n.resolveEvents(ctx, requirements)
	if err != nil {
		return err
	}
	if pass.AuthorityDigest() != n.eventPass.AuthorityDigest() || pass.CanonicalContextDigest() != n.eventPass.CanonicalContextDigest() || pass.Generation() != n.eventPass.Generation() {
		return d.ErrConflict
	}
	return nil
}

// An emitter is resolved at the actual parent's coordinate. It is never
// substituted into ROOT.To, and payload bytes never create a namespace claim.
func (n *namespaceRead) eventEmitterAllowed(root qualifiedRoot, emitter h.Address, organization string) bool {
	if n == nil || n.pointPass == nil || n.eventPass == nil {
		return false
	}
	if root.root.To == nil && root.root.CreatedAddress != nil && *root.root.CreatedAddress == emitter {
		return true
	}
	cut := h.Cut{Number: root.root.Number, Index: root.root.Index}
	for _, cell := range n.eventCells[emitter] {
		if cell.known && cell.organization == organization && h.CompareCuts(cut, cell.from) >= 0 && h.CompareCuts(cut, cell.before) < 0 {
			return true
		}
	}
	return false
}
