package guardbridge

import (
	"context"
	"errors"

	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
)

// WithNetwork is a cold immutable clone. The facade discards its local unbound
// reference before acquisition; both the private service and selected client
// provenance remain owned by the resulting Pair.
func (p *Pair) WithNetwork(expected networkidentity.Binding) (*Pair, error) {
	if p == nil || p.client == nil || p.service == nil {
		return nil, errors.New("invalid Guard network binding")
	}
	client, err := p.client.WithNetwork(expected)
	if err != nil {
		return nil, err
	}
	owned := *p
	owned.client = client
	return &owned, nil
}

// RequireCurrentSource never substitutes a facade client with the same URL.
// The exact zero head denotes an operation with no original A3 point reads.
func (p *Pair) originalSource(q *QualifiedPrepared, expected networkidentity.Binding) bool {
	if p == nil || p.client == nil || p.service == nil || q == nil || q.origin != p || q.source != p.client || q.prepared == nil || q.execution == nil || q.binding != p.client.Metadata() {
		return false
	}
	if _, ok := p.service.EvidenceFor(q.prepared); !ok {
		return false
	}
	actual, bound := p.client.BoundNetwork()
	return bound && actual == expected
}

func (p *Pair) RequireCanonicalExecution(ctx context.Context, q *QualifiedPrepared, expected networkidentity.Binding, head creationfacts.Header) error {
	if !p.originalSource(q, expected) {
		return errors.New("invalid original Guard source")
	}
	return p.client.RequireCanonicalAncestor(ctx, head)
}

func (p *Pair) RequireCurrentSource(ctx context.Context, q *QualifiedPrepared, expected networkidentity.Binding, head creationfacts.Header, execution ...creationfacts.Header) error {
	if len(execution) > 1 || !p.originalSource(q, expected) {
		return errors.New("invalid Guard network binding")
	}
	if err := p.client.RequireBoundNetwork(ctx); err != nil {
		return err
	}
	if head != (creationfacts.Header{}) {
		if err := p.client.RequireCanonicalAncestor(ctx, head); err != nil {
			return err
		}
	}
	if len(execution) == 1 && execution[0] != (creationfacts.Header{}) && execution[0] != head {
		return p.client.RequireCanonicalAncestor(ctx, execution[0])
	}
	return nil
}
