package admissionsql

import (
	"context"
	h "privacy-proxy/internal/historynamespace"
)

func (r *NamespaceReader) rangeLimits() h.RangeLimits {
	l := h.DefaultRangeLimits()
	l.Read = r.limits
	return l
}

// DiscoverRangeRequirements uses the original restricted metadata pool and one
// known-commit readonly RR. It performs no canonical node acquisition in SQL.
func (r *NamespaceReader) DiscoverRangeRequirements(ctx context.Context, input h.TrustedRangeScope) (*h.Requirements, error) {
	if r == nil || ctx == nil || !r.limits.Valid() {
		return nil, h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	limits := r.rangeLimits()
	scope, err := h.PrepareRangeScope(input, limits)
	if err != nil {
		return nil, err
	}
	var result *h.Requirements
	err = r.namespaceSnapshot(ctx, scope, func(ctx context.Context, facts h.Snapshot) error {
		var err error
		result, err = h.DiscoverRangeRequirements(ctx, scope, facts, limits)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (r *NamespaceReader) ResolveRangePass(ctx context.Context, input h.TrustedRangePass) (*h.NamespaceRangePass, error) {
	if r == nil || ctx == nil || !r.limits.Valid() {
		return nil, h.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, r.limits.Timeout)
	defer cancel()
	limits := r.rangeLimits()
	pass, err := h.PrepareRangePass(input, limits)
	if err != nil {
		return nil, err
	}
	var result *h.NamespaceRangePass
	err = r.namespaceSnapshot(ctx, pass.Scope(), func(ctx context.Context, facts h.Snapshot) error {
		var err error
		result, err = h.ResolveRangePass(ctx, pass, facts, limits)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}
