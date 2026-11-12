package admission

import (
	"context"
	"time"
)

// CheckQuoteReadiness observes only feed observations actually required by an
// enabled, enforcing, unknown-price-forbidden policy. It does not authorize a
// transaction or make monitor/unknown-price-allowed policies require a feed.
func (s *Service) CheckQuoteReadiness(ctx context.Context) error {
	if s == nil || ctx == nil || ctx.Err() != nil || s.clock == nil {
		return ErrUnavailable
	}
	var required bool
	for _, org := range s.orgs {
		settings := org.policy.Spec.Settings
		if settings.Enabled && settings.EnforcementMode == "enforce" && settings.UnknownPricePolicy == "forbidden" && len(org.quoteIDs) > 0 {
			required = true
			break
		}
	}
	if !required {
		return nil
	}
	if s.quotes == nil {
		return ErrUnavailable
	}
	quotes, err := s.captureQuotes(ctx)
	if err != nil {
		return ErrUnavailable
	}
	at := s.clock().UTC()
	for _, org := range s.orgs {
		settings := org.policy.Spec.Settings
		if !settings.Enabled || settings.EnforcementMode != "enforce" || settings.UnknownPricePolicy != "forbidden" {
			continue
		}
		for id := range org.quoteIDs {
			quote, ok := quotes.Get(id, settings.Currency)
			if !ok || !quote.Fresh(at, time.Duration(org.policy.PriceMaxAgeSeconds)*time.Second) {
				return ErrUnavailable
			}
		}
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	return nil
}
