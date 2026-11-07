package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
)

type SourceCheckOptions struct {
	OrganizationID, ActorID, Currency string
	DecisionAt                        time.Time
	PriceMaxAge                       time.Duration
}

func NewSourceChecker(store CheckStore, options SourceCheckOptions) (*Checker, error) {
	org, e := uuid.Parse(options.OrganizationID)
	if store == nil || e != nil || org == uuid.Nil || org.String() != options.OrganizationID || !identity.ValidActorID(options.ActorID) || !IsValidCurrency(options.Currency) || options.DecisionAt.IsZero() || options.DecisionAt.Location() != time.UTC || options.PriceMaxAge <= 0 || options.PriceMaxAge > 24*time.Hour {
		return nil, errors.New("invalid source compliance scope")
	}
	return &Checker{store: store, source: &options, priceStalenessThreshold: options.PriceMaxAge}, nil
}

func (c *Checker) sourceConfig(ctx context.Context, req *CheckRequest) (*ComplianceConfig, error) {
	if req == nil || req.OrgID != c.source.OrganizationID || req.UserID != c.source.ActorID {
		return nil, errors.New("source compliance scope mismatch")
	}
	v, e := c.store.GetComplianceConfig(ctx, req.OrgID)
	if e != nil {
		return nil, fmt.Errorf("source compliance configuration unavailable: %w", e)
	}
	if v == nil {
		return nil, errors.New("source compliance configuration missing")
	}
	copied := *v
	if copied.OrgID != c.source.OrganizationID || copied.Currency != c.source.Currency {
		return nil, errors.New("source compliance configuration scope mismatch")
	}
	if e := ValidatePolicySettings(copied); e != nil {
		return nil, e
	}
	return &copied, nil
}

var ErrAuditUnavailable = errors.New("compliance audit unavailable")

type AuditUnavailableError struct{ cause error }

func (e *AuditUnavailableError) Error() string        { return ErrAuditUnavailable.Error() }
func (e *AuditUnavailableError) Unwrap() error        { return e.cause }
func (e *AuditUnavailableError) Is(target error) bool { return target == ErrAuditUnavailable }
func (c *Checker) auditError(e error) error {
	if e != nil && c.source != nil {
		return &AuditUnavailableError{cause: e}
	}
	return e
}
func (c *Checker) priceStale(at time.Time) bool {
	if c.source != nil {
		return at.IsZero() || at.After(c.source.DecisionAt) || c.source.DecisionAt.Sub(at) > c.source.PriceMaxAge
	}
	return c.priceStalenessThreshold > 0 && time.Since(at) > c.priceStalenessThreshold
}
func (c *Checker) priceAge(at time.Time) time.Duration {
	if c.source != nil {
		return c.source.DecisionAt.Sub(at)
	}
	return time.Since(at)
}
