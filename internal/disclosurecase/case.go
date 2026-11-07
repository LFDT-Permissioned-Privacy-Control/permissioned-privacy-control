// Package disclosurecase implements bounded disclosure case administration.
// Cases are operational records, never independent permission grants.
package disclosurecase

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/disclosurepolicy"
	"privacy-proxy/internal/identity"
)

var (
	ErrInvalid      = errors.New("invalid disclosure request")
	ErrNotFound     = errors.New("disclosure case not found")
	ErrConflict     = errors.New("disclosure context changed")
	ErrUnauthorized = errors.New("invalid or expired access")
	ErrUnavailable  = errors.New("disclosure storage unavailable")
)

const (
	MaxRequestBytes  = 128 << 10
	MaxResponseBytes = 2 << 20
	MaxScopeBytes    = 96 << 10
)

type Case struct {
	ID, Epoch, CreatorActor, RecipientActor, RuleID, DataOrg string
	OriginalRuleDigest, OriginalBundleDigest, RequestDigest  string
	Scope                                                    disclosurepolicy.Scope
	Reference, Purpose, LegalBasis                           string
	CreatedAt, ExpiresAt                                     time.Time
	Status                                                   string
	Version                                                  int64
	IdempotencyKey                                           string
	RevokedAt                                                *time.Time
	RevokedBy, RevokeReason                                  string
}
type CreateRequest struct {
	RuleID           string                 `json:"ruleId"`
	RecipientActorID string                 `json:"recipientActorId"`
	CaseReference    string                 `json:"caseReference"`
	Purpose          string                 `json:"purpose"`
	LegalBasis       string                 `json:"legalBasis"`
	Scope            disclosurepolicy.Scope `json:"scope"`
	ExpiresAt        int64                  `json:"expiresAt"`
	IdempotencyKey   string                 `json:"idempotencyKey"`
}
type CaseResponse struct {
	CaseID               string                 `json:"caseId"`
	RuleID               string                 `json:"ruleId"`
	RecipientActorID     string                 `json:"recipientActorId"`
	CreatorActorID       string                 `json:"creatorActorId"`
	DataOrganizationID   string                 `json:"dataOrganizationId"`
	Scope                disclosurepolicy.Scope `json:"scope"`
	CaseReference        string                 `json:"caseReference"`
	Purpose              string                 `json:"purpose"`
	LegalBasis           string                 `json:"legalBasis"`
	Status               string                 `json:"status"`
	Version              int64                  `json:"version"`
	CreatedAt            int64                  `json:"createdAt"`
	ExpiresAt            int64                  `json:"expiresAt"`
	OriginalRuleDigest   string                 `json:"originalRuleDigest"`
	OriginalBundleDigest string                 `json:"originalBundleDigest"`
}

func (c Case) Response() CaseResponse {
	return CaseResponse{c.ID, c.RuleID, c.RecipientActor, c.CreatorActor, c.DataOrg, c.Scope, c.Reference, c.Purpose, c.LegalBasis, c.Status, c.Version, c.CreatedAt.Unix(), c.ExpiresAt.Unix(), c.OriginalRuleDigest, c.OriginalBundleDigest}
}

type EventSummary struct {
	Count       int    `json:"count"`
	RuleContext string `json:"ruleContext"`
}
type Event struct {
	ID, CaseID, Epoch, Actor, Action, Outcome, RuleID, RuleDigest, BundleDigest, AttemptID string
	CaseVersion                                                                            int64
	PreparedAt                                                                             time.Time
	Summary                                                                                EventSummary
}
type Position struct {
	Time time.Time
	ID   string
}
type CandidateQuery struct {
	Epoch, Recipient, Organization string
	After                          *Position
	Limit                          int
}

// A receipt exists only after Commit succeeds. The store must call authorize
// with its actual locked row, then append the returned event in that transaction.
type CommitReceipt struct{ AttemptID string }
type Store interface {
	Get(context.Context, string, string) (Case, error)
	GetByKey(context.Context, string, string, string) (Case, error)
	CreateOrGet(context.Context, Case, Event, func(Case, bool) error) (Case, CommitReceipt, error)
	WithLockedCase(context.Context, string, string, int64, func(Case) (Event, error)) (CommitReceipt, error)
	Revoke(context.Context, string, string, string, string, func(Case) error, func(Case) (Event, error)) (Case, CommitReceipt, error)
	Candidates(context.Context, CandidateQuery) ([]Case, error)
	Events(context.Context, string, string, *Position, int) ([]Event, error)
}

func ValidUUID(s string) bool {
	v, err := uuid.Parse(s)
	return err == nil && v != uuid.Nil && v.String() == s
}
func ValidDigest(s string) bool { return len(s) == 71 && s[:7] == "sha256:" && allLowerHex(s[7:]) }
func allLowerHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func ValidEpoch(s string) bool { return disclosurepolicy.Text(s, 128) }

// ValidateCase is repeated on SQL reads. A writable DB row is not accepted as
// a loosely decoded policy/grant object. Byte limits precede adapter decoding.
func ValidateCase(c Case) error {
	if !ValidUUID(c.ID) || !ValidEpoch(c.Epoch) || !identity.ValidActorID(c.CreatorActor) || !identity.ValidActorID(c.RecipientActor) || !disclosurepolicy.Text(c.RuleID, 128) || !ValidUUID(c.DataOrg) || !ValidDigest(c.OriginalRuleDigest) || !ValidDigest(c.OriginalBundleDigest) || !ValidDigest(c.RequestDigest) || !ValidUUID(c.IdempotencyKey) || c.Version < 1 || !validMetadata(c.Reference, c.Purpose, c.LegalBasis) || c.CreatedAt.Unix() < 0 || c.ExpiresAt.Unix() > disclosurepolicy.MaxUnixSeconds || !c.ExpiresAt.After(c.CreatedAt) || c.ExpiresAt.Sub(c.CreatedAt) > 30*24*time.Hour {
		return ErrInvalid
	}
	if _, err := disclosurepolicy.NormalizeScope(c.Scope, disclosurepolicy.DefaultLimits()); err != nil {
		return ErrInvalid
	}
	switch c.Status {
	case "open", "closed":
		if c.RevokedAt != nil || c.RevokedBy != "" || c.RevokeReason != "" {
			return ErrInvalid
		}
	case "revoked":
		if c.RevokedAt == nil || !identity.ValidActorID(c.RevokedBy) || !disclosurepolicy.Text(c.RevokeReason, 2048) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
func validMetadata(reference, purpose, basis string) bool {
	return disclosurepolicy.Text(reference, 256) && disclosurepolicy.Text(purpose, 4096) && (basis == "" || disclosurepolicy.Text(basis, 2048))
}
func ValidateEvent(e Event) error {
	if !ValidUUID(e.ID) || !ValidUUID(e.CaseID) || !ValidUUID(e.AttemptID) || !ValidEpoch(e.Epoch) || !identity.ValidActorID(e.Actor) || !disclosurepolicy.Text(e.RuleID, 128) || !ValidDigest(e.RuleDigest) || !ValidDigest(e.BundleDigest) || e.CaseVersion < 1 || e.PreparedAt.Unix() < 0 || e.PreparedAt.Unix() > disclosurepolicy.MaxUnixSeconds || e.Summary.Count < 0 || e.Summary.Count > 500 {
		return ErrInvalid
	}
	switch e.Action {
	case "case_opened", "case_revoked", "metadata_read", "audit_read", "exposure_prepared":
	default:
		return ErrInvalid
	}
	switch e.Outcome {
	case "allowed", "denied", "revoked":
	default:
		return ErrInvalid
	}
	if e.Summary.RuleContext != "current" && e.Summary.RuleContext != "original-history" {
		return ErrInvalid
	}
	return nil
}
