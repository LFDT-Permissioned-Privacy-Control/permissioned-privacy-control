package admission

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/nativeadmission"
	"privacy-proxy/internal/rpcexecution"
	"privacy-proxy/internal/runtimepolicy"
	"privacy-proxy/internal/transactioninput"
)

const (
	MaxRequestBytes  = 256 << 10
	MaxPreviewBytes  = 2 << 20
	MaxResponseBytes = 2 << 20
	MaxPIIBytes      = 64 << 10
	MaxWitnesses     = 1024
	MaxRecipients    = 32
)

var (
	ErrInvalid      = errors.New("invalid admission request")
	ErrUnauthorized = errors.New("invalid or expired access")
	ErrForbidden    = errors.New("compliance administration not authorized")
	ErrNotFound     = errors.New("operational record not found")
	ErrConflict     = errors.New("operational state conflict")
	ErrValuation    = errors.New("qualified valuation unavailable")
	ErrUnavailable  = errors.New("admission storage unavailable")
	ErrCoverage     = errors.New("record coverage unavailable")
)

type Scope struct {
	Network             Digest
	State               ExpectedState
	Organization, Actor string
	Hash                common.Hash
}

func (s Scope) Valid() bool {
	return s.State.Valid() && ValidUUID(s.Organization) && validActor(s.Actor) && s.Hash != (common.Hash{})
}

type CommitKind uint8

const (
	CommitAllow CommitKind = iota + 1
	CommitDeny
)

type CommitReceipt struct {
	Committed bool
	Kind      CommitKind
}

type Record struct {
	ID                              string
	Network                         Digest
	Organization, Actor             string
	OriginatorData, BeneficiaryData json.RawMessage
	TransferType                    compliance.TransferType
	Token                           *common.Address
	Beneficiary                     common.Address
	AmountWei                       string
	AmountFiat                      float64
	Currency                        string
	CreatedAt, ExpiresAt            time.Time
	UsedAt                          *time.Time
	UsedHash                        *common.Hash
	CreatedBy                       string
	PolicyDigest, QuoteDigest       Digest
}

func (r Record) EffectiveExpiry(maxSeconds int64) time.Time {
	ceiling := r.CreatedAt.Add(time.Duration(maxSeconds) * time.Second)
	if r.ExpiresAt.Before(ceiling) {
		return r.ExpiresAt
	}
	return ceiling
}
func (r Record) ValidMetadata() bool {
	_, amountErr := ParseUint256(r.AmountWei, true)
	_, fiatErr := CanonicalFiat(r.AmountFiat)
	return ValidUUID(r.ID) && ValidUUID(r.Organization) && validActor(r.Actor) && validActor(r.CreatedBy) && amountErr == nil && fiatErr == nil && r.AmountFiat > 0 && compliance.IsValidCurrency(r.Currency) && (r.TransferType == compliance.TransferTypeETH && r.Token == nil || r.TransferType == compliance.TransferTypeERC20 && r.Token != nil) && !r.CreatedAt.IsZero() && r.ExpiresAt.After(r.CreatedAt) && (r.UsedAt == nil) == (r.UsedHash == nil) && r.PolicyDigest != (Digest{})
}
func (r Record) Valid() bool {
	_, a := NormalizePII(r.OriginatorData)
	_, b := NormalizePII(r.BeneficiaryData)
	return r.ValidMetadata() && a == nil && b == nil
}

type TransferQuery struct {
	Beneficiary      common.Address
	Token            *common.Address
	AmountFiat       float64
	Currency         string
	RecordMaxSeconds int64
}

func (q TransferQuery) Covers(r Record) bool {
	return r.Beneficiary == q.Beneficiary && ((q.Token == nil && r.Token == nil) || (q.Token != nil && r.Token != nil && *q.Token == *r.Token)) && r.Currency == q.Currency && r.AmountFiat >= q.AmountFiat
}

type Event struct {
	ID                    int64
	Scope                 Scope
	Kind, Coverage        string
	From, To              *common.Address
	Token                 *common.Address
	AmountWei             *string
	AmountFiat, Threshold *float64
	Currency              *string
	Decision              string
	Monitored             bool
	Reason                string
	RecordID              *string
	DecisionAt            time.Time
	PolicyDigest          Digest
	Quote                 *Quote
	Anchor                rpcexecution.Anchor
}
type Witness struct {
	ID                               Digest
	AnchorHash                       common.Hash
	AnchorNumber, AnchorTimestamp    uint64
	EvidenceProfile                  string
	WalletVersion                    Digest
	DecisionAt                       time.Time
	ManifestDigest, ComplianceDigest Digest
	WalletEvidenceAt                 time.Time
}

func (w Witness) StableEqual(other Witness) bool {
	return w.ID == other.ID && w.AnchorHash == other.AnchorHash && w.AnchorNumber == other.AnchorNumber && w.AnchorTimestamp == other.AnchorTimestamp && w.EvidenceProfile == other.EvidenceProfile && w.WalletVersion == other.WalletVersion
}
func (w Witness) Digest() Digest {
	return HashParts("ops-privacy-witness/v1", w.AnchorHash[:], []byte(w.EvidenceProfile), []byte("proved_signer"), w.WalletVersion[:])
}

type Origin struct {
	Network             Digest
	Hash                common.Hash
	Actor, Organization string
	FirstAdmittedAt     time.Time
	Primary             Witness
}
type Share struct {
	Network             Digest
	Hash                common.Hash
	Actor, Organization string
	Recipients          []string
	RecipientDigest     Digest
	DeclaredAt          time.Time
	Witness             Witness
}

func NormalizeRecipients(in []string) ([]string, Digest, error) {
	if len(in) > MaxRecipients {
		return nil, Digest{}, ErrInvalid
	}
	out := append([]string{}, in...)
	sort.Strings(out)
	parts := make([][]byte, 0, len(out))
	for i, actor := range out {
		if !validActor(actor) || (i > 0 && actor == out[i-1]) {
			return nil, Digest{}, ErrInvalid
		}
		parts = append(parts, []byte(actor))
	}
	return out, HashParts("ops-tx-recipients/v1", parts...), nil
}
func (s Share) SameBinding(other Share) bool {
	return s.Network == other.Network && s.Hash == other.Hash && s.Actor == other.Actor && s.Organization == other.Organization && s.RecipientDigest == other.RecipientDigest && slices.Equal(s.Recipients, other.Recipients)
}

type TrustedRawInput struct {
	View           *runtimepolicy.View
	OrganizationID string
	Transaction    transactioninput.VerifiedTransaction
	Execution      *rpcexecution.CallExecution
	WalletSnapshot nativeadmission.WalletSnapshot
	Audience       []string
}
type Position struct {
	At time.Time
	ID string
}
type EventPosition struct {
	At time.Time
	ID int64
}
