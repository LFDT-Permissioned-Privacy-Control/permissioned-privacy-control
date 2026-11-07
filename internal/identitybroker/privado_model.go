package identitybroker

import (
	"context"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

type FamilyProvider string

const (
	FamilyAzure           FamilyProvider = "azure-human"
	FamilyPrivado         FamilyProvider = "privado"
	MaxPrivadoChallenges                 = 10000
	MaxPrivadoOffers                     = 64
	MaxPrivadoOfferBytes                 = 64 << 20
	MaxPrivadoCipherBytes                = privado.MaxCompactBytes + 28
)

// PrivadoHolderNetwork performs a typed canonical iden3 DID round trip. It does
// not fetch a DID document or treat syntax as authenticated holder evidence.
func PrivadoHolderNetwork(raw string) (string, bool) {
	if !validText(raw, 1024) {
		return "", false
	}
	d, e := w3c.ParseDID(raw)
	if e != nil || d.String() != raw {
		return "", false
	}
	id, e := core.IDFromDID(*d)
	if e != nil {
		return "", false
	}
	canonical, e := core.ParseDIDFromID(id)
	if e != nil || canonical.String() != raw {
		return "", false
	}
	b, e := core.BlockchainFromID(id)
	if e != nil {
		return "", false
	}
	n, e := core.NetworkIDFromID(id)
	return string(b) + ":" + string(n), e == nil
}
func validProviderMetadata(m privado.Metadata) bool {
	for _, d := range []string{m.IdentityDigest, m.ProfilePlanDigest, m.NetworkPlanDigest, m.DocumentPlanDigest} {
		if _, e := ParseDigest(d); e != nil {
			return false
		}
	}
	return true
}
func integralTime(t time.Time) bool {
	return t.Unix() >= 0 && t.Unix() <= 253402300799 && t.Equal(time.Unix(t.Unix(), 0))
}

type PrivadoStoreBinding struct {
	Scope         Scope
	SchemaVersion uint8
	Role          string
}
type PrivadoChallengeRecord struct {
	ID                       string
	Scope                    Scope
	ProfileID, ProfileDigest string
	Recipient                RecipientBinding
	Mode                     privado.Mode
	ExpectedActorID          string
	FamilyID                 string
	CurrentGeneration        *int64
	CurrentHandleHash        *Digest
	EncryptionKeyID          string
	Ciphertext               []byte
	CreatedAt, ExpiresAt     time.Time
}

func (p PrivadoChallengeRecord) Valid() bool {
	_, e := ParseDigest(p.ProfileDigest)
	capture := p.FamilyID == "" && p.CurrentGeneration == nil && p.CurrentHandleHash == nil
	if p.Mode == privado.Renew {
		capture = ValidUUID(p.FamilyID) && p.CurrentGeneration != nil && *p.CurrentGeneration >= 0 && p.CurrentHandleHash != nil && *p.CurrentHandleHash != (Digest{}) && identity.ValidActorID(p.ExpectedActorID)
	} else if p.Mode != privado.Login {
		return false
	}
	return capture && ValidUUID(p.ID) && p.Scope.Valid() && validText(p.ProfileID, 128) && e == nil && p.Recipient.Valid() && (p.ExpectedActorID == "" || identity.ValidActorID(p.ExpectedActorID)) && validText(p.EncryptionKeyID, 128) && len(p.Ciphertext) >= 28 && len(p.Ciphertext) <= 2048 && integralTime(p.CreatedAt) && integralTime(p.ExpiresAt) && p.ExpiresAt.After(p.CreatedAt) && p.ExpiresAt.Sub(p.CreatedAt) <= PendingLifetime
}

type PrivadoOfferRecord struct {
	RequestID                                                               string
	Scope                                                                   Scope
	ContextDigest, ProofDigest                                              Digest
	HolderDID, ActorID, Network, ProfileID, ProfileDigest, SourceAuthDigest string
	Provider                                                                privado.Metadata
	ClaimsAsOf, NotAfter, VerifiedAt                                        int64
	EncryptionKeyID                                                         string
	Ciphertext                                                              []byte
}

func (p PrivadoOfferRecord) Valid() bool {
	network, ok := PrivadoHolderNetwork(p.HolderDID)
	_, pd := ParseDigest(p.ProfileDigest)
	_, sd := ParseDigest(p.SourceAuthDigest)
	return ValidUUID(p.RequestID) && p.Scope.Valid() && p.ContextDigest != (Digest{}) && p.ProofDigest != (Digest{}) && ok && network == p.Network && validText(p.Network, 128) && identity.ValidActorID(p.ActorID) && validText(p.ProfileID, 128) && pd == nil && sd == nil && validProviderMetadata(p.Provider) && p.ClaimsAsOf >= 0 && p.ClaimsAsOf <= p.VerifiedAt && p.VerifiedAt < p.NotAfter && p.NotAfter <= 253402300799 && p.NotAfter-p.ClaimsAsOf <= 300 && validText(p.EncryptionKeyID, 128) && len(p.Ciphertext) >= 28 && len(p.Ciphertext) <= MaxPrivadoCipherBytes
}

type PrivadoFlowSnapshot struct {
	Challenge PrivadoChallengeRecord
	Offer     *PrivadoOfferRecord
}
type PrivadoHandleCapture struct {
	FamilyID, ActorID, ProfileID, ProfileDigest string
	Generation                                  int64
	HandleHash                                  Digest
	Recipient                                   RecipientBinding
	AbsoluteExpiresUnix                         int64
	Scope                                       Scope
}

func (c PrivadoHandleCapture) Valid() bool {
	_, e := ParseDigest(c.ProfileDigest)
	return ValidUUID(c.FamilyID) && identity.ValidActorID(c.ActorID) && validText(c.ProfileID, 128) && e == nil && c.Generation >= 0 && c.HandleHash != (Digest{}) && c.Recipient.Valid() && c.AbsoluteExpiresUnix > 0 && c.AbsoluteExpiresUnix <= 253402300799 && c.Scope.Valid()
}
func (c PrivadoHandleCapture) Matches(f Family) bool {
	return c.Valid() && f.Valid() && f.Provider == FamilyPrivado && c.Scope == f.Scope && c.FamilyID == f.ID && c.ActorID == f.Actor && c.ProfileID == f.ProfileID && c.ProfileDigest == f.ProfileDigest && c.Recipient == f.Recipient && c.AbsoluteExpiresUnix == f.AbsoluteExpiresAt.Unix()
}

type PrivadoOfferKind uint8

const (
	OfferInserted PrivadoOfferKind = iota + 1
	OfferExisting
)

type PrivadoOfferCommit struct {
	Committed bool
	Kind      PrivadoOfferKind
	Existing  *PrivadoOfferRecord
}
type PrivadoBeginKind uint8

const (
	ChallengeInserted PrivadoBeginKind = iota + 1
	ChallengeRevokeDeny
	ChallengeDenyUnchanged
)

type PrivadoBeginCommit struct {
	Committed bool
	Kind      PrivadoBeginKind
}
type PrivadoCompletion struct {
	Kind    DecisionKind
	Family  Family
	Capture *PrivadoHandleCapture
}
type PrivadoProofStore interface {
	Binding() PrivadoStoreBinding
	ReadPrivadoChallenge(context.Context, Scope, string) (PrivadoChallengeRecord, error)
	InstallPrivadoOffer(context.Context, Scope, PrivadoChallengeRecord, PrivadoOfferRecord, func() error) (PrivadoOfferCommit, error)
}
type PrivadoAppStore interface {
	Binding() PrivadoStoreBinding
	ReadPrivadoFamily(context.Context, Scope, string) (Family, error)
	InsertPrivadoLoginChallenge(context.Context, Scope, PrivadoChallengeRecord, func() error) error
	BeginPrivadoRenewChallenge(context.Context, Scope, PrivadoHandleCapture, Family, PrivadoChallengeRecord, func() error) (PrivadoBeginCommit, error)
	ReadPrivadoFlow(context.Context, Scope, string, RecipientBinding) (PrivadoFlowSnapshot, error)
	CompletePrivadoFlow(context.Context, Scope, PrivadoFlowSnapshot, PrivadoCompletion, func() error) (Commit, error)
	WithProviderFamily(context.Context, Scope, FamilyProvider, string, func(Family) (FamilyDecision, error), func() error) (Commit, error)
}
type MultiStore interface {
	Store
	PrivadoAppStore
}
