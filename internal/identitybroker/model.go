// Package identitybroker owns trusted provider grants and operational renewal
// state. Core identity verification remains local and contains no session store.
package identitybroker

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
)

const (
	PendingLifetime      = 5 * time.Minute
	FamilyLifetime       = 7 * 24 * time.Hour
	MaxPending           = 10000
	MaxFamilies          = 100000
	MaxRefreshBytes      = 32 << 10
	MaxFamilyCipherBytes = 33 << 10
)

var (
	ErrInvalid      = errors.New("invalid identity broker request")
	ErrUnauthorized = errors.New("invalid or expired authentication")
	ErrRelogin      = errors.New("reauthentication required")
	ErrUnavailable  = errors.New("identity broker unavailable")
	ErrConflict     = errors.New("identity state conflict")
)

type Digest [32]byte

func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }
func ParseDigest(raw string) (Digest, error) {
	var out Digest
	if len(raw) != 71 || !strings.HasPrefix(raw, "sha256:") {
		return out, ErrInvalid
	}
	b, err := hex.DecodeString(raw[7:])
	if err != nil || hex.EncodeToString(b) != raw[7:] {
		return out, ErrInvalid
	}
	copy(out[:], b)
	return out, nil
}
func Pack(domain string, parts ...[]byte) []byte {
	out := []byte{}
	for _, part := range append([][]byte{[]byte(domain)}, parts...) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		out = append(out, size[:]...)
		out = append(out, part...)
	}
	return out
}
func Hash(domain string, parts ...[]byte) Digest {
	return Digest(sha256.Sum256(Pack(domain, parts...)))
}
func ValidUUID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func validText(raw string, max int) bool {
	if raw == "" || len(raw) > max || !utf8.ValidString(raw) {
		return false
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

type ServiceBinding struct{ Environment, DeploymentID, Origin string }

func (b ServiceBinding) Namespace(issuer string) (Digest, error) {
	if !validText(b.Environment, 128) || !validText(b.DeploymentID, 128) || !validText(issuer, 2048) {
		return Digest{}, ErrInvalid
	}
	return Hash("ops-broker-namespace/v1", []byte(b.Environment), []byte(issuer), []byte(b.DeploymentID)), nil
}

type ExpectedState struct{ RecoveryEpoch string }

func (s ExpectedState) Valid() bool { return ValidUUID(s.RecoveryEpoch) }

type Scope struct {
	Namespace Digest
	State     ExpectedState
}

func (s Scope) Valid() bool { return s.Namespace != (Digest{}) && s.State.Valid() }

type RecipientBinding [32]byte

func (r RecipientBinding) Valid() bool { return r != (RecipientBinding{}) }

type Pending struct {
	ID                       string
	Scope                    Scope
	StateHash                Digest
	ProfileID, ProfileDigest string
	Recipient                RecipientBinding
	EncryptionKeyID          string
	Ciphertext               []byte
	CreatedAt, ExpiresAt     time.Time
}

func (p Pending) Valid() bool {
	_, err := ParseDigest(p.ProfileDigest)
	return ValidUUID(p.ID) && p.Scope.Valid() && p.StateHash != (Digest{}) && validText(p.ProfileID, 128) && err == nil && p.Recipient.Valid() && validText(p.EncryptionKeyID, 128) && len(p.Ciphertext) >= 28 && len(p.Ciphertext) <= 2048 && !p.CreatedAt.IsZero() && p.ExpiresAt.After(p.CreatedAt) && p.ExpiresAt.Sub(p.CreatedAt) <= PendingLifetime
}

type Family struct {
	ID, RequestID                               string
	Scope                                       Scope
	Actor, ProfileID, ProfileDigest             string
	Authority, Tenant, Subject                  string
	Kind                                        identity.Kind
	OIDCSubjectHash, NonceHash                  Digest
	OriginalAuthTime                            *int64
	Recipient                                   RecipientBinding
	Generation                                  int64
	CurrentHandleHash                           Digest
	EncryptionKeyID                             string
	Ciphertext                                  []byte
	CreatedAt, AbsoluteExpiresAt, LastRotatedAt time.Time
	RevokedAt                                   *time.Time
}

func (f Family) Valid() bool {
	_, digestErr := ParseDigest(f.ProfileDigest)
	return ValidUUID(f.ID) && ValidUUID(f.RequestID) && f.Scope.Valid() && identity.ValidActorID(f.Actor) && validText(f.ProfileID, 128) && digestErr == nil && ValidUUID(f.Tenant) && ValidUUID(f.Subject) && f.Authority == "https://login.microsoftonline.com/"+f.Tenant+"/v2.0" && f.Kind == identity.Human && f.OIDCSubjectHash != (Digest{}) && f.NonceHash != (Digest{}) && (f.OriginalAuthTime == nil || *f.OriginalAuthTime >= 0) && f.Recipient.Valid() && f.Generation >= 0 && f.CurrentHandleHash != (Digest{}) && validText(f.EncryptionKeyID, 128) && len(f.Ciphertext) >= 28 && len(f.Ciphertext) <= MaxFamilyCipherBytes && !f.CreatedAt.IsZero() && f.AbsoluteExpiresAt.After(f.CreatedAt) && f.AbsoluteExpiresAt.Sub(f.CreatedAt) <= FamilyLifetime && !f.LastRotatedAt.Before(f.CreatedAt) && (f.RevokedAt == nil || !f.RevokedAt.Before(f.CreatedAt))
}

type DecisionKind uint8

const (
	Create DecisionKind = iota + 1
	Rotate
	RevokeDeny
	DenyUnchanged
	RevokeSuccess
)

type FamilyDecision struct {
	Kind   DecisionKind
	Family Family
}
type Commit struct {
	Committed bool
	Kind      DecisionKind
}
type PendingTx interface{ InsertFamily(Family) error }
type Store interface {
	InsertPending(context.Context, Scope, Pending, func() error) error
	WithPending(context.Context, Scope, Digest, RecipientBinding, func(Pending, PendingTx) error, func() error) (Commit, error)
	WithFamily(context.Context, Scope, string, func(Family) (FamilyDecision, error), func() error) (Commit, error)
}
