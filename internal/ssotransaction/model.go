// Package ssotransaction defines bounded structural SSO storage values. Neither
// a Record, opaque ciphertext nor a Capture authenticates an identity or grant.
package ssotransaction

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"regexp"
)

type Digest [32]byte
type Micros int64

const MaxMicros Micros = 253402300799999999
const MetadataChargeBytes int64 = 2048
const MaxContextCipherBytes = 4096
const MaxGrantCipherBytes = 24576
const MaxPreparedResponseBytes = 32768

var ErrInvalid = errors.New("invalid SSO storage value")
var name = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func ValidName(s string) bool { return len(s) <= 128 && name.MatchString(s) }
func ValidUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	var b [32]byte
	j := 0
	for _, c := range []byte(s) {
		if c == '-' {
			continue
		}
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		b[j] = c
		j++
	}
	var decoded [16]byte
	_, err := hex.Decode(decoded[:], b[:])
	return err == nil && decoded != [16]byte{}
}
func ValidActor(s string) bool {
	if len(s) != 50 || s[:7] != "ops:p1:" {
		return false
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(s[7:])
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s[7:]
}
func (d Digest) Valid() bool { return d != Digest{} }
func (m Micros) Valid() bool { return m >= 0 && m <= MaxMicros }
func Add(m Micros, delta int64) (Micros, error) {
	if !m.Valid() || delta < 0 || delta > int64(MaxMicros-m) {
		return 0, ErrInvalid
	}
	return m + Micros(delta), nil
}

type Phase uint8

const (
	Pending Phase = iota + 1
	Ready
	Consumed
	Expired
)

type Scope struct {
	Namespace           Digest
	Epoch               string
	BrokerNamespace     Digest
	BrokerRecoveryEpoch string
}

func (s Scope) Valid() bool {
	return s.Namespace.Valid() && s.BrokerNamespace.Valid() && ValidUUID(s.Epoch) && ValidUUID(s.BrokerRecoveryEpoch)
}

type Limits struct{ ActiveRows, ReadyRows, ActiveCipherBytes, AllRows, MetadataBytes, AuditRetentionSeconds int64 }

func DefaultLimits() Limits { return Limits{200000, 40000, 1 << 30, 40000000, 128 << 30, 86400} }
func (l Limits) Valid() bool {
	return l.ActiveRows >= 1 && l.ActiveRows <= 1000000 && l.ReadyRows >= 1 && l.ReadyRows <= l.ActiveRows && l.ActiveCipherBytes >= 28672 && l.ActiveCipherBytes <= 16<<30 && l.AllRows >= l.ActiveRows && l.AllRows <= 1000000000 && l.MetadataBytes >= 2048 && l.MetadataBytes <= 2<<40 && l.AuditRetentionSeconds >= 3600 && l.AuditRetentionSeconds <= 31536000
}

type PendingRecord struct {
	ID                                           string
	Scope                                        Scope
	ClientID                                     string
	ClientCatalogDigest, IdentityDigest          Digest
	Recipient, StateHash, RedirectHash, PKCES256 Digest
	ContextKeyID                                 string
	ContextCiphertext                            []byte
	CreatedAt, ExpiresAt                         Micros
}
type ReadyFields struct {
	CodeHash                                     Digest
	CodeExpiresAt                                Micros
	GrantKeyID                                   string
	GrantCiphertext                              []byte
	ActorID, ProfileID                           string
	ProfileDigest                                Digest
	FamilyID                                     string
	FamilyGeneration                             int64
	FamilyHandleHash, AccessDigest               Digest
	AccessExpiresAt, FamilyExpiresAt, PreparedAt Micros
	CodeResponseDigest                           Digest
	CodeResponseBytes                            uint32
}
type PreparedOutput struct {
	Digest Digest
	Bytes  uint32
}
type Record struct {
	Pending       PendingRecord
	Phase         Phase
	Ready         *ReadyFields
	ConsumedAt    *Micros
	TokenResponse *PreparedOutput
	RetainUntil   *Micros
}
type Capture struct {
	ID      string
	Scope   Scope
	Phase   Phase
	Binding Digest
}

func (c Capture) Valid() bool {
	return ValidUUID(c.ID) && c.Scope.Valid() && c.Phase >= Pending && c.Phase <= Expired && c.Binding.Valid()
}
func validInput(p PendingRecord) bool {
	return ValidUUID(p.ID) && p.Scope.Valid() && ValidName(p.ClientID) && p.ClientCatalogDigest.Valid() && p.IdentityDigest.Valid() && p.Recipient.Valid() && p.StateHash.Valid() && p.RedirectHash.Valid() && p.PKCES256.Valid() && ValidName(p.ContextKeyID) && p.CreatedAt.Valid() && p.ExpiresAt.Valid() && p.ExpiresAt > p.CreatedAt && p.ExpiresAt-p.CreatedAt <= 300000000
}
func ValidatePending(p PendingRecord) error {
	if !validInput(p) || len(p.ContextCiphertext) < 28 || len(p.ContextCiphertext) > MaxContextCipherBytes {
		return ErrInvalid
	}
	return nil
}
func validReady(p PendingRecord, r ReadyFields, cipher bool) bool {
	if !validInput(p) || !r.CodeHash.Valid() || !ValidName(r.GrantKeyID) || !ValidActor(r.ActorID) || !ValidName(r.ProfileID) || !r.ProfileDigest.Valid() || !ValidUUID(r.FamilyID) || r.FamilyGeneration < 0 || !r.FamilyHandleHash.Valid() || !r.AccessDigest.Valid() || !r.CodeResponseDigest.Valid() || r.CodeResponseBytes < 1 || r.CodeResponseBytes > MaxPreparedResponseBytes {
		return false
	}
	if cipher {
		if len(r.GrantCiphertext) < 28 || len(r.GrantCiphertext) > MaxGrantCipherBytes {
			return false
		}
	} else if r.GrantCiphertext != nil {
		return false
	}
	return r.PreparedAt.Valid() && r.CodeExpiresAt.Valid() && r.AccessExpiresAt.Valid() && r.FamilyExpiresAt.Valid() && r.PreparedAt >= p.CreatedAt && r.PreparedAt < p.ExpiresAt && r.CodeExpiresAt > r.PreparedAt && r.CodeExpiresAt-r.PreparedAt <= 60000000 && r.CodeExpiresAt <= p.ExpiresAt && r.CodeExpiresAt <= r.AccessExpiresAt && r.CodeExpiresAt <= r.FamilyExpiresAt && r.AccessExpiresAt > r.PreparedAt && r.AccessExpiresAt-r.PreparedAt <= 300000000 && r.FamilyExpiresAt > r.PreparedAt
}
func ValidateReady(p PendingRecord, r ReadyFields) error {
	if ValidatePending(p) != nil || !validReady(p, r, true) {
		return ErrInvalid
	}
	return nil
}
func ValidateRecord(r Record) error {
	if !validInput(r.Pending) || r.Phase < Pending || r.Phase > Expired {
		return ErrInvalid
	}
	if r.Phase == Pending {
		if ValidatePending(r.Pending) != nil || r.Ready != nil || r.ConsumedAt != nil || r.TokenResponse != nil || r.RetainUntil != nil {
			return ErrInvalid
		}
		return nil
	}
	if r.Ready == nil || !validReady(r.Pending, *r.Ready, r.Phase == Ready) || r.RetainUntil == nil || !r.RetainUntil.Valid() {
		return ErrInvalid
	}
	if r.Phase == Ready {
		if ValidatePending(r.Pending) != nil {
			return ErrInvalid
		}
	} else if r.Pending.ContextCiphertext != nil {
		return ErrInvalid
	}
	if *r.RetainUntil < r.Ready.CodeExpiresAt || *r.RetainUntil-r.Ready.CodeExpiresAt < 3600000000 || *r.RetainUntil-r.Ready.CodeExpiresAt > 31536000000000 {
		return ErrInvalid
	}
	if r.Phase == Consumed {
		if r.ConsumedAt == nil || !r.ConsumedAt.Valid() || *r.ConsumedAt < r.Ready.PreparedAt || *r.ConsumedAt >= r.Ready.CodeExpiresAt || r.TokenResponse == nil || !r.TokenResponse.Digest.Valid() || r.TokenResponse.Bytes < 1 || r.TokenResponse.Bytes > MaxPreparedResponseBytes {
			return ErrInvalid
		}
	} else if r.ConsumedAt != nil || r.TokenResponse != nil {
		return ErrInvalid
	}
	return nil
}
func MetadataCharge(Record) int64 { return MetadataChargeBytes }
func Clone(r Record) Record {
	r.Pending.ContextCiphertext = append([]byte(nil), r.Pending.ContextCiphertext...)
	if r.Ready != nil {
		v := *r.Ready
		v.GrantCiphertext = append([]byte(nil), v.GrantCiphertext...)
		r.Ready = &v
	}
	if r.ConsumedAt != nil {
		v := *r.ConsumedAt
		r.ConsumedAt = &v
	}
	if r.TokenResponse != nil {
		v := *r.TokenResponse
		r.TokenResponse = &v
	}
	if r.RetainUntil != nil {
		v := *r.RetainUntil
		r.RetainUntil = &v
	}
	return r
}
