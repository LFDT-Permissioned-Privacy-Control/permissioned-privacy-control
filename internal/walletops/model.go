package walletops

import (
	"bytes"
	"encoding/hex"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/walletproof"
)

const (
	MaxChallenges    = 8
	MaxLinks         = 4096
	MaxRequestBytes  = 8 << 10
	MaxResponseBytes = 1 << 20
)

var (
	ErrInvalid      = errors.New("invalid wallet request")
	ErrUnauthorized = errors.New("invalid or expired access")
	ErrNotFound     = errors.New("wallet link not found")
	ErrConflict     = errors.New("wallet state conflict")
	ErrUnavailable  = errors.New("wallet service unavailable")
)

type Challenge struct {
	Namespace           Namespace
	Generation, Actor   string
	Nonce               [32]byte
	Address             common.Address
	Message             string
	IssuedAt, ExpiresAt time.Time
}

func (c Challenge) Validate(origin string) error {
	if !identity.ValidActorID(c.Actor) || !(ExpectedState{Generation: c.Generation}).Valid() {
		return ErrInvalid
	}
	m, err := walletproof.Message(walletproof.MessageFields{Origin: origin, Namespace: c.Namespace.String(), Actor: c.Actor, Address: AddressString(c.Address), Nonce: hex.EncodeToString(c.Nonce[:]), IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt})
	if err != nil || m != c.Message {
		return ErrInvalid
	}
	return nil
}

type Link struct {
	Namespace              Namespace
	Actor                  string
	Address                common.Address
	ProofKind              string
	Message                string
	Signature, MessageHash []byte
	AcceptedAt             time.Time
	Revoked                bool
	RevokedAt              time.Time
}

func (l Link) Validate() error {
	if !identity.ValidActorID(l.Actor) || l.Revoked == l.RevokedAt.IsZero() {
		return ErrInvalid
	}
	switch l.ProofKind {
	case "eip191_v2":
		if len(l.Message) == 0 || len(l.Message) > walletproof.MaxMessageBytes || len(l.Signature) != 65 || len(l.MessageHash) != 32 || l.AcceptedAt.IsZero() || !bytes.Equal(walletproof.HashMessage(l.Message), l.MessageHash) {
			return ErrInvalid
		}
	case "legacy_revoked":
		if !l.Revoked || l.Message != "" || len(l.Signature) != 0 || len(l.MessageHash) != 0 || !l.AcceptedAt.IsZero() {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type OwnershipFact struct {
	Namespace    Namespace
	Actor        string
	Address      common.Address
	ProofVersion int
	VerifiedAt   time.Time
}

func (f OwnershipFact) Valid(namespace Namespace, actor string) bool {
	return f.Namespace == namespace && f.Actor == actor && identity.ValidActorID(f.Actor) && f.ProofVersion == 2 && !f.VerifiedAt.IsZero()
}

type ChallengeRequest struct {
	Address string `json:"address"`
}
type VerifyRequest struct {
	Nonce     string `json:"nonce"`
	Address   string `json:"address"`
	Signature string `json:"signature"`
}
type ChallengeResult struct {
	Nonce     string `json:"nonce"`
	Message   string `json:"message"`
	ExpiresAt string `json:"expiresAt"`
}
type LinkResult struct {
	Address string `json:"address"`
	Status  string `json:"status"`
}
type OwnAddress struct {
	Address      string `json:"address"`
	VerifiedAt   string `json:"verifiedAt"`
	ProofVersion int    `json:"proofVersion"`
}
type ENSResult struct {
	Address string `json:"address"`
	ENSName string `json:"ensName"`
}
