// Package privado verifies bounded AuthV2/SigV2 evidence against explicit
// immutable trust. It issues no OPS credential and owns no session database.
package privado

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"privacy-proxy/internal/identity"
)

const (
	MaxProfiles      = 64
	MaxNetworks      = 8
	MaxPredicates    = 16
	MaxCompactBytes  = 1 << 20
	MaxRequestBytes  = 64 << 10
	MaxScopeBytes    = 32 << 10
	MaxInFlight      = 4
	MaxRPCRequests   = 42
	OperationTimeout = 20 * time.Second
	RPCTimeout       = 3 * time.Second
	MaxAge           = 300 * time.Second
)

var (
	ErrInvalid  = errors.New("invalid Privado provider binding")
	ErrEvidence = errors.New("invalid or expired Privado evidence")
	ErrProvider = errors.New("Privado provider unavailable")
	ErrBusy     = errors.New("Privado verifier busy")
)

type CredentialBinding struct{ RefID, Header, Value string }
type NetworkBinding struct {
	Network, ChainID, StateContract, URL string
	AllowPrivate                         bool
	Credential                           *CredentialBinding
}
type PinnedDocument struct {
	URL      string
	RawBytes []byte
}
type Options struct {
	Catalog    *identity.Catalog
	ProfileIDs []string
	Networks   []NetworkBinding
	Documents  []PinnedDocument
	Clock      identity.Clock
	// Trusted infrastructure input only. The caller owns its dial/TLS policy
	// and lifecycle; a request or proof can never choose a transport.
	Transport http.RoundTripper
}
type Metadata struct{ IdentityDigest, ProfilePlanDigest, NetworkPlanDigest, DocumentPlanDigest string }
type Mode string

const (
	Login Mode = "login"
	Renew Mode = "renew"
)

// RequestContext is saved operational input, not identity evidence. The broker
// that restores it must authenticate its pending row and recipient binding.
type RequestContext struct {
	ProfileID, RequestID string
	Nonce32              [32]byte
	CreatedAt, ExpiresAt time.Time
	CallbackURL          string
	Mode                 Mode
	ExpectedActorID      string
}

// Request is deliberately serializable for a later authenticated pending store.
// Its byte fields are detached copies, never a license to choose another query.
type Request struct {
	Context           RequestContext
	ProfileDigest     string
	Provider          Metadata
	AuthorizationJSON []byte
}
type ProofMetadata struct {
	Provider                                     Metadata
	ProfileID, ProfileDigest, HolderDID, ActorID string
	ClaimsAsOf, SourceVerifiedAt, NotAfter       int64
}
type VerifiedProof struct {
	provider *Provider
	metadata ProofMetadata
	facts    []identity.Fact
	valid    bool
}

// RequireProof pairs an opaque result with the SAME selected provider instance.
// Equal public metadata does not fingerprint its resolved secrets/transport.
func (p *Provider) RequireProof(proof *VerifiedProof) error {
	if p == nil || proof == nil || proof.provider != p {
		return ErrEvidence
	}
	return proof.RequireCurrent()
}

func (p *VerifiedProof) Metadata() ProofMetadata {
	if p == nil {
		return ProofMetadata{}
	}
	return p.metadata
}
func (p *VerifiedProof) Facts() []identity.Fact {
	if p == nil {
		return nil
	}
	return slices.Clone(p.facts)
}
func (p *VerifiedProof) Identity() identity.SourceIdentity {
	if p == nil {
		return identity.SourceIdentity{}
	}
	return identity.SourceIdentity{ProfileID: p.metadata.ProfileID, Kind: identity.Human, Authority: "privado", Subject: p.metadata.HolderDID}
}
func (p *VerifiedProof) RequireCurrent() error {
	if p == nil || !p.valid || p.provider == nil || p.provider.closed.Load() {
		return ErrEvidence
	}
	now, err := p.provider.now()
	if err != nil {
		return err
	}
	profile, ok := p.provider.profiles[p.metadata.ProfileID]
	if !ok || profile.digest != p.metadata.ProfileDigest || p.metadata.Provider != p.provider.metadata ||
		p.metadata.ClaimsAsOf > p.metadata.SourceVerifiedAt || now < p.metadata.SourceVerifiedAt || now >= p.metadata.NotAfter || now > p.metadata.ClaimsAsOf+300 {
		return ErrEvidence
	}
	return nil
}
