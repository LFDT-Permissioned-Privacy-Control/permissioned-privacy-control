package identitybroker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

const privadoRequestPath = "/api/v2/auth/privado/requests/"
const privadoProofPath = "/api/v2/auth/privado/proofs/"

type PrivadoStart struct {
	RequestID, RequestURI string
	ExpiresAt             time.Time
	SourceProfile         string
	ExpectedActorID       *string
}
type PrivadoCandidate struct {
	HolderDID, Network, ActorID, SourceProfile, ProofDigest string
	VerifiedAt, ExpiresAt                                   int64
}
type PrivadoPreview struct {
	RequestID, SourceProfile string
	ExpiresAt                int64
	Candidate                *PrivadoCandidate
}
type PrivadoConfirmation struct {
	ExpectedActorID, ExpectedHolderDID string
	ProofDigest                        Digest
	ExpectedSessionID                  *string
}
type ProofRequired struct {
	Status           string        `json:"status"`
	Provider         string        `json:"provider"`
	PrincipalKind    identity.Kind `json:"principalKind"`
	Mode             string        `json:"mode"`
	RequestID        string        `json:"requestId"`
	RequestURI       string        `json:"requestUri"`
	ExpiresAt        int64         `json:"expiresAt"`
	ActorID          string        `json:"actorId"`
	BrowserSessionID string        `json:"browserSessionId"`
	SourceProfile    string        `json:"sourceProfile"`
}
type MultiRenewal struct {
	access  *CommittedRenewal
	pending *ProofRequired
}

func (r *MultiRenewal) Access() (*CommittedRenewal, bool) {
	if r == nil || r.access == nil || r.pending != nil {
		return nil, false
	}
	return r.access, true
}
func (r *MultiRenewal) ProofRequired() (ProofRequired, bool) {
	if r == nil || r.pending == nil || r.access != nil {
		return ProofRequired{}, false
	}
	return *r.pending, true
}

func (s *Service) privadoProfile(id string) (identity.Profile, string, bool) {
	if !s.IsMulti() {
		return identity.Profile{}, "", false
	}
	source, _ := s.broker.MultiSource()
	selected := false
	for _, b := range source.PrivadoProfiles {
		selected = selected || b.ProfileID == id
	}
	if !selected {
		return identity.Profile{}, "", false
	}
	for _, p := range s.identity.Source().Profiles {
		if p.ID == id {
			d, ok := s.identity.ProfileDigest(id)
			return p, d, ok
		}
	}
	return identity.Profile{}, "", false
}
func (s *Service) callback(id string) string {
	return s.broker.CommonSettings().WebOrigin + privadoProofPath + id
}
func privadoError(e error) error {
	if errors.Is(e, privado.ErrEvidence) || errors.Is(e, privado.ErrInvalid) {
		return ErrUnauthorized
	}
	return ErrUnavailable
}
func (s *Service) challengeGate(ctx context.Context, p PrivadoChallengeRecord) error {
	if ctx.Err() != nil {
		return ErrUnavailable
	}
	now, e := s.now()
	if e != nil {
		return e
	}
	if !p.Valid() || p.Scope != s.scope || now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) {
		return ErrUnauthorized
	}
	_, digest, ok := s.privadoProfile(p.ProfileID)
	if !ok || digest != p.ProfileDigest {
		return ErrRelogin
	}
	return nil
}
func (s *Service) preparePrivadoChallenge(profileID string, recipient RecipientBinding, mode privado.Mode, expectedActor string, capture *PrivadoHandleCapture) (PrivadoChallengeRecord, error) {
	_, digest, ok := s.privadoProfile(profileID)
	if !ok || !recipient.Valid() {
		return PrivadoChallengeRecord{}, ErrInvalid
	}
	now, e := s.now()
	if e != nil {
		return PrivadoChallengeRecord{}, e
	}
	now = now.Truncate(time.Second)
	expires := now.Add(PendingLifetime)
	if capture != nil {
		expires = minTime(expires, time.Unix(capture.AbsoluteExpiresUnix, 0).UTC())
	}
	p := PrivadoChallengeRecord{ID: uuid.NewString(), Scope: s.scope, ProfileID: profileID, ProfileDigest: digest, Recipient: recipient, Mode: mode, ExpectedActorID: expectedActor, EncryptionKeyID: s.aes.active, CreatedAt: now, ExpiresAt: expires}
	if capture != nil {
		g, h := capture.Generation, capture.HandleHash
		p.FamilyID = capture.FamilyID
		p.CurrentGeneration = &g
		p.CurrentHandleHash = &h
	}
	var nonce [32]byte
	if _, e = rand.Read(nonce[:]); e != nil || nonce == ([32]byte{}) {
		return p, ErrUnavailable
	}
	c := privado.RequestContext{ProfileID: p.ProfileID, RequestID: p.ID, Nonce32: nonce, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, CallbackURL: s.callback(p.ID), Mode: p.Mode}
	if mode == privado.Renew {
		c.ExpectedActorID = expectedActor
	}
	request, e := s.privado.CreateRequest(c)
	if e != nil {
		return p, privadoError(e)
	}
	p.CreatedAt = request.Context.CreatedAt
	p.ExpiresAt = request.Context.ExpiresAt
	payload := privadoChallengePayload{1, base64.RawURLEncoding.EncodeToString(nonce[:]), s.broker.Digest(), plan(s.privado.Metadata()), Hash("ops.broker.privado.callback/v1", []byte(s.callback(p.ID))).String()}
	raw, e := json.Marshal(payload)
	if e != nil || len(raw) > 2020 {
		return p, ErrInvalid
	}
	p.Ciphertext, e = s.aes.seal(p.EncryptionKeyID, raw, privadoChallengeAAD(p))
	if e != nil {
		return p, e
	}
	if !p.Valid() {
		return p, ErrInvalid
	}
	return p, nil
}
func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}
func (s *Service) restorePrivadoChallenge(ctx context.Context, p PrivadoChallengeRecord) (privado.Request, Digest, error) {
	if e := s.challengeGate(ctx, p); e != nil {
		return privado.Request{}, Digest{}, e
	}
	raw, e := s.aes.open(p.EncryptionKeyID, p.Ciphertext, privadoChallengeAAD(p), 2048)
	if e != nil {
		return privado.Request{}, Digest{}, e
	}
	payload, nonce, e := decodePrivadoChallenge(raw)
	if e != nil {
		return privado.Request{}, Digest{}, e
	}
	if payload.SourceAuthDigest != s.broker.Digest() || payload.Provider.metadata() != s.privado.Metadata() || payload.CallbackDigest != Hash("ops.broker.privado.callback/v1", []byte(s.callback(p.ID))).String() {
		return privado.Request{}, Digest{}, ErrRelogin
	}
	c := privado.RequestContext{ProfileID: p.ProfileID, RequestID: p.ID, Nonce32: nonce, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt, CallbackURL: s.callback(p.ID), Mode: p.Mode}
	if p.Mode == privado.Renew {
		c.ExpectedActorID = p.ExpectedActorID
	}
	request, e := s.privado.CreateRequest(c)
	if e != nil {
		return privado.Request{}, Digest{}, privadoError(e)
	}
	return request, Hash("ops.broker.privado.context/v1", privadoChallengeAAD(p), raw), nil
}
func (s *Service) startOutput(p PrivadoChallengeRecord) PrivadoStart {
	var expected *string
	if p.ExpectedActorID != "" {
		v := p.ExpectedActorID
		expected = &v
	}
	return PrivadoStart{p.ID, s.broker.CommonSettings().WebOrigin + privadoRequestPath + p.ID, p.ExpiresAt, p.ProfileID, expected}
}
func (s *Service) BeginPrivadoLogin(ctx context.Context, profileID string, expectedHolderDID *string, recipient RecipientBinding) (PrivadoStart, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() {
		return PrivadoStart{}, ErrInvalid
	}
	expected := ""
	if expectedHolderDID != nil {
		if _, ok := PrivadoHolderNetwork(*expectedHolderDID); !ok {
			return PrivadoStart{}, ErrInvalid
		}
		var e error
		expected, e = s.identity.SourceActorID(identity.SourceIdentity{ProfileID: profileID, Kind: identity.Human, Authority: "privado", Subject: *expectedHolderDID})
		if e != nil {
			return PrivadoStart{}, ErrInvalid
		}
	}
	p, e := s.preparePrivadoChallenge(profileID, recipient, privado.Login, expected, nil)
	if e != nil {
		return PrivadoStart{}, e
	}
	gate := func() error { return s.challengeGate(ctx, p) }
	if e = s.app.InsertPrivadoLoginChallenge(ctx, s.scope, p, gate); e != nil {
		return PrivadoStart{}, e
	}
	if e = gate(); e != nil {
		return PrivadoStart{}, e
	}
	return s.startOutput(p), nil
}
func (s *Service) PublicPrivadoRequest(ctx context.Context, id string) ([]byte, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() || !ValidUUID(id) {
		return nil, ErrInvalid
	}
	p, e := s.proofStore.ReadPrivadoChallenge(ctx, s.scope, id)
	if e != nil {
		return nil, e
	}
	r, _, e := s.restorePrivadoChallenge(ctx, p)
	if e != nil {
		return nil, e
	}
	if e = s.challengeGate(ctx, p); e != nil {
		return nil, e
	}
	return bytes.Clone(r.AuthorizationJSON), nil
}
func (s *Service) OfferPrivadoProof(ctx context.Context, id, compact string) error {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() || !ValidUUID(id) || len(compact) == 0 || len(compact) > privado.MaxCompactBytes {
		return ErrInvalid
	}
	p, e := s.proofStore.ReadPrivadoChallenge(ctx, s.scope, id)
	if e != nil {
		return e
	}
	request, contextDigest, e := s.restorePrivadoChallenge(ctx, p)
	if e != nil {
		return e
	}
	proof, e := s.privado.Verify(ctx, request, compact)
	if e != nil {
		return privadoError(e)
	}
	m := proof.Metadata()
	if p.ExpectedActorID != "" && p.ExpectedActorID != m.ActorID {
		return ErrUnauthorized
	}
	network, ok := PrivadoHolderNetwork(m.HolderDID)
	if !ok {
		return ErrUnauthorized
	}
	offer := PrivadoOfferRecord{RequestID: id, Scope: s.scope, ContextDigest: contextDigest, ProofDigest: Hash("ops.broker.privado.proof/v1", []byte(id), []byte(compact)), HolderDID: m.HolderDID, ActorID: m.ActorID, Network: network, ProfileID: m.ProfileID, ProfileDigest: m.ProfileDigest, SourceAuthDigest: s.broker.Digest(), Provider: m.Provider, ClaimsAsOf: m.ClaimsAsOf, NotAfter: m.NotAfter, VerifiedAt: m.SourceVerifiedAt, EncryptionKeyID: s.aes.active}
	offer.Ciphertext, e = s.aes.seal(offer.EncryptionKeyID, []byte(compact), privadoOfferAAD(offer))
	if e != nil || !offer.Valid() {
		return ErrUnauthorized
	}
	gate := func() error {
		if e := s.challengeGate(ctx, p); e != nil {
			return e
		}
		return s.privado.RequireProof(proof)
	}
	commit, e := s.proofStore.InstallPrivadoOffer(ctx, s.scope, p, offer, gate)
	if e != nil {
		return e
	}
	if !commit.Committed {
		return ErrUnavailable
	}
	if commit.Kind == OfferExisting {
		if commit.Existing == nil {
			return ErrUnavailable
		}
		old := *commit.Existing
		plain, e := s.openPrivadoOffer(old, p, contextDigest)
		if e != nil {
			return e
		}
		if !bytes.Equal(plain, []byte(compact)) || old.HolderDID != offer.HolderDID || old.ActorID != offer.ActorID || old.ProofDigest != offer.ProofDigest || old.ProfileDigest != offer.ProfileDigest || old.ClaimsAsOf != offer.ClaimsAsOf || old.NotAfter != offer.NotAfter {
			return ErrUnauthorized
		}
	} else if commit.Kind != OfferInserted {
		return ErrUnavailable
	}
	return gate()
}
func (s *Service) openPrivadoOffer(o PrivadoOfferRecord, p PrivadoChallengeRecord, contextDigest Digest) ([]byte, error) {
	if !o.Valid() || o.Scope != s.scope || o.RequestID != p.ID || o.ContextDigest != contextDigest || o.ProfileID != p.ProfileID || o.ProfileDigest != p.ProfileDigest || o.SourceAuthDigest != s.broker.Digest() || o.Provider != s.privado.Metadata() || p.ExpectedActorID != "" && p.ExpectedActorID != o.ActorID {
		return nil, ErrUnauthorized
	}
	now, e := s.now()
	if e != nil {
		return nil, e
	}
	if now.Unix() < o.VerifiedAt || now.Unix() >= o.NotAfter {
		return nil, ErrUnauthorized
	}
	plain, e := s.aes.open(o.EncryptionKeyID, o.Ciphertext, privadoOfferAAD(o), MaxPrivadoCipherBytes)
	if e != nil || len(plain) > privado.MaxCompactBytes || o.ProofDigest != Hash("ops.broker.privado.proof/v1", []byte(p.ID), plain) {
		return nil, ErrUnauthorized
	}
	return plain, nil
}
func (s *Service) PreviewPrivado(ctx context.Context, id string, recipient RecipientBinding) (PrivadoPreview, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() || !ValidUUID(id) || !recipient.Valid() {
		return PrivadoPreview{}, ErrInvalid
	}
	snapshot, e := s.app.ReadPrivadoFlow(ctx, s.scope, id, recipient)
	if e != nil {
		return PrivadoPreview{}, e
	}
	_, digest, e := s.restorePrivadoChallenge(ctx, snapshot.Challenge)
	if e != nil {
		return PrivadoPreview{}, e
	}
	out := PrivadoPreview{RequestID: id, SourceProfile: snapshot.Challenge.ProfileID, ExpiresAt: snapshot.Challenge.ExpiresAt.Unix()}
	if snapshot.Offer != nil {
		offer := *snapshot.Offer
		if _, e = s.openPrivadoOffer(offer, snapshot.Challenge, digest); e != nil {
			return PrivadoPreview{}, e
		}
		out.Candidate = &PrivadoCandidate{offer.HolderDID, offer.Network, offer.ActorID, offer.ProfileID, offer.ProofDigest.String(), offer.VerifiedAt, min(offer.NotAfter, out.ExpiresAt)}
	}
	if e = s.challengeGate(ctx, snapshot.Challenge); e != nil {
		return PrivadoPreview{}, e
	}
	return out, nil
}
