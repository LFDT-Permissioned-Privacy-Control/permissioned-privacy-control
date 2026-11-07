package identitybroker

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

type CommittedPrivado struct{ result *CommittedRenewal }

func (r *CommittedPrivado) Metadata() ResultMetadata {
	if r == nil || r.result == nil {
		return ResultMetadata{}
	}
	return r.result.Metadata()
}
func (r *CommittedPrivado) RequireDeliverable() error {
	if r == nil || r.result == nil {
		return ErrUnauthorized
	}
	return r.result.RequireDeliverable()
}
func (r *CommittedPrivado) Credentials() (string, string, error) {
	if e := r.RequireDeliverable(); e != nil {
		return "", "", e
	}
	return r.result.Credentials()
}
func (r *CommittedPrivado) SessionInfo() (BrowserSession, error) {
	if e := r.RequireDeliverable(); e != nil {
		return BrowserSession{}, e
	}
	return r.result.SessionInfo()
}

func (s *Service) privadoFamilyContinuity(f Family) error {
	if !f.Valid() || f.Provider != FamilyPrivado || f.Scope != s.scope {
		return ErrUnauthorized
	}
	_, digest, ok := s.privadoProfile(f.ProfileID)
	if !ok || digest != f.ProfileDigest {
		return ErrRelogin
	}
	plain, e := s.aes.open(f.EncryptionKeyID, f.Ciphertext, privadoFamilyAAD(f), 2048)
	if e != nil {
		return e
	}
	payload, e := decodePrivadoFamily(plain)
	if e != nil {
		return e
	}
	if payload.SourceAuthDigest != s.broker.Digest() || payload.Provider.metadata() != s.privado.Metadata() {
		return ErrRelogin
	}
	return nil
}
func (s *Service) privadoFamilyMaterial(f *Family, now time.Time) (string, error) {
	handle, e := s.familyHandle(f, now)
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(privadoFamilyPayload{1, s.broker.Digest(), plan(s.privado.Metadata())})
	if e != nil || len(raw) > 2020 {
		return "", ErrInvalid
	}
	f.Ciphertext, e = s.aes.seal(f.EncryptionKeyID, raw, privadoFamilyAAD(*f))
	if e != nil {
		return "", e
	}
	if !f.Valid() {
		return "", ErrInvalid
	}
	return handle, nil
}
func (s *Service) privadoCapture(handle string, recipient RecipientBinding, expected *ExpectedSession) (PrivadoHandleCapture, refreshClaims, error) {
	if !s.IsMulti() || !recipient.Valid() {
		return PrivadoHandleCapture{}, refreshClaims{}, ErrInvalid
	}
	now, e := s.now()
	if e != nil {
		return PrivadoHandleCapture{}, refreshClaims{}, e
	}
	claims, e := s.mac.parseRefresh(handle, s.issuer.Issuer, s.scope.State.RecoveryEpoch, now.Unix())
	if e != nil {
		return PrivadoHandleCapture{}, claims, e
	}
	if expected != nil && (claims.Actor != expected.ActorID || claims.FamilyID != expected.SessionID) {
		return PrivadoHandleCapture{}, claims, ErrSessionChanged
	}
	if _, _, ok := s.privadoProfile(claims.ProfileID); !ok {
		return PrivadoHandleCapture{}, claims, ErrRelogin
	}
	capture := PrivadoHandleCapture{FamilyID: claims.FamilyID, ActorID: claims.Actor, ProfileID: claims.ProfileID, ProfileDigest: claims.ProfileDigest, Generation: claims.Generation, HandleHash: tokenHash(handle), Recipient: recipient, AbsoluteExpiresUnix: claims.Expires, Scope: s.scope}
	if !capture.Valid() {
		return capture, claims, ErrUnauthorized
	}
	return capture, claims, nil
}
func (s *Service) RenewMultiForSession(ctx context.Context, handle string, recipient RecipientBinding, expected ExpectedSession) (*MultiRenewal, error) {
	if !expected.Valid() {
		return nil, ErrInvalid
	}
	return s.renewMulti(ctx, handle, recipient, &expected)
}
func (s *Service) BootstrapMulti(ctx context.Context, handle string, recipient RecipientBinding) (*MultiRenewal, error) {
	return s.renewMulti(ctx, handle, recipient, nil)
}
func (s *Service) renewMulti(ctx context.Context, handle string, recipient RecipientBinding, expected *ExpectedSession) (*MultiRenewal, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() || !recipient.Valid() {
		return nil, ErrInvalid
	}
	now, e := s.now()
	if e != nil {
		return nil, e
	}
	claims, e := s.mac.parseRefresh(handle, s.issuer.Issuer, s.scope.State.RecoveryEpoch, now.Unix())
	if e != nil {
		return nil, e
	}
	if expected != nil && (claims.Actor != expected.ActorID || claims.FamilyID != expected.SessionID) {
		return nil, ErrSessionChanged
	}
	if p, ok := s.broker.Profile(claims.ProfileID); ok && p.Definition.Kind == identity.AzureHuman {
		var result *CommittedRenewal
		if expected == nil {
			result, e = s.RenewAzure(ctx, handle, recipient)
		} else {
			result, e = s.RenewAzureForSession(ctx, handle, recipient, *expected)
		}
		if e != nil {
			return nil, e
		}
		return &MultiRenewal{access: result}, nil
	}
	capture, claims, e := s.privadoCapture(handle, recipient, expected)
	if e != nil {
		return nil, e
	}
	family, e := s.app.ReadPrivadoFamily(ctx, s.scope, capture.FamilyID)
	if e != nil {
		return nil, e
	}
	if family.Provider != FamilyPrivado || s.familyContext(family, claims, recipient, now) != nil {
		return nil, ErrUnauthorized
	}
	if e = s.privadoFamilyContinuity(family); e != nil {
		return nil, e
	}
	p, e := s.preparePrivadoChallenge(family.ProfileID, recipient, privado.Renew, family.Actor, &capture)
	if e != nil {
		return nil, e
	}
	gate := func() error {
		if e := s.challengeGate(ctx, p); e != nil {
			return e
		}
		at, e := s.now()
		if e != nil {
			return e
		}
		return s.familyContext(family, claims, recipient, at)
	}
	commit, e := s.app.BeginPrivadoRenewChallenge(ctx, s.scope, capture, family, p, gate)
	if e != nil {
		return nil, e
	}
	if !commit.Committed {
		return nil, ErrUnavailable
	}
	if commit.Kind != ChallengeInserted {
		return nil, ErrRelogin
	}
	if e = gate(); e != nil {
		return nil, e
	}
	start := s.startOutput(p)
	pending := &ProofRequired{Status: "proof_required", Provider: "privado", PrincipalKind: identity.Human, Mode: "renew", RequestID: p.ID, RequestURI: start.RequestURI, ExpiresAt: p.ExpiresAt.Unix(), ActorID: family.Actor, BrowserSessionID: family.ID, SourceProfile: family.ProfileID}
	return &MultiRenewal{pending: pending}, nil
}

func (s *Service) buildPrivadoAccess(proof *privado.VerifiedProof, originalNotAfter, flowExpiry, familyExpiry int64) (*AccessResult, error) {
	if !s.IsMulti() || s.privado.RequireProof(proof) != nil {
		return nil, ErrUnauthorized
	}
	m := proof.Metadata()
	_, digest, ok := s.privadoProfile(m.ProfileID)
	if !ok || digest != m.ProfileDigest {
		return nil, ErrUnauthorized
	}
	now, e := s.now()
	if e != nil {
		return nil, e
	}
	expires := min(now.Unix()+300, m.NotAfter, m.ClaimsAsOf+300, originalNotAfter, flowExpiry, familyExpiry)
	if expires <= now.Unix() {
		return nil, ErrUnauthorized
	}
	actor, e := s.identity.SourceActorID(proof.Identity())
	if e != nil || actor != m.ActorID {
		return nil, ErrUnauthorized
	}
	jti, e := randomToken()
	if e != nil {
		return nil, e
	}
	notAfter := min(m.NotAfter, originalNotAfter)
	claims := identity.AccessClaims{Issuer: s.issuer.Issuer, Audience: s.issuer.Audience, Subject: actor, ID: jti, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: expires, PrincipalKind: identity.Human, SourceProfile: m.ProfileID, SourceProfileDigest: m.ProfileDigest, IdentityAuthority: "privado", SourceSubject: m.HolderDID, SourceVerifiedAt: m.SourceVerifiedAt, ClaimsAsOf: m.ClaimsAsOf, SourceNotAfter: &notAfter, Facts: proof.Facts()}
	access, e := s.signAccessClaims(claims, now)
	if e != nil {
		return nil, e
	}
	access.proof = proof
	return access, nil
}
func (s *Service) CompletePrivado(ctx context.Context, id string, recipient RecipientBinding, confirmation PrivadoConfirmation, renewalHandle string) (*CommittedPrivado, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !s.IsMulti() || !ValidUUID(id) || !recipient.Valid() || !identity.ValidActorID(confirmation.ExpectedActorID) || confirmation.ProofDigest == (Digest{}) {
		return nil, ErrInvalid
	}
	if _, ok := PrivadoHolderNetwork(confirmation.ExpectedHolderDID); !ok {
		return nil, ErrInvalid
	}
	snapshot, e := s.app.ReadPrivadoFlow(ctx, s.scope, id, recipient)
	if e != nil {
		return nil, e
	}
	p := snapshot.Challenge
	if snapshot.Offer == nil {
		return nil, ErrUnauthorized
	}
	offer := *snapshot.Offer
	request, cd, e := s.restorePrivadoChallenge(ctx, p)
	if e != nil {
		return nil, e
	}
	compact, e := s.openPrivadoOffer(offer, p, cd)
	if e != nil {
		return nil, e
	}
	if confirmation.ExpectedActorID != offer.ActorID || confirmation.ExpectedHolderDID != offer.HolderDID || confirmation.ProofDigest != offer.ProofDigest {
		return nil, ErrUnauthorized
	}
	var family Family
	var capture *PrivadoHandleCapture
	kind := Create
	if p.Mode == privado.Login {
		if confirmation.ExpectedSessionID != nil {
			return nil, ErrInvalid
		}
	} else if p.Mode == privado.Renew {
		if confirmation.ExpectedSessionID == nil || *confirmation.ExpectedSessionID != p.FamilyID || !ValidUUID(*confirmation.ExpectedSessionID) {
			return nil, ErrSessionChanged
		}
		expected := ExpectedSession{ActorID: confirmation.ExpectedActorID, SessionID: *confirmation.ExpectedSessionID}
		c, claims, e := s.privadoCapture(renewalHandle, recipient, &expected)
		if e != nil {
			return nil, e
		}
		if p.CurrentGeneration == nil || p.CurrentHandleHash == nil || c.Generation != *p.CurrentGeneration || c.HandleHash != *p.CurrentHandleHash {
			return nil, ErrUnauthorized
		}
		family, e = s.app.ReadPrivadoFamily(ctx, s.scope, c.FamilyID)
		if e != nil {
			return nil, e
		}
		now, e := s.now()
		if e != nil {
			return nil, e
		}
		if !c.Matches(family) || s.familyContext(family, claims, recipient, now) != nil || family.Generation != c.Generation || family.CurrentHandleHash != c.HandleHash || family.Subject != offer.HolderDID || family.Generation == math.MaxInt64 {
			return nil, ErrUnauthorized
		}
		if e = s.privadoFamilyContinuity(family); e != nil {
			return nil, e
		}
		capture = &c
		kind = Rotate
	} else {
		return nil, ErrUnauthorized
	}
	// Saved preview metadata is not authority. Reverify the ORIGINAL compact
	// response against the SAME owned current provider before any transaction.
	proof, e := s.privado.Verify(ctx, request, string(compact))
	if e != nil {
		return nil, privadoError(e)
	}
	m := proof.Metadata()
	if m.ActorID != offer.ActorID || m.HolderDID != offer.HolderDID || m.ProfileID != offer.ProfileID || m.ProfileDigest != offer.ProfileDigest || m.Provider != offer.Provider || m.ClaimsAsOf != offer.ClaimsAsOf || m.NotAfter != offer.NotAfter {
		return nil, ErrUnauthorized
	}
	now, e := s.now()
	if e != nil {
		return nil, e
	}
	if kind == Create {
		family = Family{Provider: FamilyPrivado, ID: uuid.NewString(), RequestID: p.ID, Scope: s.scope, Actor: m.ActorID, ProfileID: m.ProfileID, ProfileDigest: m.ProfileDigest, Authority: "privado", Subject: m.HolderDID, Kind: identity.Human, Recipient: recipient, CreatedAt: now, AbsoluteExpiresAt: now.Add(FamilyLifetime), LastRotatedAt: now}
	} else {
		family.Generation++
		family.LastRotatedAt = now
	}
	handle, e := s.privadoFamilyMaterial(&family, now)
	if e != nil {
		return nil, e
	}
	access, e := s.buildPrivadoAccess(proof, offer.NotAfter, p.ExpiresAt.Unix(), family.AbsoluteExpiresAt.Unix())
	if e != nil {
		return nil, e
	}
	access.sessionID = family.ID
	access.familyExpires = &family.AbsoluteExpiresAt
	gate := func() error {
		if e := s.challengeGate(ctx, p); e != nil {
			return e
		}
		if e := s.privado.RequireProof(proof); e != nil {
			return e
		}
		return access.RequireDeliverable()
	}
	if e = gate(); e != nil {
		return nil, e
	}
	commit, e := s.app.CompletePrivadoFlow(ctx, s.scope, snapshot, PrivadoCompletion{Kind: kind, Family: family, Capture: capture}, gate)
	if e != nil {
		return nil, e
	}
	if !commit.Committed || commit.Kind != kind {
		return nil, ErrUnavailable
	}
	result := &CommittedPrivado{result: &CommittedRenewal{access: access, refresh: handle, valid: true}}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if e = result.RequireDeliverable(); e != nil {
		return nil, e
	}
	return result, nil
}
