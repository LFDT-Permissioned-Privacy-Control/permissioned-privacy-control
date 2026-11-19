package identitybroker

import (
	"context"
	"errors"
	"math"
	"time"

	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/privado"
)

// The exact profile digest and family identity are authenticated by the family
// payload/AAD. Indices name its canonical predicates, not arbitrary new facts.
// This fits the existing2KiB family cap even at the maximum16 predicates.
type privadoSessionEvidence struct {
	ClaimsAsOf int64    `json:"claimsAsOf"`
	VerifiedAt int64    `json:"verifiedAt"`
	NotAfter   int64    `json:"notAfter"`
	Predicates []uint32 `json:"predicates"`
}

func (s *Service) newPrivadoSessionEvidence(proof *privado.VerifiedProof, until int64) (privadoSessionEvidence, error) {
	if s.privado.RequireProof(proof) != nil {
		return privadoSessionEvidence{}, ErrUnauthorized
	}
	m := proof.Metadata()
	profile, digest, ok := s.privadoProfile(m.ProfileID)
	if !ok || digest != m.ProfileDigest || until > m.NotAfter || until > m.ClaimsAsOf+300 {
		return privadoSessionEvidence{}, ErrUnauthorized
	}
	facts := proof.Facts()
	indices := []uint32{}
	for i, predicate := range profile.Predicates {
		for _, fact := range facts {
			if fact.Kind == "privado.predicate" && fact.Value == predicate.ID {
				indices = append(indices, uint32(i+1))
				break
			}
		}
	}
	if len(indices) != len(facts) {
		return privadoSessionEvidence{}, ErrUnauthorized
	}
	return privadoSessionEvidence{m.ClaimsAsOf, m.SourceVerifiedAt, until, indices}, nil
}

// Expiry is checked separately so authentic expired evidence can require a new
// proof. A malformed snapshot is always denied, never treated as an empty cache.
func (s *Service) privadoEvidenceFacts(f Family, e privadoSessionEvidence, now time.Time) ([]identity.Fact, error) {
	profile, digest, ok := s.privadoProfile(f.ProfileID)
	if !ok || digest != f.ProfileDigest || len(profile.Predicates) > privado.MaxPredicates || e.Predicates == nil || len(e.Predicates) > len(profile.Predicates) ||
		e.ClaimsAsOf < 0 || e.ClaimsAsOf > math.MaxInt64-300 || e.VerifiedAt < e.ClaimsAsOf || e.VerifiedAt > now.Unix() || e.NotAfter <= e.VerifiedAt || e.NotAfter > e.ClaimsAsOf+300 || e.NotAfter > f.AbsoluteExpiresAt.Unix() {
		return nil, ErrUnauthorized
	}
	actor, err := s.identity.SourceActorID(identity.SourceIdentity{ProfileID: f.ProfileID, Kind: identity.Human, Authority: "privado", Subject: f.Subject})
	if err != nil || actor != f.Actor {
		return nil, ErrUnauthorized
	}
	facts := make([]identity.Fact, 0, len(e.Predicates))
	seen := map[uint32]bool{}
	var previous uint32
	for _, index := range e.Predicates {
		if index <= previous || int(index) > len(profile.Predicates) {
			return nil, ErrUnauthorized
		}
		previous = index
		seen[index] = true
		facts = append(facts, identity.Fact{Kind: "privado.predicate", Value: profile.Predicates[index-1].ID})
	}
	for i, predicate := range profile.Predicates {
		if !predicate.Optional && !seen[uint32(i+1)] {
			return nil, ErrUnauthorized
		}
	}
	return facts, nil
}

func (s *Service) buildPrivadoEvidenceAccess(f Family, e privadoSessionEvidence, now time.Time) (*AccessResult, error) {
	facts, err := s.privadoEvidenceFacts(f, e, now)
	if err != nil || now.Unix() >= e.NotAfter {
		return nil, ErrUnauthorized
	}
	jti, err := randomToken()
	if err != nil {
		return nil, err
	}
	until := e.NotAfter
	claims := identity.AccessClaims{Issuer: s.issuer.Issuer, Audience: s.issuer.Audience, Subject: f.Actor, ID: jti, IssuedAt: now.Unix(), NotBefore: now.Unix(), Expires: until, PrincipalKind: identity.Human, SourceProfile: f.ProfileID, SourceProfileDigest: f.ProfileDigest, IdentityAuthority: "privado", SourceSubject: f.Subject, SourceVerifiedAt: e.VerifiedAt, ClaimsAsOf: e.ClaimsAsOf, SourceNotAfter: &until, Facts: facts}
	profile, _, _ := s.privadoProfile(f.ProfileID)
	if profile.Kind == identity.PrivadoIdentity {
		claims.SourceNotAfter = nil
	}
	return s.signAccessClaims(claims, now)
}

var errPrivadoEvidenceExpired = errors.New("original Privado session evidence expired before commit")

func (s *Service) renewPrivadoEvidence(ctx context.Context, claims refreshClaims, recipient RecipientBinding, handle string) (*CommittedRenewal, bool, error) {
	var access *AccessResult
	var successor string
	var finalGate func() error
	needsProof := false
	commit, err := s.app.WithProviderFamily(ctx, s.scope, FamilyPrivado, claims.FamilyID, func(f Family) (FamilyDecision, error) {
		now, err := s.now()
		if err != nil {
			return FamilyDecision{}, err
		}
		if err = s.familyContext(f, claims, recipient, now); err != nil {
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		if f.Generation != claims.Generation || f.CurrentHandleHash != tokenHash(handle) || f.Generation == math.MaxInt64 {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(f, now)}, nil
		}
		payload, err := s.openPrivadoFamily(f)
		if err != nil {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(f, now)}, nil
		}
		if payload.Evidence == nil {
			needsProof = true
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		evidence := *payload.Evidence
		if _, err = s.privadoEvidenceFacts(f, evidence, now); err != nil {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(f, now)}, nil
		}
		if now.Unix() >= evidence.NotAfter {
			needsProof = true
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		access, err = s.buildPrivadoEvidenceAccess(f, evidence, now)
		if err != nil {
			return FamilyDecision{}, err
		}
		f.Generation++
		f.LastRotatedAt = now
		successor, err = s.privadoFamilyMaterial(&f, now, &evidence)
		if err != nil {
			return FamilyDecision{}, err
		}
		access.familyExpires = &f.AbsoluteExpiresAt
		access.sessionID = f.ID
		finalGate = func() error {
			if ctx.Err() != nil {
				return ErrUnavailable
			}
			at, err := s.now()
			if err != nil {
				return err
			}
			if at.Unix() >= evidence.NotAfter {
				return errPrivadoEvidenceExpired
			}
			if err = s.familyContext(f, claims, recipient, at); err != nil {
				return err
			}
			return access.RequireDeliverable()
		}
		if err = finalGate(); err != nil {
			return FamilyDecision{}, err
		}
		return FamilyDecision{Kind: Rotate, Family: f}, nil
	}, func() error {
		if finalGate == nil {
			return ErrUnavailable
		}
		return finalGate()
	})
	// This private error is returned ONLY by the original precommit gate. The
	// store rolls its transaction back. Never fall back after generic SQL/commit
	// errors, cancellation, or a committed rotation whose delivery later expires.
	if errors.Is(err, errPrivadoEvidenceExpired) && !commit.Committed && ctx.Err() == nil {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !commit.Committed {
		return nil, false, ErrUnavailable
	}
	if needsProof && commit.Kind == DenyUnchanged {
		return nil, true, nil
	}
	if commit.Kind != Rotate || access == nil {
		return nil, false, ErrRelogin
	}
	result := &CommittedRenewal{access: access, refresh: successor, valid: true}
	if ctx.Err() != nil {
		return nil, false, ErrUnavailable
	}
	if err = result.RequireDeliverable(); err != nil {
		return nil, false, err
	}
	return result, false, nil
}
