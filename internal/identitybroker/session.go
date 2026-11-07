package identitybroker

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"math"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/identity"
	"privacy-proxy/internal/identitybroker/azure"
)

type Start struct {
	AuthorizationURL string
	ExpiresAt        time.Time
}

func (s *Service) BeginAzure(ctx context.Context, profileID string, recipient RecipientBinding) (Start, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	profile, ok := s.broker.Profile(profileID)
	if !ok || profile.Definition.Kind != identity.AzureHuman || !recipient.Valid() {
		return Start{}, ErrInvalid
	}
	now, err := s.now()
	if err != nil {
		return Start{}, err
	}
	state, err := randomToken()
	if err != nil {
		return Start{}, err
	}
	nonce, err := randomToken()
	if err != nil {
		return Start{}, err
	}
	pkce, err := randomToken()
	if err != nil {
		return Start{}, err
	}
	requestID, err := uuid.NewRandom()
	if err != nil {
		return Start{}, ErrUnavailable
	}
	pending := Pending{ID: requestID.String(), Scope: s.scope, StateHash: tokenHash(state), ProfileID: profileID, ProfileDigest: profile.Digest, Recipient: recipient, EncryptionKeyID: s.aes.active, CreatedAt: now, ExpiresAt: now.Add(PendingLifetime)}
	plain, err := json.Marshal(pendingSecrets{nonce, pkce})
	if err != nil {
		return Start{}, ErrUnavailable
	}
	pending.Ciphertext, err = s.aes.seal(pending.EncryptionKeyID, plain, pendingAAD(pending))
	if err != nil {
		return Start{}, err
	}
	authorize, err := s.provider.AuthorizationURL(profileID, state, nonce, pkce)
	if err != nil {
		return Start{}, ErrUnavailable
	}
	gate := func() error {
		current, err := s.now()
		if err != nil {
			return err
		}
		if current.Before(now) || !current.Before(pending.ExpiresAt) || ctx.Err() != nil {
			return ErrUnauthorized
		}
		return nil
	}
	if err := s.store.InsertPending(ctx, s.scope, pending, gate); err != nil {
		return Start{}, err
	}
	if err := gate(); err != nil {
		return Start{}, err
	}
	return Start{authorize, pending.ExpiresAt}, nil
}
func (s *Service) CompleteAzure(ctx context.Context, state, code string, recipient RecipientBinding) (*CommittedLogin, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	if !randomTokenShape(state) || len(code) == 0 || len(code) > 8192 || !recipient.Valid() {
		return nil, ErrInvalid
	}
	var access *AccessResult
	var refresh string
	var finalGate func() error
	committed, err := s.store.WithPending(ctx, s.scope, tokenHash(state), recipient, func(pending Pending, tx PendingTx) error {
		if !pending.Valid() || pending.Scope != s.scope || pending.StateHash != tokenHash(state) || subtle.ConstantTimeCompare(pending.Recipient[:], recipient[:]) != 1 {
			return ErrUnauthorized
		}
		grantStart, err := s.now()
		if err != nil {
			return err
		}
		if grantStart.Before(pending.CreatedAt) || !grantStart.Before(pending.ExpiresAt) {
			return ErrUnauthorized
		}
		profile, ok := s.broker.Profile(pending.ProfileID)
		if !ok || profile.Definition.Kind != identity.AzureHuman || profile.Digest != pending.ProfileDigest {
			return ErrUnauthorized
		}
		plain, err := s.aes.open(pending.EncryptionKeyID, pending.Ciphertext, pendingAAD(pending), 2048)
		if err != nil {
			return err
		}
		var secrets pendingSecrets
		if decodeClosed(plain, &secrets, 2048) != nil || !randomTokenShape(secrets.Nonce) || !randomTokenShape(secrets.PKCEVerifier) {
			return ErrUnauthorized
		}
		evidence, err := s.provider.ExchangeCode(ctx, pending.ProfileID, code, secrets.PKCEVerifier, secrets.Nonce)
		if err != nil {
			return providerError(err)
		}
		access, err = s.buildAccess(evidence, grantStart)
		if err != nil {
			return err
		}
		family, handle, err := s.initialFamily(pending, evidence, access, grantStart)
		if err != nil {
			return err
		}
		refresh = handle
		if err := tx.InsertFamily(family); err != nil {
			return err
		}
		access.familyExpires = &family.AbsoluteExpiresAt
		access.sessionID = family.ID
		finalGate = func() error {
			if err := s.pendingGate(pending, grantStart, ctx); err != nil {
				return err
			}
			return access.RequireDeliverable()
		}
		if err := s.pendingGate(pending, grantStart, ctx); err != nil {
			return err
		}
		return access.RequireDeliverable()
	}, func() error {
		if finalGate == nil {
			return ErrUnavailable
		}
		return finalGate()
	})
	if err != nil {
		return nil, err
	}
	if !committed.Committed || committed.Kind != Create || access == nil {
		return nil, ErrUnavailable
	}
	result := &CommittedLogin{access, refresh, true}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := result.RequireDeliverable(); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Service) pendingGate(p Pending, start time.Time, ctx context.Context) error {
	now, err := s.now()
	if err != nil {
		return err
	}
	if ctx.Err() != nil || now.Before(start) || !now.Before(p.ExpiresAt) {
		return ErrUnauthorized
	}
	return nil
}
func (s *Service) initialFamily(pending Pending, evidence azure.Evidence, access *AccessResult, start time.Time) (Family, string, error) {
	identitySource := evidence.Identity()
	if identitySource.Kind != identity.Human || identitySource.Tenant == nil {
		return Family{}, "", ErrUnauthorized
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return Family{}, "", ErrUnavailable
	}
	now, err := s.now()
	if err != nil {
		return Family{}, "", err
	}
	continuity := evidence.Continuity(start.Unix())
	family := Family{ID: id.String(), RequestID: pending.ID, Scope: s.scope, Actor: access.metadata.ActorID, ProfileID: identitySource.ProfileID, ProfileDigest: evidence.ProfileDigest(), Authority: identitySource.Authority, Tenant: *identitySource.Tenant, Subject: identitySource.Subject, Kind: identity.Human, OIDCSubjectHash: Digest(continuity.OIDCSubjectHash), NonceHash: Digest(continuity.NonceHash), OriginalAuthTime: continuity.OriginalAuthTime, Recipient: pending.Recipient, Generation: 0, EncryptionKeyID: s.aes.active, CreatedAt: start, AbsoluteExpiresAt: start.Add(FamilyLifetime), LastRotatedAt: now}
	handle, err := s.familyMaterial(&family, evidence.RefreshToken(), now)
	if err != nil {
		return Family{}, "", err
	}
	if !family.Valid() {
		return Family{}, "", ErrUnauthorized
	}
	return family, handle, nil
}
func (s *Service) familyMaterial(family *Family, refresh string, now time.Time) (string, error) {
	if len(refresh) == 0 || len(refresh) > MaxRefreshBytes {
		return "", ErrUnauthorized
	}
	jti, err := randomToken()
	if err != nil {
		return "", err
	}
	claims := refreshClaims{Issuer: s.issuer.Issuer, Audience: "ops-renewal", FamilyID: family.ID, Actor: family.Actor, ProfileID: family.ProfileID, ProfileDigest: family.ProfileDigest, Generation: family.Generation, ID: jti, IssuedAt: now.Unix(), Expires: family.AbsoluteExpiresAt.Unix(), Epoch: s.scope.State.RecoveryEpoch}
	handle, err := s.mac.mintRefresh(claims)
	if err != nil {
		return "", err
	}
	family.CurrentHandleHash = tokenHash(handle)
	family.EncryptionKeyID = s.aes.active
	family.Ciphertext, err = s.aes.seal(family.EncryptionKeyID, []byte(refresh), familyAAD(*family))
	if err != nil {
		return "", err
	}
	return handle, nil
}
func (s *Service) familyContext(f Family, claims refreshClaims, recipient RecipientBinding, now time.Time) error {
	if !f.Valid() || f.Scope != s.scope || f.ID != claims.FamilyID || f.Actor != claims.Actor || f.ProfileID != claims.ProfileID || f.ProfileDigest != claims.ProfileDigest || f.AbsoluteExpiresAt.Unix() != claims.Expires || f.Scope.State.RecoveryEpoch != claims.Epoch || subtle.ConstantTimeCompare(f.Recipient[:], recipient[:]) != 1 {
		return ErrUnauthorized
	}
	if now.Before(f.CreatedAt) || !now.Before(f.AbsoluteExpiresAt) || now.Unix() >= claims.Expires || f.RevokedAt != nil {
		return ErrUnauthorized
	}
	return nil
}
func (s *Service) RenewAzure(ctx context.Context, handle string, recipient RecipientBinding) (*CommittedRenewal, error) {
	return s.renewAzure(ctx, handle, recipient, nil)
}
func (s *Service) RenewAzureForSession(ctx context.Context, handle string, recipient RecipientBinding, expected ExpectedSession) (*CommittedRenewal, error) {
	if !expected.Valid() {
		return nil, ErrInvalid
	}
	return s.renewAzure(ctx, handle, recipient, &expected)
}
func (s *Service) renewAzure(ctx context.Context, handle string, recipient RecipientBinding, expected *ExpectedSession) (*CommittedRenewal, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	now, err := s.now()
	if err != nil {
		return nil, err
	}
	if !recipient.Valid() {
		return nil, ErrUnauthorized
	}
	claims, err := s.mac.parseRefresh(handle, s.issuer.Issuer, s.scope.State.RecoveryEpoch, now.Unix())
	if err != nil {
		return nil, err
	}
	if expected != nil && (claims.Actor != expected.ActorID || claims.FamilyID != expected.SessionID) {
		return nil, ErrSessionChanged
	}
	var access *AccessResult
	var successor string
	var finalGate func() error
	committed, err := s.store.WithFamily(ctx, s.scope, claims.FamilyID, func(family Family) (FamilyDecision, error) {
		grantStart, err := s.now()
		if err != nil {
			return FamilyDecision{}, err
		}
		if err := s.familyContext(family, claims, recipient, grantStart); err != nil {
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		if claims.Generation != family.Generation || family.CurrentHandleHash != tokenHash(handle) {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(family, grantStart)}, nil
		}
		profile, ok := s.broker.Profile(family.ProfileID)
		if !ok || profile.Digest != family.ProfileDigest || profile.Definition.Kind != identity.AzureHuman {
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		if family.Generation == math.MaxInt64 {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(family, grantStart)}, nil
		}
		plain, err := s.aes.open(family.EncryptionKeyID, family.Ciphertext, familyAAD(family), MaxFamilyCipherBytes)
		if err != nil {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(family, grantStart)}, nil
		}
		continuity := azure.Continuity{OID: family.Subject, Tenant: family.Tenant, OIDCSubjectHash: [32]byte(family.OIDCSubjectHash), NonceHash: [32]byte(family.NonceHash), OriginalAuthTime: family.OriginalAuthTime, InitialLoginAt: family.CreatedAt.Unix()}
		evidence, err := s.provider.Refresh(ctx, family.ProfileID, string(plain), continuity)
		if err != nil {
			if err == azure.ErrRelogin || err == azure.ErrEvidence {
				return FamilyDecision{Kind: RevokeDeny, Family: revoke(family, grantStart)}, nil
			}
			return FamilyDecision{}, providerError(err)
		}
		identitySource := evidence.Identity()
		actor, err := s.identity.SourceActorID(identitySource)
		if err != nil || actor != family.Actor || identitySource.Authority != family.Authority || identitySource.Subject != family.Subject || identitySource.Tenant == nil || *identitySource.Tenant != family.Tenant {
			return FamilyDecision{Kind: RevokeDeny, Family: revoke(family, grantStart)}, nil
		}
		access, err = s.buildAccess(evidence, grantStart)
		if err != nil {
			return FamilyDecision{}, err
		}
		current, err := s.now()
		if err != nil {
			return FamilyDecision{}, err
		}
		if err := s.familyContext(family, claims, recipient, current); err != nil {
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		family.Generation++
		family.LastRotatedAt = current
		successor, err = s.familyMaterial(&family, evidence.RefreshToken(), current)
		if err != nil {
			return FamilyDecision{}, err
		}
		access.familyExpires = &family.AbsoluteExpiresAt
		access.sessionID = family.ID
		finalGate = func() error {
			at, err := s.now()
			if err != nil {
				return err
			}
			if err := s.familyContext(family, claims, recipient, at); err != nil {
				return err
			}
			return access.RequireDeliverable()
		}
		if ctx.Err() != nil {
			return FamilyDecision{}, ErrUnavailable
		}
		if err := access.RequireDeliverable(); err != nil {
			return FamilyDecision{}, err
		}
		return FamilyDecision{Kind: Rotate, Family: family}, nil
	}, func() error {
		if finalGate == nil {
			return ErrUnavailable
		}
		return finalGate()
	})
	if err != nil {
		return nil, err
	}
	if !committed.Committed {
		return nil, ErrUnavailable
	}
	if committed.Kind != Rotate || access == nil {
		return nil, ErrRelogin
	}
	result := &CommittedRenewal{access, successor, true}
	if ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := result.RequireDeliverable(); err != nil {
		return nil, err
	}
	return result, nil
}
func revoke(f Family, at time.Time) Family {
	if f.RevokedAt == nil {
		f.RevokedAt = &at
	}
	return f
}
func (s *Service) Revoke(ctx context.Context, handle string, recipient RecipientBinding) error {
	return s.revokeSession(ctx, handle, recipient, nil)
}
func (s *Service) RevokeForSession(ctx context.Context, handle string, recipient RecipientBinding, expected ExpectedSession) error {
	if !expected.Valid() {
		return ErrInvalid
	}
	return s.revokeSession(ctx, handle, recipient, &expected)
}
func (s *Service) revokeSession(ctx context.Context, handle string, recipient RecipientBinding, expected *ExpectedSession) error {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	now, err := s.now()
	if err != nil {
		return err
	}
	if !recipient.Valid() {
		return ErrUnauthorized
	}
	claims, err := s.mac.parseRefresh(handle, s.issuer.Issuer, s.scope.State.RecoveryEpoch, now.Unix())
	if err != nil {
		return err
	}
	if expected != nil && (claims.Actor != expected.ActorID || claims.FamilyID != expected.SessionID) {
		return ErrSessionChanged
	}
	committed, err := s.store.WithFamily(ctx, s.scope, claims.FamilyID, func(f Family) (FamilyDecision, error) {
		now, err := s.now()
		if err != nil {
			return FamilyDecision{}, err
		}
		if err := s.familyContext(f, claims, recipient, now); err != nil {
			return FamilyDecision{Kind: DenyUnchanged}, nil
		}
		return FamilyDecision{Kind: RevokeSuccess, Family: revoke(f, now)}, nil
	}, nil)
	if err != nil {
		return err
	}
	if !committed.Committed {
		return ErrUnavailable
	}
	if committed.Kind != RevokeSuccess {
		return ErrUnauthorized
	}
	return nil
}
