package identitybroker

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"privacy-proxy/internal/identity"
	"time"
)

// SessionBinding is an owner-bound, read-only capture. It cannot mint access,
// rotate a renewal handle or substitute for verification of the original JWT.
type SessionBinding struct {
	owner     *Service
	handle    string
	recipient RecipientBinding
	expected  ExpectedSession
	metadata  SessionBindingMetadata
}
type SessionBindingMetadata struct {
	Scope                                       Scope
	ActorID, FamilyID, ProfileID, ProfileDigest string
	Provider                                    FamilyProvider
	Generation                                  int64
	HandleHash                                  Digest
	AbsoluteExpiresAt                           time.Time
}

func (b *SessionBinding) MetadataFor(s *Service) (SessionBindingMetadata, error) {
	if b == nil || s == nil || b.owner != s || !b.expected.Valid() {
		return SessionBindingMetadata{}, ErrUnauthorized
	}
	return b.metadata, nil
}
func (s *Service) AuthenticateCurrentSession(ctx context.Context, handle string, recipient RecipientBinding, expected ExpectedSession) (*SessionBinding, error) {
	if s == nil || !expected.Valid() || !recipient.Valid() {
		return nil, ErrInvalid
	}
	b := &SessionBinding{owner: s, handle: handle, recipient: recipient, expected: expected}
	m, err := s.readCurrentSession(ctx, b)
	if err != nil {
		return nil, err
	}
	b.metadata = m
	return b, nil
}
func (s *Service) RecheckCurrentSession(ctx context.Context, b *SessionBinding) error {
	if _, err := b.MetadataFor(s); err != nil {
		return err
	}
	m, err := s.readCurrentSession(ctx, b)
	if err != nil {
		return err
	}
	if m != b.metadata {
		return ErrSessionChanged
	}
	return nil
}
func (s *Service) readCurrentSession(ctx context.Context, b *SessionBinding) (SessionBindingMetadata, error) {
	ctx, cancel := brokerOperation(ctx)
	defer cancel()
	start, err := s.now()
	if err != nil {
		return SessionBindingMetadata{}, err
	}
	claims, err := s.mac.parseRefresh(b.handle, s.issuer.Issuer, s.scope.State.RecoveryEpoch, start.Unix())
	if err != nil {
		return SessionBindingMetadata{}, err
	}
	if claims.Actor != b.expected.ActorID || claims.FamilyID != b.expected.SessionID {
		return SessionBindingMetadata{}, ErrSessionChanged
	}
	provider := FamilyAzure
	if _, _, ok := s.privadoProfile(claims.ProfileID); s.IsMulti() && ok {
		provider = FamilyPrivado
	} else if p, ok := s.broker.Profile(claims.ProfileID); !ok || p.Definition.Kind != identity.AzureHuman {
		return SessionBindingMetadata{}, ErrUnauthorized
	}
	withFamily := s.store.WithFamily
	if s.IsMulti() {
		withFamily = func(c context.Context, scope Scope, id string, decision func(Family) (FamilyDecision, error), gate func() error) (Commit, error) {
			return s.app.WithProviderFamily(c, scope, provider, id, decision, gate)
		}
	}
	var found bool
	var m SessionBindingMetadata
	var finalGate func() error
	committed, err := withFamily(ctx, s.scope, claims.FamilyID, func(f Family) (FamilyDecision, error) {
		at, e := s.now()
		if e != nil {
			return FamilyDecision{}, e
		}
		if f.Provider != provider || s.familyContext(f, claims, b.recipient, at) != nil || f.Generation != claims.Generation || f.CurrentHandleHash != tokenHash(b.handle) {
			return FamilyDecision{}, ErrSessionChanged
		}
		var tenant *string
		if provider == FamilyAzure {
			tenant = &f.Tenant
		}
		actor, e := s.identity.SourceActorID(identity.SourceIdentity{ProfileID: f.ProfileID, Kind: identity.Human, Authority: f.Authority, Subject: f.Subject, Tenant: tenant})
		if e != nil || actor != f.Actor {
			return FamilyDecision{}, ErrUnauthorized
		}
		if provider == FamilyPrivado {
			if e = s.privadoFamilyContinuity(f); e != nil {
				return FamilyDecision{}, e
			}
		} else {
			p, ok := s.broker.Profile(f.ProfileID)
			if !ok || p.Digest != f.ProfileDigest || p.Definition.Kind != identity.AzureHuman {
				return FamilyDecision{}, ErrUnauthorized
			}
			if _, e = s.aes.open(f.EncryptionKeyID, f.Ciphertext, familyAAD(f), MaxFamilyCipherBytes); e != nil {
				return FamilyDecision{}, e
			}
		}
		m = SessionBindingMetadata{s.scope, f.Actor, f.ID, f.ProfileID, f.ProfileDigest, provider, f.Generation, f.CurrentHandleHash, f.AbsoluteExpiresAt}
		finalGate = func() error {
			at, e := s.now()
			if e != nil {
				return e
			}
			if ctx.Err() != nil || at.Before(start) {
				return ErrUnavailable
			}
			return s.familyContext(f, claims, b.recipient, at)
		}
		if e = finalGate(); e != nil {
			return FamilyDecision{}, e
		}
		found = true
		return FamilyDecision{Kind: DenyUnchanged}, nil
	}, func() error {
		if finalGate == nil {
			return ErrUnavailable
		}
		return finalGate()
	})
	if err != nil {
		return SessionBindingMetadata{}, err
	}
	if !committed.Committed || committed.Kind != DenyUnchanged || !found || finalGate == nil {
		return SessionBindingMetadata{}, ErrUnavailable
	}
	// DenyUnchanged intentionally bypasses the store's mutation gate. This
	// explicit gate after its known read COMMIT is therefore mandatory.
	if err = finalGate(); err != nil {
		return SessionBindingMetadata{}, err
	}
	return m, nil
}

// CheckHandoffSecrets is bounded startup-only key-role separation. No key or
// fingerprint escapes the owning Service; callers supply all selected clients.
func (s *Service) CheckHandoffSecrets(contextKey, grantKey SecretBinding, clients []SecretBinding) error {
	if s == nil || s.mac == nil || s.aes == nil || len(clients) < 1 || len(clients) > 128 {
		return ErrInvalid
	}
	all := append([]SecretBinding{contextKey, grantKey}, clients...)
	refs := map[string]bool{}
	source := s.broker.CommonSettings()
	for _, r := range source.RenewalKeys {
		refs[r.FromEnv] = true
	}
	for _, r := range source.EncryptionKeys {
		refs[r.FromEnv] = true
	}
	seen := map[[32]byte]bool{}
	for i, b := range all {
		if b.FromEnv == "" || refs[b.FromEnv] || i < 2 && len(b.Value) != 32 || i >= 2 && (len(b.Value) < 32 || len(b.Value) > 256) {
			return ErrInvalid
		}
		if i >= 2 {
			for _, v := range b.Value {
				if v < 0x21 || v > 0x7e {
					return ErrInvalid
				}
			}
		}
		var nonzero byte
		for _, v := range b.Value {
			nonzero |= v
		}
		if nonzero == 0 {
			return ErrInvalid
		}
		refs[b.FromEnv] = true
		d := sha256.Sum256(b.Value)
		if seen[d] {
			return ErrInvalid
		}
		seen[d] = true
		for _, key := range s.mac.mac {
			if len(key) == len(b.Value) {
				x := sha256.Sum256(key)
				if subtle.ConstantTimeCompare(x[:], d[:]) == 1 {
					return ErrInvalid
				}
			}
		}
		if len(b.Value) == 32 {
			for _, x := range s.aes.fingerprints {
				if subtle.ConstantTimeCompare(x[:], d[:]) == 1 {
					return ErrInvalid
				}
			}
		}
		for _, key := range [][]byte{s.private, s.private.Seed()} {
			if len(key) == len(b.Value) {
				x := sha256.Sum256(key)
				if subtle.ConstantTimeCompare(x[:], d[:]) == 1 {
					return ErrInvalid
				}
			}
		}
	}
	return nil
}
