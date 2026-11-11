package ssosql

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	m "privacy-proxy/internal/ssotransaction"
)

func scanRecord(row pgx.Row, broker m.Digest) (m.Record, error) {
	var r m.Record
	var ns, cat, identity, recipient, state, redirect, pkce, code, pdigest, handle, access, codeResponse, tokenResponse []byte
	var codeExp, gen, accessExp, familyExp, ready, codeBytes, consumed, tokenBytes, retain *int64
	var grantKey, actor, profile, family *string
	var grant []byte
	var bounded bool
	var storedBytes int64
	e := row.Scan(&r.Pending.ID, &ns, &r.Pending.Scope.Epoch, &r.Pending.Scope.BrokerRecoveryEpoch, &r.Phase, &r.Pending.ClientID, &cat, &identity, &recipient, &state, &redirect, &pkce, &r.Pending.ContextKeyID, &r.Pending.ContextCiphertext, &r.Pending.CreatedAt, &r.Pending.ExpiresAt, &code, &codeExp, &grantKey, &grant, &actor, &profile, &pdigest, &family, &gen, &handle, &access, &accessExp, &familyExp, &ready, &codeResponse, &codeBytes, &consumed, &tokenResponse, &tokenBytes, &retain, &storedBytes, &bounded)
	if errors.Is(e, pgx.ErrNoRows) {
		return m.Record{}, ErrNotFound
	}
	if e != nil || !bounded {
		return m.Record{}, ErrUnavailable
	}
	for _, b := range [][]byte{ns, cat, identity, recipient, state, redirect, pkce} {
		if len(b) != 32 {
			return m.Record{}, ErrUnavailable
		}
	}
	copy(r.Pending.Scope.Namespace[:], ns)
	r.Pending.Scope.BrokerNamespace = broker
	copy(r.Pending.ClientCatalogDigest[:], cat)
	copy(r.Pending.IdentityDigest[:], identity)
	copy(r.Pending.Recipient[:], recipient)
	copy(r.Pending.StateHash[:], state)
	copy(r.Pending.RedirectHash[:], redirect)
	copy(r.Pending.PKCES256[:], pkce)
	if r.Phase == m.Pending {
		if code != nil || codeExp != nil || grantKey != nil || grant != nil || actor != nil || profile != nil || pdigest != nil || family != nil || gen != nil || handle != nil || access != nil || accessExp != nil || familyExp != nil || ready != nil || codeResponse != nil || codeBytes != nil || retain != nil {
			return m.Record{}, ErrUnavailable
		}
	} else {
		if len(code) != 32 || codeExp == nil || grantKey == nil || actor == nil || profile == nil || len(pdigest) != 32 || family == nil || gen == nil || len(handle) != 32 || len(access) != 32 || accessExp == nil || familyExp == nil || ready == nil || len(codeResponse) != 32 || codeBytes == nil || *codeBytes < 1 || *codeBytes > m.MaxPreparedResponseBytes || retain == nil {
			return m.Record{}, ErrUnavailable
		}
		v := &m.ReadyFields{CodeExpiresAt: m.Micros(*codeExp), GrantKeyID: *grantKey, GrantCiphertext: grant, ActorID: *actor, ProfileID: *profile, FamilyID: *family, FamilyGeneration: *gen, AccessExpiresAt: m.Micros(*accessExp), FamilyExpiresAt: m.Micros(*familyExp), PreparedAt: m.Micros(*ready), CodeResponseBytes: uint32(*codeBytes)}
		copy(v.CodeHash[:], code)
		copy(v.ProfileDigest[:], pdigest)
		copy(v.FamilyHandleHash[:], handle)
		copy(v.AccessDigest[:], access)
		copy(v.CodeResponseDigest[:], codeResponse)
		r.Ready = v
		t := m.Micros(*retain)
		r.RetainUntil = &t
	}
	if consumed != nil {
		t := m.Micros(*consumed)
		r.ConsumedAt = &t
	}
	if tokenResponse != nil || tokenBytes != nil {
		if len(tokenResponse) != 32 || tokenBytes == nil || *tokenBytes < 1 || *tokenBytes > m.MaxPreparedResponseBytes {
			return m.Record{}, ErrUnavailable
		}
		v := &m.PreparedOutput{Bytes: uint32(*tokenBytes)}
		copy(v.Digest[:], tokenResponse)
		r.TokenResponse = v
	}
	if m.ValidateRecord(r) != nil || storedBytes != int64(len(r.Pending.ContextCiphertext)+len(grant)) {
		return m.Record{}, ErrUnavailable
	}
	return m.Clone(r), nil
}
func (s *Store) row(ctx context.Context, q querier, id string, lock bool) (m.Record, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	v := s.metadata.Scope
	return scanRecord(q.QueryRow(ctx, `SELECT `+rowProjection+scopedRow+suffix, id, v.Namespace[:], v.Epoch, v.BrokerRecoveryEpoch), v.BrokerNamespace)
}
func (s *Store) alive(r m.Record) error {
	now, e := s.now()
	if e != nil {
		return e
	}
	if r.Phase == m.Pending && (now < r.Pending.CreatedAt || now >= r.Pending.ExpiresAt) || r.Phase == m.Ready && (now < r.Ready.PreparedAt || now >= r.Ready.CodeExpiresAt) {
		return ErrExpired
	}
	return nil
}
func (s *Store) ReadFlow(ctx context.Context, id string, recipient m.Digest) (m.Record, error) {
	if !m.ValidUUID(id) || !recipient.Valid() {
		return m.Record{}, ErrInvalid
	}
	ctx, cancel, tx, e := s.start(ctx, "app", false)
	if e != nil {
		return m.Record{}, e
	}
	defer cancel()
	defer rollback(tx)
	r, e := s.row(ctx, tx, id, false)
	if e != nil {
		return m.Record{}, e
	}
	if r.Pending.Recipient != recipient {
		return m.Record{}, ErrNotFound
	}
	if e = s.alive(r); e != nil {
		return m.Record{}, e
	}
	if e = s.commit(ctx, tx, nil, false); e != nil {
		return m.Record{}, e
	}
	if e = s.alive(r); e != nil {
		return m.Record{}, e
	}
	return r, nil
}
func (s *Store) LookupCode(ctx context.Context, hash m.Digest) (m.Record, error) {
	if !hash.Valid() {
		return m.Record{}, ErrInvalid
	}
	ctx, cancel, tx, e := s.start(ctx, "app", false)
	if e != nil {
		return m.Record{}, e
	}
	defer cancel()
	defer rollback(tx)
	v := s.metadata.Scope
	r, e := scanRecord(tx.QueryRow(ctx, `SELECT `+rowProjection+` FROM ops_sso_v1.transactions WHERE code_hash=$1 AND namespace=$2 AND epoch=$3::uuid AND broker_epoch=$4::uuid`, hash[:], v.Namespace[:], v.Epoch, v.BrokerRecoveryEpoch), v.BrokerNamespace)
	if e != nil {
		return m.Record{}, e
	}
	if r.Phase != m.Ready {
		return m.Record{}, ErrConflict
	}
	if e = s.alive(r); e != nil {
		return m.Record{}, e
	}
	if e = s.commit(ctx, tx, nil, false); e != nil {
		return m.Record{}, e
	}
	if e = s.alive(r); e != nil {
		return m.Record{}, e
	}
	return r, nil
}
