package ssosql

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	m "privacy-proxy/internal/ssotransaction"
)

func receipt(s *Store, r m.Record, op string) (Receipt, error) {
	c, e := m.CaptureRecord(r)
	if e != nil {
		return Receipt{}, ErrUnavailable
	}
	return Receipt{s, c, op}, nil
}
func conflict(e error) error {
	var pg *pgconn.PgError
	if errors.As(e, &pg) && pg.Code == "23505" {
		return ErrConflict
	}
	return ErrUnavailable
}
func (s *Store) InsertPending(ctx context.Context, p m.PendingRecord, g CommitGate) (Receipt, error) {
	if m.ValidatePending(p) != nil || g == nil {
		return Receipt{}, ErrInvalid
	}
	if s == nil || p.Scope != s.metadata.Scope {
		return Receipt{}, ErrConflict
	}
	p.ContextCiphertext = append([]byte(nil), p.ContextCiphertext...)
	ctx, cancel, tx, e := s.start(ctx, "app", true)
	if e != nil {
		return Receipt{}, e
	}
	defer cancel()
	defer rollback(tx)
	now, e := s.now()
	if e != nil {
		return Receipt{}, e
	}
	if now < p.CreatedAt || now >= p.ExpiresAt {
		return Receipt{}, ErrExpired
	}
	r := m.Record{Pending: p, Phase: m.Pending}
	old, e := s.row(ctx, tx, p.ID, true)
	if e == nil {
		a, _ := m.CaptureRecord(old)
		b, _ := m.CaptureRecord(r)
		if a != b {
			return Receipt{}, ErrConflict
		}
		if e = s.commit(ctx, tx, g, true); e != nil {
			return Receipt{}, e
		}
		if e = s.alive(old); e != nil {
			return Receipt{}, e
		}
		return receipt(s, old, "insert-idempotent")
	}
	if !errors.Is(e, ErrNotFound) {
		return Receipt{}, e
	}
	if e = s.usage(ctx, tx, 1, 0, int64(len(p.ContextCiphertext)), 1); e != nil {
		return Receipt{}, e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO ops_sso_v1.transactions(id,namespace,epoch,broker_epoch,phase,client_id,client_catalog_digest,identity_digest,recipient,state_hash,redirect_hash,pkce_s256,context_key_id,context_ciphertext,created_us,expires_us)VALUES($1::uuid,$2,$3::uuid,$4::uuid,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`, p.ID, p.Scope.Namespace[:], p.Scope.Epoch, p.Scope.BrokerRecoveryEpoch, p.ClientID, p.ClientCatalogDigest[:], p.IdentityDigest[:], p.Recipient[:], p.StateHash[:], p.RedirectHash[:], p.PKCES256[:], p.ContextKeyID, p.ContextCiphertext, int64(p.CreatedAt), int64(p.ExpiresAt))
	if e != nil {
		return Receipt{}, conflict(e)
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrUnavailable
	}
	if e = s.commit(ctx, tx, g, true); e != nil {
		return Receipt{}, e
	}
	if e = s.alive(r); e != nil {
		return Receipt{}, e
	}
	return receipt(s, r, "insert")
}
func (s *Store) PrepareReady(ctx context.Context, c m.Capture, v m.ReadyFields, g CommitGate) (Receipt, error) {
	if !c.Valid() || c.Phase != m.Pending || g == nil || len(v.GrantCiphertext) < 28 || len(v.GrantCiphertext) > m.MaxGrantCipherBytes {
		return Receipt{}, ErrInvalid
	}
	if s == nil || c.Scope != s.metadata.Scope {
		return Receipt{}, ErrConflict
	}
	ctx, cancel, tx, e := s.start(ctx, "app", true)
	if e != nil {
		return Receipt{}, e
	}
	defer cancel()
	defer rollback(tx)
	r, e := s.row(ctx, tx, c.ID, true)
	if e != nil {
		return Receipt{}, e
	}
	actual, e := m.CaptureRecord(r)
	if e != nil || actual != c {
		return Receipt{}, ErrConflict
	}
	if m.ValidateReady(r.Pending, v) != nil {
		return Receipt{}, ErrInvalid
	}
	now, e := s.now()
	if e != nil {
		return Receipt{}, e
	}
	if now < v.PreparedAt || now >= v.CodeExpiresAt {
		return Receipt{}, ErrExpired
	}
	v.GrantCiphertext = append([]byte(nil), v.GrantCiphertext...)
	retain, e := m.Add(v.CodeExpiresAt, s.metadata.Limits.AuditRetentionSeconds*1000000)
	if e != nil {
		return Receipt{}, ErrInvalid
	}
	r.Ready = &v
	r.RetainUntil = &retain
	r.Phase = m.Ready
	if m.ValidateRecord(r) != nil {
		return Receipt{}, ErrInvalid
	}
	if e = s.usage(ctx, tx, 0, 1, int64(len(v.GrantCiphertext)), 0); e != nil {
		return Receipt{}, e
	}
	scope := s.metadata.Scope
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.transactions SET phase=2,code_hash=$5,code_expires_us=$6,grant_key_id=$7,grant_ciphertext=$8,actor_id=$9,profile_id=$10,profile_digest=$11,family_id=$12::uuid,family_generation=$13,family_handle_hash=$14,access_digest=$15,access_expires_us=$16,family_expires_us=$17,ready_us=$18,code_response_digest=$19,code_response_bytes=$20,retain_until_us=$21 WHERE id=$1::uuid AND namespace=$2 AND epoch=$3::uuid AND broker_epoch=$4::uuid AND phase=1`, c.ID, scope.Namespace[:], scope.Epoch, scope.BrokerRecoveryEpoch, v.CodeHash[:], int64(v.CodeExpiresAt), v.GrantKeyID, v.GrantCiphertext, v.ActorID, v.ProfileID, v.ProfileDigest[:], v.FamilyID, v.FamilyGeneration, v.FamilyHandleHash[:], v.AccessDigest[:], int64(v.AccessExpiresAt), int64(v.FamilyExpiresAt), int64(v.PreparedAt), v.CodeResponseDigest[:], int64(v.CodeResponseBytes), int64(retain))
	if e != nil {
		return Receipt{}, conflict(e)
	}
	if tag.RowsAffected() != 1 {
		return Receipt{}, ErrConflict
	}
	if e = s.commit(ctx, tx, g, true); e != nil {
		return Receipt{}, e
	}
	if e = s.alive(r); e != nil {
		return Receipt{}, e
	}
	return receipt(s, r, "ready")
}
func (s *Store) Consume(ctx context.Context, c m.Capture, out m.PreparedOutput, g CommitGate) (Receipt, error) {
	if !c.Valid() || c.Phase != m.Ready || !out.Digest.Valid() || out.Bytes < 1 || out.Bytes > m.MaxPreparedResponseBytes || g == nil {
		return Receipt{}, ErrInvalid
	}
	if s == nil || c.Scope != s.metadata.Scope {
		return Receipt{}, ErrConflict
	}
	ctx, cancel, tx, e := s.start(ctx, "app", true)
	if e != nil {
		return Receipt{}, e
	}
	defer cancel()
	defer rollback(tx)
	r, e := s.row(ctx, tx, c.ID, true)
	if e != nil {
		return Receipt{}, e
	}
	actual, e := m.CaptureRecord(r)
	if e != nil || actual != c {
		return Receipt{}, ErrConflict
	}
	now, e := s.now()
	if e != nil {
		return Receipt{}, e
	}
	if now < r.Ready.PreparedAt || now >= r.Ready.CodeExpiresAt {
		return Receipt{}, ErrExpired
	}
	bytes := len(r.Pending.ContextCiphertext) + len(r.Ready.GrantCiphertext)
	scope := s.metadata.Scope
	tag, e := tx.Exec(ctx, `UPDATE ops_sso_v1.transactions SET phase=3,consumed_us=$5,token_response_digest=$6,token_response_bytes=$7,context_ciphertext=NULL,grant_ciphertext=NULL WHERE id=$1::uuid AND namespace=$2 AND epoch=$3::uuid AND broker_epoch=$4::uuid AND phase=2`, c.ID, scope.Namespace[:], scope.Epoch, scope.BrokerRecoveryEpoch, int64(now), out.Digest[:], int64(out.Bytes))
	if e != nil || tag.RowsAffected() != 1 {
		return Receipt{}, ErrUnavailable
	}
	if e = s.usage(ctx, tx, -1, -1, -int64(bytes), 0); e != nil {
		return Receipt{}, e
	}
	r.Pending.ContextCiphertext = nil
	r.Ready.GrantCiphertext = nil
	r.Phase = m.Consumed
	r.ConsumedAt = &now
	r.TokenResponse = &out
	if e = s.commit(ctx, tx, g, true); e != nil {
		return Receipt{}, e
	}
	if now, e = s.now(); e != nil {
		return Receipt{}, e
	}
	if now >= r.Ready.CodeExpiresAt {
		return Receipt{}, ErrExpired
	}
	return receipt(s, r, "consume")
}
