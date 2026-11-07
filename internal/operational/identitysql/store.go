// Package identitysql is the explicitly retained operational PostgreSQL store
// for broker one-use logins and renewal families. It stores no user directory,
// memberships, provider access tokens or policy configuration.
package identitysql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
)

type Store struct {
	pool  *pgxpool.Pool
	scope b.Scope
	clock identity.Clock
	mode  string
}

var _ b.Store = (*Store)(nil)

func Open(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock) (*Store, error) {
	return open(ctx, dsn, scope, clock, "app")
}
func OpenRetention(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock) (*Store, error) {
	return open(ctx, dsn, scope, clock, "retention")
}
func open(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock, mode string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" || !scope.Valid() || clock == nil {
		return nil, b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, b.ErrUnavailable
	}
	cfg.MaxConns = 8
	cfg.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, b.ErrUnavailable
	}
	s := &Store{pool: pool, scope: scope, clock: clock, mode: mode}
	if checkSchema(ctx, pool) != nil || checkV2Privileges(ctx, pool, "", mode) != nil || checkState(ctx, pool, scope) != nil {
		pool.Close()
		return nil, b.ErrUnavailable
	}
	return s, nil
}
func (s *Store) Close() { s.pool.Close() }
func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}
func closeConnection(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}

type beginner interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
}

func begin(ctx context.Context, pool beginner) (pgx.Tx, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, b.ErrUnavailable
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','2s',true)`); err != nil {
		rollback(tx)
		return nil, b.ErrUnavailable
	}
	return tx, nil
}
func checkState(ctx context.Context, q querier, scope b.Scope) error {
	var ok bool
	err := q.QueryRow(ctx, `SELECT schema_version=2 AND migration_checksum=$1 AND namespace=$2 AND recovery_epoch=$3::uuid AND ready FROM ops_identity_v2.metadata WHERE singleton`, SchemaChecksum(), scope.Namespace.String(), scope.State.RecoveryEpoch).Scan(&ok)
	if err != nil || !ok {
		return b.ErrUnavailable
	}
	return nil
}
func (s *Store) valid(scope b.Scope) bool {
	return s.mode == "app" && scope == s.scope && scope.Valid()
}
func (s *Store) now() (time.Time, error) {
	n := s.clock().UTC().Truncate(time.Microsecond)
	if n.Unix() < 0 || n.Unix() > 253402300799 {
		return time.Time{}, b.ErrUnavailable
	}
	return n, nil
}
func CapacityLock(kind string) (int32, int32) {
	d := b.Hash("ops.broker.capacity/v1", []byte(kind))
	return int32(binary.BigEndian.Uint32(d[:4])), int32(binary.BigEndian.Uint32(d[4:8]))
}
func (t *pendingTx) capacity(kind string, max int) error {
	a, z := CapacityLock(kind)
	if _, err := t.tx.Exec(t.ctx, `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, a, z); err != nil {
		return b.ErrUnavailable
	}
	now, err := t.store.now()
	if err != nil {
		return err
	}
	query := `SELECT count(*) FROM(SELECT 1 FROM ops_identity_v2.pending_requests WHERE expires_at>$1 ORDER BY expires_at LIMIT $2)bounded`
	if kind == "family" {
		query = `SELECT count(*) FROM(SELECT 1 FROM ops_identity_v2.renewal_families WHERE revoked_at IS NULL AND absolute_expires_at>$1 ORDER BY absolute_expires_at LIMIT $2)bounded`
	}
	var n int
	if err := t.tx.QueryRow(t.ctx, query, now, max+1).Scan(&n); err != nil {
		return b.ErrUnavailable
	}
	if n >= max {
		return b.ErrConflict
	}
	return nil
}
func (s *Store) InsertPending(ctx context.Context, scope b.Scope, p b.Pending, gate func() error) error {
	if !s.valid(scope) || !p.Valid() || p.Scope != scope || gate == nil {
		return b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return err
	}
	defer rollback(tx)
	if err := checkState(ctx, tx, scope); err != nil {
		return err
	}
	t := &pendingTx{ctx: ctx, tx: tx, store: s}
	if err := t.capacity("pending", b.MaxPending); err != nil {
		return err
	}
	if err := gate(); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO ops_identity_v2.pending_requests(request_id,namespace,recovery_epoch,state_hash,profile_id,profile_digest,recipient_hash,encryption_key_id,secret_ciphertext,created_at,expires_at)VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11)`, p.ID, scope.Namespace.String(), scope.State.RecoveryEpoch, p.StateHash[:], p.ProfileID, p.ProfileDigest, p.Recipient[:], p.EncryptionKeyID, p.Ciphertext, p.CreatedAt, p.ExpiresAt)
	if err != nil {
		return b.ErrUnavailable
	}
	if err := checkState(ctx, tx, scope); err != nil {
		return err
	}
	if err := gate(); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return b.ErrUnavailable
	}
	return nil
}

type pendingTx struct {
	ctx      context.Context
	tx       pgx.Tx
	store    *Store
	pending  *b.Pending
	inserted bool
	active   bool
}

func (t *pendingTx) InsertFamily(f b.Family) error {
	if !t.active || t.inserted || t.pending == nil || !f.Valid() || f.Provider != b.FamilyAzure || f.Scope != t.store.scope || f.Generation != 0 || f.RevokedAt != nil || f.RequestID != t.pending.ID || f.ProfileID != t.pending.ProfileID || f.ProfileDigest != t.pending.ProfileDigest || f.Recipient != t.pending.Recipient {
		return b.ErrInvalid
	}
	if err := t.capacity("family", b.MaxFamilies); err != nil {
		return err
	}
	now, err := t.store.now()
	if err != nil {
		return err
	}
	if now.Before(f.CreatedAt) || !now.Before(f.AbsoluteExpiresAt) {
		return b.ErrUnauthorized
	}
	if err := insertFamily(t.ctx, t.tx, f); err != nil {
		return err
	}
	t.inserted = true
	return nil
}
func (s *Store) WithPending(ctx context.Context, scope b.Scope, hash b.Digest, recipient b.RecipientBinding, callback func(b.Pending, b.PendingTx) error, gate func() error) (b.Commit, error) {
	if !s.valid(scope) || hash == (b.Digest{}) || !recipient.Valid() || callback == nil || gate == nil {
		return b.Commit{}, b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return b.Commit{}, err
	}
	defer rollback(tx)
	if err := checkState(ctx, tx, scope); err != nil {
		return b.Commit{}, err
	}
	p := b.Pending{Scope: scope, StateHash: hash, Recipient: recipient}
	err = tx.QueryRow(ctx, `DELETE FROM ops_identity_v2.pending_requests WHERE namespace=$1 AND recovery_epoch=$2::uuid AND state_hash=$3 AND recipient_hash=$4 RETURNING request_id::text,profile_id,profile_digest,encryption_key_id,CASE WHEN octet_length(secret_ciphertext)<=2048 THEN secret_ciphertext ELSE NULL END,created_at,expires_at`, scope.Namespace.String(), scope.State.RecoveryEpoch, hash[:], recipient[:]).Scan(&p.ID, &p.ProfileID, &p.ProfileDigest, &p.EncryptionKeyID, &p.Ciphertext, &p.CreatedAt, &p.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return b.Commit{}, b.ErrUnauthorized
	}
	if err != nil || !p.Valid() {
		return b.Commit{}, b.ErrUnavailable
	}
	// Time is read after DELETE has acquired the row lock, never before waiting.
	now, err := s.now()
	if err != nil {
		return b.Commit{}, err
	}
	if now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) {
		return b.Commit{}, b.ErrUnauthorized
	}
	t := &pendingTx{ctx: ctx, tx: tx, store: s, pending: &p, active: true}
	err = callback(p, t)
	t.active = false
	if err != nil {
		return b.Commit{}, err
	}
	if !t.inserted {
		return b.Commit{}, b.ErrInvalid
	}
	if err := checkState(ctx, tx, scope); err != nil {
		return b.Commit{}, err
	}
	if err := gate(); err != nil {
		return b.Commit{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return b.Commit{}, b.ErrUnavailable
	}
	return b.Commit{Committed: true, Kind: b.Create}, nil
}

const familyColumns = `provider_kind,family_id::text,originating_request_id::text,actor_id,profile_id,profile_digest,identity_authority,source_tenant,source_subject,principal_kind,oidc_subject_hash,login_nonce_hash,original_auth_time,recipient_hash,generation,current_handle_hash,encryption_key_id,CASE WHEN provider_kind='azure-human' AND octet_length(refresh_ciphertext)<=33792 OR provider_kind='privado' AND octet_length(refresh_ciphertext)<=2048 THEN refresh_ciphertext ELSE NULL END,created_at,absolute_expires_at,last_rotated_at,revoked_at`

func scanFamily(row pgx.Row, scope b.Scope) (b.Family, error) {
	f := b.Family{Scope: scope}
	var oidc, nonce, recipient, hash []byte
	var tenant *string
	err := row.Scan(&f.Provider, &f.ID, &f.RequestID, &f.Actor, &f.ProfileID, &f.ProfileDigest, &f.Authority, &tenant, &f.Subject, &f.Kind, &oidc, &nonce, &f.OriginalAuthTime, &recipient, &f.Generation, &hash, &f.EncryptionKeyID, &f.Ciphertext, &f.CreatedAt, &f.AbsoluteExpiresAt, &f.LastRotatedAt, &f.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, b.ErrUnauthorized
	}
	if err != nil || len(recipient) != 32 || len(hash) != 32 || (f.Provider == b.FamilyAzure && (tenant == nil || len(oidc) != 32 || len(nonce) != 32)) || (f.Provider == b.FamilyPrivado && (tenant != nil || oidc != nil || nonce != nil)) {
		return f, b.ErrUnavailable
	}
	if tenant != nil {
		f.Tenant = *tenant
	}
	copy(f.OIDCSubjectHash[:], oidc)
	copy(f.NonceHash[:], nonce)
	copy(f.Recipient[:], recipient)
	copy(f.CurrentHandleHash[:], hash)
	if !f.Valid() {
		return f, b.ErrUnavailable
	}
	return f, nil
}
func sameImmutable(a, z b.Family) bool {
	return familyIdentityEqual(a, z)
}
func familyIdentityEqual(a, z b.Family) bool {
	auth := a.OriginalAuthTime == nil && z.OriginalAuthTime == nil || a.OriginalAuthTime != nil && z.OriginalAuthTime != nil && *a.OriginalAuthTime == *z.OriginalAuthTime
	return auth && a.Provider == z.Provider && a.ID == z.ID && a.RequestID == z.RequestID && a.Scope == z.Scope && a.Actor == z.Actor && a.ProfileID == z.ProfileID && a.ProfileDigest == z.ProfileDigest && a.Authority == z.Authority && a.Tenant == z.Tenant && a.Subject == z.Subject && a.Kind == z.Kind && a.OIDCSubjectHash == z.OIDCSubjectHash && a.NonceHash == z.NonceHash && a.Recipient == z.Recipient && a.CreatedAt.Equal(z.CreatedAt) && a.AbsoluteExpiresAt.Equal(z.AbsoluteExpiresAt)
}
func (s *Store) WithFamily(ctx context.Context, scope b.Scope, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	return s.withFamily(ctx, scope, b.FamilyAzure, id, callback, gate, false)
}
func (s *Store) WithProviderFamily(ctx context.Context, scope b.Scope, provider b.FamilyProvider, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error) (b.Commit, error) {
	if provider != b.FamilyAzure && provider != b.FamilyPrivado {
		return b.Commit{}, b.ErrInvalid
	}
	return s.withFamily(ctx, scope, provider, id, callback, gate, true)
}
func (s *Store) withFamily(ctx context.Context, scope b.Scope, provider b.FamilyProvider, id string, callback func(b.Family) (b.FamilyDecision, error), gate func() error, flow bool) (b.Commit, error) {
	if !s.valid(scope) || !b.ValidUUID(id) || callback == nil {
		return b.Commit{}, b.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	tx, err := begin(ctx, s.pool)
	if err != nil {
		return b.Commit{}, err
	}
	defer rollback(tx)
	if err := checkState(ctx, tx, scope); err != nil {
		return b.Commit{}, err
	}
	if flow {
		if err := lockPrivadoFlow(ctx, tx, scope); err != nil {
			return b.Commit{}, err
		}
	}
	old, err := scanFamily(tx.QueryRow(ctx, `SELECT `+familyColumns+` FROM ops_identity_v2.renewal_families WHERE namespace=$1 AND recovery_epoch=$2::uuid AND family_id=$3::uuid FOR UPDATE`, scope.Namespace.String(), scope.State.RecoveryEpoch, id), scope)
	if err != nil {
		return b.Commit{}, err
	}
	if old.Provider != provider {
		return b.Commit{}, b.ErrUnauthorized
	}
	input := old
	input.Ciphertext = bytes.Clone(old.Ciphertext)
	if old.OriginalAuthTime != nil {
		value := *old.OriginalAuthTime
		input.OriginalAuthTime = &value
	}
	decision, err := callback(input)
	if err != nil {
		return b.Commit{}, err
	}
	if err := s.applyFamilyDecision(ctx, tx, scope, old, decision, gate); err != nil {
		return b.Commit{}, err
	}
	if err := checkState(ctx, tx, scope); err != nil {
		return b.Commit{}, err
	}
	if decision.Kind == b.Rotate {
		if err := gate(); err != nil {
			return b.Commit{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return b.Commit{}, b.ErrUnavailable
	}
	return b.Commit{Committed: true, Kind: decision.Kind}, nil
}

// applyFamilyDecision is the one shared monotonic family mutation engine.
// Provider calls and result construction belong to the caller's prepared path.
func (s *Store) applyFamilyDecision(ctx context.Context, tx pgx.Tx, scope b.Scope, old b.Family, decision b.FamilyDecision, gate func() error) error {
	id := old.ID
	f := decision.Family
	switch decision.Kind {
	case b.DenyUnchanged:
	case b.Rotate:
		if gate == nil || old.RevokedAt != nil || !f.Valid() || !sameImmutable(old, f) || old.Generation == int64(^uint64(0)>>1) || f.Generation != old.Generation+1 || f.RevokedAt != nil || f.CurrentHandleHash == old.CurrentHandleHash || f.LastRotatedAt.Before(old.LastRotatedAt) {
			return b.ErrInvalid
		}
		now, err := s.now()
		if err != nil {
			return err
		}
		if now.Before(f.LastRotatedAt) || !now.Before(f.AbsoluteExpiresAt) {
			return b.ErrUnauthorized
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_identity_v2.renewal_families SET generation=$4,current_handle_hash=$5,encryption_key_id=$6,refresh_ciphertext=$7,last_rotated_at=$8 WHERE namespace=$1 AND recovery_epoch=$2::uuid AND family_id=$3::uuid`, scope.Namespace.String(), scope.State.RecoveryEpoch, id, f.Generation, f.CurrentHandleHash[:], f.EncryptionKeyID, f.Ciphertext, f.LastRotatedAt)
		if err != nil || tag.RowsAffected() != 1 {
			return b.ErrUnavailable
		}
	case b.RevokeDeny, b.RevokeSuccess:
		if !f.Valid() || !sameImmutable(old, f) || f.RevokedAt == nil || f.RevokedAt.Before(old.CreatedAt) {
			return b.ErrInvalid
		}
		tag, err := tx.Exec(ctx, `UPDATE ops_identity_v2.renewal_families SET revoked_at=COALESCE(revoked_at,$4) WHERE namespace=$1 AND recovery_epoch=$2::uuid AND family_id=$3::uuid`, scope.Namespace.String(), scope.State.RecoveryEpoch, id, *f.RevokedAt)
		if err != nil || tag.RowsAffected() != 1 {
			return b.ErrUnavailable
		}
	default:
		return b.ErrInvalid
	}
	return nil
}
