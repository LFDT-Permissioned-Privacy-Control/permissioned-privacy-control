package identitysql

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/jackc/pgx/v5"
	"privacy-proxy/internal/identity"
	b "privacy-proxy/internal/identitybroker"
)

type ProofStore struct{ store *Store }

var _ b.MultiStore = (*Store)(nil)
var _ b.PrivadoProofStore = (*ProofStore)(nil)

func OpenPrivateV2(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock) (*Store, error) {
	return open(ctx, dsn, scope, clock, "app")
}
func OpenProofV2(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock) (*ProofStore, error) {
	s, e := open(ctx, dsn, scope, clock, "proof")
	if e != nil {
		return nil, e
	}
	return &ProofStore{s}, nil
}
func OpenRetentionV2(ctx context.Context, dsn string, scope b.Scope, clock identity.Clock) (*Store, error) {
	return open(ctx, dsn, scope, clock, "retention")
}
func (s *ProofStore) Close() { s.store.Close() }
func (s *Store) Binding() b.PrivadoStoreBinding {
	role := "private-app"
	if s.mode == "proof" {
		role = "public-proof"
	} else if s.mode == "retention" {
		role = "retention"
	}
	return b.PrivadoStoreBinding{Scope: s.scope, SchemaVersion: 2, Role: role}
}
func (s *ProofStore) Binding() b.PrivadoStoreBinding { return s.store.Binding() }
func lockPrivadoFlow(ctx context.Context, tx pgx.Tx, scope b.Scope) error {
	a, z := CapacityLock("privado-flow/v1:" + scope.Namespace.String())
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::integer,$2::integer)`, a, z); e != nil {
		return b.ErrUnavailable
	}
	return nil
}

const challengeColumns = `request_id::text,profile_id,profile_digest,recipient_hash,mode,expected_actor_id,family_id::text,current_generation,current_handle_hash,encryption_key_id,CASE WHEN octet_length(context_ciphertext)<=2048 THEN context_ciphertext ELSE NULL END,created_at,expires_at`
const offerColumns = `request_id::text,context_digest,proof_digest,holder_did,actor_id,network,profile_id,profile_digest,source_auth_digest,identity_digest,profile_plan_digest,network_plan_digest,document_plan_digest,claims_as_of,not_after,verified_at,encryption_key_id,CASE WHEN octet_length(proof_ciphertext)<=1048604 THEN proof_ciphertext ELSE NULL END`

func scanChallenge(row pgx.Row, scope b.Scope) (b.PrivadoChallengeRecord, error) {
	p := b.PrivadoChallengeRecord{Scope: scope}
	var expected, family *string
	var recipient, hash []byte
	e := row.Scan(&p.ID, &p.ProfileID, &p.ProfileDigest, &recipient, &p.Mode, &expected, &family, &p.CurrentGeneration, &hash, &p.EncryptionKeyID, &p.Ciphertext, &p.CreatedAt, &p.ExpiresAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, b.ErrUnauthorized
	}
	if e != nil || len(recipient) != 32 || hash != nil && len(hash) != 32 {
		return p, b.ErrUnavailable
	}
	if expected != nil {
		p.ExpectedActorID = *expected
	}
	if family != nil {
		p.FamilyID = *family
	}
	copy(p.Recipient[:], recipient)
	if hash != nil {
		h := b.Digest{}
		copy(h[:], hash)
		p.CurrentHandleHash = &h
	}
	if !p.Valid() {
		return p, b.ErrUnavailable
	}
	return p, nil
}
func scanOffer(row pgx.Row, scope b.Scope) (b.PrivadoOfferRecord, error) {
	p := b.PrivadoOfferRecord{Scope: scope}
	var cd, pd []byte
	e := row.Scan(&p.RequestID, &cd, &pd, &p.HolderDID, &p.ActorID, &p.Network, &p.ProfileID, &p.ProfileDigest, &p.SourceAuthDigest, &p.Provider.IdentityDigest, &p.Provider.ProfilePlanDigest, &p.Provider.NetworkPlanDigest, &p.Provider.DocumentPlanDigest, &p.ClaimsAsOf, &p.NotAfter, &p.VerifiedAt, &p.EncryptionKeyID, &p.Ciphertext)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, b.ErrUnauthorized
	}
	if e != nil || len(cd) != 32 || len(pd) != 32 {
		return p, b.ErrUnavailable
	}
	copy(p.ContextDigest[:], cd)
	copy(p.ProofDigest[:], pd)
	if !p.Valid() {
		return p, b.ErrUnavailable
	}
	return p, nil
}
func readChallenge(ctx context.Context, q querier, scope b.Scope, id string) (b.PrivadoChallengeRecord, error) {
	return scanChallenge(q.QueryRow(ctx, `SELECT `+challengeColumns+` FROM ops_identity_v2.privado_challenges WHERE namespace=$1 AND recovery_epoch=$2::uuid AND request_id=$3::uuid`, scope.Namespace.String(), scope.State.RecoveryEpoch, id), scope)
}
func readOffer(ctx context.Context, q querier, scope b.Scope, id string) (b.PrivadoOfferRecord, error) {
	return scanOffer(q.QueryRow(ctx, `SELECT `+offerColumns+` FROM ops_identity_v2.privado_offers WHERE namespace=$1 AND recovery_epoch=$2::uuid AND request_id=$3::uuid`, scope.Namespace.String(), scope.State.RecoveryEpoch, id), scope)
}
func readFamily(ctx context.Context, q querier, scope b.Scope, id string, lock bool) (b.Family, error) {
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanFamily(q.QueryRow(ctx, `SELECT `+familyColumns+` FROM ops_identity_v2.renewal_families WHERE namespace=$1 AND recovery_epoch=$2::uuid AND family_id=$3::uuid`+suffix, scope.Namespace.String(), scope.State.RecoveryEpoch, id), scope)
}
func checkChallengeCurrent(s *Store, p b.PrivadoChallengeRecord) error {
	now, e := s.now()
	if e != nil {
		return e
	}
	if now.Before(p.CreatedAt) || !now.Before(p.ExpiresAt) {
		return b.ErrUnauthorized
	}
	return nil
}
func endPrivado(ctx context.Context, tx pgx.Tx, scope b.Scope, gate func() error) error {
	if e := checkState(ctx, tx, scope); e != nil {
		return e
	}
	if gate != nil {
		if e := gate(); e != nil {
			return e
		}
	}
	if e := tx.Commit(ctx); e != nil {
		return b.ErrUnavailable
	}
	return nil
}
func (s *ProofStore) ReadPrivadoChallenge(ctx context.Context, scope b.Scope, id string) (b.PrivadoChallengeRecord, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if s == nil || s.store.mode != "proof" || scope != s.store.scope || !b.ValidUUID(id) {
		return b.PrivadoChallengeRecord{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.store.pool)
	if e != nil {
		return b.PrivadoChallengeRecord{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.PrivadoChallengeRecord{}, e
	}
	p, e := readChallenge(ctx, tx, scope, id)
	if e != nil {
		return p, e
	}
	if e = checkChallengeCurrent(s.store, p); e != nil {
		return p, e
	}
	if e = endPrivado(ctx, tx, scope, nil); e != nil {
		return b.PrivadoChallengeRecord{}, e
	}
	return p, nil
}
func (s *Store) ReadPrivadoFamily(ctx context.Context, scope b.Scope, id string) (b.Family, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !s.valid(scope) || !b.ValidUUID(id) {
		return b.Family{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.pool)
	if e != nil {
		return b.Family{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.Family{}, e
	}
	f, e := readFamily(ctx, tx, scope, id, false)
	if e != nil {
		return f, e
	}
	if e = endPrivado(ctx, tx, scope, nil); e != nil {
		return b.Family{}, e
	}
	return f, nil
}
func challengeQuota(ctx context.Context, tx pgx.Tx, scope b.Scope) error {
	var n int64
	if tx.QueryRow(ctx, `SELECT count(*) FROM(SELECT 1 FROM ops_identity_v2.privado_challenges WHERE namespace=$1 ORDER BY request_id LIMIT 10001)bounded`, scope.Namespace.String()).Scan(&n) != nil {
		return b.ErrUnavailable
	}
	if n >= b.MaxPrivadoChallenges {
		return b.ErrConflict
	}
	return nil
}
func insertChallenge(ctx context.Context, tx pgx.Tx, p b.PrivadoChallengeRecord) error {
	var expected, family any
	if p.ExpectedActorID != "" {
		expected = p.ExpectedActorID
	}
	if p.FamilyID != "" {
		family = p.FamilyID
	}
	var hash any
	if p.CurrentHandleHash != nil {
		hash = p.CurrentHandleHash[:]
	}
	_, e := tx.Exec(ctx, `INSERT INTO ops_identity_v2.privado_challenges(request_id,namespace,recovery_epoch,profile_id,profile_digest,recipient_hash,mode,expected_actor_id,family_id,current_generation,current_handle_hash,encryption_key_id,context_ciphertext,created_at,expires_at)VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9::uuid,$10,$11,$12,$13,$14,$15)`, p.ID, p.Scope.Namespace.String(), p.Scope.State.RecoveryEpoch, p.ProfileID, p.ProfileDigest, p.Recipient[:], p.Mode, expected, family, p.CurrentGeneration, hash, p.EncryptionKeyID, p.Ciphertext, p.CreatedAt, p.ExpiresAt)
	if e != nil {
		return b.ErrUnavailable
	}
	return nil
}
func (s *Store) InsertPrivadoLoginChallenge(ctx context.Context, scope b.Scope, p b.PrivadoChallengeRecord, gate func() error) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !s.valid(scope) || !p.Valid() || p.Scope != scope || p.Mode != "login" || gate == nil {
		return b.ErrInvalid
	}
	tx, e := begin(ctx, s.pool)
	if e != nil {
		return e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return e
	}
	if e = lockPrivadoFlow(ctx, tx, scope); e != nil {
		return e
	}
	if e = challengeQuota(ctx, tx, scope); e != nil {
		return e
	}
	if e = checkChallengeCurrent(s, p); e != nil {
		return e
	}
	if e = gate(); e != nil {
		return e
	}
	if e = insertChallenge(ctx, tx, p); e != nil {
		return e
	}
	return endPrivado(ctx, tx, scope, gate)
}
func (s *ProofStore) InstallPrivadoOffer(ctx context.Context, scope b.Scope, expected b.PrivadoChallengeRecord, p b.PrivadoOfferRecord, gate func() error) (b.PrivadoOfferCommit, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if s == nil || s.store.mode != "proof" || scope != s.store.scope || !expected.Valid() || expected.Scope != scope || !p.Valid() || p.Scope != scope || p.RequestID != expected.ID || p.ProfileID != expected.ProfileID || p.ProfileDigest != expected.ProfileDigest || expected.ExpectedActorID != "" && p.ActorID != expected.ExpectedActorID || gate == nil {
		return b.PrivadoOfferCommit{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.store.pool)
	if e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	if e = lockPrivadoFlow(ctx, tx, scope); e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	actual, e := readChallenge(ctx, tx, scope, expected.ID)
	if e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	if !reflect.DeepEqual(actual, expected) {
		return b.PrivadoOfferCommit{}, b.ErrUnauthorized
	}
	if e = checkChallengeCurrent(s.store, actual); e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	existing, e := readOffer(ctx, tx, scope, expected.ID)
	if e == nil {
		if e = endPrivado(ctx, tx, scope, gate); e != nil {
			return b.PrivadoOfferCommit{}, e
		}
		return b.PrivadoOfferCommit{Committed: true, Kind: b.OfferExisting, Existing: &existing}, nil
	}
	if !errors.Is(e, b.ErrUnauthorized) {
		return b.PrivadoOfferCommit{}, e
	}
	var n, size int64
	if tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(proof_ciphertext)::bigint),0) FROM(SELECT proof_ciphertext FROM ops_identity_v2.privado_offers WHERE namespace=$1 ORDER BY request_id LIMIT 65)bounded`, scope.Namespace.String()).Scan(&n, &size) != nil {
		return b.PrivadoOfferCommit{}, b.ErrUnavailable
	}
	if n >= b.MaxPrivadoOffers || size > b.MaxPrivadoOfferBytes-int64(len(p.Ciphertext)) {
		return b.PrivadoOfferCommit{}, b.ErrConflict
	}
	if e = gate(); e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO ops_identity_v2.privado_offers(request_id,namespace,recovery_epoch,context_digest,proof_digest,holder_did,actor_id,network,profile_id,profile_digest,source_auth_digest,identity_digest,profile_plan_digest,network_plan_digest,document_plan_digest,claims_as_of,not_after,verified_at,encryption_key_id,proof_ciphertext)VALUES($1::uuid,$2,$3::uuid,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`, p.RequestID, scope.Namespace.String(), scope.State.RecoveryEpoch, p.ContextDigest[:], p.ProofDigest[:], p.HolderDID, p.ActorID, p.Network, p.ProfileID, p.ProfileDigest, p.SourceAuthDigest, p.Provider.IdentityDigest, p.Provider.ProfilePlanDigest, p.Provider.NetworkPlanDigest, p.Provider.DocumentPlanDigest, p.ClaimsAsOf, p.NotAfter, p.VerifiedAt, p.EncryptionKeyID, p.Ciphertext)
	if e != nil {
		return b.PrivadoOfferCommit{}, b.ErrUnavailable
	}
	if e = endPrivado(ctx, tx, scope, gate); e != nil {
		return b.PrivadoOfferCommit{}, e
	}
	return b.PrivadoOfferCommit{Committed: true, Kind: b.OfferInserted}, nil
}
func sameFamily(a, z b.Family) bool {
	return familyIdentityEqual(a, z) && a.Generation == z.Generation && a.CurrentHandleHash == z.CurrentHandleHash && a.EncryptionKeyID == z.EncryptionKeyID && bytes.Equal(a.Ciphertext, z.Ciphertext) && a.LastRotatedAt.Equal(z.LastRotatedAt) && reflect.DeepEqual(a.RevokedAt, z.RevokedAt)
}

func (s *Store) BeginPrivadoRenewChallenge(ctx context.Context, scope b.Scope, capture b.PrivadoHandleCapture, expected b.Family, p b.PrivadoChallengeRecord, gate func() error) (b.PrivadoBeginCommit, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !s.valid(scope) || !capture.Valid() || capture.Scope != scope || !expected.Valid() || expected.Provider != b.FamilyPrivado || !p.Valid() || p.Scope != scope || p.Mode != "renew" || p.FamilyID != capture.FamilyID || p.Recipient != capture.Recipient || p.ExpectedActorID != capture.ActorID || p.ProfileID != capture.ProfileID || p.ProfileDigest != capture.ProfileDigest || p.CurrentGeneration == nil || *p.CurrentGeneration != capture.Generation || p.CurrentHandleHash == nil || *p.CurrentHandleHash != capture.HandleHash || gate == nil {
		return b.PrivadoBeginCommit{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.pool)
	if e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	if e = lockPrivadoFlow(ctx, tx, scope); e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	old, e := readFamily(ctx, tx, scope, capture.FamilyID, true)
	if e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	now, e := s.now()
	if e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	kind := b.ChallengeDenyUnchanged
	if capture.Matches(old) && old.RevokedAt == nil && !now.Before(old.CreatedAt) && now.Before(old.AbsoluteExpiresAt) && now.Unix() < capture.AbsoluteExpiresUnix {
		if capture.Generation != old.Generation || capture.HandleHash != old.CurrentHandleHash {
			f := old
			f.RevokedAt = &now
			if e = s.applyFamilyDecision(ctx, tx, scope, old, b.FamilyDecision{Kind: b.RevokeDeny, Family: f}, nil); e != nil {
				return b.PrivadoBeginCommit{}, e
			}
			kind = b.ChallengeRevokeDeny
		} else if sameFamily(old, expected) {
			if e = checkChallengeCurrent(s, p); e != nil {
				return b.PrivadoBeginCommit{}, e
			}
			if e = challengeQuota(ctx, tx, scope); e != nil {
				return b.PrivadoBeginCommit{}, e
			}
			if e = gate(); e != nil {
				return b.PrivadoBeginCommit{}, e
			}
			if e = insertChallenge(ctx, tx, p); e != nil {
				return b.PrivadoBeginCommit{}, e
			}
			kind = b.ChallengeInserted
		}
	}
	finalGate := gate
	if kind != b.ChallengeInserted {
		finalGate = nil
	}
	if e = endPrivado(ctx, tx, scope, finalGate); e != nil {
		return b.PrivadoBeginCommit{}, e
	}
	return b.PrivadoBeginCommit{Committed: true, Kind: kind}, nil
}
func (s *Store) ReadPrivadoFlow(ctx context.Context, scope b.Scope, id string, recipient b.RecipientBinding) (b.PrivadoFlowSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !s.valid(scope) || !b.ValidUUID(id) || !recipient.Valid() {
		return b.PrivadoFlowSnapshot{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.pool)
	if e != nil {
		return b.PrivadoFlowSnapshot{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.PrivadoFlowSnapshot{}, e
	}
	p, e := readChallenge(ctx, tx, scope, id)
	if e != nil {
		return b.PrivadoFlowSnapshot{}, e
	}
	if p.Recipient != recipient {
		return b.PrivadoFlowSnapshot{}, b.ErrUnauthorized
	}
	if e = checkChallengeCurrent(s, p); e != nil {
		return b.PrivadoFlowSnapshot{}, e
	}
	out := b.PrivadoFlowSnapshot{Challenge: p}
	offer, e := readOffer(ctx, tx, scope, id)
	if e == nil {
		out.Offer = &offer
	} else if !errors.Is(e, b.ErrUnauthorized) {
		return b.PrivadoFlowSnapshot{}, e
	}
	if e = endPrivado(ctx, tx, scope, nil); e != nil {
		return b.PrivadoFlowSnapshot{}, e
	}
	return out, nil
}
func insertFamily(ctx context.Context, tx pgx.Tx, f b.Family) error {
	var tenant, oidc, nonce any
	if f.Provider == b.FamilyAzure {
		tenant = f.Tenant
		oidc = f.OIDCSubjectHash[:]
		nonce = f.NonceHash[:]
	}
	_, e := tx.Exec(ctx, `INSERT INTO ops_identity_v2.renewal_families(family_id,originating_request_id,namespace,recovery_epoch,actor_id,profile_id,profile_digest,identity_authority,source_tenant,source_subject,principal_kind,oidc_subject_hash,login_nonce_hash,original_auth_time,recipient_hash,generation,current_handle_hash,encryption_key_id,refresh_ciphertext,created_at,absolute_expires_at,last_rotated_at,revoked_at,provider_kind)VALUES($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`, f.ID, f.RequestID, f.Scope.Namespace.String(), f.Scope.State.RecoveryEpoch, f.Actor, f.ProfileID, f.ProfileDigest, f.Authority, tenant, f.Subject, string(f.Kind), oidc, nonce, f.OriginalAuthTime, f.Recipient[:], f.Generation, f.CurrentHandleHash[:], f.EncryptionKeyID, f.Ciphertext, f.CreatedAt, f.AbsoluteExpiresAt, f.LastRotatedAt, f.RevokedAt, f.Provider)
	if e != nil {
		return b.ErrUnavailable
	}
	return nil
}
func (s *Store) CompletePrivadoFlow(ctx context.Context, scope b.Scope, expected b.PrivadoFlowSnapshot, prepared b.PrivadoCompletion, gate func() error) (b.Commit, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	p := expected.Challenge
	f := prepared.Family
	if !s.valid(scope) || !p.Valid() || p.Scope != scope || expected.Offer == nil || !expected.Offer.Valid() || !f.Valid() || f.Scope != scope || f.Provider != b.FamilyPrivado || f.Actor != expected.Offer.ActorID || f.Subject != expected.Offer.HolderDID || f.ProfileID != p.ProfileID || f.ProfileDigest != p.ProfileDigest || f.Recipient != p.Recipient || f.RevokedAt != nil || gate == nil {
		return b.Commit{}, b.ErrInvalid
	}
	if p.Mode == "login" {
		if prepared.Kind != b.Create || prepared.Capture != nil || f.RequestID != p.ID || f.Generation != 0 {
			return b.Commit{}, b.ErrInvalid
		}
	} else if p.Mode == "renew" {
		if prepared.Kind != b.Rotate || prepared.Capture == nil || !prepared.Capture.Matches(f) || f.ID != p.FamilyID {
			return b.Commit{}, b.ErrInvalid
		}
	} else {
		return b.Commit{}, b.ErrInvalid
	}
	tx, e := begin(ctx, s.pool)
	if e != nil {
		return b.Commit{}, e
	}
	defer rollback(tx)
	if e = checkState(ctx, tx, scope); e != nil {
		return b.Commit{}, e
	}
	if e = lockPrivadoFlow(ctx, tx, scope); e != nil {
		return b.Commit{}, e
	}
	if prepared.Kind == b.Create {
		t := pendingTx{ctx: ctx, tx: tx, store: s}
		if e = t.capacity("family", b.MaxFamilies); e != nil {
			return b.Commit{}, e
		}
	}
	var old b.Family
	if prepared.Kind == b.Rotate {
		old, e = readFamily(ctx, tx, scope, p.FamilyID, true)
		if e != nil {
			return b.Commit{}, e
		}
		capture := prepared.Capture
		now, e := s.now()
		if e != nil {
			return b.Commit{}, e
		}
		if !capture.Matches(old) || old.RevokedAt != nil || old.Generation != capture.Generation || old.CurrentHandleHash != capture.HandleHash || p.CurrentGeneration == nil || old.Generation != *p.CurrentGeneration || p.CurrentHandleHash == nil || old.CurrentHandleHash != *p.CurrentHandleHash || now.Before(old.CreatedAt) || !now.Before(old.AbsoluteExpiresAt) {
			return b.Commit{}, b.ErrUnauthorized
		}
	}
	actual, e := readChallenge(ctx, tx, scope, p.ID)
	if e != nil {
		return b.Commit{}, e
	}
	offer, e := readOffer(ctx, tx, scope, p.ID)
	if e != nil {
		return b.Commit{}, e
	}
	if !reflect.DeepEqual(actual, p) || !reflect.DeepEqual(offer, *expected.Offer) {
		return b.Commit{}, b.ErrUnauthorized
	}
	if e = checkChallengeCurrent(s, actual); e != nil {
		return b.Commit{}, e
	}
	if e = gate(); e != nil {
		return b.Commit{}, e
	}
	if prepared.Kind == b.Create {
		now, e := s.now()
		if e != nil {
			return b.Commit{}, e
		}
		if now.Before(f.CreatedAt) || !now.Before(f.AbsoluteExpiresAt) {
			return b.Commit{}, b.ErrUnauthorized
		}
		if e = insertFamily(ctx, tx, f); e != nil {
			return b.Commit{}, e
		}
	} else if e = s.applyFamilyDecision(ctx, tx, scope, old, b.FamilyDecision{Kind: b.Rotate, Family: f}, gate); e != nil {
		return b.Commit{}, e
	}
	// Exact immutable snapshot was compared under the shared namespace lock.
	// Conditional deletion is the one-use mutation; child proof cascades.
	deleted, e := scanChallenge(tx.QueryRow(ctx, `DELETE FROM ops_identity_v2.privado_challenges WHERE namespace=$1 AND recovery_epoch=$2::uuid AND request_id=$3::uuid AND context_ciphertext=$4 RETURNING `+challengeColumns, scope.Namespace.String(), scope.State.RecoveryEpoch, p.ID, p.Ciphertext), scope)
	if e != nil || !reflect.DeepEqual(deleted, p) {
		return b.Commit{}, b.ErrUnauthorized
	}
	if e = endPrivado(ctx, tx, scope, gate); e != nil {
		return b.Commit{}, e
	}
	return b.Commit{Committed: true, Kind: prepared.Kind}, nil
}
