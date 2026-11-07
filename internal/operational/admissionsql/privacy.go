package admissionsql

import (
	"errors"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
)

const witnessColumns = `witness_id,anchor_hash,anchor_number::text,anchor_timestamp::text,evidence_profile,wallet_version,decision_at,manifest_digest,compliance_digest,wallet_evidence_at`

type witnessScan struct {
	w                                        a.Witness
	id, anchor, wallet, manifest, compliance []byte
	number, timestamp                        string
}

func (s *witnessScan) destinations() []any {
	return []any{&s.id, &s.anchor, &s.number, &s.timestamp, &s.w.EvidenceProfile, &s.wallet, &s.w.DecisionAt, &s.manifest, &s.compliance, &s.w.WalletEvidenceAt}
}
func (s *witnessScan) finish() (a.Witness, error) {
	if len(s.id) != 32 || len(s.anchor) != 32 || len(s.wallet) != 32 || len(s.manifest) != 32 || len(s.compliance) != 32 {
		return a.Witness{}, a.ErrUnavailable
	}
	copy(s.w.ID[:], s.id)
	copy(s.w.AnchorHash[:], s.anchor)
	copy(s.w.WalletVersion[:], s.wallet)
	copy(s.w.ManifestDigest[:], s.manifest)
	copy(s.w.ComplianceDigest[:], s.compliance)
	var err error
	s.w.AnchorNumber, err = strconv.ParseUint(s.number, 10, 64)
	if err != nil {
		return a.Witness{}, a.ErrUnavailable
	}
	s.w.AnchorTimestamp, err = strconv.ParseUint(s.timestamp, 10, 64)
	if err != nil || !s.w.Valid() {
		return a.Witness{}, a.ErrUnavailable
	}
	return s.w, nil
}
func witnessValues(w a.Witness) []any {
	return []any{w.ID[:], w.AnchorHash[:], strconv.FormatUint(w.AnchorNumber, 10), strconv.FormatUint(w.AnchorTimestamp, 10), w.EvidenceProfile, w.WalletVersion[:], w.DecisionAt, w.ManifestDigest[:], w.ComplianceDigest[:], w.WalletEvidenceAt}
}
func (t *rawTx) GetOrigin() (a.Origin, bool, error) {
	var o a.Origin
	var w witnessScan
	o.Network = t.scope.Network
	o.Hash = t.scope.Hash
	values := append([]any{&o.Actor, &o.Organization, &o.FirstAdmittedAt}, w.destinations()...)
	err := t.tx.QueryRow(t.ctx, `SELECT actor_id,org_id::text,first_admitted_at,`+witnessColumns+` FROM ops_admission_v2.qualified_tx_origins WHERE network_key=$1 AND tx_hash=$2`, t.scope.Network[:], t.scope.Hash[:]).Scan(values...)
	if errors.Is(err, pgx.ErrNoRows) {
		return o, false, nil
	}
	if err != nil {
		return o, false, a.ErrUnavailable
	}
	o.Primary, err = w.finish()
	if err != nil || !o.Valid() {
		return o, false, a.ErrUnavailable
	}
	return o, true, nil
}
func (t *rawTx) PutOrigin(o a.Origin) (bool, error) {
	if !o.Valid() || o.Network != t.scope.Network || o.Hash != t.scope.Hash || o.Actor != t.scope.Actor || o.Organization != t.scope.Organization {
		return false, a.ErrInvalid
	}
	existing, exists, err := t.GetOrigin()
	if err != nil {
		return false, err
	}
	if exists {
		if existing.Actor != o.Actor || existing.Organization != o.Organization {
			return false, a.ErrConflict
		}
		return false, t.PutWitness(o.Primary)
	}
	values := append([]any{o.Network[:], o.Hash[:], o.Actor, o.Organization, o.FirstAdmittedAt}, witnessValues(o.Primary)...)
	_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.qualified_tx_origins(network_key,tx_hash,actor_id,org_id,first_admitted_at,witness_id,anchor_hash,anchor_number,anchor_timestamp,evidence_profile,wallet_version,decision_at,manifest_digest,compliance_digest,wallet_evidence_at)VALUES($1,$2,$3,$4::uuid,$5,$6,$7,$8::numeric,$9::numeric,$10,$11,$12,$13,$14,$15)`, values...)
	if err != nil {
		return false, dbError(err)
	}
	t.effects = true
	return true, nil
}
func (t *rawTx) PutWitness(w a.Witness) error {
	if !w.Valid() {
		return a.ErrInvalid
	}
	o, exists, err := t.GetOrigin()
	if err != nil {
		return err
	}
	if !exists || o.Actor != t.scope.Actor || o.Organization != t.scope.Organization {
		return a.ErrConflict
	}
	if o.Primary.ID == w.ID {
		if !o.Primary.StableEqual(w) {
			return a.ErrConflict
		}
		return nil
	}
	var old witnessScan
	err = t.tx.QueryRow(t.ctx, `SELECT `+witnessColumns+` FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1 AND tx_hash=$2 AND witness_id=$3`, t.scope.Network[:], t.scope.Hash[:], w.ID[:]).Scan(old.destinations()...)
	if err == nil {
		stored, err := old.finish()
		if err != nil {
			return err
		}
		if !stored.StableEqual(w) {
			return a.ErrConflict
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return a.ErrUnavailable
	}
	var count int
	if err = t.tx.QueryRow(t.ctx, `SELECT count(*) FROM ops_admission_v2.extra_privacy_witnesses WHERE network_key=$1 AND tx_hash=$2`, t.scope.Network[:], t.scope.Hash[:]).Scan(&count); err != nil {
		return a.ErrUnavailable
	}
	if count >= a.MaxWitnesses-1 {
		return a.ErrConflict
	}
	values := append([]any{t.scope.Network[:], t.scope.Hash[:]}, witnessValues(w)...)
	_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.extra_privacy_witnesses(network_key,tx_hash,witness_id,anchor_hash,anchor_number,anchor_timestamp,evidence_profile,wallet_version,decision_at,manifest_digest,compliance_digest,wallet_evidence_at)VALUES($1,$2,$3,$4,$5::numeric,$6::numeric,$7,$8,$9,$10,$11,$12)`, values...)
	if err != nil {
		return dbError(err)
	}
	t.effects = true
	return nil
}
func (t *rawTx) GetShare() (a.Share, bool, error) {
	s := a.Share{Network: t.scope.Network, Hash: t.scope.Hash}
	var digest, anchor, manifest, wallet []byte
	var number, timestamp string
	err := t.tx.QueryRow(t.ctx, `SELECT sender_actor_id,sender_org_id::text,recipients,recipient_digest,declared_at,anchor_hash,anchor_number::text,anchor_timestamp::text,manifest_digest,wallet_version,wallet_evidence_at FROM ops_admission_v2.tx_shares WHERE network_key=$1 AND tx_hash=$2`, t.scope.Network[:], t.scope.Hash[:]).Scan(&s.Actor, &s.Organization, &s.Recipients, &digest, &s.DeclaredAt, &anchor, &number, &timestamp, &manifest, &wallet, &s.Witness.WalletEvidenceAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return s, false, nil
	}
	if err != nil || len(digest) != 32 || len(anchor) != 32 || len(manifest) != 32 || len(wallet) != 32 {
		return s, false, a.ErrUnavailable
	}
	copy(s.RecipientDigest[:], digest)
	s.Witness.AnchorHash = common.BytesToHash(anchor)
	copy(s.Witness.ManifestDigest[:], manifest)
	copy(s.Witness.WalletVersion[:], wallet)
	s.Witness.AnchorNumber, err = strconv.ParseUint(number, 10, 64)
	if err != nil {
		return s, false, a.ErrUnavailable
	}
	s.Witness.AnchorTimestamp, err = strconv.ParseUint(timestamp, 10, 64)
	if err != nil || !s.Valid() {
		return s, false, a.ErrUnavailable
	}
	return s, true, nil
}
func (t *rawTx) PutShare(s a.Share) error {
	if !s.Valid() || s.Network != t.scope.Network || s.Hash != t.scope.Hash || s.Actor != t.scope.Actor || s.Organization != t.scope.Organization {
		return a.ErrInvalid
	}
	// Sharing never crosses an already established data organization's fence.
	o, exists, err := t.GetOrigin()
	if err != nil {
		return err
	}
	if exists && o.Organization != s.Organization {
		return a.ErrConflict
	}
	old, exists, err := t.GetShare()
	if err != nil {
		return err
	}
	if exists {
		if !old.SameBinding(s) {
			return a.ErrConflict
		}
		return nil
	}
	_, err = t.tx.Exec(t.ctx, `INSERT INTO ops_admission_v2.tx_shares(network_key,tx_hash,sender_actor_id,sender_org_id,recipients,recipient_digest,declared_at,anchor_hash,anchor_number,anchor_timestamp,manifest_digest,wallet_version,wallet_evidence_at)VALUES($1,$2,$3,$4::uuid,$5::text[],$6,$7,$8,$9::numeric,$10::numeric,$11,$12,$13)`, s.Network[:], s.Hash[:], s.Actor, s.Organization, s.Recipients, s.RecipientDigest[:], s.DeclaredAt, s.Witness.AnchorHash[:], strconv.FormatUint(s.Witness.AnchorNumber, 10), strconv.FormatUint(s.Witness.AnchorTimestamp, 10), s.Witness.ManifestDigest[:], s.Witness.WalletVersion[:], s.Witness.WalletEvidenceAt)
	if err != nil {
		return dbError(err)
	}
	t.effects = true
	return nil
}
