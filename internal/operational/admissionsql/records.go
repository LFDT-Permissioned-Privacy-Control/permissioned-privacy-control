package admissionsql

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
)

const recordMetadataColumns = `id::text,network_key,org_id::text,actor_id,NULL::jsonb,NULL::jsonb,transfer_type,token,beneficiary,amount_wei,CASE WHEN octet_length(amount_fiat::text)<=512 THEN amount_fiat::text ELSE NULL END,currency,created_at,expires_at,used_at,used_tx_hash,created_by_actor,creation_policy_digest,quote_digest`
const recordFullColumns = `id::text,network_key,org_id::text,actor_id,CASE WHEN octet_length(originator_data::text)<=65536 THEN originator_data::text ELSE NULL END,CASE WHEN octet_length(beneficiary_data::text)<=65536 THEN beneficiary_data::text ELSE NULL END,transfer_type,token,beneficiary,amount_wei,CASE WHEN octet_length(amount_fiat::text)<=512 THEN amount_fiat::text ELSE NULL END,currency,created_at,expires_at,used_at,used_tx_hash,created_by_actor,creation_policy_digest,quote_digest`

func storedFiat(raw string) (float64, error) {
	if len(raw) == 0 || len(raw) > 512 {
		return 0, a.ErrUnavailable
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, a.ErrUnavailable
	}
	if _, err := a.CanonicalFiat(v); err != nil {
		return 0, a.ErrUnavailable
	}
	return v, nil
}
func scanRecord(row pgx.Row, pii bool, covered *bool) (a.Record, bool, error) {
	var out a.Record
	var network, token, beneficiary, usedHash, policy, quote []byte
	var value string
	values := []any{&out.ID, &network, &out.Organization, &out.Actor, &out.OriginatorData, &out.BeneficiaryData, &out.TransferType, &token, &beneficiary, &out.AmountWei, &value, &out.Currency, &out.CreatedAt, &out.ExpiresAt, &out.UsedAt, &usedHash, &out.CreatedBy, &policy, &quote}
	if covered != nil {
		values = append(values, covered)
	}
	err := row.Scan(values...)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, false, nil
	}
	if err != nil || len(network) != 32 || len(beneficiary) != 20 || len(policy) != 32 || len(quote) != 32 || (token != nil && len(token) != 20) || (usedHash != nil && len(usedHash) != 32) {
		return out, false, a.ErrUnavailable
	}
	copy(out.Network[:], network)
	copy(out.PolicyDigest[:], policy)
	copy(out.QuoteDigest[:], quote)
	out.Beneficiary = common.BytesToAddress(beneficiary)
	if token != nil {
		v := common.BytesToAddress(token)
		out.Token = &v
	}
	if usedHash != nil {
		h := common.BytesToHash(usedHash)
		out.UsedHash = &h
	}
	out.AmountFiat, err = storedFiat(value)
	if err != nil || !out.ValidMetadata() || (pii && !out.Valid()) {
		return out, false, a.ErrUnavailable
	}
	return out, true, nil
}
func tokenBytes(q a.TransferQuery) []byte {
	if q.Token == nil {
		return nil
	}
	return q.Token.Bytes()
}
func (r recordReader) BoundRecord(query a.TransferQuery) (a.Record, bool, error) {
	value, err := a.CanonicalFiat(query.AmountFiat)
	if err != nil || query.RecordMaxSeconds <= 0 || query.RecordMaxSeconds > 30*86400 {
		return a.Record{}, false, a.ErrInvalid
	}
	covered := false
	out, exists, err := scanRecord(r.q.QueryRow(r.ctx, `SELECT `+recordMetadataColumns+`,(beneficiary=$5 AND token IS NOT DISTINCT FROM $6::bytea AND currency=$7 AND amount_fiat>=$8::numeric)FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND actor_id=$3 AND used_tx_hash=$4`, r.scope.Network[:], r.scope.Organization, r.scope.Actor, r.scope.Hash[:], query.Beneficiary[:], tokenBytes(query), query.Currency, value), false, &covered)
	if err != nil {
		return out, false, err
	}
	if exists {
		if !covered {
			return a.Record{}, true, nil
		}
		return out, true, nil
	}
	var known bool
	err = r.q.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND org_id=$2::uuid AND actor_id=$3 AND tx_hash=$4 AND record_id IS NOT NULL)`, r.scope.Network[:], r.scope.Organization, r.scope.Actor, r.scope.Hash[:]).Scan(&known)
	if err != nil {
		return out, false, a.ErrUnavailable
	}
	if known {
		return out, true, a.ErrCoverage
	}
	return out, false, nil
}
func (r recordReader) FindUnused(query a.TransferQuery, now time.Time) (a.Record, bool, error) {
	value, err := a.CanonicalFiat(query.AmountFiat)
	if err != nil || query.RecordMaxSeconds <= 0 || query.RecordMaxSeconds > 30*86400 {
		return a.Record{}, false, a.ErrInvalid
	}
	return scanRecord(r.q.QueryRow(r.ctx, `SELECT `+recordMetadataColumns+` FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND actor_id=$3 AND beneficiary=$4 AND token IS NOT DISTINCT FROM $5::bytea AND currency=$6 AND amount_fiat>=$7::numeric AND used_at IS NULL AND created_at<=$8 AND expires_at>$8 AND created_at>$9 ORDER BY created_at DESC,id DESC LIMIT 1`, r.scope.Network[:], r.scope.Organization, r.scope.Actor, query.Beneficiary[:], tokenBytes(query), query.Currency, value, now, now.Add(-time.Duration(query.RecordMaxSeconds)*time.Second)), false, nil)
}
func (t *rawTx) ClaimUnused(query a.TransferQuery, now time.Time) (a.Record, bool, error) {
	// The bridge checks BoundRecord under this same hash lock before asking
	// for an unused record. The scoped unique index is the final backstop.
	value, err := a.CanonicalFiat(query.AmountFiat)
	if err != nil || query.RecordMaxSeconds <= 0 || query.RecordMaxSeconds > 30*86400 {
		return a.Record{}, false, a.ErrInvalid
	}
	out, exists, err := scanRecord(t.tx.QueryRow(t.ctx, `UPDATE ops_admission_v2.travel_records SET used_at=$8,used_tx_hash=$10 WHERE id=(SELECT id FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND actor_id=$3 AND beneficiary=$4 AND token IS NOT DISTINCT FROM $5::bytea AND currency=$6 AND amount_fiat>=$7::numeric AND used_at IS NULL AND created_at<=$8 AND expires_at>$8 AND created_at>$9 ORDER BY created_at DESC,id DESC LIMIT 1 FOR UPDATE SKIP LOCKED)RETURNING `+recordMetadataColumns, t.scope.Network[:], t.scope.Organization, t.scope.Actor, query.Beneficiary[:], tokenBytes(query), query.Currency, value, now, now.Add(-time.Duration(query.RecordMaxSeconds)*time.Second), t.scope.Hash[:]), false, nil)
	if err == nil && exists {
		t.effects = true
	}
	return out, exists, err
}
func (s *Store) CreateRecord(ctx context.Context, network a.Digest, expected a.ExpectedState, record a.Record, prepare func(*a.Record) error) (a.Record, error) {
	if s.mode != "app" || prepare == nil || record.Network != network {
		return a.Record{}, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, false)
	if err != nil {
		return a.Record{}, err
	}
	defer rollback(tx)
	if err := state(ctx, tx, network, expected); err != nil {
		return a.Record{}, err
	}
	if err := prepare(&record); err != nil {
		return a.Record{}, err
	}
	if !record.Valid() || record.UsedAt != nil {
		return a.Record{}, a.ErrInvalid
	}
	value, _ := a.CanonicalFiat(record.AmountFiat)
	var token []byte
	if record.Token != nil {
		token = record.Token.Bytes()
	}
	_, err = tx.Exec(ctx, `INSERT INTO ops_admission_v2.travel_records(id,network_key,org_id,actor_id,originator_data,beneficiary_data,transfer_type,token,beneficiary,amount_wei,amount_fiat,currency,created_at,expires_at,created_by_actor,creation_policy_digest,quote_digest)VALUES($1::uuid,$2,$3::uuid,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$11::numeric,$12,$13,$14,$15,$16,$17)`, record.ID, network[:], record.Organization, record.Actor, record.OriginatorData, record.BeneficiaryData, record.TransferType, token, record.Beneficiary[:], record.AmountWei, value, record.Currency, record.CreatedAt, record.ExpiresAt, record.CreatedBy, record.PolicyDigest[:], record.QuoteDigest[:])
	if err != nil {
		return a.Record{}, dbError(err)
	}
	if err := prepareFinalCheck(prepare, &record); err != nil {
		return a.Record{}, err
	}
	if err := state(ctx, tx, network, expected); err != nil {
		return a.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return a.Record{}, a.ErrUnavailable
	}
	return record, nil
}

// Preparation owns the same captured source/quote view. A second invocation
// checks freshness but must not change already inserted immutable values.
func prepareFinalCheck(prepare func(*a.Record) error, record *a.Record) error {
	copy := *record
	copy.OriginatorData = bytes.Clone(record.OriginatorData)
	copy.BeneficiaryData = bytes.Clone(record.BeneficiaryData)
	if record.Token != nil {
		value := *record.Token
		copy.Token = &value
	}
	if err := prepare(&copy); err != nil {
		return err
	}
	if !reflect.DeepEqual(copy, *record) {
		return a.ErrInvalid
	}
	return nil
}
func (s *Store) GetRecord(ctx context.Context, network a.Digest, expected a.ExpectedState, org, id string) (a.Record, error) {
	if !a.ValidUUID(org) || !a.ValidUUID(id) {
		return a.Record{}, a.ErrNotFound
	}
	var out a.Record
	err := s.readReady(ctx, network, expected, func(ctx context.Context, tx pgx.Tx) error {
		record, exists, err := scanRecord(tx.QueryRow(ctx, `SELECT `+recordFullColumns+` FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND id=$3::uuid`, network[:], org, id), true, nil)
		out = record
		if err == nil && !exists {
			return a.ErrNotFound
		}
		return err
	})
	return out, err
}
func (s *Store) ListRecords(ctx context.Context, network a.Digest, expected a.ExpectedState, org string, position a.Position, limit int) ([]a.Record, error) {
	if !a.ValidUUID(org) || limit < 1 || limit > 101 {
		return nil, a.ErrInvalid
	}
	hasPosition := !position.At.IsZero()
	if hasPosition && !a.ValidUUID(position.ID) {
		return nil, a.ErrInvalid
	}
	if !hasPosition {
		position.ID = "00000000-0000-0000-0000-000000000000"
		position.At = time.Unix(0, 0)
	}
	out := []a.Record{}
	err := s.readReady(ctx, network, expected, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+recordMetadataColumns+` FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND(NOT $3::boolean OR(created_at,id)<($4,$5::uuid))ORDER BY created_at DESC,id DESC LIMIT $6`, network[:], org, hasPosition, position.At, position.ID, limit)
		if err != nil {
			return a.ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			record, _, err := scanRecord(rows, false, nil)
			if err != nil {
				return err
			}
			out = append(out, record)
		}
		if rows.Err() != nil {
			return a.ErrUnavailable
		}
		return nil
	})
	return out, err
}
func (s *Store) DeleteUnused(ctx context.Context, network a.Digest, expected a.ExpectedState, org, id string, gate func() error) (bool, error) {
	if s.mode != "app" || !a.ValidUUID(org) || !a.ValidUUID(id) || gate == nil {
		return false, a.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := begin(ctx, s.pool, false)
	if err != nil {
		return false, err
	}
	defer rollback(tx)
	if err := state(ctx, tx, network, expected); err != nil {
		return false, err
	}
	if err := gate(); err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `DELETE FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND id=$3::uuid AND used_at IS NULL`, network[:], org, id)
	if err != nil {
		return false, dbError(err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ops_admission_v2.travel_records WHERE network_key=$1 AND org_id=$2::uuid AND id=$3::uuid)`, network[:], org, id).Scan(&exists); err != nil {
			return false, a.ErrUnavailable
		}
		if exists {
			return false, a.ErrConflict
		}
	}
	if err := gate(); err != nil {
		return false, err
	}
	if err := state(ctx, tx, network, expected); err != nil {
		return false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return false, a.ErrUnavailable
	}
	return tag.RowsAffected() == 1, nil
}
