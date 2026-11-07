// Package disclosuresql is the narrow initial operational SQL adapter for
// disclosure cases and their audit. It reads no users, groups or policy tables.
package disclosuresql

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	c "privacy-proxy/internal/disclosurecase"
	"privacy-proxy/internal/disclosurepolicy"
)

type Store struct{ pool *pgxpool.Pool }

var _ c.Store = (*Store)(nil)

func Open(ctx context.Context, dsn string) (*Store, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, c.ErrInvalid
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, c.ErrUnavailable
	}
	config.MaxConns = 8
	config.ConnConfig.ConnectTimeout = 3 * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, c.ErrUnavailable
	}
	store := &Store{pool: pool}
	if err := store.CheckSchema(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.checkAppPrivileges(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}
func (s *Store) Close() { s.pool.Close() }
func bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}
func (s *Store) begin(ctx context.Context) (pgx.Tx, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, c.ErrUnavailable
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout','1s',true),set_config('statement_timeout','3s',true)`); err != nil {
		_ = tx.Rollback(ctx)
		return nil, c.ErrUnavailable
	}
	return tx, nil
}

const caseColumns = `case_id::text,store_epoch,creator_actor,recipient_actor,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,
 CASE WHEN octet_length(immutable_scope::text)<=98304 THEN immutable_scope::text ELSE NULL END,
 case_reference,purpose,legal_basis,created_at,expires_at,status,version,idempotency_key::text,revoked_at,COALESCE(revoked_by_actor,''),COALESCE(revoke_reason,'')`

func scanCase(row pgx.Row) (c.Case, error) {
	var out c.Case
	var raw []byte
	err := row.Scan(&out.ID, &out.Epoch, &out.CreatorActor, &out.RecipientActor, &out.RuleID, &out.DataOrg, &out.OriginalRuleDigest, &out.OriginalBundleDigest, &out.RequestDigest, &raw, &out.Reference, &out.Purpose, &out.LegalBasis, &out.CreatedAt, &out.ExpiresAt, &out.Status, &out.Version, &out.IdempotencyKey, &out.RevokedAt, &out.RevokedBy, &out.RevokeReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return c.Case{}, c.ErrNotFound
	}
	if err != nil || len(raw) > c.MaxScopeBytes {
		return c.Case{}, c.ErrUnavailable
	}
	out.Scope, err = disclosurepolicy.DecodeScope(raw, disclosurepolicy.DefaultLimits())
	if err != nil || c.ValidateCase(out) != nil {
		return c.Case{}, c.ErrUnavailable
	}
	return out, nil
}
func (s *Store) Get(ctx context.Context, id, epoch string) (c.Case, error) {
	if !c.ValidUUID(id) || !c.ValidEpoch(epoch) {
		return c.Case{}, c.ErrNotFound
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	return scanCase(s.pool.QueryRow(ctx, `SELECT `+caseColumns+` FROM ops_v2.disclosure_cases WHERE case_id=$1::uuid AND store_epoch=$2`, id, epoch))
}
func (s *Store) GetByKey(ctx context.Context, epoch, actor, key string) (c.Case, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	out, err := scanCase(s.pool.QueryRow(ctx, `SELECT `+caseColumns+` FROM ops_v2.disclosure_cases WHERE creator_actor=$1 AND idempotency_key=$2::uuid`, actor, key))
	if err != nil {
		return c.Case{}, err
	}
	if out.Epoch != epoch {
		return c.Case{}, c.ErrConflict
	}
	return out, nil
}
func locked(ctx context.Context, tx pgx.Tx, id, epoch string) (c.Case, error) {
	return scanCase(tx.QueryRow(ctx, `SELECT `+caseColumns+` FROM ops_v2.disclosure_cases WHERE case_id=$1::uuid AND store_epoch=$2 FOR UPDATE`, id, epoch))
}

func appendEvent(ctx context.Context, tx pgx.Tx, event c.Event) error {
	if c.ValidateEvent(event) != nil {
		return c.ErrUnavailable
	}
	raw, err := json.Marshal(event.Summary)
	if err != nil || len(raw) > 8192 {
		return c.ErrUnavailable
	}
	_, err = tx.Exec(ctx, `INSERT INTO ops_v2.disclosure_events(event_id,case_id,store_epoch,actor,action,outcome,rule_id,rule_digest,bundle_digest,case_version,prepared_at,summary,attempt_id)
 VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12::jsonb,$13::uuid)`, event.ID, event.CaseID, event.Epoch, event.Actor, event.Action, event.Outcome, event.RuleID, event.RuleDigest, event.BundleDigest, event.CaseVersion, event.PreparedAt, raw, event.AttemptID)
	if err != nil {
		return c.ErrUnavailable
	}
	return nil
}
func commit(ctx context.Context, tx pgx.Tx, event c.Event) (c.CommitReceipt, error) {
	if err := tx.Commit(ctx); err != nil {
		return c.CommitReceipt{}, c.ErrUnavailable
	}
	return c.CommitReceipt{AttemptID: event.AttemptID}, nil
}

func (s *Store) CreateOrGet(ctx context.Context, wanted c.Case, event c.Event, authorize func(c.Case, bool) error) (c.Case, c.CommitReceipt, error) {
	if c.ValidateCase(wanted) != nil || wanted.Status != "open" || wanted.Version != 1 || authorize == nil {
		return c.Case{}, c.CommitReceipt{}, c.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	defer rollback(tx)
	raw, err := json.Marshal(wanted.Scope)
	if err != nil || len(raw) > c.MaxScopeBytes {
		return c.Case{}, c.CommitReceipt{}, c.ErrInvalid
	}
	tag, err := tx.Exec(ctx, `INSERT INTO ops_v2.disclosure_cases(case_id,store_epoch,creator_actor,recipient_actor,rule_id,data_org,original_rule_digest,original_bundle_digest,request_digest,immutable_scope,case_reference,purpose,legal_basis,created_at,expires_at,status,version,idempotency_key)
 VALUES($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14,$15,'open',1,$16::uuid) ON CONFLICT(creator_actor,idempotency_key) DO NOTHING`, wanted.ID, wanted.Epoch, wanted.CreatorActor, wanted.RecipientActor, wanted.RuleID, wanted.DataOrg, wanted.OriginalRuleDigest, wanted.OriginalBundleDigest, wanted.RequestDigest, raw, wanted.Reference, wanted.Purpose, wanted.LegalBasis, wanted.CreatedAt, wanted.ExpiresAt, wanted.IdempotencyKey)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, c.ErrUnavailable
	}
	isNew := tag.RowsAffected() == 1
	actual := wanted
	if !isNew {
		actual, err = scanCase(tx.QueryRow(ctx, `SELECT `+caseColumns+` FROM ops_v2.disclosure_cases WHERE creator_actor=$1 AND idempotency_key=$2::uuid FOR UPDATE`, wanted.CreatorActor, wanted.IdempotencyKey))
		if err != nil {
			return c.Case{}, c.CommitReceipt{}, err
		}
		if actual.Epoch != wanted.Epoch || actual.RequestDigest != wanted.RequestDigest {
			return c.Case{}, c.CommitReceipt{}, c.ErrConflict
		}
	}
	if err := authorize(actual, isNew); err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	event.CaseID = actual.ID
	event.CaseVersion = actual.Version
	event.RuleID = actual.RuleID
	if event.Epoch != actual.Epoch || event.Actor != wanted.CreatorActor || event.Action != "case_opened" {
		return c.Case{}, c.CommitReceipt{}, c.ErrUnavailable
	}
	if !isNew {
		event.Action = "metadata_read"
	}
	if err := appendEvent(ctx, tx, event); err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	receipt, err := commit(ctx, tx, event)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	return actual, receipt, nil
}
func (s *Store) WithLockedCase(ctx context.Context, id, epoch string, version int64, authorize func(c.Case) (c.Event, error)) (c.CommitReceipt, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return c.CommitReceipt{}, err
	}
	defer rollback(tx)
	row, err := locked(ctx, tx, id, epoch)
	if err != nil {
		return c.CommitReceipt{}, err
	}
	if row.Version != version {
		return c.CommitReceipt{}, c.ErrConflict
	}
	event, err := authorize(row)
	if err != nil {
		return c.CommitReceipt{}, err
	}
	if event.CaseID != row.ID || event.Epoch != epoch || event.CaseVersion != row.Version {
		return c.CommitReceipt{}, c.ErrUnavailable
	}
	if err := appendEvent(ctx, tx, event); err != nil {
		return c.CommitReceipt{}, err
	}
	return commit(ctx, tx, event)
}
func (s *Store) Revoke(ctx context.Context, id, epoch, actor, reason string, authorize func(c.Case) error, makeEvent func(c.Case) (c.Event, error)) (c.Case, c.CommitReceipt, error) {
	ctx, cancel := bounded(ctx)
	defer cancel()
	tx, err := s.begin(ctx)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	defer rollback(tx)
	row, err := locked(ctx, tx, id, epoch)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	if err := authorize(row); err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	changed := row.Status == "open"
	if changed {
		if row.Version == int64(^uint64(0)>>1) {
			return c.Case{}, c.CommitReceipt{}, c.ErrConflict
		}
		row, err = scanCase(tx.QueryRow(ctx, `UPDATE ops_v2.disclosure_cases SET status='revoked',version=version+1,revoked_at=clock_timestamp(),revoked_by_actor=$3,revoke_reason=$4 WHERE case_id=$1::uuid AND store_epoch=$2 RETURNING `+caseColumns, id, epoch, actor, reason))
		if err != nil {
			return c.Case{}, c.CommitReceipt{}, err
		}
	}
	event, err := makeEvent(row)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	if !changed {
		event.Action = "metadata_read"
		event.Outcome = "allowed"
		event.Summary.Count = 0
	}
	if event.CaseID != row.ID || event.Epoch != epoch || event.CaseVersion != row.Version {
		return c.Case{}, c.CommitReceipt{}, c.ErrUnavailable
	}
	if err := appendEvent(ctx, tx, event); err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	receipt, err := commit(ctx, tx, event)
	if err != nil {
		return c.Case{}, c.CommitReceipt{}, err
	}
	return row, receipt, nil
}

func (s *Store) Candidates(ctx context.Context, q c.CandidateQuery) ([]c.Case, error) {
	if q.Limit < 1 || q.Limit > 500 || !c.ValidEpoch(q.Epoch) || (q.Recipient == "") == (q.Organization == "") {
		return nil, c.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	var afterTime any
	var afterID any
	if q.After != nil {
		afterTime = q.After.Time
		afterID = q.After.ID
	}
	rows, err := s.pool.Query(ctx, `SELECT `+caseColumns+` FROM ops_v2.disclosure_cases WHERE store_epoch=$1 AND (($2<>'' AND recipient_actor=$2) OR ($3<>'' AND data_org=$3)) AND ($4::timestamptz IS NULL OR (created_at,case_id)<($4::timestamptz,$5::uuid)) ORDER BY created_at DESC,case_id DESC LIMIT $6`, q.Epoch, q.Recipient, q.Organization, afterTime, afterID, q.Limit)
	if err != nil {
		return nil, c.ErrUnavailable
	}
	defer rows.Close()
	out := []c.Case{}
	for rows.Next() {
		row, err := scanCase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	if rows.Err() != nil {
		return nil, c.ErrUnavailable
	}
	return out, nil
}

func (s *Store) Events(ctx context.Context, id, epoch string, after *c.Position, limit int) ([]c.Event, error) {
	if !c.ValidUUID(id) || !c.ValidEpoch(epoch) || limit < 1 || limit > 101 {
		return nil, c.ErrInvalid
	}
	ctx, cancel := bounded(ctx)
	defer cancel()
	var afterTime any
	var afterID any
	if after != nil {
		afterTime = after.Time
		afterID = after.ID
	}
	rows, err := s.pool.Query(ctx, `SELECT event_id::text,case_id::text,store_epoch,actor,action,outcome,rule_id,rule_digest,bundle_digest,case_version,prepared_at,CASE WHEN octet_length(summary::text)<=8192 THEN summary::text ELSE NULL END,attempt_id::text FROM ops_v2.disclosure_events WHERE case_id=$1::uuid AND store_epoch=$2 AND ($3::timestamptz IS NULL OR (prepared_at,event_id)<($3::timestamptz,$4::uuid)) ORDER BY prepared_at DESC,event_id DESC LIMIT $5`, id, epoch, afterTime, afterID, limit)
	if err != nil {
		return nil, c.ErrUnavailable
	}
	defer rows.Close()
	out := []c.Event{}
	for rows.Next() {
		var e c.Event
		var raw []byte
		err := rows.Scan(&e.ID, &e.CaseID, &e.Epoch, &e.Actor, &e.Action, &e.Outcome, &e.RuleID, &e.RuleDigest, &e.BundleDigest, &e.CaseVersion, &e.PreparedAt, &raw, &e.AttemptID)
		if err != nil || decodeSummary(raw, &e.Summary) != nil || c.ValidateEvent(e) != nil {
			return nil, c.ErrUnavailable
		}
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, c.ErrUnavailable
	}
	return out, nil
}
