package admissionsql

import (
	"context"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/jackc/pgx/v5"
	a "privacy-proxy/internal/admission"
)

func addressBytes(v *common.Address) []byte {
	if v == nil {
		return nil
	}
	return v.Bytes()
}
func numeric(v *float64) any {
	if v == nil {
		return nil
	}
	out, _ := a.CanonicalFiat(*v)
	return out
}
func boundedNumeric(column string) string {
	return `CASE WHEN octet_length(` + column + `::text)<=512 THEN ` + column + `::text WHEN ` + column + ` IS NULL THEN NULL ELSE 'invalid' END`
}

func (t *rawTx) AppendEvent(e a.Event) (int64, error) {
	if !e.Valid() || e.Scope != t.scope {
		return 0, a.ErrInvalid
	}
	var qDigest []byte
	var qID, qSource, qValue any
	var qAsOf, qObserved any
	if e.Quote != nil {
		q := e.Quote
		qDigest = q.Digest[:]
		qID = q.ID
		qSource = q.SourceID
		qValue, _ = a.CanonicalFiat(q.Value)
		qAsOf = q.ProviderAsOf
		qObserved = q.FetchedAt
	}
	var id int64
	err := t.tx.QueryRow(t.ctx, `INSERT INTO ops_admission_v2.compliance_events(network_key,tx_hash,actor_id,org_id,kind,coverage,from_address,to_address,token,amount_wei,amount_fiat,threshold_fiat,currency,decision,monitored,reason,record_id,decision_at,policy_digest,quote_digest,quote_id,quote_source,quote_value,quote_as_of,quote_observed_at,anchor_hash,anchor_number,anchor_timestamp,evidence_profile)VALUES($1,$2,$3,$4::uuid,$5,$6,$7,$8,$9,$10,$11::numeric,$12::numeric,$13,$14,$15,$16,$17::uuid,$18,$19,$20,$21,$22,$23::numeric,$24,$25,$26,$27::numeric,$28::numeric,$29)RETURNING id`, t.scope.Network[:], t.scope.Hash[:], t.scope.Actor, t.scope.Organization, e.Kind, e.Coverage, addressBytes(e.From), addressBytes(e.To), addressBytes(e.Token), e.AmountWei, numeric(e.AmountFiat), numeric(e.Threshold), e.Currency, e.Decision, e.Monitored, e.Reason, e.RecordID, e.DecisionAt, e.PolicyDigest[:], qDigest, qID, qSource, qValue, qAsOf, qObserved, e.Anchor.Hash[:], strconv.FormatUint(e.Anchor.Number, 10), strconv.FormatUint(e.Anchor.Timestamp, 10), e.Anchor.Profile).Scan(&id)
	if err != nil || id <= 0 {
		return 0, a.ErrUnavailable
	}
	return id, nil
}

var eventColumns = `id,tx_hash,actor_id,org_id::text,kind,coverage,from_address,to_address,token,amount_wei,` + boundedNumeric("amount_fiat") + `,` + boundedNumeric("threshold_fiat") + `,currency,decision,monitored,reason,record_id::text,decision_at,policy_digest,quote_digest,quote_id,quote_source,` + boundedNumeric("quote_value") + `,quote_as_of,quote_observed_at,anchor_hash,anchor_number::text,anchor_timestamp::text,evidence_profile`

func scanEvent(row pgx.Row, network a.Digest, expected a.ExpectedState) (a.Event, error) {
	e := a.Event{Scope: a.Scope{Network: network, State: expected}}
	var hash, from, to, token, policy, quote, anchor []byte
	var fiat, threshold, qID, qSource, qValue *string
	var qAsOf, qObserved *time.Time
	var number, timestamp string
	err := row.Scan(&e.ID, &hash, &e.Scope.Actor, &e.Scope.Organization, &e.Kind, &e.Coverage, &from, &to, &token, &e.AmountWei, &fiat, &threshold, &e.Currency, &e.Decision, &e.Monitored, &e.Reason, &e.RecordID, &e.DecisionAt, &policy, &quote, &qID, &qSource, &qValue, &qAsOf, &qObserved, &anchor, &number, &timestamp, &e.Anchor.Profile)
	if err != nil || len(hash) != 32 || len(policy) != 32 || len(anchor) != 32 {
		return e, a.ErrUnavailable
	}
	copy(e.Scope.Hash[:], hash)
	copy(e.PolicyDigest[:], policy)
	copy(e.Anchor.Hash[:], anchor)
	e.Anchor.OrganizationID = e.Scope.Organization
	e.Anchor.Number, err = strconv.ParseUint(number, 10, 64)
	if err != nil {
		return e, a.ErrUnavailable
	}
	e.Anchor.Timestamp, err = strconv.ParseUint(timestamp, 10, 64)
	if err != nil {
		return e, a.ErrUnavailable
	}
	for _, pair := range []struct {
		raw []byte
		dst **common.Address
	}{{from, &e.From}, {to, &e.To}, {token, &e.Token}} {
		if pair.raw != nil {
			if len(pair.raw) != 20 {
				return e, a.ErrUnavailable
			}
			v := common.BytesToAddress(pair.raw)
			*pair.dst = &v
		}
	}
	for _, pair := range []struct {
		raw *string
		dst **float64
	}{{fiat, &e.AmountFiat}, {threshold, &e.Threshold}} {
		if pair.raw != nil {
			v, err := storedFiat(*pair.raw)
			if err != nil {
				return e, err
			}
			*pair.dst = &v
		}
	}
	if quote != nil {
		if len(quote) != 32 || qID == nil || qSource == nil || qValue == nil || qAsOf == nil || qObserved == nil || e.Currency == nil {
			return e, a.ErrUnavailable
		}
		v, err := storedFiat(*qValue)
		if err != nil {
			return e, err
		}
		q := a.Quote{ID: *qID, Currency: *e.Currency, SourceID: *qSource, Value: v, ProviderAsOf: *qAsOf, FetchedAt: *qObserved}
		copy(q.Digest[:], quote)
		e.Quote = &q
	} else if qID != nil || qSource != nil || qValue != nil || qAsOf != nil || qObserved != nil {
		return e, a.ErrUnavailable
	}
	if e.ID <= 0 || !e.Valid() {
		return e, a.ErrUnavailable
	}
	return e, nil
}
func (s *Store) ListEvents(ctx context.Context, network a.Digest, expected a.ExpectedState, org string, position a.EventPosition, limit int) ([]a.Event, error) {
	if s.mode == "retention" || !a.ValidUUID(org) || limit < 1 || limit > 101 || (!position.At.IsZero() && position.ID <= 0) {
		return nil, a.ErrInvalid
	}
	hasPosition := !position.At.IsZero()
	if !hasPosition {
		position.At = time.Unix(0, 0)
		position.ID = 0
	}
	out := []a.Event{}
	err := s.readReady(ctx, network, expected, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+eventColumns+` FROM ops_admission_v2.compliance_events WHERE network_key=$1 AND org_id=$2::uuid AND(NOT $3::boolean OR(decision_at,id)<($4,$5::bigint))ORDER BY decision_at DESC,id DESC LIMIT $6`, network[:], org, hasPosition, position.At, position.ID, limit)
		if err != nil {
			return a.ErrUnavailable
		}
		defer rows.Close()
		for rows.Next() {
			e, err := scanEvent(rows, network, expected)
			if err != nil {
				return err
			}
			if e.Scope.Organization != org {
				return a.ErrUnavailable
			}
			out = append(out, e)
		}
		if rows.Err() != nil {
			return a.ErrUnavailable
		}
		return nil
	})
	return out, err
}
