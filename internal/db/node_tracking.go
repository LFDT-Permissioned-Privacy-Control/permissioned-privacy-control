package db

// RD-1410: the execution-tracking store (plan §4.10, §4.11). Every write is a
// batch in one transaction that
//   - asserts the tracking database's incarnation (G59), so work issued before
//     the database was recreated cannot touch a new row;
//   - locks the binding rows it changes in hash order (one global lock order
//     for every multi-row writer);
//   - computes the pending-quota delta as is_pending(after) − is_pending(before)
//     from the locked before-state (§4.8.2), sums it, and updates the shared
//     pending_quota row last, so its lock is held only until commit.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
)

// Binding states (node_tx_binding.state) and final states (node_tx_status).
const (
	TrackPending        int16 = 1
	TrackProvisional    int16 = 2
	TrackRenewalStopped int16 = 3
	TrackTombstone      int16 = 4
	TrackIncluded       int16 = 10
	TrackReverted       int16 = 11
	TrackDropped        int16 = 12
)

// Reason codes (node_tx_binding.reason, node_tx_status.reason,
// node_tx_identities.reason).
const (
	TrackReasonNone                 int16 = 0
	TrackReasonResubmitted          int16 = 1
	TrackReasonRevived              int16 = 2
	TrackReasonOrganizationDeleted  int16 = 3
	TrackReasonEffectsBelowFloor    int16 = 4
	TrackReasonOwnershipConflict    int16 = 5
	TrackReasonEffectsFloorMissing  int16 = 6
	TrackReasonNonceConsumed        int16 = 7
	TrackReasonMaxAge               int16 = 8
	TrackReasonFinalizedLeaseExpiry int16 = 9
)

// History actors (node_tx_identities.actor).
const (
	trackActorClient int16 = 1
	trackActorSystem int16 = 2
)

// TrackStateName is the API name of a tracking state.
func TrackStateName(state int16) string {
	switch state {
	case TrackPending:
		return "pending"
	case TrackProvisional:
		return "provisional"
	case TrackRenewalStopped, TrackTombstone:
		return "renewal_stopped"
	case TrackIncluded:
		return "included"
	case TrackReverted:
		return "reverted"
	case TrackDropped:
		return "dropped"
	default:
		return "unknown"
	}
}

// TrackReasonName is the API name of a reason code ("" for none).
func TrackReasonName(reason int16) string {
	switch reason {
	case TrackReasonOrganizationDeleted:
		return "organization_deleted"
	case TrackReasonEffectsBelowFloor, TrackReasonOwnershipConflict, TrackReasonEffectsFloorMissing:
		// One opaque name: which other organisation owns an address, or the
		// replay floor, is not the submitter's to learn.
		return "effects_not_applied"
	case TrackReasonNonceConsumed:
		return "nonce_consumed"
	case TrackReasonMaxAge:
		return "max_age"
	case TrackReasonFinalizedLeaseExpiry:
		return "finalized_lease_expiry"
	default:
		return ""
	}
}

func isPending(state int16) int64 {
	if state == TrackPending {
		return 1
	}
	return 0
}

// ErrTrackingIncarnation: the tracking database's incarnation differs from
// the one the work was issued under (the database was recreated). The work has
// no effect; the caller re-reads tracking_meta and adopts the new one.
var ErrTrackingIncarnation = errors.New("execution-tracking database incarnation changed")

// TrackAdmission is one request-path binding write (the intent saved before
// transport).
type TrackAdmission struct {
	Hash          []byte // 32 bytes
	PrincipalID   uuid.UUID
	OrgID         uuid.UUID
	Signer        []byte // 20 bytes
	Nonce         uint64
	ContextID     uuid.UUID
	EnvelopeHash  []byte // 32 bytes
	ExpiresAt     time.Time
	MinVersion    uint64
	Raw           []byte
	VisibleTo     []string
	VisibleSender string // the sender DID; required when VisibleTo is set
	// ClaimOwner is the instance delivering this generation; the claim keeps
	// the lease keeper off the row until ClaimTTL passes.
	ClaimOwner uuid.UUID
	ClaimTTL   time.Duration
}

func (a TrackAdmission) validate() error {
	if len(a.Hash) != 32 || len(a.Signer) != 20 || len(a.EnvelopeHash) != 32 || a.PrincipalID == uuid.Nil || a.OrgID == uuid.Nil || a.ContextID == uuid.Nil || a.Nonce > 1<<63-1 || a.MinVersion == 0 || a.MinVersion > 1<<63-1 || len(a.Raw) == 0 || a.ExpiresAt.IsZero() || a.ClaimTTL < 0 {
		return fmt.Errorf("invalid tracking admission")
	}
	if (len(a.VisibleTo) == 0) != (a.VisibleSender == "") {
		return fmt.Errorf("invalid tracking admission visibility")
	}
	return nil
}

// AdmitOutcome is the result of one admission.
type AdmitOutcome uint8

const (
	// AdmitInserted: a new binding (generation 1).
	AdmitInserted AdmitOutcome = iota + 1
	// AdmitResubmitted: the same principal's binding exists in flight; its
	// generation advanced (quota unchanged).
	AdmitResubmitted
	// AdmitRevived: the same principal's renewal_stopped or tombstone binding
	// became pending again, a fresh admission.
	AdmitRevived
	// AdmitConflict: H is bound to another principal, organisation, signer or
	// visibility list, live, tombstoned or final. Nothing was written.
	AdmitConflict
	// AdmitFinal: H already has a final status for this principal. Nothing was
	// written.
	AdmitFinal
	// AdmitOverLimit: refused, the pending-work limit is reached. Nothing was
	// written.
	AdmitOverLimit
	// AdmitInvalid: the admission itself is malformed. Nothing was written.
	AdmitInvalid
)

// AdmitResult is the result of one admission of a batch.
type AdmitResult struct {
	Outcome    AdmitOutcome
	Generation int32
	State      int16
}

// Written reports whether the admission's identity was recorded.
func (r AdmitResult) Written() bool {
	return r.Outcome == AdmitInserted || r.Outcome == AdmitResubmitted || r.Outcome == AdmitRevived
}

func (e *ExecDB) assertIncarnation(ctx context.Context, tx *sql.Tx, inc uuid.UUID) error {
	var current uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT incarnation FROM tracking_meta`).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) || isUndefinedTable(err) {
		return ErrTrackingUninitialised
	}
	if err != nil {
		return err
	}
	if current != inc {
		return ErrTrackingIncarnation
	}
	return nil
}

// trackTx runs fn in one transaction after the incarnation assertion,
// retrying serialization failures and deadlocks.
func (e *ExecDB) trackTx(ctx context.Context, inc uuid.UUID, fn func(*sql.Tx) error) error {
	return withRetry(ctx, func() error {
		tx, err := e.pool.conn.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := e.assertIncarnation(ctx, tx, inc); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	})
}

// payloadBucketSQL is the current payload ring bucket (16 × 15 minutes) on
// the database clock.
const payloadBucketSQL = `SELECT (floor(extract(epoch FROM clock_timestamp()) / 900)::bigint % 16)::smallint`

func addQuota(ctx context.Context, tx *sql.Tx, delta int64) (int64, error) {
	var used int64
	if delta == 0 {
		return 0, nil
	}
	err := tx.QueryRowContext(ctx, `UPDATE pending_quota SET used = used + $1 RETURNING used`, delta).Scan(&used)
	return used, err
}

// AdmitBatch writes a batch of request-path intents in one transaction (one
// commit for the whole batch, plan §6.1). Per hash, the first intent of the
// batch is written first, later ones as resubmissions of it. A different
// principal, organisation, signer or visibility list for a bound hash is a
// conflict, whether the binding is live, a tombstone or final (G13, G58).
// With limit > 0, an admission that would make a binding pending (+1) is
// refused once the pending quota exceeds limit; resubmissions (Δ 0) are never
// refused (G63). Refused admissions write nothing.
func (e *ExecDB) AdmitBatch(ctx context.Context, inc uuid.UUID, limit int64, batch []TrackAdmission) ([]AdmitResult, error) {
	// An invalid admission is refused on its own; it never fails the
	// requests batched with it.
	refused := map[int]AdmitOutcome{}
	for i, a := range batch {
		if a.validate() != nil {
			refused[i] = AdmitInvalid
		}
	}
	// rounds[k] holds the k-th intent of each hash (indexes into batch).
	var rounds [][]int
	seen := map[string]int{}
	for i, a := range batch {
		if _, invalid := refused[i]; invalid {
			continue
		}
		k := seen[string(a.Hash)]
		seen[string(a.Hash)] = k + 1
		if k == len(rounds) {
			rounds = append(rounds, nil)
		}
		rounds[k] = append(rounds[k], i)
	}
	var results []AdmitResult
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		var bucket int16
		if err := tx.QueryRowContext(ctx, payloadBucketSQL).Scan(&bucket); err != nil {
			return err
		}
		for i, outcome := range refused {
			if outcome != AdmitInvalid {
				delete(refused, i) // a retried transaction starts over
			}
		}
		for attempt := 0; attempt <= len(batch); attempt++ {
			if _, err := tx.ExecContext(ctx, `SAVEPOINT admit`); err != nil {
				return err
			}
			written, retry, err := admitAttempt(ctx, tx, inc, limit, bucket, batch, rounds, refused)
			if err != nil {
				return err
			}
			if retry {
				if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT admit`); err != nil {
					return err
				}
				continue
			}
			results = make([]AdmitResult, len(batch))
			for i := range batch {
				if outcome, ok := refused[i]; ok {
					results[i] = AdmitResult{Outcome: outcome}
					continue
				}
				row := written[i]
				results[i] = AdmitResult{Outcome: AdmitResubmitted, Generation: row.generation, State: row.state}
				switch {
				case !row.prev.Valid:
					results[i].Outcome = AdmitInserted
				case row.prev.Int16 == TrackRenewalStopped || row.prev.Int16 == TrackTombstone:
					results[i].Outcome = AdmitRevived
				}
			}
			return nil
		}
		return fmt.Errorf("tracking admission did not converge")
	})
	if err != nil {
		return nil, err
	}
	return results, nil
}

type admitRow struct {
	prev       sql.NullInt16
	state      int16
	generation int32
}

// admitAttempt runs one attempt after SAVEPOINT. It returns retry=true after
// adding refusals (already final, over limit); the caller rolls back to the
// savepoint, which also releases this attempt's row and quota locks.
func admitAttempt(ctx context.Context, tx *sql.Tx, inc uuid.UUID, limit int64, bucket int16, batch []TrackAdmission, rounds [][]int, refused map[int]AdmitOutcome) (map[int]admitRow, bool, error) {
	written := map[int]admitRow{}
	var order []int // written intents, round by round
	for _, round := range rounds {
		var members []int
		for _, i := range round {
			if _, no := refused[i]; !no {
				members = append(members, i)
			}
		}
		if len(members) == 0 {
			continue
		}
		sort.Slice(members, func(x, y int) bool { return bytes.Compare(batch[members[x]].Hash, batch[members[y]].Hash) < 0 })
		rows, err := upsertRound(ctx, tx, inc, bucket, batch, members)
		if err != nil {
			return nil, false, err
		}
		for _, i := range members {
			if row, ok := rows[string(batch[i].Hash)]; ok {
				written[i] = row
				order = append(order, i)
			} else {
				refused[i] = AdmitConflict
			}
		}
	}
	// A fresh insert of a hash that is already final would rebind an executed
	// transaction: refuse it. The final row commits with the binding's
	// delete, so this read, after the insert, sees it.
	var fresh [][]byte
	for _, i := range order {
		if !written[i].prev.Valid {
			fresh = append(fresh, batch[i].Hash)
		}
	}
	if len(fresh) > 0 {
		finals, err := finalStatuses(ctx, tx, fresh)
		if err != nil {
			return nil, false, err
		}
		if len(finals) > 0 {
			for i := range batch {
				if final, ok := finals[string(batch[i].Hash)]; ok {
					// Only the owner of an executed transaction is answered
					// with it; a dropped one can never execute.
					if batch[i].PrincipalID == final.principal && final.state != TrackDropped {
						refused[i] = AdmitFinal
					} else {
						refused[i] = AdmitConflict
					}
				}
			}
			return nil, true, nil
		}
	}
	var delta int64
	var plus []int
	var payloadHashes, payloadRaw [][]byte
	var history []int
	for _, i := range order {
		row := written[i]
		before := int16(0)
		if row.prev.Valid {
			before = row.prev.Int16
		}
		d := isPending(row.state) - isPending(before)
		delta += d
		if d > 0 {
			plus = append(plus, i)
		}
		if !row.prev.Valid || before == TrackRenewalStopped || before == TrackTombstone {
			payloadHashes = append(payloadHashes, batch[i].Hash)
			payloadRaw = append(payloadRaw, batch[i].Raw)
		}
		if row.generation >= 2 {
			history = append(history, i)
		}
	}
	if len(payloadHashes) > 0 {
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_payload (bucket, tx_hash, raw_tx) SELECT $1, h, r FROM unnest($2::bytea[], $3::bytea[]) AS t(h, r) ON CONFLICT DO NOTHING`, bucket, payloadHashes, payloadRaw); err != nil {
			return nil, false, err
		}
	}
	if len(history) > 0 {
		n := len(history)
		hashes, generations, contexts, envelopes, expiries, versions, reasons := make([][]byte, n), make([]int64, n), make([]string, n), make([][]byte, n), make([]time.Time, n), make([]int64, n), make([]int64, n)
		for k, i := range history {
			a, row := batch[i], written[i]
			hashes[k], generations[k], contexts[k], envelopes[k], expiries[k], versions[k] = a.Hash, int64(row.generation), a.ContextID.String(), a.EnvelopeHash, a.ExpiresAt, int64(a.MinVersion)
			reasons[k] = int64(TrackReasonResubmitted)
			if row.prev.Valid && (row.prev.Int16 == TrackRenewalStopped || row.prev.Int16 == TrackTombstone) {
				reasons[k] = int64(TrackReasonRevived)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_identities (tx_hash, generation, context_id, envelope_hash, expires_at, min_version, reason, actor)
 SELECT h, g, c, e, x, m, r, $8 FROM unnest($1::bytea[], $2::int[], $3::uuid[], $4::bytea[], $5::timestamptz[], $6::bigint[], $7::smallint[]) AS t(h, g, c, e, x, m, r)`, hashes, generations, contexts, envelopes, expiries, versions, reasons, trackActorClient); err != nil {
			return nil, false, err
		}
	}
	// The shared quota row last: its lock is held only until commit.
	used, err := addQuota(ctx, tx, delta)
	if err != nil {
		return nil, false, err
	}
	if limit > 0 && delta > 0 && used > limit {
		excess := used - limit
		if excess > int64(len(plus)) {
			excess = int64(len(plus))
		}
		for _, i := range plus[int64(len(plus))-excess:] {
			refused[i] = AdmitOverLimit
		}
		return nil, true, nil
	}
	return written, false, nil
}

// upsertRound writes one intent per hash (members sorted by hash, so rows are
// locked in hash order) and returns the written rows by hash. A hash missing
// from the result did not match the bound principal, organisation, signer and
// visibility (a conflict).
func upsertRound(ctx context.Context, tx *sql.Tx, inc uuid.UUID, bucket int16, batch []TrackAdmission, members []int) (map[string]admitRow, error) {
	n := len(members)
	hashes, signers, envelopes := make([][]byte, n), make([][]byte, n), make([][]byte, n)
	principals, orgs, contexts, visible, senders := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]sql.NullString, n)
	nonces, versions, ttls := make([]int64, n), make([]int64, n), make([]int64, n)
	expiries := make([]time.Time, n)
	owners := make([]sql.NullString, n)
	for k, i := range members {
		a := batch[i]
		hashes[k], signers[k], envelopes[k] = a.Hash, a.Signer, a.EnvelopeHash
		principals[k], orgs[k], contexts[k] = a.PrincipalID.String(), a.OrgID.String(), a.ContextID.String()
		to := a.VisibleTo
		if to == nil {
			to = []string{}
		}
		encoded, err := json.Marshal(to)
		if err != nil {
			return nil, err
		}
		visible[k] = string(encoded)
		if a.VisibleSender != "" {
			senders[k] = sql.NullString{String: a.VisibleSender, Valid: true}
		}
		nonces[k], versions[k], ttls[k] = int64(a.Nonce), int64(a.MinVersion), a.ClaimTTL.Milliseconds()
		expiries[k] = a.ExpiresAt
		if a.ClaimOwner != uuid.Nil {
			owners[k] = sql.NullString{String: a.ClaimOwner.String(), Valid: true}
		}
	}
	rows, err := tx.QueryContext(ctx, `INSERT INTO node_tx_binding AS b (tx_hash, principal_id, org_id, signer, nonce, state, generation, context_id, envelope_hash, expires_at, min_version, incarnation, issued_contexts, visible_to, visible_sender, claim_owner, claim_expires, payload_bucket)
 SELECT t.h, t.p, t.o, t.s, t.n, 1, 1, t.c, t.e, t.x, t.m, $13, ARRAY[t.c], ARRAY(SELECT jsonb_array_elements_text(t.v::jsonb)), t.vs, t.co,
        CASE WHEN t.co IS NULL THEN NULL ELSE clock_timestamp() + t.ttl * interval '1 millisecond' END, $14
 FROM unnest($1::bytea[], $2::uuid[], $3::uuid[], $4::bytea[], $5::bigint[], $6::uuid[], $7::bytea[], $8::timestamptz[], $9::bigint[], $10::text[], $11::text[], $12::uuid[], $15::bigint[])
      WITH ORDINALITY AS t(h, p, o, s, n, c, e, x, m, v, vs, co, ttl, ord)
 ORDER BY t.ord
 ON CONFLICT (tx_hash) DO UPDATE SET
   prev_state = b.state,
   generation = b.generation + 1,
   context_id = EXCLUDED.context_id,
   envelope_hash = EXCLUDED.envelope_hash,
   expires_at = EXCLUDED.expires_at,
   min_version = EXCLUDED.min_version,
   issued_contexts = (b.issued_contexts || EXCLUDED.context_id)[greatest(1, cardinality(b.issued_contexts) - 14):],
   claim_owner = EXCLUDED.claim_owner,
   claim_boot = NULL,
   claim_expires = EXCLUDED.claim_expires,
   state = CASE WHEN b.state IN (3, 4) THEN 1 ELSE b.state END,
   reason = CASE WHEN b.state IN (3, 4) THEN 0 ELSE b.reason END,
   created_at = CASE WHEN b.state IN (3, 4) THEN clock_timestamp() ELSE b.created_at END,
   payload_bucket = CASE WHEN b.state IN (3, 4) THEN EXCLUDED.payload_bucket ELSE b.payload_bucket END,
   delivered_generation = CASE WHEN b.state IN (3, 4) THEN NULL ELSE b.delivered_generation END,
   delivered_boot = CASE WHEN b.state IN (3, 4) THEN NULL ELSE b.delivered_boot END
 WHERE b.principal_id = EXCLUDED.principal_id AND b.org_id = EXCLUDED.org_id AND b.signer = EXCLUDED.signer
   AND b.visible_to = EXCLUDED.visible_to AND b.visible_sender IS NOT DISTINCT FROM EXCLUDED.visible_sender
   AND b.incarnation = EXCLUDED.incarnation
 RETURNING b.tx_hash, b.prev_state, b.state, b.generation`,
		hashes, principals, orgs, signers, nonces, contexts, envelopes, expiries, versions, visible, senders, owners, inc.String(), bucket, ttls)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]admitRow{}
	for rows.Next() {
		var hash []byte
		var row admitRow
		if err := rows.Scan(&hash, &row.prev, &row.state, &row.generation); err != nil {
			return nil, err
		}
		out[string(hash)] = row
	}
	return out, rows.Err()
}

type finalStatus struct {
	principal uuid.UUID
	state     int16
}

// finalStatuses returns, for each hash with a final status row, the principal
// and state of its latest one.
func finalStatuses(ctx context.Context, tx *sql.Tx, hashes [][]byte) (map[string]finalStatus, error) {
	rows, err := tx.QueryContext(ctx, `SELECT DISTINCT ON (tx_hash) tx_hash, principal_id, state FROM node_tx_status WHERE tx_hash = ANY($1) ORDER BY tx_hash, final_at DESC`, hashes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]finalStatus{}
	for rows.Next() {
		var hash []byte
		var f finalStatus
		if err := rows.Scan(&hash, &f.principal, &f.state); err != nil {
			return nil, err
		}
		out[string(hash)] = f
	}
	return out, rows.Err()
}

// ReleaseUndelivered is the transition of a binding whose only identity the
// node definitively refused before admission (-32012, facts pending): the row
// is deleted (Δ −1) only if it is still exactly the fresh insert of this
// request — pending, generation 1 with this context, never upserted again
// (no resubmission or revival), never acknowledged. Anything else is left as
// it is. Returns whether the row was deleted.
func (e *ExecDB) ReleaseUndelivered(ctx context.Context, inc uuid.UUID, hash []byte, contextID uuid.UUID) (bool, error) {
	if len(hash) != 32 || contextID == uuid.Nil {
		return false, fmt.Errorf("invalid tracking release")
	}
	var released bool
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		var n int64
		if err := tx.QueryRowContext(ctx, `WITH target AS (
   SELECT tx_hash FROM node_tx_binding
   WHERE tx_hash = $1 AND state = 1 AND generation = 1 AND context_id = $2 AND prev_state IS NULL AND delivered_generation IS NULL AND incarnation = $3
   FOR UPDATE)
 , gone AS (DELETE FROM node_tx_binding b USING target WHERE b.tx_hash = target.tx_hash RETURNING 1)
 SELECT count(*) FROM gone`, hash, contextID.String(), inc.String()).Scan(&n); err != nil {
			return err
		}
		released = n == 1
		_, err := addQuota(ctx, tx, -n)
		return err
	})
	return released, err
}

// TrackTransition is one non-final state change of a binding.
type TrackTransition struct {
	Hash        []byte
	From, To    int16
	Generation  int32 // 0: any generation
	Reason      int16
	BlockNumber *uint64 // the including block (provisional)
}

func allowedTransition(from, to int16) bool {
	switch {
	case from == TrackPending && (to == TrackProvisional || to == TrackRenewalStopped):
		return true
	case from == TrackProvisional && to == TrackPending: // reorged out
		return true
	case from == TrackRenewalStopped && (to == TrackProvisional || to == TrackTombstone): // late inclusion; finalized lease expiry
		return true
	}
	return false
}

// ApplyTransitions applies non-final transitions in one transaction. A
// transition applies only if the locked row is still in From (and at
// Generation, when set); otherwise it is skipped, so a stale or repeated
// observation writes nothing. Making a row provisional records its delivery
// (the inclusion is the acknowledgement); a reorg back to pending clears it.
// Returns which transitions applied.
func (e *ExecDB) ApplyTransitions(ctx context.Context, inc uuid.UUID, transitions []TrackTransition) ([]bool, error) {
	byHash := map[string]int{}
	var hashes [][]byte
	for i, t := range transitions {
		if len(t.Hash) != 32 || !allowedTransition(t.From, t.To) || (t.BlockNumber != nil && *t.BlockNumber > 1<<63-1) {
			return nil, fmt.Errorf("invalid tracking transition")
		}
		if _, dup := byHash[string(t.Hash)]; dup {
			return nil, fmt.Errorf("duplicate tracking transition")
		}
		byHash[string(t.Hash)] = i
		hashes = append(hashes, t.Hash)
	}
	applied := make([]bool, len(transitions))
	if len(transitions) == 0 {
		return applied, nil
	}
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		for i := range applied {
			applied[i] = false
		}
		locked, err := lockBindings(ctx, tx, inc, hashes)
		if err != nil {
			return err
		}
		var delta int64
		var hs [][]byte
		var tos, reasons []int64
		var blocks []sql.NullInt64
		var stopped []int
		for hash, row := range locked {
			i := byHash[hash]
			t := transitions[i]
			if row.state != t.From || (t.Generation != 0 && row.generation != t.Generation) {
				continue
			}
			applied[i] = true
			delta += isPending(t.To) - isPending(row.state)
			hs, tos, reasons = append(hs, t.Hash), append(tos, int64(t.To)), append(reasons, int64(t.Reason))
			block := sql.NullInt64{}
			if t.BlockNumber != nil {
				block = sql.NullInt64{Int64: int64(*t.BlockNumber), Valid: true}
			}
			blocks = append(blocks, block)
			if t.To == TrackRenewalStopped || t.To == TrackTombstone {
				stopped = append(stopped, i)
			}
		}
		if len(hs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE node_tx_binding b SET
   state = v.st,
   reason = v.r,
   block_number = CASE WHEN v.st = 2 THEN v.blk WHEN v.st = 1 THEN NULL ELSE b.block_number END,
   delivered_generation = CASE WHEN v.st = 2 THEN b.generation WHEN v.st = 1 THEN NULL ELSE b.delivered_generation END,
   delivered_boot = CASE WHEN v.st = 1 THEN NULL ELSE b.delivered_boot END,
   claim_owner = CASE WHEN v.st = 1 THEN NULL ELSE b.claim_owner END,
   claim_boot = CASE WHEN v.st = 1 THEN NULL ELSE b.claim_boot END,
   claim_expires = CASE WHEN v.st = 1 THEN NULL ELSE b.claim_expires END
 FROM unnest($1::bytea[], $2::smallint[], $3::smallint[], $4::bigint[]) AS v(h, st, r, blk)
 WHERE b.tx_hash = v.h`, hs, tos, reasons, nullInts(blocks)); err != nil {
			return err
		}
		if len(stopped) > 0 {
			sh, sr := make([][]byte, len(stopped)), make([]int64, len(stopped))
			for k, i := range stopped {
				sh[k], sr[k] = transitions[i].Hash, int64(transitions[i].Reason)
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_identities (tx_hash, generation, context_id, reason, actor)
 SELECT b.tx_hash, b.generation, b.context_id, v.r, $3 FROM node_tx_binding b JOIN unnest($1::bytea[], $2::smallint[]) AS v(h, r) ON v.h = b.tx_hash`, sh, sr, trackActorSystem); err != nil {
				return err
			}
		}
		_, err = addQuota(ctx, tx, delta)
		return err
	})
	if err != nil {
		return nil, err
	}
	return applied, nil
}

type lockedBinding struct {
	state          int16
	generation     int32
	principal, org uuid.UUID
	admitXid       uint64
}

// lockBindings locks the bindings of hashes in hash order (the global lock
// order) and returns their current state.
func lockBindings(ctx context.Context, tx *sql.Tx, inc uuid.UUID, hashes [][]byte) (map[string]lockedBinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tx_hash, state, generation, principal_id, org_id, admit_xid::text FROM node_tx_binding WHERE tx_hash = ANY($1) AND incarnation = $2 ORDER BY tx_hash FOR UPDATE`, hashes, inc.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]lockedBinding{}
	for rows.Next() {
		var hash []byte
		var row lockedBinding
		var xid string
		if err := rows.Scan(&hash, &row.state, &row.generation, &row.principal, &row.org, &xid); err != nil {
			return nil, err
		}
		if row.admitXid, err = strconv.ParseUint(xid, 10, 64); err != nil {
			return nil, err
		}
		out[string(hash)] = row
	}
	return out, rows.Err()
}

// nullInts renders nullable integers as a text[] castable to bigint[].
func nullInts(values []sql.NullInt64) []sql.NullString {
	out := make([]sql.NullString, len(values))
	for i, v := range values {
		if v.Valid {
			out[i] = sql.NullString{String: strconv.FormatInt(v.Int64, 10), Valid: true}
		}
	}
	return out
}

// TrackFinal is one final transition: the binding is deleted and its status
// row inserted in the same transaction.
type TrackFinal struct {
	Hash        []byte
	State       int16 // TrackIncluded, TrackReverted or TrackDropped
	Reason      int16
	BlockNumber *uint64
	// The binding must still belong to this principal and organisation (the
	// node's answer is checked against it again under the lock).
	PrincipalID, OrgID uuid.UUID
	// AdmitXid, when set, must be the binding's: a binding released and
	// admitted again since it was read is a different binding.
	AdmitXid uint64
}

// FinalizeBatch finalizes bindings in one transaction: delete the binding,
// insert the insert-once status row, and release the quota of rows that were
// still pending (pending → final is −1; every other state carries none). A
// final status beats any recorded non-final state; it is not fenced by
// generation or context, because a finalized inclusion makes every generation
// obsolete (K19). Returns which finals applied.
func (e *ExecDB) FinalizeBatch(ctx context.Context, inc uuid.UUID, finals []TrackFinal) ([]bool, error) {
	byHash := map[string]int{}
	var hashes [][]byte
	for i, f := range finals {
		if len(f.Hash) != 32 || f.State < TrackIncluded || f.State > TrackDropped || (f.BlockNumber != nil && *f.BlockNumber > 1<<63-1) {
			return nil, fmt.Errorf("invalid tracking final")
		}
		if _, dup := byHash[string(f.Hash)]; dup {
			return nil, fmt.Errorf("duplicate tracking final")
		}
		byHash[string(f.Hash)] = i
		hashes = append(hashes, f.Hash)
	}
	applied := make([]bool, len(finals))
	if len(finals) == 0 {
		return applied, nil
	}
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		for i := range applied {
			applied[i] = false
		}
		locked, err := lockBindings(ctx, tx, inc, hashes)
		if err != nil {
			return err
		}
		var delta int64
		var hs [][]byte
		var states, reasons []int64
		var blocks []sql.NullInt64
		for hash, row := range locked {
			i := byHash[hash]
			f := finals[i]
			if row.principal != f.PrincipalID || row.org != f.OrgID || (f.AdmitXid != 0 && row.admitXid != f.AdmitXid) {
				continue
			}
			applied[i] = true
			delta -= isPending(row.state)
			hs, states, reasons = append(hs, f.Hash), append(states, int64(f.State)), append(reasons, int64(f.Reason))
			block := sql.NullInt64{}
			if f.BlockNumber != nil {
				block = sql.NullInt64{Int64: int64(*f.BlockNumber), Valid: true}
			}
			blocks = append(blocks, block)
		}
		if len(hs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `WITH gone AS (DELETE FROM node_tx_binding b USING unnest($1::bytea[]) AS v(h) WHERE b.tx_hash = v.h RETURNING b.tx_hash, b.principal_id, b.org_id)
 INSERT INTO node_tx_status (tx_hash, principal_id, org_id, state, reason, block_number)
 SELECT g.tx_hash, g.principal_id, g.org_id, v.st, v.r, v.blk FROM gone g JOIN unnest($1::bytea[], $2::smallint[], $3::smallint[], $4::bigint[]) AS v(h, st, r, blk) ON v.h = g.tx_hash`, hs, states, reasons, nullInts(blocks)); err != nil {
			return err
		}
		_, err = addQuota(ctx, tx, delta)
		return err
	})
	if err != nil {
		return nil, err
	}
	return applied, nil
}

// TrackAck is one delivery acknowledgement held in memory by the instance
// that delivered it.
type TrackAck struct {
	Hash       []byte
	Generation int32
}

// FlushAcks records acknowledgements of rows that are still pending at the
// acknowledged generation and not yet recorded as delivered. It is the batched
// flush for rows that did not reach another transition first (R12.6): a row
// already provisional, final or at a newer generation writes nothing. Rows
// another writer holds are skipped (SKIP LOCKED) and stay in memory. The node
// does not report a boot id yet, so delivered_boot stays NULL (never the
// cached boot, §4.8.4). Returns the acknowledged hashes that are settled
// (written or no longer applicable).
func (e *ExecDB) FlushAcks(ctx context.Context, inc uuid.UUID, acks []TrackAck) (map[string]bool, error) {
	if len(acks) == 0 {
		return map[string]bool{}, nil
	}
	sort.Slice(acks, func(i, j int) bool { return bytes.Compare(acks[i].Hash, acks[j].Hash) < 0 })
	hashes, generations := make([][]byte, len(acks)), make([]int64, len(acks))
	for i, a := range acks {
		hashes[i], generations[i] = a.Hash, int64(a.Generation)
	}
	settled := map[string]bool{}
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		clear(settled)
		// Rows locked by another writer are the only ones not settled here.
		rows, err := tx.QueryContext(ctx, `WITH v AS (SELECT * FROM unnest($1::bytea[], $2::int[]) AS v(h, g)),
 target AS (SELECT b.tx_hash, v.g FROM node_tx_binding b JOIN v ON b.tx_hash = v.h
            WHERE b.state = 1 AND b.generation = v.g AND b.delivered_generation IS DISTINCT FROM v.g AND b.incarnation = $3
            ORDER BY b.tx_hash FOR UPDATE OF b SKIP LOCKED),
 written AS (UPDATE node_tx_binding b SET delivered_generation = target.g, claim_owner = NULL, claim_boot = NULL, claim_expires = NULL
             FROM target WHERE b.tx_hash = target.tx_hash RETURNING b.tx_hash)
 SELECT v.h FROM v WHERE EXISTS (SELECT 1 FROM written w WHERE w.tx_hash = v.h)
    OR NOT EXISTS (SELECT 1 FROM node_tx_binding b WHERE b.tx_hash = v.h AND b.state = 1 AND b.generation = v.g AND b.delivered_generation IS DISTINCT FROM v.g)`, hashes, generations, inc.String())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var hash []byte
			if err := rows.Scan(&hash); err != nil {
				return err
			}
			settled[string(hash)] = true
		}
		return rows.Err()
	})
	return settled, err
}

// TrackedTransaction is a binding (in flight) or a final status row.
type TrackedTransaction struct {
	Hash           []byte
	PrincipalID    uuid.UUID
	OrgID          uuid.UUID
	State          int16
	Reason         int16
	Generation     int32 // 0 for final rows
	ContextID      uuid.UUID
	IssuedContexts []uuid.UUID
	BlockNumber    *uint64
	VisibleTo      []string
	VisibleSender  string
	CreatedAt      time.Time
	FinalAt        *time.Time
	AdmitXid       uint64
}

// Final reports whether the row is a final status.
func (t TrackedTransaction) Final() bool { return t.State >= TrackIncluded }

const trackedColumns = `tx_hash, principal_id, org_id, state, reason, generation, context_id, issued_contexts, block_number, visible_to, visible_sender, created_at, admit_xid::text`

func scanTracked(row interface{ Scan(...any) error }) (TrackedTransaction, error) {
	var t TrackedTransaction
	var block sql.NullInt64
	var sender sql.NullString
	var xid string
	var issued []string
	if err := row.Scan(&t.Hash, &t.PrincipalID, &t.OrgID, &t.State, &t.Reason, &t.Generation, &t.ContextID, ScanTextArray(&issued), &block, ScanTextArray(&t.VisibleTo), &sender, &t.CreatedAt, &xid); err != nil {
		return t, err
	}
	for _, s := range issued {
		id, err := uuid.Parse(s)
		if err != nil {
			return t, err
		}
		t.IssuedContexts = append(t.IssuedContexts, id)
	}
	if block.Valid {
		b := uint64(block.Int64)
		t.BlockNumber = &b
	}
	t.VisibleSender = sender.String
	var err error
	t.AdmitXid, err = strconv.ParseUint(xid, 10, 64)
	return t, err
}

// LookupTracked returns H's binding, or else its latest final status row
// (sql.ErrNoRows when OPS holds neither, e.g. after retention). The caller
// checks the principal (G44).
func (e *ExecDB) LookupTracked(ctx context.Context, hash []byte) (TrackedTransaction, error) {
	t, err := scanTracked(e.pool.conn.QueryRowContext(ctx, `SELECT `+trackedColumns+` FROM node_tx_binding WHERE tx_hash = $1`, hash))
	if !errors.Is(err, sql.ErrNoRows) {
		return t, err
	}
	var final TrackedTransaction
	var block sql.NullInt64
	var at time.Time
	err = e.pool.conn.QueryRowContext(ctx, `SELECT tx_hash, principal_id, org_id, state, reason, block_number, final_at FROM node_tx_status WHERE tx_hash = $1 ORDER BY final_at DESC LIMIT 1`, hash).Scan(&final.Hash, &final.PrincipalID, &final.OrgID, &final.State, &final.Reason, &block, &at)
	if err != nil {
		return final, err
	}
	if block.Valid {
		b := uint64(block.Int64)
		final.BlockNumber = &b
	}
	final.FinalAt = &at
	return final, nil
}

// TrackingHorizon is the snapshot xmin: every transaction below it has ended,
// so bindings with admit_xid below it are all visible now.
func (e *ExecDB) TrackingHorizon(ctx context.Context) (uint64, error) {
	var xmin string
	if err := e.pool.conn.QueryRowContext(ctx, `SELECT pg_snapshot_xmin(pg_current_snapshot())::text`).Scan(&xmin); err != nil {
		return 0, err
	}
	return strconv.ParseUint(xmin, 10, 64)
}

// ListTracked pages through bindings admitted in [fromXid, toXid) in admit_xid
// order, at most limit rows after (afterXid, afterHash) of the previous page.
// With toXid from TrackingHorizon no binding is ever skipped, whatever order
// concurrent batches commit in.
func (e *ExecDB) ListTracked(ctx context.Context, fromXid, toXid uint64, after []byte, limit int) ([]TrackedTransaction, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	if after == nil {
		after = []byte{}
	}
	rows, err := e.pool.conn.QueryContext(ctx, `SELECT `+trackedColumns+` FROM node_tx_binding
 WHERE admit_xid < $2::text::xid8 AND (admit_xid, tx_hash) > ($1::text::xid8, $3::bytea)
 ORDER BY admit_xid, tx_hash LIMIT $4`, strconv.FormatUint(fromXid, 10), strconv.FormatUint(toXid, 10), after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TrackedTransaction
	for rows.Next() {
		t, err := scanTracked(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TrackedPayload returns the raw transaction of an in-flight binding
// (sql.ErrNoRows once its payload bucket was truncated).
func (e *ExecDB) TrackedPayload(ctx context.Context, hash []byte) ([]byte, error) {
	var raw []byte
	err := e.pool.conn.QueryRowContext(ctx, `SELECT p.raw_tx FROM node_tx_binding b JOIN node_tx_payload p ON p.bucket = b.payload_bucket AND p.tx_hash = b.tx_hash WHERE b.tx_hash = $1`, hash).Scan(&raw)
	return raw, err
}

// PendingQuota returns the pending quota and the count of pending bindings
// (equal after every committed batch, G63).
func (e *ExecDB) PendingQuota(ctx context.Context) (used, pending int64, err error) {
	err = e.pool.conn.QueryRowContext(ctx, `SELECT (SELECT used FROM pending_quota), (SELECT count(*) FROM node_tx_binding WHERE state = 1)`).Scan(&used, &pending)
	return used, pending, err
}
