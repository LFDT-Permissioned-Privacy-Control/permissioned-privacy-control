package db

// RD-1410: the execution-tracking store (plan §4.10, §4.11). Every write is a
// batch in one transaction that
//   - asserts the tracking database's incarnation (G59), so work issued before
//     the database was recreated cannot touch a new row;
//   - locks the binding rows it changes in hash order (one global lock order
//     for every multi-row writer);
//   - computes the pending-quota delta as is_pending(after) − is_pending(before)
//     from the locked before-state (§4.8.2) for the global row, and
//     is_held(after) − is_held(before) (pending or renewal_stopped: the
//     bindings a principal holds) for the per-principal and per-organization
//     shares, and updates the principals' rows, then the organizations', then
//     the shared pending_quota row last, so the global lock is held only until
//     commit.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	// Renewal refusals (renewal_stopped, plan §4.8.1): the full admission
	// re-check or the pool refused; none is final.
	TrackReasonPrincipalBanned  int16 = 20
	TrackReasonKYCMissing       int16 = 21
	TrackReasonNotMember        int16 = 22
	TrackReasonMethodNotAllowed int16 = 23
	TrackReasonSenderUnlinked   int16 = 24
	TrackReasonComplianceDenied int16 = 25
	TrackReasonPrincipalDeleted int16 = 26
	TrackReasonNonceConflict    int16 = 27
	TrackReasonReplacedInPool   int16 = 28
	// The deployment's read profile no longer accepts visibleTo.
	TrackReasonVisibilityNotAllowed int16 = 29
	// The node kept refusing a renewed identity.
	TrackReasonNodeRejected int16 = 30
	// Renewal triggers (history rows of system generations).
	TrackReasonUndelivered   int16 = 40
	TrackReasonNodeRestarted int16 = 41
	TrackReasonEvicted       int16 = 42
	TrackReasonReorged       int16 = 43
	TrackReasonLeaseExpiring int16 = 44
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
	case TrackRenewalStopped:
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
	case TrackReasonPrincipalBanned:
		return "principal_banned"
	case TrackReasonKYCMissing:
		return "kyc_missing"
	case TrackReasonNotMember:
		return "not_member"
	case TrackReasonMethodNotAllowed:
		return "method_not_allowed"
	case TrackReasonSenderUnlinked:
		return "sender_unlinked"
	case TrackReasonComplianceDenied:
		return "compliance_denied"
	case TrackReasonPrincipalDeleted:
		return "principal_deleted"
	case TrackReasonNonceConflict:
		return "nonce_conflict"
	case TrackReasonReplacedInPool:
		return "replaced_in_pool"
	case TrackReasonVisibilityNotAllowed:
		return "visible_to_not_allowed"
	case TrackReasonNodeRejected:
		return "node_rejected"
	case TrackReasonUndelivered:
		return "undelivered"
	case TrackReasonNodeRestarted:
		return "node_restarted"
	case TrackReasonEvicted:
		return "evicted"
	case TrackReasonReorged:
		return "reorged"
	case TrackReasonLeaseExpiring:
		return "lease_expiring"
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

// isHeld: the binding counts toward its principal's and organization's
// share — pending, or renewal_stopped and not yet final (independent review,
// finding 2: stopped rows are bounded per owner, never unbounded).
func isHeld(state int16) int64 {
	if state == TrackPending || state == TrackRenewalStopped {
		return 1
	}
	return 0
}

// heldStatesSQL is isHeld as a predicate on node_tx_binding.
const heldStatesSQL = `state IN (1, 3)`

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
	// the lease keeper off the row until ClaimTTL passes, while the node is
	// still ClaimBoot (the boot the request delivers to; Nil: unknown).
	ClaimOwner uuid.UUID
	ClaimBoot  uuid.UUID
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
	// AdmitResubmitted: the same principal's binding exists in flight and this
	// envelope dominates the stored one (§4.8.3): it is the new generation
	// (quota unchanged).
	AdmitResubmitted
	// AdmitRevived: the same principal's renewal_stopped binding became
	// pending again, a fresh admission.
	AdmitRevived
	// AdmitConflict: H is bound to another principal, organisation, signer or
	// visibility list, live, stopped or final, or is dropped. Nothing was
	// written.
	AdmitConflict
	// AdmitFinal: H already has a final status for this principal. Nothing was
	// written.
	AdmitFinal
	// AdmitOverLimit: refused, the pending-work limit is reached. Nothing was
	// written.
	AdmitOverLimit
	// AdmitInvalid: the admission itself is malformed. Nothing was written.
	AdmitInvalid
	// AdmitKept: the same principal's in-flight binding holds an envelope that
	// dominates or equals this one (it was signed earlier, or is the same):
	// the stored generation stays current and meets this attempt's floor.
	// The caller may send this envelope only if it meets the returned stored
	// MinVersion too; otherwise it must re-read the clock and sign again.
	AdmitKept
	// AdmitIncomparable: neither envelope dominates the other (only after a
	// database clock step): the stored one is kept and nothing about this
	// attempt is recorded; the caller re-reads the clock and signs again.
	AdmitIncomparable
	// AdmitPrincipalOverLimit: refused, the submitting principal's own
	// pending-work limit is reached. Nothing was written.
	AdmitPrincipalOverLimit
	// AdmitOrgOverLimit: refused, the organization's pending-work limit is
	// reached. Nothing was written.
	AdmitOrgOverLimit
)

// TrackLimits bounds the work admissions may make renewable (plan §4.8.2):
// Global is L_admit over every principal; Principal and Org are one
// principal's and one organization's share. 0 disables a bound (the quota is
// still counted).
type TrackLimits struct {
	Global, Principal, Org int64
}

// AdmitResult is the result of one admission of a batch.
type AdmitResult struct {
	Outcome    AdmitOutcome
	Generation int32
	State      int16
	// ContextID is the binding's current context after the write (the
	// winner): this admission's own when it was written.
	ContextID uuid.UUID
	// MinVersion is the winner's fact floor, including when the stored
	// identity dominates this attempt and survives it.
	MinVersion uint64
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

// quotaDelta accumulates one batch's quota changes: the global
// is_pending(after) − is_pending(before), and is_held(after) − is_held(before)
// per principal and per organization (both identity columns of the binding,
// never updated).
type quotaDelta struct {
	global           *int64
	principals, orgs map[uuid.UUID]int64
}

func newQuotaDelta() quotaDelta {
	return quotaDelta{global: new(int64), principals: map[uuid.UUID]int64{}, orgs: map[uuid.UUID]int64{}}
}

// move records one binding's change of state (0: no row).
func (q quotaDelta) move(principal, org uuid.UUID, before, after int16) {
	*q.global += isPending(after) - isPending(before)
	if d := isHeld(after) - isHeld(before); d != 0 {
		q.principals[principal] += d
		q.orgs[org] += d
	}
}

// quotaShares are the per-key pending counters next to the global row, in
// lock order (table and key column names are constants, never input).
var quotaShares = []struct{ table, key string }{
	{"pending_quota_principal", "principal_id"},
	{"pending_quota_org", "org_id"},
}

// applyQuota applies a batch's quota deltas: the principals' rows (in key
// order, one statement), the organizations' rows likewise, then the global
// row last, so its lock is held only until commit. It returns the global
// used count (0 when it did not change) and each changed principal's and
// organization's. Every writer takes binding rows first, so the lock order is
// bindings → principal rows → organization rows → the global row.
func applyQuota(ctx context.Context, tx *sql.Tx, deltas quotaDelta) (used int64, perPrincipal, perOrg map[uuid.UUID]int64, err error) {
	if perPrincipal, err = applyShare(ctx, tx, quotaShares[0].table, quotaShares[0].key, deltas.principals); err != nil {
		return 0, nil, nil, err
	}
	if perOrg, err = applyShare(ctx, tx, quotaShares[1].table, quotaShares[1].key, deltas.orgs); err != nil {
		return 0, nil, nil, err
	}
	if *deltas.global != 0 {
		err = tx.QueryRowContext(ctx, `UPDATE pending_quota SET used = used + $1 RETURNING used`, *deltas.global).Scan(&used)
	}
	return used, perPrincipal, perOrg, err
}

// applyShare applies signed deltas to one per-key counter table in key order
// and returns the new counts. A count that would go below zero means the
// counters drifted (for example an instance of an older release kept
// admitting after the counters were added): that key is recounted under its
// row lock, which this transaction holds, so every other writer of its
// bindings applies its delta after this transaction commits and the recount
// (this transaction's own changes included) stays exact.
func applyShare(ctx context.Context, tx *sql.Tx, table, key string, deltas map[uuid.UUID]int64) (map[uuid.UUID]int64, error) {
	var keys []uuid.UUID
	for k, d := range deltas {
		if d != 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	ids, ds := make([]string, len(keys)), make([]int64, len(keys))
	for i, k := range keys {
		ids[i], ds[i] = k.String(), deltas[k]
	}
	rows, err := tx.QueryContext(ctx, `INSERT INTO `+table+` AS q (`+key+`, used)
 SELECT k, d FROM unnest($1::uuid[], $2::bigint[]) WITH ORDINALITY AS t(k, d, ord) ORDER BY t.ord
 ON CONFLICT (`+key+`) DO UPDATE SET used = q.used + EXCLUDED.used
 RETURNING `+key+`, used`, ids, ds)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]int64, len(keys))
	var drifted []uuid.UUID
	for rows.Next() {
		var k uuid.UUID
		var used int64
		if err := rows.Scan(&k, &used); err != nil {
			rows.Close()
			return nil, err
		}
		if used < 0 {
			drifted = append(drifted, k)
		}
		out[k] = used
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, k := range drifted {
		var recounted int64
		if err := tx.QueryRowContext(ctx, `UPDATE `+table+` SET used = (SELECT count(*) FROM node_tx_binding WHERE `+key+` = $1 AND `+heldStatesSQL+`) WHERE `+key+` = $1 RETURNING used`, k.String()).Scan(&recounted); err != nil {
			return nil, err
		}
		out[k] = recounted
		slog.Error("execution-tracking pending quota share had drifted below zero; recounted", "table", table, "key", k, "pending", recounted)
	}
	return out, nil
}

// AdmitBatch writes a batch of request-path intents in one transaction (one
// commit for the whole batch, plan §6.1). Per hash, the first intent of the
// batch is written first, later ones as resubmissions of it. A different
// principal, organisation, signer or visibility list for a bound hash is a
// conflict, whether the binding is live, stopped or final (G13, G58).
// A new binding is refused once its principal's or organization's share
// (pending and stopped bindings) exceeds limits.Principal or limits.Org
// (AdmitPrincipalOverLimit, AdmitOrgOverLimit); an admission that makes a
// binding pending (a new one or a revival) is refused once the global quota
// exceeds limits.Global (AdmitOverLimit); resubmissions (no change) are never
// refused (G63). Refused admissions write nothing.
func (e *ExecDB) AdmitBatch(ctx context.Context, inc uuid.UUID, limits TrackLimits, batch []TrackAdmission) ([]AdmitResult, error) {
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
			written, retry, err := admitAttempt(ctx, tx, inc, limits, bucket, batch, rounds, refused)
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
				results[i] = AdmitResult{Outcome: AdmitResubmitted, Generation: row.generation, State: row.state, ContextID: row.context, MinVersion: row.minVersion}
				switch {
				case !row.prev.Valid:
					results[i].Outcome = AdmitInserted
				case !row.replaced && row.incomparable:
					results[i].Outcome = AdmitIncomparable
				case !row.replaced:
					results[i].Outcome = AdmitKept
				case row.prev.Int16 == TrackRenewalStopped:
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
	context    uuid.UUID
	minVersion uint64
	// replaced: this admission's envelope is now the binding's (inserted,
	// revived or dominating); incomparable: kept because neither envelope
	// dominates the other.
	replaced, incomparable bool
}

// admitAttempt runs one attempt after SAVEPOINT. It returns retry=true after
// adding refusals (already final, over limit); the caller rolls back to the
// savepoint, which also releases this attempt's row and quota locks.
func admitAttempt(ctx context.Context, tx *sql.Tx, inc uuid.UUID, limits TrackLimits, bucket int16, batch []TrackAdmission, rounds [][]int, refused map[int]AdmitOutcome) (map[int]admitRow, bool, error) {
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
	deltas := newQuotaDelta()
	var plus, held []int // admissions that add pending work, and that add a held row
	var payloadHashes, payloadRaw [][]byte
	var history []int
	for _, i := range order {
		row := written[i]
		before := int16(0)
		if row.prev.Valid {
			before = row.prev.Int16
		}
		deltas.move(batch[i].PrincipalID, batch[i].OrgID, before, row.state)
		if isPending(row.state) > isPending(before) {
			plus = append(plus, i)
		}
		if isHeld(row.state) > isHeld(before) {
			held = append(held, i)
		}
		if row.replaced && (!row.prev.Valid || before == TrackRenewalStopped) {
			payloadHashes = append(payloadHashes, batch[i].Hash)
			payloadRaw = append(payloadRaw, batch[i].Raw)
		}
		// Every envelope that may reach the node is recorded before transport
		// (G38): a new generation, and also a kept one (the node may install
		// it, e.g. when it no longer holds the stored identity).
		if (row.generation >= 2 || !row.replaced) && !row.incomparable {
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
			if row.replaced && row.prev.Valid && row.prev.Int16 == TrackRenewalStopped {
				reasons[k] = int64(TrackReasonRevived)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO node_tx_identities (tx_hash, generation, context_id, envelope_hash, expires_at, min_version, reason, actor)
 SELECT h, g, c, e, x, m, r, $8 FROM unnest($1::bytea[], $2::int[], $3::uuid[], $4::bytea[], $5::timestamptz[], $6::bigint[], $7::smallint[]) AS t(h, g, c, e, x, m, r)`, hashes, generations, contexts, envelopes, expiries, versions, reasons, trackActorClient); err != nil {
			return nil, false, err
		}
	}
	// The principals' and organizations' rows, then the shared quota row
	// last: its lock is held only until commit.
	used, perPrincipal, perOrg, err := applyQuota(ctx, tx, deltas)
	if err != nil {
		return nil, false, err
	}
	// Admissions are Δ ≥ 0 only, so a principal, an organization or the total
	// over its limit is over because of this batch's +1 rows (or a reorg back
	// that already pushed it over, which this batch must not add to): refuse
	// the excess, latest first, and re-run without them. A share counts the
	// rows its owner holds (held: new bindings), the total the pending work
	// (plus: new bindings and revivals).
	refuseExcess := func(limit int64, counts map[uuid.UUID]int64, keyOf func(int) uuid.UUID, outcome AdmitOutcome) bool {
		if limit <= 0 {
			return false
		}
		byKey := map[uuid.UUID][]int{}
		for _, i := range held {
			byKey[keyOf(i)] = append(byKey[keyOf(i)], i)
		}
		refusedAny := false
		for k, rows := range byKey {
			if excess := min(counts[k]-limit, int64(len(rows))); excess > 0 {
				for _, i := range rows[int64(len(rows))-excess:] {
					refused[i] = outcome
				}
				refusedAny = true
			}
		}
		return refusedAny
	}
	if refuseExcess(limits.Principal, perPrincipal, func(i int) uuid.UUID { return batch[i].PrincipalID }, AdmitPrincipalOverLimit) ||
		refuseExcess(limits.Org, perOrg, func(i int) uuid.UUID { return batch[i].OrgID }, AdmitOrgOverLimit) {
		return nil, true, nil
	}
	if limits.Global > 0 && len(plus) > 0 && used > limits.Global {
		excess := min(used-limits.Global, int64(len(plus)))
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
	owners, boots := make([]sql.NullString, n), make([]sql.NullString, n)
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
		if a.ClaimBoot != uuid.Nil {
			boots[k] = sql.NullString{String: a.ClaimBoot.String(), Valid: true}
		}
	}
	// A same-principal conflict either replaces the stored envelope (a
	// revival of a stopped binding, or an envelope that dominates it: floor
	// and expiry both at least the stored ones, not both equal; §4.8.3) or
	// keeps it unchanged. Every SET expression reads the stored row (b.*), so
	// "replace" is evaluated once against it. max_expires_at keeps the longest
	// lease of any identity recorded for the binding (a revival may sign a
	// shorter one while the node keeps the longer).
	rows, err := tx.QueryContext(ctx, `INSERT INTO node_tx_binding AS b (tx_hash, principal_id, org_id, signer, nonce, state, generation, context_id, envelope_hash, expires_at, max_expires_at, min_version, incarnation, issued_contexts, visible_to, visible_sender, claim_owner, claim_boot, claim_expires, payload_bucket)
 SELECT t.h, t.p, t.o, t.s, t.n, 1, 1, t.c, t.e, t.x, t.x, t.m, $13, ARRAY[t.c], ARRAY(SELECT jsonb_array_elements_text(t.v::jsonb)), t.vs, t.co, t.cb,
        CASE WHEN t.co IS NULL THEN NULL ELSE clock_timestamp() + t.ttl * interval '1 millisecond' END, $14
 FROM unnest($1::bytea[], $2::uuid[], $3::uuid[], $4::bytea[], $5::bigint[], $6::uuid[], $7::bytea[], $8::timestamptz[], $9::bigint[], $10::text[], $11::text[], $12::uuid[], $15::bigint[], $16::uuid[])
      WITH ORDINALITY AS t(h, p, o, s, n, c, e, x, m, v, vs, co, ttl, cb, ord)
 ORDER BY t.ord
 ON CONFLICT (tx_hash) DO UPDATE SET
   prev_state = b.state,
   generation = CASE WHEN `+replaceSQL+` THEN b.generation + 1 ELSE b.generation END,
   context_id = CASE WHEN `+replaceSQL+` THEN EXCLUDED.context_id ELSE b.context_id END,
   envelope_hash = CASE WHEN `+replaceSQL+` THEN EXCLUDED.envelope_hash ELSE b.envelope_hash END,
   expires_at = CASE WHEN `+replaceSQL+` THEN EXCLUDED.expires_at ELSE b.expires_at END,
   max_expires_at = greatest(b.max_expires_at, EXCLUDED.expires_at),
   min_version = CASE WHEN `+replaceSQL+` THEN EXCLUDED.min_version ELSE b.min_version END,
   issued_contexts = CASE WHEN EXCLUDED.context_id = ANY(b.issued_contexts)
                               OR NOT (`+replaceSQL+` OR (b.min_version >= EXCLUDED.min_version AND b.expires_at >= EXCLUDED.expires_at)) THEN b.issued_contexts
                          ELSE (b.issued_contexts || EXCLUDED.context_id)[greatest(1, cardinality(b.issued_contexts) - 14):] END,
   claim_owner = CASE WHEN `+replaceSQL+` THEN EXCLUDED.claim_owner ELSE b.claim_owner END,
   claim_boot = CASE WHEN `+replaceSQL+` THEN EXCLUDED.claim_boot ELSE b.claim_boot END,
   claim_expires = CASE WHEN `+replaceSQL+` THEN EXCLUDED.claim_expires ELSE b.claim_expires END,
   state = CASE WHEN b.state = 3 THEN 1 ELSE b.state END,
   reason = CASE WHEN b.state = 3 THEN 0 ELSE b.reason END,
   created_at = CASE WHEN b.state = 3 THEN clock_timestamp() ELSE b.created_at END,
   payload_bucket = CASE WHEN b.state = 3 THEN EXCLUDED.payload_bucket ELSE b.payload_bucket END,
   delivered_generation = CASE WHEN b.state = 3 THEN NULL ELSE b.delivered_generation END,
   delivered_boot = CASE WHEN b.state = 3 THEN NULL ELSE b.delivered_boot END
 WHERE b.principal_id = EXCLUDED.principal_id AND b.org_id = EXCLUDED.org_id AND b.signer = EXCLUDED.signer
   AND b.visible_to = EXCLUDED.visible_to AND b.visible_sender IS NOT DISTINCT FROM EXCLUDED.visible_sender
   AND b.incarnation = EXCLUDED.incarnation
 RETURNING b.tx_hash, b.prev_state, b.state, b.generation, b.context_id, b.min_version, b.expires_at`,
		hashes, principals, orgs, signers, nonces, contexts, envelopes, expiries, versions, visible, senders, owners, inc.String(), bucket, ttls, boots)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byHash := make(map[string]TrackAdmission, n)
	for _, i := range members {
		byHash[string(batch[i].Hash)] = batch[i]
	}
	out := map[string]admitRow{}
	for rows.Next() {
		var hash []byte
		var row admitRow
		var minVersion int64
		var expires time.Time
		if err := rows.Scan(&hash, &row.prev, &row.state, &row.generation, &row.context, &minVersion, &expires); err != nil {
			return nil, err
		}
		a := byHash[string(hash)]
		row.minVersion = uint64(minVersion)
		row.replaced = row.context == a.ContextID
		// Kept: the stored envelope covers the attempt (equal or dominating),
		// or neither covers the other (incomparable: re-sign).
		row.incomparable = !row.replaced && (uint64(minVersion) < a.MinVersion || expires.Before(a.ExpiresAt))
		out[string(hash)] = row
	}
	return out, rows.Err()
}

// replaceSQL: a same-principal admission replaces the stored envelope when it
// revives a stopped binding, or dominates the stored envelope.
const replaceSQL = `(b.state = 3 OR (EXCLUDED.min_version >= b.min_version AND EXCLUDED.expires_at >= b.expires_at AND (EXCLUDED.min_version, EXCLUDED.expires_at) <> (b.min_version, b.expires_at)))`

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
		var principal, org uuid.UUID
		err := tx.QueryRowContext(ctx, `WITH target AS (
   SELECT tx_hash FROM node_tx_binding
   WHERE tx_hash = $1 AND state = 1 AND generation = 1 AND context_id = $2 AND prev_state IS NULL AND delivered_generation IS NULL AND incarnation = $3
   FOR UPDATE)
 DELETE FROM node_tx_binding b USING target WHERE b.tx_hash = target.tx_hash RETURNING b.principal_id, b.org_id`, hash, contextID.String(), inc.String()).Scan(&principal, &org)
		if errors.Is(err, sql.ErrNoRows) {
			released = false
			return nil
		}
		if err != nil {
			return err
		}
		released = true
		deltas := newQuotaDelta()
		deltas.move(principal, org, TrackPending, 0)
		_, _, _, err = applyQuota(ctx, tx, deltas)
		return err
	})
	return released, err
}

// TrackRenewal is one lease-keeper generation (plan §4.8.7): decided on the
// binding at (Generation, ContextID, AdmitXid), replacing its envelope.
type TrackRenewal struct {
	Hash         []byte
	Generation   int32
	ContextID    uuid.UUID
	AdmitXid     uint64
	NewContextID uuid.UUID
	EnvelopeHash []byte
	ExpiresAt    time.Time
	MinVersion   uint64
	Reason       int16 // the trigger, recorded in history
	// TravelRuleRecord is the travel-rule record the renewal's compliance
	// re-check accepted (uuid.Nil: none needed).
	TravelRuleRecord uuid.UUID
	ClaimOwner       uuid.UUID
	ClaimBoot        uuid.UUID
	ClaimTTL         time.Duration
}

// RenewBatch records keeper generations in one transaction (before any of
// them is sent): each applies only to a binding that is still pending at the
// generation, context and admission it was decided on, so a renewal never
// touches a provisional, stopped or final row, a row a client resubmitted
// meanwhile, or a hash released and admitted again (an UPDATE, never an
// insert). It records the generation in history (actor system, with its
// trigger and travel-rule record) and claims the row for the keeper. The
// quota is unchanged (pending → pending). Returns which renewals applied.
func (e *ExecDB) RenewBatch(ctx context.Context, inc uuid.UUID, renewals []TrackRenewal) ([]bool, error) {
	byHash := map[string]int{}
	var hashes [][]byte
	for i, r := range renewals {
		if len(r.Hash) != 32 || r.Generation <= 0 || r.ContextID == uuid.Nil || r.NewContextID == uuid.Nil || len(r.EnvelopeHash) != 32 || r.MinVersion == 0 || r.MinVersion > 1<<63-1 || r.ExpiresAt.IsZero() || r.ClaimOwner == uuid.Nil || r.ClaimTTL <= 0 {
			return nil, fmt.Errorf("invalid tracking renewal")
		}
		if _, dup := byHash[string(r.Hash)]; dup {
			return nil, fmt.Errorf("duplicate tracking renewal")
		}
		byHash[string(r.Hash)] = i
		hashes = append(hashes, r.Hash)
	}
	applied := make([]bool, len(renewals))
	if len(renewals) == 0 {
		return applied, nil
	}
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		clear(applied)
		locked, err := lockBindings(ctx, tx, inc, hashes)
		if err != nil {
			return err
		}
		var hs, envelopes [][]byte
		var contexts, owners, records []string
		var boots []sql.NullString
		var expiries []time.Time
		var versions, ttls, reasons []int64
		for hash, row := range locked {
			i := byHash[hash]
			r := renewals[i]
			if row.state != TrackPending || row.generation != r.Generation || row.context != r.ContextID || (r.AdmitXid != 0 && row.admitXid != r.AdmitXid) {
				continue
			}
			applied[i] = true
			hs, envelopes = append(hs, r.Hash), append(envelopes, r.EnvelopeHash)
			contexts, owners = append(contexts, r.NewContextID.String()), append(owners, r.ClaimOwner.String())
			record := sql.NullString{}
			if r.TravelRuleRecord != uuid.Nil {
				record = sql.NullString{String: r.TravelRuleRecord.String(), Valid: true}
			}
			records = append(records, record.String)
			boot := sql.NullString{}
			if r.ClaimBoot != uuid.Nil {
				boot = sql.NullString{String: r.ClaimBoot.String(), Valid: true}
			}
			boots = append(boots, boot)
			expiries, versions = append(expiries, r.ExpiresAt), append(versions, int64(r.MinVersion))
			ttls, reasons = append(ttls, r.ClaimTTL.Milliseconds()), append(reasons, int64(r.Reason))
		}
		if len(hs) == 0 {
			return nil
		}
		if _, err := tx.ExecContext(ctx, `WITH v AS (SELECT * FROM unnest($1::bytea[], $2::uuid[], $3::bytea[], $4::timestamptz[], $5::bigint[], $6::uuid[], $7::uuid[], $8::bigint[], $9::smallint[], $10::text[])
              AS v(h, c, e, x, m, co, cb, ttl, r, tr)),
 renewed AS (UPDATE node_tx_binding b SET
   generation = b.generation + 1, context_id = v.c, envelope_hash = v.e, expires_at = v.x, max_expires_at = greatest(b.max_expires_at, v.x), min_version = v.m,
   issued_contexts = (b.issued_contexts || v.c)[greatest(1, cardinality(b.issued_contexts) - 14):],
   claim_owner = v.co, claim_boot = v.cb, claim_expires = clock_timestamp() + v.ttl * interval '1 millisecond'
   FROM v WHERE b.tx_hash = v.h
   RETURNING b.tx_hash, b.generation, v.c, v.e, v.x, v.m, v.r, v.tr)
 INSERT INTO node_tx_identities (tx_hash, generation, context_id, envelope_hash, expires_at, min_version, reason, actor, travel_rule_record)
 SELECT tx_hash, generation, c, e, x, m, r, $11, nullif(tr, '')::uuid FROM renewed`,
			hs, contexts, envelopes, expiries, versions, owners, boots, ttls, reasons, records, trackActorSystem); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return applied, nil
}

// TrackTransition is one non-final state change of a binding.
type TrackTransition struct {
	Hash        []byte
	From, To    int16
	Generation  int32 // 0: any generation
	Reason      int16
	BlockNumber *uint64 // the including block (provisional)
	// Boot and ContextID: the node boot whose status answer observed the
	// inclusion (provisional), and the context that executed. Inclusion
	// records the delivery of the current generation only when it is that
	// context; the identity stays with that node process until finality, so
	// a reorg back to pending needs no renewal unless the boot changed, the
	// lease ran out or the pool lost the transaction.
	Boot      uuid.UUID
	ContextID uuid.UUID
	// Undelivered (provisional → pending only): the node answered a
	// definitive canonical miss (a block lost by a crash, N7): the delivery
	// record is cleared, so the lease keeper redelivers the transaction.
	Undelivered bool
}

func allowedTransition(from, to int16) bool {
	switch {
	case from == TrackPending && (to == TrackProvisional || to == TrackRenewalStopped):
		return true
	case from == TrackProvisional && to == TrackPending: // reorged out
		return true
	case from == TrackRenewalStopped && to == TrackProvisional: // late inclusion
		return true
	}
	return false
}

// ApplyTransitions applies non-final transitions in one transaction. A
// transition applies only if the locked row is still in From (and at
// Generation, when set); otherwise it is skipped, so a stale or repeated
// observation writes nothing. Making a row provisional records the delivery
// of its current generation to the observing boot when that generation's
// context executed (the inclusion is the acknowledgement); a reorg back to
// pending keeps it. Returns which transitions applied.
func (e *ExecDB) ApplyTransitions(ctx context.Context, inc uuid.UUID, transitions []TrackTransition) ([]bool, error) {
	byHash := map[string]int{}
	var hashes [][]byte
	for i, t := range transitions {
		if len(t.Hash) != 32 || !allowedTransition(t.From, t.To) || (t.BlockNumber != nil && *t.BlockNumber > 1<<63-1) || (t.Undelivered && (t.From != TrackProvisional || t.To != TrackPending)) {
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
		deltas := newQuotaDelta()
		var hs [][]byte
		var tos, reasons []int64
		var blocks []sql.NullInt64
		var boots, executed []sql.NullString
		var undelivered []bool
		var stopped []int
		for hash, row := range locked {
			i := byHash[hash]
			t := transitions[i]
			if row.state != t.From || (t.Generation != 0 && row.generation != t.Generation) {
				continue
			}
			applied[i] = true
			deltas.move(row.principal, row.org, row.state, t.To)
			hs, tos, reasons = append(hs, t.Hash), append(tos, int64(t.To)), append(reasons, int64(t.Reason))
			block := sql.NullInt64{}
			if t.BlockNumber != nil {
				block = sql.NullInt64{Int64: int64(*t.BlockNumber), Valid: true}
			}
			blocks = append(blocks, block)
			boot := sql.NullString{}
			if t.Boot != uuid.Nil {
				boot = sql.NullString{String: t.Boot.String(), Valid: true}
			}
			boots = append(boots, boot)
			ctx := sql.NullString{}
			if t.ContextID != uuid.Nil {
				ctx = sql.NullString{String: t.ContextID.String(), Valid: true}
			}
			executed = append(executed, ctx)
			undelivered = append(undelivered, t.Undelivered)
			if t.To == TrackRenewalStopped {
				stopped = append(stopped, i)
			}
		}
		if len(hs) == 0 {
			return nil
		}
		// Inclusion proves delivery to the node boot that reported it; a reorg
		// back to pending keeps that record (the node keeps the identity until
		// finality), so only a restart, a lapsed lease or a lost pool entry
		// makes the row undelivered again.
		if _, err := tx.ExecContext(ctx, `UPDATE node_tx_binding b SET
   state = v.st,
   reason = v.r,
   block_number = CASE WHEN v.st = 2 THEN v.blk WHEN v.st = 1 THEN NULL ELSE b.block_number END,
   delivered_generation = CASE WHEN v.st = 2 AND (v.ctx IS NULL OR v.ctx = b.context_id) THEN b.generation WHEN v.und THEN NULL ELSE b.delivered_generation END,
   delivered_boot = CASE WHEN v.st = 2 AND (v.ctx IS NULL OR v.ctx = b.context_id) THEN coalesce(v.boot, b.delivered_boot) WHEN v.und THEN NULL ELSE b.delivered_boot END
 FROM unnest($1::bytea[], $2::smallint[], $3::smallint[], $4::bigint[], $5::uuid[], $6::uuid[], $7::bool[]) AS v(h, st, r, blk, boot, ctx, und)
 WHERE b.tx_hash = v.h`, hs, tos, reasons, nullInts(blocks), boots, executed, undelivered); err != nil {
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
		_, _, _, err = applyQuota(ctx, tx, deltas)
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
	context        uuid.UUID
	principal, org uuid.UUID
	admitXid       uint64
	maxExpiresAt   time.Time
}

// lockBindings locks the bindings of hashes in hash order (the global lock
// order) and returns their current state.
func lockBindings(ctx context.Context, tx *sql.Tx, inc uuid.UUID, hashes [][]byte) (map[string]lockedBinding, error) {
	rows, err := tx.QueryContext(ctx, `SELECT tx_hash, state, generation, context_id, principal_id, org_id, admit_xid::text, max_expires_at FROM node_tx_binding WHERE tx_hash = ANY($1) AND incarnation = $2 ORDER BY tx_hash FOR UPDATE`, hashes, inc.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]lockedBinding{}
	for rows.Next() {
		var hash []byte
		var row lockedBinding
		var xid string
		if err := rows.Scan(&hash, &row.state, &row.generation, &row.context, &row.principal, &row.org, &xid, &row.maxExpiresAt); err != nil {
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
	// RequireStopped: apply only to a binding that is renewal_stopped
	// (dropped on finalized evidence; a binding revived meanwhile is pending
	// again and is left alone).
	RequireStopped bool
	// Generation, when set, must be the binding's: a decision taken on an
	// earlier generation (revived and stopped again since) is stale.
	Generation int32
	// ExpiresBy, when set, requires every identity recorded for the binding
	// to have expired by then (max_expires_at ≤ ExpiresBy): the timestamp of
	// the finalized block a lease-expiry dropped rests on.
	ExpiresBy *time.Time
}

// FinalizeBatch finalizes bindings in one transaction: delete the binding,
// insert the insert-once status row, and release the quota of rows that were
// still pending (pending → final is −1 globally) and the owners' shares of
// pending and stopped rows. A
// final status beats any recorded non-final state; it is not fenced by
// generation or context, because a finalized inclusion makes every generation
// obsolete (K19). Returns which finals applied.
func (e *ExecDB) FinalizeBatch(ctx context.Context, inc uuid.UUID, finals []TrackFinal) ([]bool, error) {
	byHash := map[string]int{}
	var hashes [][]byte
	for i, f := range finals {
		if len(f.Hash) != 32 || f.State < TrackIncluded || f.State > TrackDropped || (f.BlockNumber != nil && *f.BlockNumber > 1<<63-1) || (f.State == TrackDropped && f.Reason == TrackReasonFinalizedLeaseExpiry) {
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
		deltas := newQuotaDelta()
		var hs [][]byte
		var states, reasons []int64
		var blocks []sql.NullInt64
		for hash, row := range locked {
			i := byHash[hash]
			f := finals[i]
			if row.principal != f.PrincipalID || row.org != f.OrgID || (f.AdmitXid != 0 && row.admitXid != f.AdmitXid) {
				continue
			}
			if f.RequireStopped && row.state != TrackRenewalStopped {
				continue
			}
			if (f.Generation != 0 && row.generation != f.Generation) || (f.ExpiresBy != nil && row.maxExpiresAt.After(*f.ExpiresBy)) {
				continue
			}
			applied[i] = true
			deltas.move(row.principal, row.org, row.state, 0)
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
		_, _, _, err = applyQuota(ctx, tx, deltas)
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
	// Boot is the boot id of the node response that acknowledged it (never
	// the cached one, §4.8.4).
	Boot uuid.UUID
}

// FlushAcks records acknowledgements of rows that are still pending at the
// acknowledged generation and not yet recorded as delivered to that boot. It
// is the batched flush for rows that did not reach another transition first
// (R12.6): a row already provisional, final or at a newer generation writes
// nothing (G28, G29). The boot recorded is the one of the response that
// acknowledged the delivery (G35); it also releases the delivery claim. Rows
// another writer holds are skipped (SKIP LOCKED) and stay in memory. Returns
// the acknowledged hashes that are settled (written or no longer applicable).
func (e *ExecDB) FlushAcks(ctx context.Context, inc uuid.UUID, acks []TrackAck) (map[string]bool, error) {
	if len(acks) == 0 {
		return map[string]bool{}, nil
	}
	sort.Slice(acks, func(i, j int) bool { return bytes.Compare(acks[i].Hash, acks[j].Hash) < 0 })
	hashes, generations, boots := make([][]byte, len(acks)), make([]int64, len(acks)), make([]string, len(acks))
	for i, a := range acks {
		hashes[i], generations[i], boots[i] = a.Hash, int64(a.Generation), a.Boot.String()
	}
	settled := map[string]bool{}
	err := e.trackTx(ctx, inc, func(tx *sql.Tx) error {
		clear(settled)
		// Rows locked by another writer are the only ones not settled here.
		rows, err := tx.QueryContext(ctx, `WITH v AS (SELECT * FROM unnest($1::bytea[], $2::int[], $4::uuid[]) AS v(h, g, boot)),
 target AS (SELECT b.tx_hash, v.g, v.boot FROM node_tx_binding b JOIN v ON b.tx_hash = v.h
            WHERE b.state = 1 AND b.generation = v.g AND (b.delivered_generation, b.delivered_boot) IS DISTINCT FROM (v.g, v.boot) AND b.incarnation = $3
            ORDER BY b.tx_hash FOR UPDATE OF b SKIP LOCKED),
 written AS (UPDATE node_tx_binding b SET delivered_generation = target.g, delivered_boot = target.boot, claim_owner = NULL, claim_boot = NULL, claim_expires = NULL
             FROM target WHERE b.tx_hash = target.tx_hash RETURNING b.tx_hash)
 SELECT v.h FROM v WHERE EXISTS (SELECT 1 FROM written w WHERE w.tx_hash = v.h)
    OR NOT EXISTS (SELECT 1 FROM node_tx_binding b WHERE b.tx_hash = v.h AND b.state = 1 AND b.generation = v.g AND (b.delivered_generation, b.delivered_boot) IS DISTINCT FROM (v.g, v.boot))`, hashes, generations, inc.String(), boots)
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
	// In-flight rows only: the binding's signer and nonce, its current
	// envelope's floor and expiry, the delivery and claim state, and the
	// database clock when it was read.
	Signer     []byte
	Nonce      uint64
	MinVersion uint64
	ExpiresAt  time.Time
	// MaxExpiresAt: the longest lease of any identity recorded for the
	// binding (at least ExpiresAt).
	MaxExpiresAt        time.Time
	DeliveredGeneration *int32
	DeliveredBoot       uuid.UUID // Nil: not recorded
	ClaimOwner          uuid.UUID
	ClaimBoot           uuid.UUID
	ClaimExpires        *time.Time
	DBNow               time.Time
}

// Final reports whether the row is a final status.
func (t TrackedTransaction) Final() bool { return t.State >= TrackIncluded }

// DeliveredTo reports whether the current generation was acknowledged by
// the node boot (a delivery to an earlier boot was lost by its restart).
func (t TrackedTransaction) DeliveredTo(boot uuid.UUID) bool {
	return boot != uuid.Nil && t.DeliveredGeneration != nil && *t.DeliveredGeneration == t.Generation && t.DeliveredBoot == boot
}

// ClaimedFor reports whether a delivery claim holds the row at now for the
// node boot: a claim is void once its boot is not the current one, and
// expires so a crashed owner is taken over (§4.8.4).
func (t TrackedTransaction) ClaimedFor(boot uuid.UUID, now time.Time) bool {
	return t.ClaimOwner != uuid.Nil && t.ClaimExpires != nil && now.Before(*t.ClaimExpires) && t.ClaimBoot != uuid.Nil && t.ClaimBoot == boot
}

const trackedColumns = `tx_hash, principal_id, org_id, state, reason, generation, context_id, issued_contexts, block_number, visible_to, visible_sender, created_at, admit_xid::text,
 signer, nonce, min_version, expires_at, max_expires_at, delivered_generation, delivered_boot, claim_owner, claim_boot, claim_expires, clock_timestamp()`

func scanTracked(row interface{ Scan(...any) error }) (TrackedTransaction, error) {
	var t TrackedTransaction
	var block sql.NullInt64
	var sender sql.NullString
	var xid string
	var issued []string
	var nonce, minVersion int64
	var delivered sql.NullInt32
	var deliveredBoot, claimOwner, claimBoot uuid.NullUUID
	var claimExpires sql.NullTime
	if err := row.Scan(&t.Hash, &t.PrincipalID, &t.OrgID, &t.State, &t.Reason, &t.Generation, &t.ContextID, ScanTextArray(&issued), &block, ScanTextArray(&t.VisibleTo), &sender, &t.CreatedAt, &xid,
		&t.Signer, &nonce, &minVersion, &t.ExpiresAt, &t.MaxExpiresAt, &delivered, &deliveredBoot, &claimOwner, &claimBoot, &claimExpires, &t.DBNow); err != nil {
		return t, err
	}
	t.Nonce, t.MinVersion = uint64(nonce), uint64(minVersion)
	if delivered.Valid {
		g := delivered.Int32
		t.DeliveredGeneration = &g
	}
	t.DeliveredBoot, t.ClaimOwner, t.ClaimBoot = deliveredBoot.UUID, claimOwner.UUID, claimBoot.UUID
	if claimExpires.Valid {
		at := claimExpires.Time
		t.ClaimExpires = &at
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

// TrackedBatch re-reads in-flight bindings by hash (missing hashes are
// absent): the lease keeper's authoritative point read before it acts.
func (e *ExecDB) TrackedBatch(ctx context.Context, hashes [][]byte) ([]TrackedTransaction, error) {
	if len(hashes) == 0 {
		return nil, nil
	}
	rows, err := e.pool.conn.QueryContext(ctx, `SELECT `+trackedColumns+` FROM node_tx_binding WHERE tx_hash = ANY($1)`, hashes)
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

// TrackedPayloads returns the raw transactions of in-flight bindings by hash
// (absent once a payload bucket was truncated).
func (e *ExecDB) TrackedPayloads(ctx context.Context, hashes [][]byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	if len(hashes) == 0 {
		return out, nil
	}
	rows, err := e.pool.conn.QueryContext(ctx, `SELECT b.tx_hash, p.raw_tx FROM node_tx_binding b JOIN node_tx_payload p ON p.bucket = b.payload_bucket AND p.tx_hash = b.tx_hash WHERE b.tx_hash = ANY($1)`, hashes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var hash, raw []byte
		if err := rows.Scan(&hash, &raw); err != nil {
			return nil, err
		}
		out[string(hash)] = raw
	}
	return out, rows.Err()
}

// DiscoveryHorizon is the discovery horizon of this database: every
// transaction of this database with an id below Horizon has ended, so
// bindings with admit_xid below it are all visible now. Only this database's
// transactions insert bindings, so the transactions of other databases on the
// same server are excluded (independent review, finding 3): the cluster-wide
// snapshot xmin would wait for the oldest write transaction anywhere on the
// server. An in-progress id is excluded only when it is attributed to another
// database — pg_stat_activity shows it on a backend of another database
// (visible to an unprivileged role; a backend never changes database), or
// pg_prepared_xacts shows it prepared in another database — and any other id
// holds the horizon. Ids not in the snapshot's in-progress list are at or
// above its xmax (newer transactions too). The 32-bit backend ids are compared
// with the 64-bit ids modulo 2^32 (in-progress ids are within 2^31 of each
// other). Next is the snapshot's xmax: Horizon < Next means a transaction of
// this database (or an unattributed one) is in progress. ClusterWide: those
// views could not be read (revoked), so Horizon is the cluster-wide xmin.
type DiscoveryHorizon struct {
	Horizon, Next uint64
	ClusterWide   bool
}

// TrackingHorizon reads the discovery horizon (see DiscoveryHorizon).
func (e *ExecDB) TrackingHorizon(ctx context.Context) (DiscoveryHorizon, error) {
	var h, n string
	err := e.pool.conn.QueryRowContext(ctx, trackingHorizonSQL).Scan(&h, &n)
	out := DiscoveryHorizon{}
	if isInsufficientPrivilege(err) {
		// Still correct, but held by every database's transactions.
		out.ClusterWide = true
		err = e.pool.conn.QueryRowContext(ctx, `SELECT pg_snapshot_xmin(s)::text, pg_snapshot_xmax(s)::text FROM pg_current_snapshot() AS s`).Scan(&h, &n)
	}
	if err != nil {
		return DiscoveryHorizon{}, err
	}
	if out.Horizon, err = strconv.ParseUint(h, 10, 64); err != nil {
		return DiscoveryHorizon{}, err
	}
	if out.Next, err = strconv.ParseUint(n, 10, 64); err != nil {
		return DiscoveryHorizon{}, err
	}
	return out, nil
}

const trackingHorizonSQL = `WITH s AS (SELECT pg_current_snapshot() AS snap),
 other AS (
   SELECT backend_xid::text::bigint AS x FROM pg_stat_activity
    WHERE backend_xid IS NOT NULL AND datid IS NOT NULL
      AND datid <> (SELECT oid FROM pg_database WHERE datname = current_database())
   UNION ALL
   SELECT transaction::text::bigint FROM pg_prepared_xacts WHERE database <> current_database())
 SELECT least(pg_snapshot_xmax(snap),
              (SELECT min(x) FROM pg_snapshot_xip(snap) AS x
                WHERE (x::text::numeric % 4294967296)::bigint NOT IN (SELECT x FROM other)))::text,
        pg_snapshot_xmax(snap)::text
 FROM s`

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

// PendingQuotaMismatches counts principals and organizations whose share
// counter differs from their count of held (pending or stopped) bindings (0
// after every committed batch, G63), read in one snapshot.
func (e *ExecDB) PendingQuotaMismatches(ctx context.Context) (int64, error) {
	var n int64
	err := e.pool.conn.QueryRowContext(ctx, quotaMismatchSQL).Scan(&n)
	return n, err
}

// quotaMismatchSQL counts share counters that differ from the bindings.
const quotaMismatchSQL = `SELECT
 (SELECT count(*) FROM pending_quota_principal q
   FULL JOIN (SELECT principal_id, count(*) AS pending FROM node_tx_binding WHERE ` + heldStatesSQL + ` GROUP BY principal_id) b USING (principal_id)
   WHERE coalesce(q.used, 0) <> coalesce(b.pending, 0))
+(SELECT count(*) FROM pending_quota_org q
   FULL JOIN (SELECT org_id, count(*) AS pending FROM node_tx_binding WHERE ` + heldStatesSQL + ` GROUP BY org_id) b USING (org_id)
   WHERE coalesce(q.used, 0) <> coalesce(b.pending, 0))`
