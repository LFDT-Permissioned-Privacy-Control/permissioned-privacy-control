package server

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/loggate"
	"privacy-proxy/internal/nodepolicy"
)

// The reconciler discovers node outcomes of tracked transactions and writes
// only what changed (plan §4.5, §4.10): it runs on the elected instance, keeps
// its schedule in memory (rebuilt by one scan at the start of every term and
// after the tracking database is recreated), and writes transitions and
// finals in batches per tick.

type nodeOutcomeClient interface {
	TransactionStatus(context.Context, string) (nodepolicy.TransactionStatus, error)
}

// nodeEffectsStore is the main-database side of finality: the exactly-once
// effects transaction and the principal DIDs of the audit events.
type nodeEffectsStore interface {
	ApplyNodeTxEffects(context.Context, nodepolicy.Network, db.NodeTxEffects) (db.NodeTxEffectsResult, error)
	ExternalIDsByUserID(context.Context, []string) (map[string]string, error)
}

// systemAuditBuffer is the durable audit buffer system decisions are appended
// to before they commit (plan §4.8.6).
type systemAuditBuffer interface {
	AppendBatch([][]byte) ([]uint64, error)
}

const (
	reconcileTick        = time.Second
	reconcilePollWorkers = 16
	reconcileMaxPolls    = 4096 // per tick
	reconcileStatusWait  = 5 * time.Second
	reconcileMaxBackoff  = 15 * time.Second
	reconcileScanPage    = 1000
	// reconcileSettle: a row still pending this long after admission is
	// polled with a growing interval (up to reconcileMaxBackoff).
	reconcileSettle = 30 * time.Second
	// reconcileRefreshAfter consecutive failures re-read the binding (a row
	// released or rebound meanwhile leaves or is replaced in the schedule).
	reconcileRefreshAfter = 3
)

// systemEventNamespace derives deterministic correlation ids of system
// events, so a decision audited twice (a crash between the append and its
// commit) is recognisable as the same decision.
var systemEventNamespace = uuid.MustParse("5f0c3c8e-7f39-4d0b-9a55-0b1c6c1ad410")

type trackedRow struct {
	row      db.TrackedTransaction
	hashHex  string
	nextPoll time.Time
	backoff  time.Duration
	failures int // consecutive failed polls or finals
	// audited: the finality event of this binding was appended; a retried
	// finalization in the same term is not audited again.
	audited bool
}

type nodeReconciler struct {
	tracking *nodeTracking
	main     nodeEffectsStore
	node     nodeOutcomeClient
	audit    systemAuditBuffer
	network  nodepolicy.Network
	now      func() time.Time
	log      loggate.Gate

	epoch   uint64
	inc     uuid.UUID
	rows    map[string]*trackedRow
	cursor  uint64 // admit_xid discovered below
	scanned bool
	head    uint64 // highest finalized block seen
}

func newNodeReconciler(tracking *nodeTracking, main nodeEffectsStore, node nodeOutcomeClient, audit systemAuditBuffer, network nodepolicy.Network) *nodeReconciler {
	return &nodeReconciler{tracking: tracking, main: main, node: node, audit: audit, network: network, now: time.Now}
}

func runNodeReconciler(ctx context.Context, r *nodeReconciler) {
	timer := time.NewTicker(reconcileTick)
	defer timer.Stop()
	for {
		if err := r.tick(ctx); err != nil && ctx.Err() == nil {
			if suppressed, ok := r.log.Allow("reconcile:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
				slog.Warn("node transaction reconciliation pending", "error", err, "suppressed", suppressed)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
	}
}

// reset drops the schedule: the next tick rescans the tracking database.
func (r *nodeReconciler) reset() {
	r.rows, r.cursor, r.scanned, r.head = map[string]*trackedRow{}, 0, false, 0
	r.inc, r.epoch = r.tracking.incarnation(), r.tracking.epoch.Load()
}

// tick runs one reconciliation pass.
func (r *nodeReconciler) tick(ctx context.Context) error {
	if r.rows == nil || r.epoch != r.tracking.epoch.Load() {
		r.reset()
	}
	if err := r.discover(ctx); err != nil {
		return r.recreated(ctx, err)
	}
	observations := r.poll(ctx)
	return r.recreated(ctx, r.apply(ctx, observations))
}

// recreated adopts a recreated tracking database and resets the schedule.
func (r *nodeReconciler) recreated(ctx context.Context, err error) error {
	if trackingRecreated(err) {
		r.tracking.adoptAfter(ctx, r.inc)
		r.rows = nil
	}
	return err
}

// discover adds bindings admitted since the last pass: every row whose
// inserting transaction ended below the snapshot horizon (none is skipped,
// whatever order concurrent batches committed in).
func (r *nodeReconciler) discover(ctx context.Context) error {
	horizon, err := r.tracking.store.TrackingHorizon(ctx)
	if err != nil {
		return err
	}
	if horizon <= r.cursor && r.scanned {
		return nil
	}
	var after []byte
	from := r.cursor
	for {
		page, err := r.tracking.store.ListTracked(ctx, from, horizon, after, reconcileScanPage)
		if err != nil {
			return err
		}
		for _, row := range page {
			key := string(row.Hash)
			// A hash released and admitted again is a new binding (possibly
			// another principal's): it replaces the scheduled one.
			if known, ok := r.rows[key]; !ok || known.row.AdmitXid != row.AdmitXid {
				r.rows[key] = &trackedRow{row: row, hashHex: "0x" + hex.EncodeToString(row.Hash)}
			}
		}
		if len(page) < reconcileScanPage {
			break
		}
		last := page[len(page)-1]
		from, after = last.AdmitXid, last.Hash
	}
	r.cursor, r.scanned = horizon, true
	return nil
}

type observation struct {
	tracked *trackedRow
	status  nodepolicy.TransactionStatus
	err     error
}

// due reports whether a row is polled this tick. Provisional rows are polled
// only once a finalized head at or above their block was seen, plus the
// lowest one each tick to learn the head (finality-driven, G62).
func (r *nodeReconciler) due(now time.Time) []*trackedRow {
	var out []*trackedRow
	var lowest *trackedRow
	for _, t := range r.rows {
		if t.nextPoll.After(now) {
			continue
		}
		if t.row.State == db.TrackProvisional && t.row.BlockNumber != nil && *t.row.BlockNumber > r.head {
			if lowest == nil || *t.row.BlockNumber < *lowest.row.BlockNumber {
				lowest = t
			}
			continue
		}
		out = append(out, t)
		if len(out) >= reconcileMaxPolls-1 { // one slot stays for the head probe
			break
		}
	}
	if lowest != nil {
		out = append(out, lowest)
	}
	return out
}

func (r *nodeReconciler) poll(ctx context.Context) []observation {
	rows := r.due(r.now())
	out := make([]observation, len(rows))
	var wg sync.WaitGroup
	slots := make(chan struct{}, reconcilePollWorkers)
	for i, t := range rows {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int, t *trackedRow) {
			defer wg.Done()
			defer func() { <-slots }()
			request, cancel := context.WithTimeout(ctx, reconcileStatusWait)
			defer cancel()
			status, err := r.node.TransactionStatus(request, t.hashHex)
			if err == nil && (status.TransactionHash != t.hashHex || status.PrincipalID != t.row.PrincipalID.String() || status.OrgID != t.row.OrgID.String()) {
				// Another identity's outcome for this hash is never recorded
				// against this binding.
				err = nodepolicy.ErrNodeResponse
			}
			if err == nil {
				err = status.Validate()
			}
			out[i] = observation{tracked: t, status: status, err: err}
		}(i, t)
	}
	wg.Wait()
	return out
}

// apply turns one tick's observations into batched writes: provisional and
// reorg transitions in one batch; finals audited first, then their main-
// database effects, then one finality batch. Unchanged observations write
// nothing.
func (r *nodeReconciler) apply(ctx context.Context, observations []observation) error {
	now := r.now()
	var transitions []db.TrackTransition
	var finals []*observation
	var failures []error
	for i := range observations {
		o := &observations[i]
		t := o.tracked
		if o.err != nil {
			r.delay(t, now)
			failures = append(failures, o.err)
			if t.failures%reconcileRefreshAfter == 0 {
				r.refresh(ctx, t)
			}
			continue
		}
		t.backoff, t.failures, t.nextPoll = 0, 0, now.Add(reconcileTick)
		outcome := o.status.Execution
		if outcome.FinalizedBlockNumber != nil && *outcome.FinalizedBlockNumber > r.head {
			r.head = *outcome.FinalizedBlockNumber
		}
		switch {
		case outcome.Finalized && (outcome.Status == "included" || outcome.Status == "reverted"):
			finals = append(finals, o)
		case outcome.Status == "included" || outcome.Status == "reverted":
			switch t.row.State {
			case db.TrackPending, db.TrackRenewalStopped:
				block := *outcome.BlockNumber
				transitions = append(transitions, db.TrackTransition{Hash: t.row.Hash, From: t.row.State, To: db.TrackProvisional, BlockNumber: &block})
			case db.TrackTombstone:
				// Revived since it was read: re-read, transition next tick.
				r.refresh(ctx, t)
			}
		case t.row.State == db.TrackProvisional:
			// The including block left the canonical chain before finality.
			transitions = append(transitions, db.TrackTransition{Hash: t.row.Hash, From: db.TrackProvisional, To: db.TrackPending})
		default:
			// pending, denied or expired at the node: nothing changed here.
			// A row that stays so is polled ever less often.
			if outcome.Status != "pending" || now.Sub(t.row.CreatedAt) > reconcileSettle {
				t.backoff = min(max(2*t.backoff, 2*time.Second), reconcileMaxBackoff)
				t.nextPoll = now.Add(t.backoff)
			}
		}
	}
	if len(transitions) > 0 {
		applied, err := r.tracking.store.ApplyTransitions(ctx, r.inc, transitions)
		if err != nil {
			// Finals do not depend on the transitions: record them anyway.
			failures = append(failures, err)
			applied = nil
		}
		for i, ok := range applied {
			t := r.rows[string(transitions[i].Hash)]
			if t == nil {
				continue
			}
			if ok {
				t.row.State, t.row.BlockNumber = transitions[i].To, transitions[i].BlockNumber
			} else {
				r.refresh(ctx, t)
			}
		}
	}
	if len(finals) > 0 {
		if err := r.finalize(ctx, finals); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// refresh re-reads a row whose transition did not apply or keeps failing
// (another writer changed it, or it was released and admitted again); a row
// gone from the bindings leaves the schedule.
func (r *nodeReconciler) refresh(ctx context.Context, t *trackedRow) {
	row, err := r.tracking.store.LookupTracked(ctx, t.row.Hash)
	switch {
	case err == nil && !row.Final():
		if row.AdmitXid != t.row.AdmitXid {
			r.rows[string(row.Hash)] = &trackedRow{row: row, hashHex: t.hashHex}
			return
		}
		t.row = row
	case err == nil || errors.Is(err, sql.ErrNoRows):
		delete(r.rows, string(t.row.Hash))
	}
}

// delay schedules a failed row's next attempt with a growing interval.
func (r *nodeReconciler) delay(t *trackedRow, now time.Time) {
	t.failures++
	t.backoff = min(max(2*t.backoff, time.Second), reconcileMaxBackoff)
	t.nextPoll = now.Add(t.backoff)
}

// finalize records a tick's final outcomes (plan §4.8.6, §4.11):
//  1. one ops.system.finalized audit event per binding is appended to the
//     durable audit buffer (one fsync'd batch) — fail closed: without a
//     buffer, or on an append failure, nothing is finalized; a retry in the
//     same term does not append it again, and its correlation id is derived
//     from the binding, so a re-audit after a crash is recognisable;
//  2. transactions with side effects apply them in the main database from a
//     fresh read of the binding, exactly once by marker; a permanent refusal
//     (below the replay floor, an address another organisation owns) is
//     audited as ops.system.effects_refused, alerted, and finalized with a
//     reason; other errors retry with a growing interval;
//  3. one tracking finality batch deletes the bindings — only the bindings
//     that were read (same admission) — and inserts the status rows.
//
// A crash between the steps re-runs them: the effects are skipped by their
// markers and the audit trail over-reports, never under-reports.
func (r *nodeReconciler) finalize(ctx context.Context, finals []*observation) error {
	if r.audit == nil {
		return errSystemAuditUnavailable
	}
	now := r.now()
	type ready struct {
		o      *observation
		final  db.TrackFinal
		effect *db.NodeTxEffects
	}
	var batch []ready
	var failures []error
	for _, o := range finals {
		t, outcome := o.tracked, o.status.Execution
		state := db.TrackIncluded
		if outcome.Status == "reverted" {
			state = db.TrackReverted
		}
		block := *outcome.BlockNumber
		wantsEffects := state == db.TrackIncluded && (len(outcome.Created) > 0 || len(t.row.VisibleTo) > 0)
		if wantsEffects {
			// Effects come from the binding as it is now, never from a
			// schedule entry that outlived a release and re-admission.
			row, err := r.tracking.store.LookupTracked(ctx, t.row.Hash)
			if err != nil || row.Final() || row.AdmitXid != t.row.AdmitXid {
				r.refresh(ctx, t)
				continue
			}
			t.row = row
		}
		item := ready{o: o, final: db.TrackFinal{Hash: t.row.Hash, State: state, BlockNumber: &block, PrincipalID: t.row.PrincipalID, OrgID: t.row.OrgID, AdmitXid: t.row.AdmitXid}}
		if state == db.TrackIncluded && (len(outcome.Created) > 0 || len(t.row.VisibleTo) > 0) {
			item.effect = &db.NodeTxEffects{TransactionHash: t.hashHex, PrincipalID: t.row.PrincipalID.String(), OrgID: t.row.OrgID.String(), BlockNumber: block,
				Ownership: len(outcome.Created) > 0, Created: outcome.Created,
				Visibility: len(t.row.VisibleTo) > 0, VisibleTo: t.row.VisibleTo, VisibleSender: t.row.VisibleSender}
		}
		batch = append(batch, item)
	}
	if len(batch) == 0 {
		return nil
	}
	principals := make([]string, 0, len(batch))
	for _, item := range batch {
		principals = append(principals, item.o.tracked.row.PrincipalID.String())
	}
	dids, err := r.main.ExternalIDsByUserID(ctx, principals)
	if err != nil {
		return err
	}
	var events [][]byte
	var audited []*trackedRow
	for _, item := range batch {
		if item.o.tracked.audited {
			continue
		}
		event, err := r.systemEvent(item.o, item.final, dids, "ops.system.finalized", 200, "")
		if err != nil {
			return err
		}
		events, audited = append(events, event), append(audited, item.o.tracked)
	}
	if len(events) > 0 {
		if _, err := r.audit.AppendBatch(events); err != nil {
			for _, item := range batch {
				r.delay(item.o.tracked, now)
			}
			return fmt.Errorf("%w: %v", errSystemAuditUnavailable, err)
		}
		for _, t := range audited {
			t.audited = true
		}
	}
	var refusals [][]byte
	finalsToWrite := make([]db.TrackFinal, 0, len(batch))
	for _, item := range batch {
		if item.effect != nil {
			reason, err := r.applyEffects(ctx, *item.effect)
			if err != nil {
				r.delay(item.o.tracked, now)
				failures = append(failures, err)
				continue // retried later; the binding stays
			}
			if reason != db.TrackReasonNone && reason != db.TrackReasonOrganizationDeleted {
				event, err := r.systemEvent(item.o, item.final, dids, "ops.system.effects_refused", 403, db.TrackReasonName(reason))
				if err != nil {
					return err
				}
				refusals = append(refusals, event)
			}
			item.final.Reason = reason
		}
		finalsToWrite = append(finalsToWrite, item.final)
	}
	if len(refusals) > 0 {
		if _, err := r.audit.AppendBatch(refusals); err != nil {
			return fmt.Errorf("%w: %v", errSystemAuditUnavailable, err)
		}
	}
	if len(finalsToWrite) == 0 {
		return errors.Join(failures...)
	}
	applied, err := r.tracking.store.FinalizeBatch(ctx, r.inc, finalsToWrite)
	if err != nil {
		for _, item := range batch {
			r.delay(item.o.tracked, now)
		}
		return errors.Join(append(failures, err)...)
	}
	for i, ok := range applied {
		t := r.rows[string(finalsToWrite[i].Hash)]
		if t == nil {
			continue
		}
		if ok {
			delete(r.rows, string(finalsToWrite[i].Hash))
		} else {
			r.refresh(ctx, t) // released, rebound or changed meanwhile
		}
	}
	return errors.Join(failures...)
}

// errSystemAuditUnavailable: a system decision could not be audited first,
// so it was not taken (fail closed, plan §4.8.6).
var errSystemAuditUnavailable = errors.New("system decision not audited: durable audit buffer unavailable")

// applyEffects runs the effects transaction and maps permanent refusals to a
// final reason (those effects are then not applied, and an alert is logged).
func (r *nodeReconciler) applyEffects(ctx context.Context, effect db.NodeTxEffects) (int16, error) {
	result, err := r.main.ApplyNodeTxEffects(ctx, r.network, effect)
	switch {
	case err == nil && result.Note == "organization_deleted":
		return db.TrackReasonOrganizationDeleted, nil
	case err == nil && result.OwnershipConflicts > 0:
		slog.Error("finalized deployment created an address another organisation owns: that address was not registered", "tx", effect.TransactionHash, "conflicts", result.OwnershipConflicts)
		return db.TrackReasonOwnershipConflict, nil
	case err == nil:
		return db.TrackReasonNone, nil
	case errors.Is(err, db.ErrBelowReplayFloor):
		slog.Error("finalized transaction is at or below the effects replay floor: effects not applied", "tx", effect.TransactionHash, "block", effect.BlockNumber)
		return db.TrackReasonEffectsBelowFloor, nil
	default:
		return 0, err
	}
}

// systemEvent encodes a system-decision audit event (plan §4.8.6): on behalf
// of the principal, with the transaction, context, generation, incarnation,
// outcome, actor and reason in the hashed parameters, and a correlation id
// derived from the decision.
func (r *nodeReconciler) systemEvent(o *observation, final db.TrackFinal, dids map[string]string, method string, status int, reason string) ([]byte, error) {
	t := o.tracked
	principal := t.row.PrincipalID.String()
	external := dids[principal]
	if external == "" {
		external = "principal:" + principal // deleted before finality
	}
	fields := map[string]any{
		"tx_hash": t.hashHex, "context_id": o.status.ContextID, "generation": t.row.Generation,
		"incarnation": r.inc.String(), "state": db.TrackStateName(final.State), "block_number": *final.BlockNumber,
		"facts_version": o.status.Execution.FactsVersion, "actor": "system:finality",
	}
	if reason != "" {
		fields["reason"] = reason
	}
	params, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	id := uuid.NewSHA1(systemEventNamespace, []byte(fmt.Sprintf("%s|%s|%s|%d|%d", method, r.inc, t.hashHex, t.row.AdmitXid, *final.BlockNumber)))
	return json.Marshal(db.AccessLogRecord{ExternalID: external, Method: method, StatusCode: status, CorrelationID: id.String(), Params: params, OrgID: t.row.OrgID.String(), DenialReason: reason})
}
