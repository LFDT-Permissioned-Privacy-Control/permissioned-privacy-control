package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/loggate"
	"privacy-proxy/internal/nodepolicy"
)

// The lease keeper (plan §4.8, P3): one per elected term, sharing the
// reconciler's in-memory schedule. It renews pending bindings that the node
// does not hold for its current boot — never delivered (an OPS crash between
// the intent and transport, a failed send), lost by a node restart (a new
// boot id), evicted from the pool, or whose lease is about to run out —
// after a full admission re-check, signing at the database clock, auditing
// the decision first, recording it, and only then delivering it on the
// recovery lane. It stops renewing at the maximum age or on a refused
// re-check (renewal_stopped, not final), and records dropped only on
// finalized nonce evidence. Congestion renewal (the TTL/2…TTL−R window, the
// budget and backpressure) is P8.

// keeperNode delivers keeper identities on the recovery lane.
type keeperNode interface {
	SubmitRecovery(context.Context, []byte, string) (nodepolicy.Submission, error)
}

// keeperClock is the single issuing clock (plan §4.8.3).
type keeperClock interface {
	NodePolicyClock(context.Context) (uint64, time.Time, error)
}

const (
	// keeperMaxPerTick bounds the bindings the keeper decides on per tick.
	keeperMaxPerTick = 512
	keeperWorkers    = 16
	keeperSendWait   = 5 * time.Second
	keeperMaxBackoff = 15 * time.Second
	// keeperMinLease: a lease that short is not worth signing; the binding is
	// at its maximum age.
	keeperMinLease = 10 * time.Second
	// keeperDropInterval spaces the dropped-evidence reads per binding.
	keeperDropInterval = 30 * time.Second
	// keeperEvictAfter: a binding still pending at the node this long after
	// admission is checked against the node's pool (same-boot eviction).
	keeperEvictAfter  = 30 * time.Second
	keeperIdleRecheck = 30 * time.Second
	// keeperMaxRejections: consecutive node refusals of one recorded
	// generation before the keeper stops renewing it.
	keeperMaxRejections = 3
	// keeperAuditPause: after the audit buffer refused a batch, no renewal is
	// re-checked for this long (re-checks write compliance decisions).
	keeperAuditPause = 30 * time.Second
	// keeperTickBudget bounds the keeper's node and chain calls per tick, so
	// a slow node never stalls reconciliation for long.
	keeperTickBudget = 10 * time.Second
	// keeperRefreshInterval: stopped rows are re-read this often (a
	// same-principal resubmission may have revived one).
	keeperRefreshInterval = 10 * time.Second
)

// keeperResend is a recorded, audited generation whose delivery failed for a
// transient reason: it is sent again unchanged (no new decision) while the
// node keeps its boot and the lease has room.
type keeperResend struct {
	wire       []byte
	raw        string
	generation int32
	boot       uuid.UUID
	expires    time.Time
	next       time.Time
	backoff    time.Duration
	// rejected counts consecutive answers refusing it (not transport errors).
	rejected int
}

type nodeKeeper struct {
	node    keeperNode
	chain   nodeChainReader // nil: no eviction or dropped evidence
	checker renewalChecker
	clock   keeperClock
	signer  nodepolicy.Signer
	ttl     time.Duration
	maxAge  time.Duration
	network nodepolicy.Network
	// boot is the node's current boot id from a fresh, ready status read, and
	// the sequence of that read.
	boot func() (uuid.UUID, bool, uint64)
	now  func() time.Time
	log  loggate.Gate

	owner    uuid.UUID // this term's claim owner
	lastBoot uuid.UUID
	// seenBoot/seenRead: a new boot id is adopted only once a later status
	// read, on a later tick, still reports it (a flapping answer must not
	// renew every pending transaction).
	seenBoot uuid.UUID
	seenRead uint64
	// auditPausedUntil: renewals wait after the audit buffer refused.
	auditPausedUntil time.Time
}

// margin is R = TTL/4 (plan §4.8.2): a lease this close to its end is
// renewed.
func (k *nodeKeeper) margin() time.Duration { return k.ttl / 4 }

// reset starts a term: a new claim owner, and every pending binding is
// reconsidered once the node's boot is known (the takeover scan, G12).
func (k *nodeKeeper) reset() {
	k.owner, k.lastBoot = uuid.New(), uuid.Nil
}

type keeperJob struct {
	t       *trackedRow
	row     db.TrackedTransaction
	trigger int16
	raw     []byte
	did     string
	event   uuid.UUID
	refusal int16
	record  uuid.UUID
	err     error
	// signed
	wire     []byte
	renewal  db.TrackRenewal
	identity nodepolicy.Identity
}

type keeperStop struct {
	t          *trackedRow
	row        db.TrackedTransaction
	generation int32
	reason     int16
	method     string
	status     int
	event      uuid.UUID
}

// tick runs one keeper pass after the reconciler's.
func (k *nodeKeeper) tick(ctx context.Context, r *nodeReconciler) error {
	now := k.now()
	boot, ready, read := k.boot()
	switch {
	case !ready || boot == k.lastBoot || k.lastBoot == uuid.Nil:
		k.seenBoot, k.seenRead = uuid.Nil, 0
	case boot != k.seenBoot || read <= k.seenRead:
		// A new boot id: confirm it with a later status read before renewing
		// for it.
		if boot != k.seenBoot {
			k.seenBoot, k.seenRead = boot, read
		}
		ready = false
	}
	if ready && boot != k.lastBoot {
		if k.lastBoot != uuid.Nil {
			slog.Info("execution node restarted: renewing every pending transaction it no longer holds", "boot_id", boot)
		}
		k.lastBoot = boot
		for _, t := range r.rows {
			t.keepAt = time.Time{}
		}
	}
	var failures []error
	failures = append(failures, k.refreshStopped(ctx, r, now))
	// Node and chain calls share one budget per tick; a call cut short is a
	// transient failure (resent or retried next tick), never a decision.
	budget, cancel := context.WithTimeout(ctx, keeperTickBudget)
	defer cancel()
	if ready {
		failures = append(failures, k.resend(ctx, budget, r, boot, now))
	}
	failures = append(failures, k.renew(ctx, budget, r, boot, ready, now))
	failures = append(failures, k.dropped(ctx, budget, r, now))
	return errors.Join(failures...)
}

// refreshStopped re-reads stopped rows periodically: a same-principal
// resubmission revives a stopped binding (back to pending, same admission),
// which the schedule would not notice otherwise.
func (k *nodeKeeper) refreshStopped(ctx context.Context, r *nodeReconciler, now time.Time) error {
	var due []*trackedRow
	for _, t := range r.rows {
		if (t.row.State == db.TrackRenewalStopped || t.row.State == db.TrackTombstone) && !t.refreshAt.After(now) {
			due = append(due, t)
			if len(due) >= keeperMaxPerTick {
				break
			}
		}
	}
	if len(due) == 0 {
		return nil
	}
	hashes := make([][]byte, len(due))
	for i, t := range due {
		hashes[i], t.refreshAt = t.row.Hash, now.Add(keeperRefreshInterval)
	}
	fresh, err := r.tracking.store.TrackedBatch(ctx, hashes)
	if err != nil {
		return err
	}
	for _, row := range fresh {
		t := r.rows[string(row.Hash)]
		if t == nil {
			continue
		}
		if row.AdmitXid != t.row.AdmitXid {
			r.rows[string(row.Hash)] = &trackedRow{row: row, hashHex: t.hashHex}
			continue
		}
		if row.State != t.row.State {
			t.row, t.keepAt, t.flag, t.dropSeen = row, time.Time{}, 0, time.Time{}
		}
	}
	return nil
}

// candidate is the in-memory pre-filter (possibly stale only towards "less
// delivered"); every decision is taken on a fresh read.
func (k *nodeKeeper) candidate(t *trackedRow, boot uuid.UUID, now time.Time) bool {
	row := t.row
	if row.State != db.TrackPending || t.resend != nil || t.keepAt.After(now) {
		return false
	}
	return t.flag != 0 || !row.CreatedAt.Add(k.maxAge).After(now) || row.ExpiresAt.Sub(now) <= k.margin() ||
		(!row.DeliveredTo(boot) && !row.ClaimedFor(boot, now))
}

// trigger is why a fresh pending row needs a new generation (0: it does not).
func (k *nodeKeeper) trigger(t *trackedRow, row db.TrackedTransaction, boot uuid.UUID) int16 {
	if t.flag != 0 {
		return t.flag
	}
	if !row.DeliveredTo(boot) && !row.ClaimedFor(boot, row.DBNow) {
		if row.DeliveredGeneration != nil && *row.DeliveredGeneration == row.Generation && row.DeliveredBoot != uuid.Nil {
			return db.TrackReasonNodeRestarted
		}
		return db.TrackReasonUndelivered
	}
	if row.ExpiresAt.Sub(row.DBNow) <= k.margin() {
		return db.TrackReasonLeaseExpiring
	}
	return 0
}

// nextCheck is when a fresh row that needs nothing now could need the keeper
// (claim expiry, the renewal margin, the maximum age), at most
// keeperIdleRecheck away; boot changes, evictions and reorgs reset it.
func (k *nodeKeeper) nextCheck(row db.TrackedTransaction, now time.Time) time.Time {
	at := row.DBNow.Add(keeperIdleRecheck)
	for _, candidate := range []time.Time{row.ExpiresAt.Add(-k.margin()), row.CreatedAt.Add(k.maxAge)} {
		if candidate.Before(at) {
			at = candidate
		}
	}
	if row.ClaimExpires != nil && row.ClaimExpires.Before(at) {
		at = *row.ClaimExpires
	}
	return now.Add(at.Sub(row.DBNow))
}

func keeperBackoff(t *trackedRow, now time.Time) {
	t.keepBackoff = min(max(2*t.keepBackoff, time.Second), keeperMaxBackoff)
	t.keepAt = now.Add(t.keepBackoff)
}

// renew decides on the candidate bindings: stop at the maximum age, or
// re-check, sign, audit, record and deliver a new generation.
func (k *nodeKeeper) renew(ctx, transport context.Context, r *nodeReconciler, boot uuid.UUID, ready bool, now time.Time) error {
	var candidates []*trackedRow
	for _, t := range r.rows {
		if k.candidate(t, boot, now) {
			candidates = append(candidates, t)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	// Earliest expiry first (plan §4.8.7), within the per-tick bound.
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].row.ExpiresAt.Before(candidates[j].row.ExpiresAt) })
	if len(candidates) > keeperMaxPerTick {
		candidates = candidates[:keeperMaxPerTick]
	}
	hashes := make([][]byte, len(candidates))
	for i, t := range candidates {
		hashes[i] = t.row.Hash
	}
	fresh, err := r.tracking.store.TrackedBatch(ctx, hashes)
	if err != nil {
		for _, t := range candidates {
			keeperBackoff(t, now)
		}
		return err
	}
	byHash := make(map[string]db.TrackedTransaction, len(fresh))
	for _, row := range fresh {
		byHash[string(row.Hash)] = row
	}
	var stops []*keeperStop
	var jobs []*keeperJob
	for _, t := range candidates {
		key := string(t.row.Hash)
		row, ok := byHash[key]
		if !ok {
			t.keepAt = now.Add(reconcileTick) // finalized or released: the reconciler refreshes it
			continue
		}
		if row.AdmitXid != t.row.AdmitXid {
			r.rows[key] = &trackedRow{row: row, hashHex: t.hashHex}
			continue
		}
		t.row = row
		if row.State != db.TrackPending {
			t.flag = 0
			continue
		}
		if !row.CreatedAt.Add(k.maxAge).After(row.DBNow) {
			stops = append(stops, &keeperStop{t: t, row: row, generation: row.Generation, reason: db.TrackReasonMaxAge, method: "ops.system.renewal_stopped", status: 410})
			continue
		}
		trigger := k.trigger(t, row, boot)
		if trigger == 0 {
			t.keepAt, t.keepBackoff = k.nextCheck(row, now), 0
			continue
		}
		if !ready || now.Before(k.auditPausedUntil) {
			// Renewals go only to a ready node with a known boot, and wait
			// while the audit buffer is refusing.
			t.keepAt = now.Add(reconcileTick)
			continue
		}
		jobs = append(jobs, &keeperJob{t: t, row: row, trigger: trigger, event: uuid.New()})
	}
	var failures []error
	if len(jobs) > 0 {
		var more []*keeperStop
		jobs, more, err = k.recheck(ctx, r, jobs, now)
		stops = append(stops, more...)
		failures = append(failures, err)
	}
	if len(jobs) > 0 {
		var more []*keeperStop
		jobs, more, err = k.sign(ctx, jobs, now)
		stops = append(stops, more...)
		failures = append(failures, err)
	}
	if len(jobs) == 0 && len(stops) == 0 {
		return errors.Join(failures...)
	}
	// Audit first (plan §4.8.6): fail closed, nothing is decided without it.
	if err := k.audit(ctx, r, jobs, stops); err != nil {
		for _, j := range jobs {
			keeperBackoff(j.t, now)
		}
		for _, s := range stops {
			keeperBackoff(s.t, now)
		}
		return errors.Join(append(failures, err)...)
	}
	failures = append(failures, k.stop(ctx, r, stops, now))
	if len(jobs) == 0 {
		return errors.Join(failures...)
	}
	renewals := make([]db.TrackRenewal, len(jobs))
	for i, j := range jobs {
		renewals[i] = j.renewal
	}
	applied, err := r.tracking.store.RenewBatch(ctx, r.inc, renewals)
	if err != nil {
		for _, j := range jobs {
			keeperBackoff(j.t, now)
		}
		return errors.Join(append(failures, err)...)
	}
	var recorded []*keeperJob
	for i, j := range jobs {
		if !applied[i] {
			j.t.keepAt = now // changed meanwhile: re-read next tick
			continue
		}
		row := &j.t.row
		row.Generation, row.ContextID, row.ExpiresAt, row.MinVersion = row.Generation+1, j.renewal.NewContextID, j.renewal.ExpiresAt, j.renewal.MinVersion
		claimUntil := now.Add(deliveryClaimTTL)
		row.ClaimOwner, row.ClaimBoot, row.ClaimExpires = k.owner, boot, &claimUntil
		j.t.flag = 0
		recorded = append(recorded, j)
	}
	failures = append(failures, k.deliver(transport, ctx, r, recorded, boot, now))
	return errors.Join(failures...)
}

// recheck runs the admission re-check of every job (bounded concurrency).
// Infrastructure errors leave the binding as it is, to retry.
func (k *nodeKeeper) recheck(ctx context.Context, r *nodeReconciler, jobs []*keeperJob, now time.Time) ([]*keeperJob, []*keeperStop, error) {
	hashes := make([][]byte, len(jobs))
	principals := make([]string, len(jobs))
	for i, j := range jobs {
		hashes[i], principals[i] = j.row.Hash, j.row.PrincipalID.String()
	}
	payloads, err := r.tracking.store.TrackedPayloads(ctx, hashes)
	if err != nil {
		for _, j := range jobs {
			keeperBackoff(j.t, now)
		}
		return nil, nil, err
	}
	dids, err := r.main.ExternalIDsByUserID(ctx, principals)
	if err != nil {
		for _, j := range jobs {
			keeperBackoff(j.t, now)
		}
		return nil, nil, err
	}
	var wg sync.WaitGroup
	slots := make(chan struct{}, keeperWorkers)
	for _, j := range jobs {
		j.raw, j.did = payloads[string(j.row.Hash)], dids[j.row.PrincipalID.String()]
		if len(j.raw) == 0 {
			j.err = fmt.Errorf("raw transaction of a pending binding is no longer retained")
			continue
		}
		slots <- struct{}{}
		wg.Add(1)
		go func(j *keeperJob) {
			defer wg.Done()
			defer func() { <-slots }()
			j.refusal, j.record, j.err = k.checker.Recheck(ctx, j.row, j.raw, j.did, j.event)
		}(j)
	}
	wg.Wait()
	var ok []*keeperJob
	var stops []*keeperStop
	var failures []error
	for _, j := range jobs {
		switch {
		case j.err != nil:
			keeperBackoff(j.t, now)
			failures = append(failures, j.err)
		case j.refusal != 0:
			stops = append(stops, &keeperStop{t: j.t, row: j.row, generation: j.row.Generation, reason: j.refusal, method: "ops.system.renewal_refused", status: 403, event: j.event})
		default:
			ok = append(ok, j)
		}
	}
	if len(failures) > 0 {
		if suppressed, allowed := k.log.Allow("recheck", time.Now(), failureLogEvery); allowed {
			slog.Warn("lease keeper re-check unavailable; retried", "failed", len(failures), "error", failures[0], "suppressed", suppressed)
		}
	}
	return ok, stops, nil
}

// sign reads the issuing clock once, after every re-check of the tick (a
// revocation committed before it raises the floor, G27), and signs each
// renewal: same principal, organisation, signer and binding; the floor is the
// clock version; the lease is capped at the maximum age, and never shorter
// than the stored one (so it dominates it, T17).
func (k *nodeKeeper) sign(ctx context.Context, jobs []*keeperJob, now time.Time) ([]*keeperJob, []*keeperStop, error) {
	version, dbNow, err := k.clock.NodePolicyClock(ctx)
	if err != nil || version == 0 {
		for _, j := range jobs {
			keeperBackoff(j.t, now)
		}
		return nil, nil, errors.Join(err, nodepolicy.ErrNodeUnavailable)
	}
	var signed []*keeperJob
	var stops []*keeperStop
	for _, j := range jobs {
		row := j.row
		expires := dbNow.Add(k.ttl)
		if cap := row.CreatedAt.Add(k.maxAge); cap.Before(expires) {
			expires = cap
		}
		if row.ExpiresAt.After(expires) {
			expires = row.ExpiresAt
		}
		expires = expires.Truncate(time.Second)
		if expires.Sub(dbNow) < keeperMinLease {
			stops = append(stops, &keeperStop{t: j.t, row: row, generation: row.Generation, reason: db.TrackReasonMaxAge, method: "ops.system.renewal_stopped", status: 410, event: j.event})
			continue
		}
		if version < row.MinVersion {
			keeperBackoff(j.t, now) // the clock cannot go back; never sign below the stored floor
			continue
		}
		identity := nodepolicy.Identity{Header: nodepolicy.Header{Network: k.signerNetwork(), IssuedAt: dbNow.Unix(), ExpiresAt: expires.Unix()}, Scope: "transaction", ContextID: uuid.NewString(),
			PrincipalID: row.PrincipalID.String(), OrgID: row.OrgID.String(), Signer: "0x" + hex.EncodeToString(row.Signer), BindingHash: "0x" + hex.EncodeToString(row.Hash), MinSnapshotVersion: version}
		wire, err := k.signer.Seal("identity", identity)
		if err != nil {
			keeperBackoff(j.t, now)
			continue
		}
		contextID, _ := uuid.Parse(identity.ContextID)
		envelope := sha256.Sum256(wire)
		j.wire, j.identity = wire, identity
		j.renewal = db.TrackRenewal{Hash: row.Hash, Generation: row.Generation, ContextID: row.ContextID, AdmitXid: row.AdmitXid, NewContextID: contextID, EnvelopeHash: envelope[:],
			ExpiresAt: time.Unix(identity.ExpiresAt, 0), MinVersion: version, Reason: j.trigger, TravelRuleRecord: j.record, ClaimOwner: k.owner, ClaimBoot: k.lastBoot, ClaimTTL: deliveryClaimTTL}
		signed = append(signed, j)
	}
	return signed, stops, nil
}

func (k *nodeKeeper) signerNetwork() nodepolicy.Network { return k.network }

// audit appends every decision of the tick to the durable audit buffer in one
// fsync'd batch before any of them is committed or delivered.
func (k *nodeKeeper) audit(ctx context.Context, r *nodeReconciler, jobs []*keeperJob, stops []*keeperStop) error {
	if r.audit == nil {
		return errSystemAuditUnavailable
	}
	principals := make([]string, 0, len(jobs)+len(stops))
	for _, j := range jobs {
		principals = append(principals, j.row.PrincipalID.String())
	}
	for _, s := range stops {
		principals = append(principals, s.row.PrincipalID.String())
	}
	dids, err := r.main.ExternalIDsByUserID(ctx, principals)
	if err != nil {
		return err
	}
	var events [][]byte
	for _, j := range jobs {
		method := "ops.system.recovery"
		if j.trigger == db.TrackReasonLeaseExpiring {
			method = "ops.system.identity_renewal"
		}
		event, err := k.event(r, j.row, dids, method, 200, j.event, j.trigger, map[string]any{"context_id": j.identity.ContextID, "generation": j.row.Generation + 1, "min_version": j.identity.MinSnapshotVersion, "expires_at": j.identity.ExpiresAt})
		if err != nil {
			return err
		}
		events = append(events, event)
	}
	for _, s := range stops {
		if s.event == uuid.Nil {
			s.event = uuid.New()
		}
		event, err := k.event(r, s.row, dids, s.method, s.status, s.event, s.reason, map[string]any{"context_id": s.row.ContextID.String(), "generation": s.generation})
		if err != nil {
			return err
		}
		events = append(events, event)
	}
	if len(events) == 0 {
		return nil
	}
	if _, err := r.audit.AppendBatch(events); err != nil {
		// Renewals pause: their re-checks write compliance decisions.
		k.auditPausedUntil = k.now().Add(keeperAuditPause)
		return fmt.Errorf("%w: %v", errSystemAuditUnavailable, err)
	}
	return nil
}

// event encodes a keeper decision (plan §4.8.6): a system action on behalf
// of the principal, with the reason, the transaction and the identity in the
// hashed parameters and a random event id.
func (k *nodeKeeper) event(r *nodeReconciler, row db.TrackedTransaction, dids map[string]string, method string, status int, id uuid.UUID, reason int16, extra map[string]any) ([]byte, error) {
	principal := row.PrincipalID.String()
	external := dids[principal]
	if external == "" {
		external = "principal:" + principal
	}
	fields := map[string]any{"tx_hash": "0x" + hex.EncodeToString(row.Hash), "incarnation": r.inc.String(), "actor": "system:identity-renewal", "reason": db.TrackReasonName(reason)}
	for key, value := range extra {
		fields[key] = value
	}
	params, err := json.Marshal(fields)
	if err != nil {
		return nil, err
	}
	denial := ""
	if status != 200 {
		denial = db.TrackReasonName(reason)
	}
	return json.Marshal(db.AccessLogRecord{ExternalID: external, Method: method, StatusCode: status, CorrelationID: id.String(), Params: params, OrgID: row.OrgID.String(), DenialReason: denial})
}

// stop commits audited stops: pending → renewal_stopped, fenced by the
// generation the decision was taken on.
func (k *nodeKeeper) stop(ctx context.Context, r *nodeReconciler, stops []*keeperStop, now time.Time) error {
	if len(stops) == 0 {
		return nil
	}
	transitions := make([]db.TrackTransition, 0, len(stops))
	index := map[string]*keeperStop{}
	for _, s := range stops {
		if _, dup := index[string(s.row.Hash)]; dup {
			continue
		}
		index[string(s.row.Hash)] = s
		transitions = append(transitions, db.TrackTransition{Hash: s.row.Hash, From: db.TrackPending, To: db.TrackRenewalStopped, Generation: s.generation, Reason: s.reason})
	}
	applied, err := r.tracking.store.ApplyTransitions(ctx, r.inc, transitions)
	if err != nil {
		for _, s := range stops {
			keeperBackoff(s.t, now)
		}
		return err
	}
	for i, ok := range applied {
		s := index[string(transitions[i].Hash)]
		if ok {
			s.t.row.State, s.t.row.Reason = db.TrackRenewalStopped, s.reason
			s.t.resend, s.t.flag = nil, 0
			slog.Info("lease keeper stopped renewing a transaction (it may still settle)", "tx", s.t.hashHex, "reason", db.TrackReasonName(s.reason))
		} else {
			s.t.keepAt = now
		}
	}
	return nil
}

// deliver sends recorded generations on the recovery lane. A success is
// acknowledged against the answering boot; a definitive pool refusal stops
// renewal (audited); anything else is resent unchanged later.
func (k *nodeKeeper) deliver(transport, ctx context.Context, r *nodeReconciler, jobs []*keeperJob, boot uuid.UUID, now time.Time) error {
	type result struct {
		submitted nodepolicy.Submission
		err       error
	}
	results := make([]result, len(jobs))
	var wg sync.WaitGroup
	slots := make(chan struct{}, keeperWorkers)
	for i, j := range jobs {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int, j *keeperJob) {
			defer wg.Done()
			defer func() { <-slots }()
			send, cancel := context.WithTimeout(transport, keeperSendWait)
			defer cancel()
			results[i].submitted, results[i].err = k.node.SubmitRecovery(send, j.wire, "0x"+hex.EncodeToString(j.raw))
		}(i, j)
	}
	wg.Wait()
	var stops []*keeperStop
	for i, j := range jobs {
		k.settle(r, j.t, j.wire, "0x"+hex.EncodeToString(j.raw), j.t.row.Generation, time.Unix(j.identity.ExpiresAt, 0), results[i].submitted, results[i].err, boot, now, &stops)
	}
	if len(stops) == 0 {
		return nil
	}
	if err := k.audit(ctx, r, nil, stops); err != nil {
		for _, s := range stops {
			keeperBackoff(s.t, now)
		}
		return err
	}
	return k.stop(ctx, r, stops, now)
}

// settle records one delivery outcome.
func (k *nodeKeeper) settle(r *nodeReconciler, t *trackedRow, wire []byte, raw string, generation int32, expires time.Time, submitted nodepolicy.Submission, err error, boot uuid.UUID, now time.Time, stops *[]*keeperStop) {
	var rejection *nodepolicy.PoolRejection
	switch {
	case err == nil:
		answered, parseErr := uuid.Parse(submitted.BootID)
		if parseErr == nil {
			r.tracking.ack(t.row.Hash, generation, r.inc, answered)
		}
		t.resend, t.keepBackoff = nil, 0
		t.keepAt = now.Add(deliveryClaimTTL)
	case errors.As(err, &rejection):
		reason := db.TrackReasonNonceConflict
		if rejection.Reason == nodepolicy.PoolReplaced {
			reason = db.TrackReasonReplacedInPool
		}
		t.resend = nil
		*stops = append(*stops, &keeperStop{t: t, row: t.row, generation: generation, reason: reason, method: "ops.system.renewal_stopped", status: 410})
	case errors.Is(err, nodepolicy.ErrNodeRejected) && t.resend != nil && t.resend.rejected >= keeperMaxRejections-1:
		// The node keeps refusing this recorded generation (it answers, so it
		// is not unavailable): stop renewing instead of re-authorizing it until
		// the maximum age. The transaction is not final.
		t.resend = nil
		*stops = append(*stops, &keeperStop{t: t, row: t.row, generation: generation, reason: db.TrackReasonNodeRejected, method: "ops.system.renewal_stopped", status: 410})
	default:
		backoff, rejected := time.Second, 0
		if t.resend != nil {
			backoff, rejected = min(2*t.resend.backoff, keeperMaxBackoff), t.resend.rejected
		}
		if errors.Is(err, nodepolicy.ErrNodeRejected) {
			rejected++
		}
		t.resend = &keeperResend{wire: wire, raw: raw, generation: generation, boot: boot, expires: expires, next: now.Add(backoff), backoff: backoff, rejected: rejected}
		if suppressed, ok := k.log.Allow("deliver:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
			slog.Warn("lease keeper delivery failed; resent unchanged", "error", err, "suppressed", suppressed)
		}
	}
}

// resend sends failed generations again, unchanged, while the node keeps the
// boot they were decided for and their lease has room; otherwise the binding
// goes back to the keeper's candidates (a new decision with a full re-check).
func (k *nodeKeeper) resend(ctx, transport context.Context, r *nodeReconciler, boot uuid.UUID, now time.Time) error {
	var due []*trackedRow
	for _, t := range r.rows {
		if t.resend == nil {
			continue
		}
		if t.row.State != db.TrackPending || t.row.Generation != t.resend.generation || t.resend.boot != boot || t.resend.expires.Sub(now) <= k.margin() {
			t.resend, t.keepAt = nil, time.Time{}
			continue
		}
		if !t.resend.next.After(now) && len(due) < keeperMaxPerTick {
			due = append(due, t)
		}
	}
	if len(due) == 0 {
		return nil
	}
	type result struct {
		submitted nodepolicy.Submission
		err       error
	}
	results := make([]result, len(due))
	var wg sync.WaitGroup
	slots := make(chan struct{}, keeperWorkers)
	for i, t := range due {
		slots <- struct{}{}
		wg.Add(1)
		go func(i int, t *trackedRow) {
			defer wg.Done()
			defer func() { <-slots }()
			send, cancel := context.WithTimeout(transport, keeperSendWait)
			defer cancel()
			results[i].submitted, results[i].err = k.node.SubmitRecovery(send, t.resend.wire, t.resend.raw)
		}(i, t)
	}
	wg.Wait()
	var stops []*keeperStop
	for i, t := range due {
		rs := t.resend
		k.settle(r, t, rs.wire, rs.raw, rs.generation, rs.expires, results[i].submitted, results[i].err, boot, now, &stops)
	}
	if len(stops) == 0 {
		return nil
	}
	if err := k.audit(ctx, r, nil, stops); err != nil {
		for _, s := range stops {
			keeperBackoff(s.t, now)
		}
		return err
	}
	return k.stop(ctx, r, stops, now)
}

// dropped records the final dropped status of stopped bindings whose nonce
// the signer's finalized nonce has passed with no own receipt (plan §4.8.1):
// the evidence is read at the finalized block the private node reported,
// pinned by its hash, in one request, and the private status is re-read
// right before the decision; finalized lease expiry alone is never enough.
func (k *nodeKeeper) dropped(ctx, transport context.Context, r *nodeReconciler, now time.Time) error {
	if k.chain == nil || r.head == 0 || r.headHash == "" {
		return nil
	}
	bySigner := map[string][]*trackedRow{}
	for _, t := range r.rows {
		if (t.row.State == db.TrackRenewalStopped || t.row.State == db.TrackTombstone) && !t.dropAt.After(now) && len(t.row.Signer) == 20 {
			signer := "0x" + hex.EncodeToString(t.row.Signer)
			if len(bySigner[signer]) < maxChainBatch-2 {
				bySigner[signer] = append(bySigner[signer], t)
			}
		}
	}
	var candidates []*trackedRow
	var failures []error
	for signer, rows := range bySigner {
		if transport.Err() != nil {
			break // the tick's budget is spent; the rest wait for the next tick
		}
		hashes := make([]string, len(rows))
		for i, t := range rows {
			hashes[i] = t.hashHex
		}
		read, cancel := context.WithTimeout(transport, keeperSendWait)
		nonce, receipts, err := k.chain.DroppedEvidence(read, r.head, r.headHash, signer, hashes)
		cancel()
		for _, t := range rows {
			t.dropAt = now.Add(keeperDropInterval)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		for _, t := range rows {
			if nonce > t.row.Nonce && !receipts[t.hashHex] {
				candidates = append(candidates, t)
			} else {
				t.dropSeen = time.Time{}
			}
		}
	}
	if len(candidates) == 0 {
		return errors.Join(failures...)
	}
	// The private node must answer definitively that it holds no inclusion:
	// a non-included status, or its refusal to know the hash (after a restart
	// or release). No answer decides nothing. The same verdict must hold on
	// two reads at least keeperDropInterval apart, so one lagging or
	// inconsistent backend cannot make a final failure.
	var confirmed []*trackedRow
	for _, t := range candidates {
		read, cancel := context.WithTimeout(transport, keeperSendWait)
		status, err := r.node.TransactionStatus(read, t.hashHex)
		cancel()
		switch {
		case err == nil && (status.Execution.Status == "included" || status.Execution.Status == "reverted"):
			t.dropSeen = time.Time{}
			continue // the reconciler records the inclusion
		case err != nil && !nodepolicy.NodeRefused(err):
			continue // no definitive answer (unavailable, internal, limited): no decision
		}
		if t.dropSeen.IsZero() {
			t.dropSeen = now
			continue
		}
		if now.Sub(t.dropSeen) < keeperDropInterval {
			continue
		}
		confirmed = append(confirmed, t)
	}
	if len(confirmed) == 0 {
		return errors.Join(failures...)
	}
	var stops []*keeperStop
	for _, t := range confirmed {
		stops = append(stops, &keeperStop{t: t, row: t.row, generation: t.row.Generation, reason: db.TrackReasonNonceConsumed, method: "ops.system.dropped", status: 410, event: uuid.New()})
	}
	if err := k.audit(ctx, r, nil, stops); err != nil {
		return errors.Join(append(failures, err)...)
	}
	finals := make([]db.TrackFinal, len(confirmed))
	for i, t := range confirmed {
		finals[i] = db.TrackFinal{Hash: t.row.Hash, State: db.TrackDropped, Reason: db.TrackReasonNonceConsumed, PrincipalID: t.row.PrincipalID, OrgID: t.row.OrgID, AdmitXid: t.row.AdmitXid, RequireStopped: true}
	}
	applied, err := r.tracking.store.FinalizeBatch(ctx, r.inc, finals)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	for i, ok := range applied {
		if ok {
			delete(r.rows, string(finals[i].Hash))
			slog.Info("transaction dropped: its nonce is used by a finalized transaction", "tx", confirmed[i].hashHex)
		} else {
			r.refresh(ctx, confirmed[i])
		}
	}
	return errors.Join(failures...)
}
