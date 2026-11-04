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
	"privacy-proxy/internal/config"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/loggate"
	"privacy-proxy/internal/nodepolicy"
)

// The lease keeper (plan §4.8, P3 and P8): one per elected term, sharing the
// reconciler's in-memory schedule. It renews pending bindings that the node
// does not hold for its current boot — never delivered (an OPS crash between
// the intent and transport, a failed send), lost by a node restart (a new
// boot id), evicted from the pool — or whose lease has entered the renewal
// window (at most TTL/2 left, plan §4.8.2), after a full admission re-check,
// signing at the database clock, auditing the decision first, recording it,
// and only then delivering it on the recovery lane. Renewals are spent within
// the renewal budget, earliest expiry first. It stops renewing at the maximum
// age or on a refused re-check (renewal_stopped, not final), and records
// dropped only on finalized nonce evidence.

// keeperNode delivers keeper identities on the recovery lane.
type keeperNode interface {
	SubmitRecovery(context.Context, []byte, string) (nodepolicy.Submission, error)
}

// keeperClock is the single issuing clock (plan §4.8.3).
type keeperClock interface {
	NodePolicyClock(context.Context) (uint64, time.Time, error)
}

const (
	// keeperMaxPerTick bounds the bindings the keeper reads and decides on per
	// tick (at least one budget burst, keeperBudgetBurst).
	keeperMaxPerTick = 512
	keeperWorkers    = 16
	keeperMaxBackoff = 15 * time.Second
	// keeperBudgetBurst: the renewal budget accrues for at least this long
	// between ticks (and for the whole gap after a slower tick, so a slow tick
	// loses no capacity); it is refilled every tick, so idle time banks
	// nothing.
	keeperBudgetBurst = 2 * time.Second
	// keeperRecheckDeadline: re-checks are started only this long into a
	// tick; the rest keep their budget for the next one, so a slow checker
	// never holds up reconciliation for long (each re-check is bounded by
	// keeperRecheckWait on its own).
	keeperRecheckDeadline = 2 * time.Second
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

// The keeper's cadence and per-step bounds are the ones startup validates
// the renewal arithmetic against (config.DefaultKeeperTiming).
var (
	keeperSendWait    = config.DefaultKeeperTiming.Delivery
	keeperRecheckWait = config.DefaultKeeperTiming.Recheck
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
	// budget is the renewal budget (renewals per second, plan §4.8.2); 0:
	// unbounded. tokens accrue at budget per second up to keeperBudgetBurst.
	budget   int
	tokens   float64
	tokensAt time.Time
	network  nodepolicy.Network
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

// margin is R = TTL/4 (plan §4.8.2): a renewal must land before a lease has
// less than this left.
func (k *nodeKeeper) margin() time.Duration { return k.ttl / 4 }

// windowOpens is TTL/2: a pending lease with at most this much left may be
// renewed; between it and the margin the budget spreads renewals by expiry.
func (k *nodeKeeper) windowOpens() time.Duration { return k.ttl / 2 }

// renewedExpiry is the expiry a renewal at now would sign: a full lease,
// capped at the maximum age, never shorter than the stored one.
func (k *nodeKeeper) renewedExpiry(row db.TrackedTransaction, now time.Time) time.Time {
	expires := now.Add(k.ttl)
	if cap := row.CreatedAt.Add(k.maxAge); cap.Before(expires) {
		expires = cap
	}
	if row.ExpiresAt.After(expires) {
		expires = row.ExpiresAt
	}
	return expires.Truncate(time.Second)
}

// extends reports whether a renewal at now would lengthen the lease at all
// (by a second or more). Leases are capped at the maximum age, so a renewal
// near it extends to the cap once and the next would gain nothing: the keeper
// then waits for the stop instead of re-authorizing for nothing. Any smaller
// threshold would let the lease lapse before the stop.
func (k *nodeKeeper) extends(row db.TrackedTransaction, now time.Time) bool {
	return k.renewedExpiry(row, now).Sub(row.ExpiresAt) >= time.Second
}

// refill accrues the budget for the time since the previous tick: the
// budget rate holds over slow ticks, and an idle keeper banks at most
// keeperBudgetBurst. Called once per tick.
func (k *nodeKeeper) refill(now time.Time) {
	if k.budget <= 0 {
		return
	}
	if k.tokensAt.IsZero() {
		k.tokens = float64(k.budget) // a new term starts with one second's worth
	} else if elapsed := now.Sub(k.tokensAt); elapsed > 0 {
		limit := float64(k.budget) * max(keeperBudgetBurst, elapsed).Seconds()
		k.tokens = min(limit, k.tokens+float64(k.budget)*elapsed.Seconds())
	}
	k.tokensAt = now
}

// spend takes up to n renewals from the budget and returns how many may
// proceed; refund returns unused ones.
func (k *nodeKeeper) spend(n int) int {
	if k.budget <= 0 {
		return n
	}
	granted := min(n, int(k.tokens))
	k.tokens -= float64(granted)
	return granted
}

func (k *nodeKeeper) refund(n int) {
	if k.budget > 0 {
		k.tokens += float64(n)
	}
}

// perTick is how many candidates a tick reads: the renewals the budget
// allows now plus room for stops.
func (k *nodeKeeper) perTick() int {
	return keeperMaxPerTick + int(k.tokens)
}

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
	// deferred: not re-checked this tick (the tick's re-check deadline).
	deferred bool
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
	// extra are further hashed audit parameters (the evidence of dropped).
	extra map[string]any
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
		if t.row.State == db.TrackRenewalStopped && !t.refreshAt.After(now) {
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
		if row.State != t.row.State || row.Generation != t.row.Generation {
			// Revived (and possibly stopped again): evidence read for the
			// earlier generation does not count, and a pending row leaves the
			// slow lane.
			t.row, t.keepAt, t.flag, t.dropSeen = row, time.Time{}, 0, time.Time{}
			if row.State != db.TrackRenewalStopped {
				t.backoff, t.nextPoll = 0, time.Time{}
			}
		} else {
			t.row.MaxExpiresAt = row.MaxExpiresAt
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
	return t.flag != 0 || !row.CreatedAt.Add(k.maxAge).After(now) || row.ExpiresAt.Sub(now) <= k.windowOpens() ||
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
	if row.ExpiresAt.Sub(row.DBNow) <= k.windowOpens() && k.extends(row, row.DBNow) {
		return db.TrackReasonLeaseExpiring
	}
	return 0
}

// nextCheck is when a fresh row that needs nothing now could need the keeper
// (claim expiry, the window opening while a renewal can still extend the
// lease, the maximum age), at most keeperIdleRecheck and at least one tick
// away; boot changes, evictions and reorgs reset it.
func (k *nodeKeeper) nextCheck(row db.TrackedTransaction, now time.Time) time.Time {
	at := row.DBNow.Add(keeperIdleRecheck)
	candidates := []time.Time{row.CreatedAt.Add(k.maxAge)}
	if opens := row.ExpiresAt.Add(-k.windowOpens()); opens.After(row.DBNow) || k.extends(row, row.DBNow) {
		candidates = append(candidates, opens)
	}
	if row.ClaimExpires != nil {
		candidates = append(candidates, *row.ClaimExpires)
	}
	for _, candidate := range candidates {
		if candidate.Before(at) {
			at = candidate
		}
	}
	return now.Add(max(at.Sub(row.DBNow), reconcileTick))
}

func keeperBackoff(t *trackedRow, now time.Time) {
	t.keepBackoff = min(max(2*t.keepBackoff, time.Second), keeperMaxBackoff)
	t.keepAt = now.Add(t.keepBackoff)
}

// renew decides on the candidate bindings: stop at the maximum age, or
// re-check, sign, audit, record and deliver a new generation.
func (k *nodeKeeper) renew(ctx, transport context.Context, r *nodeReconciler, boot uuid.UUID, ready bool, now time.Time) error {
	k.refill(now)
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
	if len(candidates) > k.perTick() {
		candidates = candidates[:k.perTick()]
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
	// The renewal budget (plan §4.8.2), earliest expiry first: the rest wait
	// for the next tick. Stops above take no budget.
	if granted := k.spend(len(jobs)); granted < len(jobs) {
		for _, j := range jobs[granted:] {
			j.t.keepAt = now.Add(reconcileTick)
		}
		if suppressed, ok := k.log.Allow("budget", time.Now(), failureLogEvery); ok {
			slog.Info("lease keeper renewals deferred by the renewal budget", "deferred", len(jobs)-granted, "budget_per_s", k.budget, "suppressed", suppressed)
		}
		jobs = jobs[:granted]
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
		if row.ExpiresAt.After(row.MaxExpiresAt) {
			row.MaxExpiresAt = row.ExpiresAt
		}
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
	deadline := time.Now().Add(keeperRecheckDeadline)
	for _, j := range jobs {
		j.raw, j.did = payloads[string(j.row.Hash)], dids[j.row.PrincipalID.String()]
		if len(j.raw) == 0 {
			j.err = fmt.Errorf("raw transaction of a pending binding is no longer retained")
			continue
		}
		slots <- struct{}{} // a slot first: waiting for one counts against the deadline
		if time.Now().After(deadline) {
			// Not started this tick: it keeps its budget for the next one.
			<-slots
			j.deferred = true
			continue
		}
		wg.Add(1)
		go func(j *keeperJob) {
			defer wg.Done()
			defer func() { <-slots }()
			check, cancel := context.WithTimeout(ctx, keeperRecheckWait)
			defer cancel()
			j.refusal, j.record, j.err = k.checker.Recheck(check, j.row, j.raw, j.did, j.event)
		}(j)
	}
	wg.Wait()
	var ok []*keeperJob
	var stops []*keeperStop
	var failures []error
	deferred := 0
	for _, j := range jobs {
		switch {
		case j.deferred:
			deferred++
			j.t.keepAt = now.Add(reconcileTick)
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
	if deferred > 0 {
		k.refund(deferred)
		// The keeper cannot spend its budget: renewals may fall behind their
		// deadline (degraded mode, plan §4.8.2).
		if suppressed, allowed := k.log.Allow("recheck-slow", time.Now(), failureLogEvery); allowed {
			slog.Warn("lease keeper re-checks too slow for the renewal budget; renewals deferred", "deferred", deferred, "budget_per_s", k.budget, "suppressed", suppressed)
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
		k.refund(len(jobs)) // nothing was decided
		return nil, nil, errors.Join(err, nodepolicy.ErrNodeUnavailable)
	}
	var signed []*keeperJob
	var stops []*keeperStop
	for _, j := range jobs {
		row := j.row
		expires := k.renewedExpiry(row, dbNow)
		if j.trigger == db.TrackReasonLeaseExpiring && !k.extends(row, dbNow) {
			// The issuing clock disagrees with the tracking database's: no
			// gain, no decision; the row waits for the maximum age.
			j.t.keepAt = k.nextCheck(row, now)
			k.refund(1)
			continue
		}
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
		params := map[string]any{"context_id": s.row.ContextID.String(), "generation": s.generation}
		for key, value := range s.extra {
			params[key] = value
		}
		event, err := k.event(r, s.row, dids, s.method, s.status, s.event, s.reason, params)
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

// evidenceClient is the private node's batched status call with dropped
// evidence (A3 wire: receipts and sender nonces at its finalized block).
type evidenceClient interface {
	TransactionEvidence(context.Context, []string, []string) (nodepolicy.TransactionStatusBatch, error)
}

// dropped records the final dropped status of a stopped binding that can no
// longer execute, on one of three pieces of finalized evidence (plan §4.8.1,
// independent review finding 2):
//   - nonce_consumed: the signer's nonce at a finalized block has passed the
//     transaction's, and no canonical block holds it;
//   - finalized_lease_expiry: a finalized block is at or past the expiry of
//     every identity OPS recorded for it (max_expires_at), and no canonical
//     block holds it: the node validates the identity at the block timestamp,
//     timestamps increase, and OPS issues stopped bindings no new identity;
//   - nonce_consumed as well: the hash is included in a finalized block under
//     another principal or organization (a resubmission of a transaction that
//     already executed), so this binding never will.
//
// A node that offers the batched status call answers from its own finalized
// block in one call; otherwise the evidence is read from the public RPC at
// the finalized block the private node reported, pinned by its hash, and the
// private status is re-read right before the decision. Either way the same
// verdict must hold on two reads at least keeperDropInterval apart, and a
// missing or invalid answer (a null entry or receipt, no finalized block)
// decides nothing.
func (k *nodeKeeper) dropped(ctx, transport context.Context, r *nodeReconciler, now time.Time) error {
	if evidence, ok := r.node.(evidenceClient); ok && r.batched != nil && r.batched() {
		return k.droppedFromNode(ctx, transport, r, evidence, now)
	}
	return k.droppedFromChain(ctx, transport, r, now)
}

// droppedDue lists stopped rows whose evidence is due, by signer.
func (k *nodeKeeper) droppedDue(r *nodeReconciler, now time.Time, perSigner int) map[string][]*trackedRow {
	bySigner := map[string][]*trackedRow{}
	for _, t := range r.rows {
		if t.row.State == db.TrackRenewalStopped && !t.dropAt.After(now) && len(t.row.Signer) == 20 {
			signer := "0x" + hex.EncodeToString(t.row.Signer)
			if len(bySigner[signer]) < perSigner {
				bySigner[signer] = append(bySigner[signer], t)
			}
		}
	}
	return bySigner
}

// dropVerdict is the final nonce-consumption verdict supported by an
// evidence read (reason 0: none).
type dropVerdict struct {
	reason int16
	// foreignOnly: a canonical block holds the hash; only the private
	// status (final under another submission) can still make it a verdict.
	foreignOnly bool
}

// judgeDrop requires finalized nonce consumption. Expiry of every identity
// issued so far cannot make the raw transaction permanently unexecutable:
// a fresh identity could still execute its unused nonce. The stopped binding
// must survive status retention and keep refusing a different principal.
func judgeDrop(t *trackedRow, receipt bool, nonce uint64, nonceKnown bool) dropVerdict {
	switch {
	case receipt:
		return dropVerdict{}
	case nonceKnown && nonce > t.row.Nonce:
		return dropVerdict{reason: db.TrackReasonNonceConsumed}
	}
	return dropVerdict{}
}

// observeDrop records one evidence verdict for a row and reports whether it
// is now confirmed (the same verdict, keeperDropInterval apart).
func observeDrop(t *trackedRow, consumed bool, now time.Time) bool {
	if !consumed {
		t.dropSeen = time.Time{}
		return false
	}
	if t.dropSeen.IsZero() {
		t.dropSeen = now
		return false
	}
	return now.Sub(t.dropSeen) >= keeperDropInterval
}

func (k *nodeKeeper) droppedFromNode(ctx, transport context.Context, r *nodeReconciler, node evidenceClient, now time.Time) error {
	var candidates []*trackedRow
	var hashes, senders []string
	senderIndex := map[string]int{}
	for signer, rows := range k.droppedDue(r, now, nodepolicy.MaxStatusBatch) {
		if len(hashes)+len(rows) > nodepolicy.MaxStatusBatch {
			break // the rest next tick (dropAt unchanged)
		}
		senderIndex[signer] = len(senders)
		senders = append(senders, signer)
		for _, t := range rows {
			candidates = append(candidates, t)
			hashes = append(hashes, t.hashHex)
		}
	}
	if len(candidates) == 0 || transport.Err() != nil {
		return nil
	}
	read, cancel := context.WithTimeout(transport, keeperSendWait)
	batch, err := node.TransactionEvidence(read, hashes, senders)
	cancel()
	for _, t := range candidates {
		t.dropAt = now.Add(keeperDropInterval)
	}
	if err != nil {
		return err
	}
	var confirmed []*trackedRow
	var evidence []dropEvidence
	for i, t := range candidates {
		entry := batch.Statuses[i]
		if entry != nil && (entry.Err != nil || entry.NotFound) {
			// An invalid status answer, or a definitive miss (the node holds
			// no identity), says nothing about finality; the receipt and
			// nonce below are read independently of it.
			entry = nil
		}
		if entry != nil && (entry.Status.Execution.Status == "included" || entry.Status.Execution.Status == "reverted") {
			if entry.Status.PrincipalID == t.row.PrincipalID.String() && entry.Status.OrgID == t.row.OrgID.String() {
				t.dropSeen = time.Time{}
				continue // the reconciler records the inclusion
			}
			// Executed under another submission: final once finalized.
			if !entry.Status.Execution.Finalized || batch.Finalized == nil {
				continue
			}
			if observeDrop(t, true, now) {
				confirmed = append(confirmed, t)
				evidence = append(evidence, dropEvidence{source: "private_node", verdict: dropVerdict{reason: db.TrackReasonNonceConsumed}, foreign: true,
					block: batch.Finalized.Number, hash: batch.Finalized.Hash, firstSeen: t.dropSeen})
			}
			continue
		}
		receipt := batch.Receipts[i]
		if batch.Finalized == nil || receipt == nil {
			continue // no evidence either way: no decision, no reset
		}
		var nonce uint64
		if batch.SenderNonces != nil {
			nonce = batch.SenderNonces[senderIndex["0x"+hex.EncodeToString(t.row.Signer)]]
		}
		finalizedAt := time.Unix(batch.Finalized.Timestamp, 0)
		verdict := judgeDrop(t, *receipt, nonce, batch.SenderNonces != nil)
		if observeDrop(t, verdict.reason != 0, now) {
			confirmed = append(confirmed, t)
			evidence = append(evidence, dropEvidence{source: "private_node", verdict: verdict, block: batch.Finalized.Number, hash: batch.Finalized.Hash, timestamp: finalizedAt, nonce: nonce, nonceKnown: batch.SenderNonces != nil, firstSeen: t.dropSeen})
		}
	}
	return k.finalizeDropped(ctx, r, confirmed, evidence, nil)
}

// dropEvidence is what a dropped decision rests on, recorded in its audit
// event: the source, the verdict, the finalized block (number, hash,
// timestamp) it was read at, the sender's nonce there, whether the hash
// executed under another submission, and when the same verdict was first read.
type dropEvidence struct {
	source     string
	verdict    dropVerdict
	foreign    bool
	block      uint64
	hash       string
	timestamp  time.Time
	nonce      uint64
	nonceKnown bool
	firstSeen  time.Time
}

func (k *nodeKeeper) droppedFromChain(ctx, transport context.Context, r *nodeReconciler, now time.Time) error {
	if k.chain == nil || r.head == 0 || r.headHash == "" {
		return nil
	}
	var candidates []*trackedRow
	nonces := map[*trackedRow]uint64{}
	verdicts := map[*trackedRow]dropVerdict{}
	var finalizedAt time.Time
	var failures []error
	for signer, rows := range k.droppedDue(r, now, maxChainBatch-2) {
		if transport.Err() != nil {
			break // the tick's budget is spent; the rest wait for the next tick
		}
		hashes := make([]string, len(rows))
		for i, t := range rows {
			hashes[i] = t.hashHex
		}
		read, cancel := context.WithTimeout(transport, keeperSendWait)
		evidence, err := k.chain.DroppedEvidence(read, r.head, r.headHash, signer, hashes)
		cancel()
		for _, t := range rows {
			t.dropAt = now.Add(keeperDropInterval)
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		finalizedAt = evidence.Timestamp
		for _, t := range rows {
			verdict := judgeDrop(t, evidence.Receipts[t.hashHex], evidence.Nonce, true)
			if evidence.Receipts[t.hashHex] {
				// Included: possibly under another submission, which the
				// private status below decides.
				verdict = dropVerdict{reason: db.TrackReasonNonceConsumed, foreignOnly: true}
			}
			if verdict.reason != 0 {
				candidates = append(candidates, t)
				nonces[t], verdicts[t] = evidence.Nonce, verdict
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
	// or release). No answer decides nothing.
	var confirmed []*trackedRow
	var evidence []dropEvidence
	for _, t := range candidates {
		read, cancel := context.WithTimeout(transport, keeperSendWait)
		status, err := r.node.TransactionStatus(read, t.hashHex)
		cancel()
		foreign := false
		switch {
		case err == nil && (status.Execution.Status == "included" || status.Execution.Status == "reverted"):
			if status.PrincipalID == t.row.PrincipalID.String() && status.OrgID == t.row.OrgID.String() || !status.Execution.Finalized {
				t.dropSeen = time.Time{}
				continue // the reconciler records the inclusion, or it is not final yet
			}
			foreign = true // final under another submission
		case verdicts[t].foreignOnly:
			continue // included, but the private node does not say under whom
		case err != nil && !nodepolicy.NodeNotFound(err) && (!nodepolicy.NodeRefused(err) || (r.notFound != nil && r.notFound())):
			// No definitive answer (unavailable, internal, limited; and for a
			// node that reports misses, its opaque -32000): no decision.
			continue
		}
		if observeDrop(t, true, now) {
			confirmed = append(confirmed, t)
			verdict := verdicts[t]
			if foreign {
				verdict = dropVerdict{reason: db.TrackReasonNonceConsumed}
			}
			evidence = append(evidence, dropEvidence{source: "public_rpc", verdict: verdict, foreign: foreign, block: r.head, hash: r.headHash, timestamp: finalizedAt, nonce: nonces[t], nonceKnown: true, firstSeen: t.dropSeen})
		}
	}
	return k.finalizeDropped(ctx, r, confirmed, evidence, failures)
}

// finalizeDropped audits and records confirmed dropped decisions (only for
// bindings still stopped), each with its evidence in the audit event. The
// decision is re-judged on a fresh read first (state, generation, admission
// and admission), so no event is appended for a final the
// database fences would refuse.
func (k *nodeKeeper) finalizeDropped(ctx context.Context, r *nodeReconciler, confirmed []*trackedRow, evidence []dropEvidence, failures []error) error {
	if len(confirmed) == 0 {
		return errors.Join(failures...)
	}
	hashes := make([][]byte, len(confirmed))
	for i, t := range confirmed {
		hashes[i] = t.row.Hash
	}
	fresh, err := r.tracking.store.TrackedBatch(ctx, hashes)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	byHash := make(map[string]db.TrackedTransaction, len(fresh))
	for _, row := range fresh {
		byHash[string(row.Hash)] = row
	}
	keptRows, keptEvidence := confirmed[:0:0], evidence[:0:0]
	for i, t := range confirmed {
		row, ok := byHash[string(t.row.Hash)]
		e := evidence[i]
		switch {
		case !ok:
			r.refresh(ctx, t) // final or released meanwhile
		case row.AdmitXid != t.row.AdmitXid || row.State != db.TrackRenewalStopped || row.Generation != t.row.Generation:
			if row.AdmitXid == t.row.AdmitXid {
				t.row = row
				if row.State != db.TrackRenewalStopped {
					t.backoff, t.nextPoll = 0, time.Time{} // revived: off the slow lane
				}
			} else {
				r.rows[string(row.Hash)] = &trackedRow{row: row, hashHex: t.hashHex}
			}
			t.dropSeen = time.Time{} // the evidence was for another state: read it again
		default:
			t.row = row
			keptRows, keptEvidence = append(keptRows, t), append(keptEvidence, e)
		}
	}
	confirmed, evidence = keptRows, keptEvidence
	if len(confirmed) == 0 {
		return errors.Join(failures...)
	}
	var stops []*keeperStop
	for i, t := range confirmed {
		e := evidence[i]
		extra := map[string]any{"evidence": e.source, "finalized_block_number": e.block, "finalized_block_hash": e.hash, "nonce": t.row.Nonce, "evidence_first_seen": e.firstSeen.UTC().Format(time.RFC3339)}
		if e.nonceKnown {
			extra["sender_finalized_nonce"] = e.nonce
		}
		if !e.timestamp.IsZero() {
			extra["finalized_block_timestamp"] = e.timestamp.UTC().Format(time.RFC3339)
		}

		if e.foreign {
			extra["executed_by_another_submission"] = true
		}
		stops = append(stops, &keeperStop{t: t, row: t.row, generation: t.row.Generation, reason: e.verdict.reason, method: "ops.system.dropped", status: 410, event: uuid.New(), extra: extra})
	}
	if err := k.audit(ctx, r, nil, stops); err != nil {
		return errors.Join(append(failures, err)...)
	}
	finals := make([]db.TrackFinal, len(confirmed))
	for i, t := range confirmed {
		// Fenced under the row lock by the generation the nonce evidence
		// was read for, so a concurrent revival cannot be finalized.
		finals[i] = db.TrackFinal{Hash: t.row.Hash, State: db.TrackDropped, Reason: evidence[i].verdict.reason, PrincipalID: t.row.PrincipalID, OrgID: t.row.OrgID, AdmitXid: t.row.AdmitXid,
			RequireStopped: true, Generation: t.row.Generation}
	}
	applied, err := r.tracking.store.FinalizeBatch(ctx, r.inc, finals)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	for i, ok := range applied {
		if ok {
			delete(r.rows, string(finals[i].Hash))
			slog.Info("transaction dropped: it will not execute as submitted", "tx", confirmed[i].hashHex, "reason", db.TrackReasonName(finals[i].Reason))
		} else {
			confirmed[i].dropSeen = time.Time{} // two fresh reads again
			r.refresh(ctx, confirmed[i])
		}
	}
	return errors.Join(failures...)
}
