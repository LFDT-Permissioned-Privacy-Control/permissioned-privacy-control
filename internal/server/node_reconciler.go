package server

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
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

// batchedOutcomeClient is reconciliation option A (plan §4.5, G9): up to
// nodepolicy.MaxStatusBatch hashes per call, used while the node advertises
// nodepolicy.CapabilityTransactionStatuses.
type batchedOutcomeClient interface {
	TransactionStatuses(context.Context, []string) (nodepolicy.TransactionStatusBatch, error)
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
	reconcileMaxPolls    = 4096 // per tick, one status call per transaction
	// reconcileMaxBatchedPolls bounds a tick's polls with the batched status
	// call (MaxStatusBatch per call, reconcileBatchCalls at once): above the
	// pending work of the expected rate, so the pending-work limit is not
	// reached merely because inclusions are observed late.
	reconcileMaxBatchedPolls = 16384
	reconcileStatusWait      = 5 * time.Second
	reconcileMaxBackoff      = 15 * time.Second
	reconcileScanPage        = 1000
	// reconcileSettle: a row still pending this long after admission is
	// polled with a growing interval (up to reconcileMaxBackoff).
	reconcileSettle = 30 * time.Second
	// reconcileRefreshAfter consecutive failures re-read the binding (a row
	// released or rebound meanwhile leaves or is replaced in the schedule),
	// at most reconcileMaxRefreshes per tick (a node outage fails every row).
	reconcileRefreshAfter = 3
	reconcileMaxRefreshes = 256
	// reconcilePollDeadline: batched status calls are started only this long
	// into a tick; rows not polled stay due for the next one, so a slow node
	// never holds the keeper and the transitions up for long.
	reconcilePollDeadline = 2 * time.Second
	// discoverStallAfter: a discovery horizon held this long by a
	// transaction in progress is alerted, and bindings are then also found by
	// a full scan, at most this often, until it moves again.
	discoverStallAfter = 10 * time.Second
	// reconcileQuarantine: a row whose status the node answered invalidly is
	// polled again after this long, doubling up to reconcileQuarantineMax
	// while the answers stay invalid; the rows answered with it proceed.
	reconcileQuarantine    = 30 * time.Second
	reconcileQuarantineMax = 10 * time.Minute
	// discoverFullScanPages bounds one tick's share of a full scan; the next
	// tick resumes it.
	discoverFullScanPages = 20
)

// Alert kinds (counted in node_tracking_alerts_total).
const (
	alertInvalidStatus    = "invalid_status"
	alertProtocolMismatch = "protocol_mismatch"
	alertDiscoveryStalled = "discovery_stalled"
	alertHorizonFallback  = "horizon_fallback"
)

// errForeignOutcome: the node's outcome for the hash belongs to another
// principal or organization (for example a shared signer's resubmission of a
// transaction that already executed): never recorded against this binding.
var errForeignOutcome = errors.New("node outcome belongs to another submission")

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
	// quarantine: the current interval of a row the node keeps answering
	// invalidly (0: not quarantined).
	quarantine time.Duration
	// audited: the finality event of this binding was appended; a retried
	// finalization in the same term is not audited again. refusalAudited:
	// likewise for its effects_refused event.
	audited, refusalAudited bool

	// Lease keeper state (in memory, per term): not a keeper candidate before
	// keepAt; flag is a trigger the reconciler observed (evicted); resend is a
	// recorded generation whose delivery is retried; dropAt spaces dropped
	// evidence reads; evictAt spaces pool checks.
	forcePoll   bool // re-poll a provisional row above the head (canonical change)
	keepAt      time.Time
	keepBackoff time.Duration
	flag        int16
	resend      *keeperResend
	dropAt      time.Time
	dropSeen    time.Time // first read of dropped evidence (two are required)
	refreshAt   time.Time // next re-read of a stopped row
	evictAt     time.Time
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
	// horizon and horizonAt: the last discovery horizon and since when it has
	// not moved while a transaction held it; fullScanAt: when the last full
	// scan started; rescan: a full scan is due (handed-over admissions were
	// lost); full: the resume point of a full scan in progress.
	horizon    uint64
	horizonAt  time.Time
	fullScanAt time.Time
	rescan     bool
	full       *scanResume
	// head and headHash: the highest effective finalized block the node
	// reported (final and written).
	head     uint64
	headHash string
	// canonical: the node's canonical epoch from batched status answers; a
	// change re-polls every provisional row (a reorg below the head).
	canonical     uint64
	canonicalBoot string
	canonicalSeen bool
	// batched reports whether the node advertises the batched status call.
	batched func() bool
	keeper  *nodeKeeper
	// alert counts an anomaly by kind (nil: not counted).
	alert func(kind string)
}

func (r *nodeReconciler) raise(kind string) {
	if r.alert != nil {
		r.alert(kind)
	}
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
	r.rows, r.cursor, r.scanned, r.head, r.headHash, r.canonicalSeen = map[string]*trackedRow{}, 0, false, 0, "", false
	r.horizon, r.horizonAt, r.fullScanAt, r.rescan, r.full = 0, time.Time{}, time.Time{}, false, nil
	r.inc, r.epoch = r.tracking.incarnation(), r.tracking.epoch.Load()
	// The term's first pass scans every binding, so handed-over hashes from
	// before it (or from another incarnation) are not needed.
	r.tracking.drainAdmitted()
	if r.keeper != nil {
		r.keeper.reset()
	}
}

// tick runs one reconciliation pass.
func (r *nodeReconciler) tick(ctx context.Context) error {
	if r.rows == nil || r.epoch != r.tracking.epoch.Load() {
		r.reset()
	}
	// A discovery failure never stops the rows already scheduled from being
	// polled, transitioned and released (finding 3).
	discoverErr := r.discover(ctx)
	if trackingRecreated(discoverErr) {
		return r.recreated(ctx, discoverErr)
	}
	observations := r.poll(ctx)
	err := errors.Join(discoverErr, r.apply(ctx, observations))
	if r.keeper != nil && !trackingRecreated(err) {
		err = errors.Join(err, r.keeper.tick(ctx, r))
	}
	return r.recreated(ctx, err)
}

// recreated adopts a recreated tracking database and resets the schedule.
func (r *nodeReconciler) recreated(ctx context.Context, err error) error {
	if trackingRecreated(err) {
		r.tracking.adoptAfter(ctx, r.inc)
		r.rows = nil
	}
	return err
}

// discover adds bindings admitted since the last pass (independent review,
// finding 3, for what may hold it up):
//   - this instance's own admissions, handed over in memory, at once;
//   - every row whose inserting transaction ended below this database's
//     discovery horizon (none is skipped, whatever order concurrent batches
//     committed in); only this database's transactions hold the horizon;
//   - every binding by a full scan at the start of a term, after lost
//     hand-overs, and while a transaction of this database holds the horizon
//     longer than discoverStallAfter (alerted), so even then other instances'
//     admissions are discovered and their quota released. A full scan reads
//     at most discoverFullScanPages pages per tick and resumes.
func (r *nodeReconciler) discover(ctx context.Context) error {
	handErr := r.discoverHandedOver(ctx)
	read, err := r.tracking.store.TrackingHorizon(ctx)
	if err != nil {
		return errors.Join(handErr, err)
	}
	if read.ClusterWide {
		r.raise(alertHorizonFallback)
		if suppressed, ok := r.log.Allow("horizon-fallback", time.Now(), failureLogEvery); ok {
			slog.Warn("execution-tracking discovery uses the cluster-wide horizon (pg_stat_activity or pg_prepared_xacts is not readable): other databases' long transactions can delay discovery", "suppressed", suppressed)
		}
	}
	horizon, next := read.Horizon, read.Next
	now := r.now()
	if horizon != r.horizon || horizon >= next || r.horizonAt.IsZero() {
		r.horizon, r.horizonAt = horizon, now
	}
	stalled := horizon < next && now.Sub(r.horizonAt) >= discoverStallAfter
	if r.full == nil && (!r.scanned || r.rescan || (stalled && !now.Before(r.fullScanAt.Add(discoverStallAfter)))) {
		if stalled {
			r.raise(alertDiscoveryStalled)
			if suppressed, ok := r.log.Allow("discovery-stalled", time.Now(), failureLogEvery); ok {
				slog.Error("execution-tracking discovery horizon held by a long transaction in the execution-tracking database: discovering by full scan until it ends", "held_for", now.Sub(r.horizonAt).Truncate(time.Second), "suppressed", suppressed)
			}
		}
		r.full, r.fullScanAt, r.rescan = &scanResume{cursor: horizon}, now, false
	}
	if r.full != nil {
		done, err := r.scan(ctx, r.full, math.MaxInt64, discoverFullScanPages)
		if err != nil {
			return errors.Join(handErr, err)
		}
		if !done {
			return handErr
		}
		// Every binding visible when the scan started is scheduled; the
		// cursor resumes from the horizon read then.
		if !r.scanned || r.full.cursor > r.cursor {
			r.cursor = r.full.cursor
		}
		r.full, r.scanned = nil, true
	}
	if horizon <= r.cursor {
		return handErr
	}
	if _, err := r.scan(ctx, &scanResume{from: r.cursor}, horizon, 0); err != nil {
		return errors.Join(handErr, err)
	}
	r.cursor = horizon
	return handErr
}

// scanResume is a keyset position in admit_xid order; cursor is, for a full
// scan, the horizon read when it started.
type scanResume struct {
	from   uint64
	after  []byte
	cursor uint64
}

// scan schedules bindings admitted in [at.from, to) by admit_xid from the
// resume point, at most pages pages (0: all); it reports whether it reached
// the end and otherwise leaves the resume point at the next page.
func (r *nodeReconciler) scan(ctx context.Context, at *scanResume, to uint64, pages int) (bool, error) {
	for n := 0; pages == 0 || n < pages; n++ {
		page, err := r.tracking.store.ListTracked(ctx, at.from, to, at.after, reconcileScanPage)
		if err != nil {
			return false, err
		}
		for _, row := range page {
			r.schedule(row)
		}
		if len(page) < reconcileScanPage {
			return true, nil
		}
		last := page[len(page)-1]
		at.from, at.after = last.AdmitXid, last.Hash
	}
	return false, nil
}

// schedule adds a binding read from the database. A hash released and
// admitted again is a new binding (possibly another principal's): it
// replaces the scheduled one.
func (r *nodeReconciler) schedule(row db.TrackedTransaction) *trackedRow {
	key := string(row.Hash)
	if known, ok := r.rows[key]; ok && known.row.AdmitXid == row.AdmitXid {
		return known
	}
	t := &trackedRow{row: row, hashHex: "0x" + hex.EncodeToString(row.Hash)}
	r.rows[key] = t
	return t
}

// discoverHandedOver schedules this instance's own admissions from a fresh
// read; a revived binding already scheduled is refreshed (as refreshStopped
// does). Lost hand-overs make the next pass rescan.
func (r *nodeReconciler) discoverHandedOver(ctx context.Context) error {
	hashes, lost := r.tracking.drainAdmitted()
	r.rescan = r.rescan || lost
	for start := 0; start < len(hashes); start += reconcileScanPage {
		rows, err := r.tracking.store.TrackedBatch(ctx, hashes[start:min(start+reconcileScanPage, len(hashes))])
		if err != nil {
			r.rescan = true
			return err
		}
		for _, row := range rows {
			t := r.schedule(row)
			if t.row.State != row.State && !t.row.Final() {
				t.row, t.keepAt, t.flag, t.dropSeen = row, time.Time{}, 0, time.Time{}
			}
		}
	}
	return nil
}

type observation struct {
	tracked *trackedRow
	status  nodepolicy.TransactionStatus
	err     error
	// pooled: the batched answer's pool flag for a not-included transaction
	// (nil: unknown, the single call does not report it).
	pooled *bool
}

// due reports whether a row is polled this tick. Provisional rows are polled
// only once a finalized head at or above their block was seen, plus the
// lowest one each tick to learn the head (finality-driven, G62).
func (r *nodeReconciler) due(now time.Time, limit int) []*trackedRow {
	var out []*trackedRow
	var lowest *trackedRow
	for _, t := range r.rows {
		if t.nextPoll.After(now) {
			continue
		}
		if t.row.State == db.TrackProvisional && t.row.BlockNumber != nil && *t.row.BlockNumber > r.head && !t.forcePoll {
			if lowest == nil || *t.row.BlockNumber < *lowest.row.BlockNumber {
				lowest = t
			}
			continue
		}
		out = append(out, t)
		if len(out) >= limit-1 { // one slot stays for the head probe
			break
		}
	}
	if lowest != nil {
		out = append(out, lowest)
	}
	return out
}

func (r *nodeReconciler) poll(ctx context.Context) []observation {
	client, batched := r.node.(batchedOutcomeClient)
	batched = batched && r.batched != nil && r.batched()
	limit := reconcileMaxPolls
	if batched {
		limit = reconcileMaxBatchedPolls
	}
	rows := r.due(r.now(), limit)
	if batched && len(rows) > 0 {
		return r.pollBatched(ctx, client, rows)
	}
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
			if err == nil {
				err = status.Validate()
			}
			if err == nil && status.TransactionHash != t.hashHex {
				err = nodepolicy.ErrInvalidStatus
			}
			if err == nil && (status.PrincipalID != t.row.PrincipalID.String() || status.OrgID != t.row.OrgID.String()) {
				// Another identity's outcome for this hash is never recorded
				// against this binding.
				err = errForeignOutcome
			}
			out[i] = observation{tracked: t, status: status, err: err}
		}(i, t)
	}
	wg.Wait()
	return out
}

// unknownContext stands for an executed context that is not a UUID OPS
// issued: it never matches a binding's current context.
var unknownContext = uuid.MustParse("ffffffff-ffff-ffff-ffff-ffffffffffff")

// reconcileBatchCalls bounds the batched status calls in flight per tick.
const reconcileBatchCalls = 4

// pollBatched is option A: the due rows in batches of MaxStatusBatch, a few
// calls at a time. The batch's finalized head advances the head; a change of
// the canonical epoch (a reorg) re-polls every provisional row next tick.
func (r *nodeReconciler) pollBatched(ctx context.Context, client batchedOutcomeClient, rows []*trackedRow) []observation {
	out := make([]observation, len(rows))
	var wg sync.WaitGroup
	var mu sync.Mutex
	slots := make(chan struct{}, reconcileBatchCalls)
	type epochSeen struct {
		epoch uint64
		boot  string
	}
	var epochs []epochSeen
	deadline := time.Now().Add(reconcilePollDeadline)
	polled := len(rows)
	for start := 0; start < len(rows); start += nodepolicy.MaxStatusBatch {
		chunk := rows[start:min(start+nodepolicy.MaxStatusBatch, len(rows))]
		slots <- struct{}{}
		if time.Now().After(deadline) {
			<-slots
			polled = start // the rest stay due for the next tick
			break
		}
		wg.Add(1)
		go func(start int, chunk []*trackedRow) {
			defer wg.Done()
			defer func() { <-slots }()
			hashes := make([]string, len(chunk))
			for i, t := range chunk {
				hashes[i] = t.hashHex
			}
			request, cancel := context.WithTimeout(ctx, reconcileStatusWait)
			defer cancel()
			batch, err := client.TransactionStatuses(request, hashes)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				epochs = append(epochs, epochSeen{batch.CanonicalEpoch, batch.BootID})
				if f := batch.Finalized; f != nil && f.Number > r.head {
					r.head, r.headHash = f.Number, f.Hash
				}
				// Every answered entry invalid (two or more): the node and
				// OPS disagree on the protocol, not about one transaction.
				answered, invalid := 0, 0
				for _, entry := range batch.Statuses {
					if entry != nil {
						answered++
						if entry.Err != nil {
							invalid++
						}
					}
				}
				if answered >= 2 && invalid == answered {
					err = nodepolicy.ErrNodeResponse
					r.raise(alertProtocolMismatch)
				}
			}
			for i, t := range chunk {
				o := observation{tracked: t, err: err}
				if err == nil {
					entry := batch.Statuses[i]
					switch {
					case entry == nil:
						o.err = nodepolicy.ErrNodeRejected // unknown to the node
					case entry.Err != nil:
						o.err = entry.Err // this hash alone: quarantined
					case entry.Status.PrincipalID != t.row.PrincipalID.String() || entry.Status.OrgID != t.row.OrgID.String():
						o.err = errForeignOutcome
					default:
						pooled := entry.Pooled
						o.status, o.pooled = entry.Status, &pooled
					}
				}
				out[start+i] = o
			}
		}(start, chunk)
	}
	wg.Wait()
	// The epoch counts within one node process: a different value, or a new
	// boot (a restart may have truncated unwritten blocks), re-polls every
	// provisional row once and is adopted. A new boot (an upgraded node, say)
	// also ends every quarantine.
	for _, seen := range epochs {
		if r.canonicalSeen && (seen.epoch != r.canonical || seen.boot != r.canonicalBoot) {
			for _, t := range r.rows {
				if t.row.State == db.TrackProvisional {
					t.nextPoll, t.forcePoll = time.Time{}, true
				}
				if seen.boot != r.canonicalBoot && t.quarantine > 0 {
					t.nextPoll, t.quarantine = time.Time{}, 0
				}
			}
		}
		r.canonical, r.canonicalBoot, r.canonicalSeen = seen.epoch, seen.boot, true
	}
	return out[:polled]
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
	var evictChecks []*trackedRow
	refreshes := 0
	for i := range observations {
		o := &observations[i]
		t := o.tracked
		if o.err != nil {
			switch {
			case errors.Is(o.err, nodepolicy.ErrInvalidStatus):
				r.quarantine(t, now)
			default:
				r.delay(t, now)
			}
			failures = append(failures, o.err)
			if t.failures%reconcileRefreshAfter == 0 && refreshes < reconcileMaxRefreshes {
				refreshes++
				r.refresh(ctx, t)
			}
			continue
		}
		t.backoff, t.failures, t.nextPoll, t.forcePoll, t.quarantine = 0, 0, now.Add(reconcileTick), false, 0
		outcome := o.status.Execution
		if outcome.FinalizedBlockNumber != nil && *outcome.FinalizedBlockNumber > r.head && outcome.FinalizedBlockHash != nil {
			r.head, r.headHash = *outcome.FinalizedBlockNumber, *outcome.FinalizedBlockHash
		}
		answered, _ := uuid.Parse(o.status.BootID)
		switch {
		case outcome.Finalized && (outcome.Status == "included" || outcome.Status == "reverted"):
			finals = append(finals, o)
		case outcome.Status == "included" || outcome.Status == "reverted":
			switch t.row.State {
			case db.TrackPending, db.TrackRenewalStopped:
				block := *outcome.BlockNumber
				executed, err := uuid.Parse(o.status.ContextID)
				if err != nil {
					executed = unknownContext // never the current context
				}
				transitions = append(transitions, db.TrackTransition{Hash: t.row.Hash, From: t.row.State, To: db.TrackProvisional, BlockNumber: &block, Boot: answered, ContextID: executed})
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
			// Same-boot eviction (G37): pending at the node long after
			// admission, but no longer in its pool.
			if t.row.State == db.TrackPending && outcome.Status == "pending" && now.Sub(t.row.CreatedAt) > keeperEvictAfter && !t.evictAt.After(now) {
				if o.pooled != nil {
					t.evictAt = now.Add(keeperEvictAfter)
					if !*o.pooled {
						r.markEvicted(t)
					}
				} else {
					evictChecks = append(evictChecks, t)
				}
			}
		}
	}
	r.checkEvictions(ctx, evictChecks, now)
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
				if transitions[i].To == db.TrackProvisional && transitions[i].Boot != uuid.Nil && (transitions[i].ContextID == uuid.Nil || transitions[i].ContextID == t.row.ContextID) {
					generation := t.row.Generation
					t.row.DeliveredGeneration, t.row.DeliveredBoot = &generation, transitions[i].Boot
				}
				if transitions[i].To == db.TrackPending {
					t.keepAt = time.Time{} // reorged out: the keeper reconsiders it
				}
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

// markEvicted flags a pending row the node's pool no longer holds: the keeper
// renews it (the raw transaction is re-pooled with a new generation).
func (r *nodeReconciler) markEvicted(t *trackedRow) {
	t.flag, t.keepAt = db.TrackReasonEvicted, time.Time{}
}

// checkEvictions asks the node's public RPC whether it still holds pending
// rows (the single status call does not report the pool). A transaction the
// node holds in neither its pool nor its chain was evicted; an unavailable
// answer decides nothing.
func (r *nodeReconciler) checkEvictions(ctx context.Context, rows []*trackedRow, now time.Time) {
	if len(rows) == 0 || r.keeper == nil || r.keeper.chain == nil {
		return
	}
	if len(rows) > maxChainBatch {
		rows = rows[:maxChainBatch]
	}
	hashes := make([]string, len(rows))
	for i, t := range rows {
		hashes[i] = t.hashHex
		t.evictAt = now.Add(keeperEvictAfter)
	}
	known, err := r.keeper.chain.Known(ctx, hashes)
	if err != nil {
		return
	}
	for _, t := range rows {
		if !known[t.hashHex] {
			r.markEvicted(t)
		}
	}
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

// quarantine holds back a row whose status the node answered invalidly (a
// protocol violation for that transaction, independent review finding 1): it
// is polled ever less often, alerted and counted, and every other row goes on
// as before. It leaves the quarantine at its first valid answer; a restart
// clears it.
func (r *nodeReconciler) quarantine(t *trackedRow, now time.Time) {
	t.failures++
	t.quarantine = min(max(2*t.quarantine, reconcileQuarantine), reconcileQuarantineMax)
	t.nextPoll = now.Add(t.quarantine)
	r.raise(alertInvalidStatus)
	if suppressed, ok := r.log.Allow("invalid-status", time.Now(), failureLogEvery); ok {
		slog.Error("execution node answered an invalid status for a transaction: it is polled less often until answered validly; other transactions are unaffected", "tx", t.hashHex, "next_poll_in", t.quarantine, "suppressed", suppressed)
	}
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
//     audited as ops.system.effects_refused before it commits — an address
//     refusal inside the effects transaction, a floor refusal (nothing
//     applied) before the tracking finalize — alerted, and finalized with a
//     reason (the marker keeps an address refusal, so a retry after the
//     effects committed keeps it); other errors retry with a growing interval;
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
	var refused []*trackedRow
	finalsToWrite := make([]db.TrackFinal, 0, len(batch))
	for _, item := range batch {
		if item.effect != nil {
			t := item.o.tracked
			// An address refusal commits with the ownership bit: its event is
			// appended inside the effects transaction, before the commit.
			item.effect.BeforeCommit = func(result db.NodeTxEffectsResult) error {
				if result.OwnershipConflicts == 0 || t.refusalAudited {
					return nil
				}
				event, err := r.systemEvent(item.o, item.final, dids, "ops.system.effects_refused", 403, db.TrackReasonName(db.TrackReasonOwnershipConflict))
				if err != nil {
					return err
				}
				// Bounded: the effects transaction holds the organization's
				// configuration scope while it waits. A late success only
				// over-reports (the decision is retried).
				if err := r.appendWithin([][]byte{event}, effectsAuditWait); err != nil {
					return fmt.Errorf("%w: %v", errSystemAuditUnavailable, err)
				}
				t.refusalAudited = true
				return nil
			}
			reason, err := r.applyEffects(ctx, *item.effect)
			if err != nil {
				r.delay(t, now)
				failures = append(failures, err)
				continue // retried later; the binding stays
			}
			if reason == db.TrackReasonEffectsBelowFloor && !t.refusalAudited {
				// Nothing was applied: the refusal commits with the final
				// status, so it is audited before the finality batch.
				event, err := r.systemEvent(item.o, item.final, dids, "ops.system.effects_refused", 403, db.TrackReasonName(reason))
				if err != nil {
					return err
				}
				refusals, refused = append(refusals, event), append(refused, t)
			}
			item.final.Reason = reason
		}
		finalsToWrite = append(finalsToWrite, item.final)
	}
	if len(refusals) > 0 {
		if _, err := r.audit.AppendBatch(refusals); err != nil {
			return fmt.Errorf("%w: %v", errSystemAuditUnavailable, err)
		}
		for _, t := range refused {
			t.refusalAudited = true
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

// effectsAuditWait bounds the audit append made inside an effects
// transaction.
const effectsAuditWait = 5 * time.Second

// errAuditTimeout: the durable audit buffer did not answer in time.
var errAuditTimeout = errors.New("durable audit buffer did not answer in time")

// appendWithin appends events, waiting at most wait for the buffer.
func (r *nodeReconciler) appendWithin(events [][]byte, wait time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := r.audit.AppendBatch(events)
		done <- err
	}()
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return errAuditTimeout
	}
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
