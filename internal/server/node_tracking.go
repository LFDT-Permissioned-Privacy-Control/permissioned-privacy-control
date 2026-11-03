package server

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/loggate"
)

// trackingStore is the execution-tracking database as the request path and
// the reconciler use it (db.ExecDB).
type trackingStore interface {
	AdmitBatch(context.Context, uuid.UUID, db.TrackLimits, []db.TrackAdmission) ([]db.AdmitResult, error)
	ReleaseUndelivered(context.Context, uuid.UUID, []byte, uuid.UUID) (bool, error)
	FlushAcks(context.Context, uuid.UUID, []db.TrackAck) (map[string]bool, error)
	ApplyTransitions(context.Context, uuid.UUID, []db.TrackTransition) ([]bool, error)
	FinalizeBatch(context.Context, uuid.UUID, []db.TrackFinal) ([]bool, error)
	RenewBatch(context.Context, uuid.UUID, []db.TrackRenewal) ([]bool, error)
	TrackedBatch(context.Context, [][]byte) ([]db.TrackedTransaction, error)
	TrackedPayloads(context.Context, [][]byte) (map[string][]byte, error)
	LookupTracked(context.Context, []byte) (db.TrackedTransaction, error)
	TrackingHorizon(context.Context) (uint64, error)
	ListTracked(context.Context, uint64, uint64, []byte, int) ([]db.TrackedTransaction, error)
	TrackingMeta(context.Context) (db.TrackingMeta, error)
}

// Request-path tracking parameters (plan §4.8.4, §6.1, R12.6).
const (
	// trackingMaxBatch bounds one group-committed admission batch.
	trackingMaxBatch = 512
	// trackingCommitters is the number of concurrent batch writers per
	// instance: each takes whatever queued while the others committed.
	trackingCommitters = 2
	// deliveryClaimTTL keeps the lease keeper off a row while the request
	// that admitted it delivers it (delivery timeout + margin).
	deliveryClaimTTL = 20 * time.Second
	// ackFlushDelay: an acknowledgement is written only for a row that has
	// not reached another transition by then (it is coalesced otherwise);
	// well inside deliveryClaimTTL.
	ackFlushDelay = 5 * time.Second
	// ackBufferMax bounds the in-memory acknowledgements; losing one only
	// causes an idempotent redelivery.
	ackBufferMax = 200_000
	// adoptSpacing bounds re-reads of tracking_meta after an incarnation
	// mismatch.
	adoptSpacing = time.Second
)

// errTrackingUnavailable: the intent could not be recorded; nothing was sent.
var errTrackingUnavailable = errors.New("execution tracking unavailable")

// nodeTracking is the request path's side of the tracking database: a
// no-timer group committer for admissions (each request waits for its own
// batch's commit before transport, Q6 (a)), the in-memory acknowledgement
// buffer, and the tracking incarnation every write is fenced by.
type nodeTracking struct {
	store    trackingStore
	instance uuid.UUID // the delivery-claim owner
	// limits are the pending-work limits admissions are held to (plan
	// §4.8.2): L_admit and the per-principal cap. Zero: counted only.
	limits db.TrackLimits

	inc       atomic.Pointer[uuid.UUID]
	epoch     atomic.Uint64 // bumped on every adoption
	adoptMu   sync.Mutex
	adoptedAt time.Time
	// adopt re-initialises a recreated tracking database (owner: migrate,
	// record the network) and returns its incarnation; nil re-reads it.
	adopt func(context.Context) (uuid.UUID, error)

	queue chan *admitRequest
	log   loggate.Gate

	ackMu sync.Mutex
	acks  map[string]pendingAck

	// commits counts admission batch commits (tests and the batch report).
	commits atomic.Int64
}

type admitRequest struct {
	admission db.TrackAdmission
	done      chan admitReply
}

type admitReply struct {
	result db.AdmitResult
	inc    uuid.UUID
	err    error
}

type pendingAck struct {
	generation int32
	inc        uuid.UUID
	boot       uuid.UUID
	at         time.Time
}

func newNodeTracking(store trackingStore, inc uuid.UUID, adopt func(context.Context) (uuid.UUID, error)) *nodeTracking {
	t := &nodeTracking{store: store, instance: uuid.New(), adopt: adopt, queue: make(chan *admitRequest, 4*trackingMaxBatch), acks: map[string]pendingAck{}}
	t.inc.Store(&inc)
	return t
}

// incarnation is the tracking incarnation fresh work is issued under.
func (t *nodeTracking) incarnation() uuid.UUID { return *t.inc.Load() }

// adoptAfter re-reads (or re-initialises) the tracking database after work
// under stale saw ErrTrackingIncarnation or ErrTrackingUninitialised, at most
// once per adoptSpacing. Outstanding work keeps its old incarnation and stays
// refused; fresh work captures the new one (G59).
func (t *nodeTracking) adoptAfter(ctx context.Context, stale uuid.UUID) uuid.UUID {
	t.adoptMu.Lock()
	defer t.adoptMu.Unlock()
	if current := t.incarnation(); current != stale || time.Since(t.adoptedAt) < adoptSpacing {
		return current
	}
	t.adoptedAt = time.Now()
	var next uuid.UUID
	var err error
	if t.adopt != nil {
		next, err = t.adopt(ctx)
	} else {
		var meta db.TrackingMeta
		meta, err = t.store.TrackingMeta(ctx)
		next = meta.Incarnation
	}
	if err != nil || next == uuid.Nil {
		if suppressed, ok := t.log.Allow("adopt", time.Now(), failureLogEvery); ok {
			slog.Warn("execution-tracking database unavailable for adoption", "error", err, "suppressed", suppressed)
		}
		return stale
	}
	if next != stale {
		t.inc.Store(&next)
		t.epoch.Add(1)
		slog.Warn("execution-tracking database was recreated: adopted its new incarnation; work issued before it has no effect", "incarnation", next)
	}
	return next
}

func trackingRecreated(err error) bool {
	return errors.Is(err, db.ErrTrackingIncarnation) || errors.Is(err, db.ErrTrackingUninitialised)
}

// run starts the committers and the acknowledgement flusher until ctx ends;
// the returned function waits for them.
func (t *nodeTracking) run(ctx context.Context) func() {
	var wg sync.WaitGroup
	for i := 0; i < trackingCommitters; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); t.commitLoop(ctx) }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); t.ackLoop(ctx) }()
	return wg.Wait
}

// admit records one intent and waits for its batch's commit (before any
// transport). It returns the result and the incarnation it was written under.
func (t *nodeTracking) admit(ctx context.Context, a db.TrackAdmission) (db.AdmitResult, uuid.UUID, error) {
	a.ClaimOwner, a.ClaimTTL = t.instance, deliveryClaimTTL
	req := &admitRequest{admission: a, done: make(chan admitReply, 1)}
	select {
	case t.queue <- req:
	case <-ctx.Done():
		return db.AdmitResult{}, uuid.Nil, ctx.Err()
	}
	select {
	case reply := <-req.done:
		return reply.result, reply.inc, reply.err
	case <-ctx.Done():
		// The batch may still commit: the row is then pending and undelivered,
		// which the lease keeper delivers; a client resend is idempotent.
		return db.AdmitResult{}, uuid.Nil, ctx.Err()
	}
}

// commitLoop is the no-timer group committer (V1-3): it takes whatever has
// queued, up to trackingMaxBatch, and writes it in one transaction.
func (t *nodeTracking) commitLoop(ctx context.Context) {
	for {
		var first *admitRequest
		select {
		case <-ctx.Done():
			return
		case first = <-t.queue:
		}
		batch := []*admitRequest{first}
	fill:
		for len(batch) < trackingMaxBatch {
			select {
			case next := <-t.queue:
				batch = append(batch, next)
			default:
				break fill
			}
		}
		t.commitBatch(ctx, batch)
	}
}

func (t *nodeTracking) commitBatch(ctx context.Context, batch []*admitRequest) {
	admissions := make([]db.TrackAdmission, len(batch))
	for i, r := range batch {
		admissions[i] = r.admission
	}
	// The batch outlives a single request's cancellation; it is bounded on
	// its own.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	inc := t.incarnation()
	results, err := t.store.AdmitBatch(writeCtx, inc, t.limits, admissions)
	if trackingRecreated(err) {
		// Fresh admissions were written nowhere: re-run them under the
		// adopted incarnation.
		if next := t.adoptAfter(writeCtx, inc); next != inc {
			inc = next
			results, err = t.store.AdmitBatch(writeCtx, inc, t.limits, admissions)
		}
	}
	if err == nil {
		t.commits.Add(1)
	} else if suppressed, ok := t.log.Allow("admit:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
		slog.Warn("execution-tracking admission batch failed", "batch", len(batch), "error", err, "suppressed", suppressed)
	}
	for i, r := range batch {
		reply := admitReply{inc: inc, err: err}
		if err == nil {
			reply.result = results[i]
		}
		r.done <- reply
	}
}

// release is the -32012 transition of a request whose fresh insert the node
// refused before admission (db.ReleaseUndelivered).
func (t *nodeTracking) release(ctx context.Context, inc uuid.UUID, hash []byte, contextID uuid.UUID) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := t.store.ReleaseUndelivered(writeCtx, inc, hash, contextID); err != nil && !trackingRecreated(err) {
		if suppressed, ok := t.log.Allow("release:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
			slog.Warn("execution-tracking release failed; the row stays pending and undelivered", "error", err, "suppressed", suppressed)
		}
	}
}

// stop is the transition of a binding whose delivery the node's pool refused
// definitively (-32013): pending → renewal_stopped at the generation the
// request recorded, so the keeper does not renew it (not final, §4.8.1).
func (t *nodeTracking) stop(ctx context.Context, inc uuid.UUID, hash []byte, generation int32, reason int16) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := t.store.ApplyTransitions(writeCtx, inc, []db.TrackTransition{{Hash: hash, From: db.TrackPending, To: db.TrackRenewalStopped, Generation: generation, Reason: reason}}); err != nil && !trackingRecreated(err) {
		if suppressed, ok := t.log.Allow("stop:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
			slog.Warn("execution-tracking stop failed; the keeper rediscovers the pool refusal", "error", err, "suppressed", suppressed)
		}
	}
}

// ack records a delivery acknowledgement in memory only (G14: nothing is
// written on the request path), against the boot id of the node response
// that carried it (G35). It is written later only if the row has not reached
// another transition first (R12.6).
func (t *nodeTracking) ack(hash []byte, generation int32, inc, boot uuid.UUID) {
	if boot == uuid.Nil {
		return
	}
	t.ackMu.Lock()
	defer t.ackMu.Unlock()
	if len(t.acks) >= ackBufferMax {
		return // an unrecorded acknowledgement only costs a redelivery
	}
	key := string(hash)
	if prior, ok := t.acks[key]; ok && prior.generation > generation {
		return
	}
	t.acks[key] = pendingAck{generation: generation, inc: inc, boot: boot, at: time.Now()}
}

func (t *nodeTracking) ackLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		t.flushAcks(ctx, time.Now().Add(-ackFlushDelay))
	}
}

// flushAcks writes the acknowledgements older than before, in batches.
func (t *nodeTracking) flushAcks(ctx context.Context, before time.Time) {
	current := t.incarnation()
	var due []db.TrackAck
	t.ackMu.Lock()
	for key, a := range t.acks {
		if a.inc != current {
			delete(t.acks, key) // issued under a recreated database: void
			continue
		}
		if a.at.Before(before) {
			due = append(due, db.TrackAck{Hash: []byte(key), Generation: a.generation, Boot: a.boot})
		}
	}
	t.ackMu.Unlock()
	for start := 0; start < len(due); start += 1000 {
		chunk := due[start:min(start+1000, len(due))]
		settled, err := t.store.FlushAcks(ctx, current, chunk)
		if err != nil {
			if trackingRecreated(err) {
				t.adoptAfter(ctx, current)
			} else if suppressed, ok := t.log.Allow("ack:"+nodeErrorClass(err), time.Now(), failureLogEvery); ok {
				slog.Warn("execution-tracking acknowledgement flush failed; retried", "error", err, "suppressed", suppressed)
			}
			return
		}
		t.ackMu.Lock()
		for _, a := range chunk {
			if settled[string(a.Hash)] {
				if prior, ok := t.acks[string(a.Hash)]; ok && prior.generation == a.Generation && prior.boot == a.Boot {
					delete(t.acks, string(a.Hash))
				}
			}
		}
		t.ackMu.Unlock()
	}
}
