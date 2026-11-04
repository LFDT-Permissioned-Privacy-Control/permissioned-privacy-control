package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/db"
	"privacy-proxy/internal/nodepolicy"
)

// The request path's delivery outcomes (B3b): a definitive pool refusal
// stops renewal (not final) and answers 409; any other node failure after the
// intent was saved is "unknown, OPS delivers it" (503, the row stays
// pending); an acknowledgement is recorded against the boot that answered.
func TestBridgeDeliveryOutcomes(t *testing.T) {
	t.Run("pool_rejection_stops_renewal", func(t *testing.T) {
		bridge, node, tracking := newBridgeFixture(t)
		node.submitErr = &nodepolicy.PoolRejection{Reason: nodepolicy.PoolNonceUsed}
		tx := newSignedTransfer(t, 0)
		if _, err := tx.submit(t, bridge, uuid.NewString(), uuid.NewString()); !errors.Is(err, errPoolRejected) {
			t.Fatalf("pool rejection: %v", err)
		}
		row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
		if err != nil || row.State != db.TrackRenewalStopped || row.Reason != db.TrackReasonNonceConflict || row.Final() {
			t.Fatalf("after -32013: %+v %v", row, err)
		}
	})
	t.Run("ambiguous_failure_is_pending", func(t *testing.T) {
		bridge, node, tracking := newBridgeFixture(t)
		node.submitErr = nodepolicy.ErrNodeRejected
		tx := newSignedTransfer(t, 0)
		if _, err := tx.submit(t, bridge, uuid.NewString(), uuid.NewString()); !errors.Is(err, errSubmissionPending) {
			t.Fatalf("generic rejection after the intent was saved: %v", err)
		}
		if row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash)); err != nil || row.State != db.TrackPending {
			t.Fatalf("row %+v %v", row, err)
		}
	})
	// G35: the status cache already shows the next boot when the answer of
	// the previous one arrives: the acknowledgement is that boot's, so the
	// row stays undelivered for the current one.
	t.Run("ack_is_bound_to_the_answering_boot", func(t *testing.T) {
		bridge, node, tracking := newBridgeFixture(t)
		answered, current := uuid.New(), uuid.New()
		node.boot = hexBoot(answered)
		tx := newSignedTransfer(t, 0)
		if _, err := tx.submit(t, bridge, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		bridge.tracking.flushAcks(context.Background(), time.Now().Add(time.Hour))
		row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
		if err != nil || row.DeliveredTo(current) || !row.DeliveredTo(answered) {
			t.Fatalf("the acknowledgement is not bound to the boot that answered: %+v %v", row, err)
		}
		again := newSignedTransfer(t, 0)
		if _, err := again.submit(t, bridge, uuid.NewString(), uuid.NewString()); err != nil {
			t.Fatal(err)
		}
		bridge.tracking.flushAcks(context.Background(), time.Now().Add(time.Hour))
		if row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, again.hash)); err != nil || !row.DeliveredTo(answered) {
			t.Fatalf("acknowledgement of the current boot not recorded: %+v %v", row, err)
		}
	})
	// G26 on the request path: A signed before B, B admitted first, A saved
	// last: A is still sent (the node answers a dominated attempt as success)
	// but B stays current and A acknowledges nothing.
	t.Run("dominated_attempt_is_sent_not_acknowledged", func(t *testing.T) {
		bridge, node, tracking := newBridgeFixture(t)
		node.boot = hexBoot(uuid.New())
		at := time.Unix(1020, 0)
		bridge.now = func() time.Time { return at }
		principal, org := uuid.NewString(), uuid.NewString()
		tx := newSignedTransfer(t, 0)
		request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: principal, OrgID: org, Signer: tx.signer, BindingHash: tx.hash}
		a, err := bridge.PrepareIdentity(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		at = time.Unix(1021, 0)
		b, err := bridge.PrepareIdentity(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := bridge.SubmitTransaction(context.Background(), b, tx.raw, NodeSubmissionMetadata{}); err != nil {
			t.Fatal(err)
		}
		calls := node.calls.Load()
		if _, err := bridge.SubmitTransaction(context.Background(), a, tx.raw, NodeSubmissionMetadata{}); err != nil {
			t.Fatalf("dominated attempt: %v", err)
		}
		if node.calls.Load() != calls+1 {
			t.Fatal("the dominated attempt was not sent")
		}
		row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
		if err != nil || row.ContextID.String() != identityContextID(b) || row.Generation != 1 {
			t.Fatalf("the earlier envelope replaced the later one: %+v %v", row, err)
		}
	})
}

// A delayed lower-floor attempt must not install its old identity into an
// empty registry after a restart, even though a newer binding dominates it.
func TestDominatedAttemptCannotBypassTheStoredFloorAfterRestart(t *testing.T) {
	bridge, node, tracking := newBridgeFixture(t)
	clock := &steppingClock{}
	bridge.source, bridge.now = clock, clock.now
	clock.set(7, 1020, 0, 0)
	tx := newSignedTransfer(t, 0)
	request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: uuid.NewString(), OrgID: uuid.NewString(), Signer: tx.signer, BindingHash: tx.hash}
	old, err := bridge.PrepareIdentity(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	clock.set(8, 1021, 0, 0)
	node.status.Version = 8
	bridge.observe(context.Background())
	winner, err := bridge.PrepareIdentity(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.SubmitTransaction(context.Background(), winner, tx.raw, NodeSubmissionMetadata{}); err != nil {
		t.Fatal(err)
	}
	// The restart retained older facts, and the winning identity is gone.
	node.status.Version = 7
	node.status.BootID = hexBoot(uuid.New())
	bridge.observe(context.Background())
	calls := node.calls.Load()
	if _, err := bridge.SubmitTransaction(context.Background(), old, tx.raw, NodeSubmissionMetadata{}); err == nil || node.calls.Load() != calls {
		t.Fatalf("lower-floor identity reached restarted node: error=%v sends=%d", err, node.calls.Load()-calls)
	}
	row, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
	if err != nil || row.MinVersion != 8 {
		t.Fatalf("winning floor: %+v error=%v", row, err)
	}
}

// G13 + the conflict answer: a hash bound to another principal is refused
// before the compliance step with one opaque 409, whatever the cause.
func TestRebindingConflictIsAnOpaque409BeforeCompliance(t *testing.T) {
	p, _, node, raw := nodeRPCFixture(t)
	probe := &conflictingService{nodeRPCService: node}
	p.nodeExecution = probe
	got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
	if got.Error == nil || got.Error.StatusCode != http.StatusConflict || got.Error.Message != "transaction conflicts with an earlier submission" || got.Error.Reason != ReasonTransactionConflict {
		t.Fatalf("conflict answer: %+v", got.Error)
	}
	if len(node.prepared) != 0 || len(node.submissions) != 0 || !probe.probed {
		t.Fatal("a conflicting hash reached identity preparation or the node")
	}
	if wireReason(ReasonTransactionConflict) != ReasonWireGenericDenied || wireReason(ReasonPoolRejected) != ReasonWireGenericDenied {
		t.Fatal("conflict reasons must stay collapsed on the wire")
	}
}

type conflictingService struct {
	*nodeRPCService
	probed bool
}

func (c *conflictingService) BindingConflicts(context.Context, []byte, string, string, string) (bool, error) {
	c.probed = true
	return true, nil
}

func hexBoot(id uuid.UUID) string {
	b, _ := id.MarshalBinary()
	return hex.EncodeToString(b)
}

// steppingClock is an issuing clock whose fact version and time the test
// moves (a database clock step back is the only way two envelopes of one
// principal become incomparable, §4.8.3).
type steppingClock struct {
	mu      sync.Mutex
	version uint64
	at      int64
	reads   int
	// after, when set, replaces version/at from the given read on.
	afterRead int
	afterAt   int64
}

func (c *steppingClock) NodePolicyVersion(context.Context) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version, nil
}

func (c *steppingClock) NodePolicyClock(context.Context) (uint64, time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
	if c.afterRead > 0 && c.reads >= c.afterRead {
		c.at = c.afterAt
	}
	return c.version, time.Unix(c.at, 0), nil
}

func (c *steppingClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Unix(c.at, 0)
}

func (c *steppingClock) set(version uint64, at int64, afterRead int, afterAt int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.version, c.at, c.reads, c.afterRead, c.afterAt = version, at, 0, afterRead, afterAt
}

// The request-path half of G34 (B3b leftover): an attempt neither envelope
// of which dominates the other (higher floor, earlier expiry after a database
// clock step back) is signed again at the current clock, at most twice; a
// re-signed envelope that dominates is recorded and sent once; one that stays
// incomparable is refused as unavailable with nothing sent and the stored
// generation unchanged.
func TestRequestPathResignsIncomparableEnvelope(t *testing.T) {
	for _, recovers := range []bool{true, false} {
		name := "clock_recovers"
		if !recovers {
			name = "clock_stays_behind"
		}
		t.Run(name, func(t *testing.T) {
			bridge, node, tracking := newBridgeFixture(t)
			clock := &steppingClock{}
			bridge.source, bridge.now = clock, clock.now
			principal, org := uuid.NewString(), uuid.NewString()
			tx := newSignedTransfer(t, 0)
			request := NodeExecutionIdentityRequest{Scope: "transaction", PrincipalID: principal, OrgID: org, Signer: tx.signer, BindingHash: tx.hash}
			clock.set(7, 1021, 0, 0)
			first, err := bridge.PrepareIdentity(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := bridge.SubmitTransaction(context.Background(), first, tx.raw, NodeSubmissionMetadata{}); err != nil {
				t.Fatal(err)
			}
			// The database clock steps back one second while the fact version
			// rises (and the node applies it): (8, 1020+TTL) against the stored
			// (7, 1021+TTL).
			afterAt := int64(1020)
			if recovers {
				afterAt = 1022 // the re-sign reads a clock past the stored expiry
			}
			node.status.Version = 8
			clock.set(8, 1020, 2, afterAt)
			second, err := bridge.PrepareIdentity(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			calls := node.calls.Load()
			_, err = bridge.SubmitTransaction(context.Background(), second, tx.raw, NodeSubmissionMetadata{})
			row, lookupErr := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, tx.hash))
			if lookupErr != nil {
				t.Fatal(lookupErr)
			}
			if recovers {
				if err != nil || node.calls.Load() != calls+1 {
					t.Fatalf("re-signed attempt: err=%v sends=%d", err, node.calls.Load()-calls)
				}
				if row.Generation != 2 || row.MinVersion != 8 || row.ContextID.String() == identityContextID(first) || row.ContextID.String() == identityContextID(second) {
					t.Fatalf("the re-signed envelope is not the current generation: %+v", row)
				}
				return
			}
			if !errors.Is(err, nodepolicy.ErrNodeUnavailable) || node.calls.Load() != calls {
				t.Fatalf("an envelope that stays incomparable: err=%v sends=%d", err, node.calls.Load()-calls)
			}
			if clock.reads < 3 {
				t.Fatalf("re-signed %d times, want 2", clock.reads-1)
			}
			if row.Generation != 1 || row.MinVersion != 7 || row.ContextID.String() != identityContextID(first) {
				t.Fatalf("the stored generation changed: %+v", row)
			}
		})
	}
}

// G25 (request path): admission is held to the pending-work limits before
// anything is sent — a principal over its own cap gets 429, everyone over the
// global limit 503, both with Retry-After — while a retry of a hash that is
// already charged is never refused and is sent again.
func TestPendingWorkLimitBackpressuresBeforeRenewalDebt(t *testing.T) {
	bridge, node, tracking := newBridgeFixture(t)
	bridge.tracking.limits = db.TrackLimits{Global: 3, Principal: 2}
	org := uuid.NewString()
	busy, other := uuid.NewString(), uuid.NewString()
	var admitted []signedTransfer
	for i := 0; i < 2; i++ {
		tx := newSignedTransfer(t, 0)
		if _, err := tx.submit(t, bridge, busy, org); err != nil {
			t.Fatal(err)
		}
		admitted = append(admitted, tx)
	}
	calls := node.calls.Load()
	over := newSignedTransfer(t, 0)
	if _, err := over.submit(t, bridge, busy, org); !errors.Is(err, errPrincipalPendingLimit) {
		t.Fatalf("a principal over its own cap: %v", err)
	}
	if node.calls.Load() != calls {
		t.Fatal("a refused admission was sent")
	}
	if _, err := tracking.runtime.LookupTracked(context.Background(), hashBytes(t, over.hash)); err == nil {
		t.Fatal("a refused admission was recorded")
	}
	if _, err := newSignedTransfer(t, 0).submit(t, bridge, other, org); err != nil {
		t.Fatalf("another principal is blocked by the busy one: %v", err)
	}
	if _, err := newSignedTransfer(t, 0).submit(t, bridge, other, org); !errors.Is(err, errPendingLimit) {
		t.Fatalf("over the global limit: %v", err)
	}
	if node.calls.Load() != calls+1 {
		t.Fatal("a refused admission was sent")
	}
	// A retry of an already-charged hash is Δ 0 and never refused.
	if _, err := admitted[0].submit(t, bridge, busy, org); err != nil {
		t.Fatalf("a retry of a charged hash was refused: %v", err)
	}
	if node.calls.Load() != calls+2 {
		t.Fatal("the retry was not sent")
	}
	used, pending, err := tracking.runtime.PendingQuota(context.Background())
	if err != nil || used != 3 || pending != 3 {
		t.Fatalf("quota %d/%d %v", used, pending, err)
	}

	// The answers on the RPC path.
	for _, c := range []struct {
		err    error
		status int
		reason string
	}{
		{errPendingLimit, http.StatusServiceUnavailable, ReasonPendingLimit},
		{errPrincipalPendingLimit, http.StatusTooManyRequests, ReasonPrincipalPendingLimit},
		{errOrgPendingLimit, http.StatusTooManyRequests, ReasonOrgPendingLimit},
	} {
		p, _, service, raw := nodeRPCFixture(t)
		service.executionErr = c.err
		got := p.Process(context.Background(), nodeRPCRequest(t, "eth_sendRawTransaction", []any{raw}))
		if got.Error == nil || got.Error.StatusCode != c.status || got.Error.Reason != c.reason || got.Error.RetryAfter != 1 {
			t.Fatalf("%v answered %+v", c.err, got.Error)
		}
		if wireReason(c.reason) != c.reason {
			t.Fatalf("%s must reach a verbose caller: it describes the caller's own request", c.reason)
		}
	}
}

// outcomeTracking answers every admission with a fixed outcome.
type outcomeTracking struct {
	trackingStore
	outcome db.AdmitOutcome
}

func (o outcomeTracking) AdmitBatch(_ context.Context, _ uuid.UUID, _ db.TrackLimits, batch []db.TrackAdmission) ([]db.AdmitResult, error) {
	out := make([]db.AdmitResult, len(batch))
	for i := range out {
		out[i] = db.AdmitResult{Outcome: o.outcome}
	}
	return out, nil
}

// Every admission outcome that did not record the transaction is refused
// before transport, including one this release does not know (fail closed).
func TestUnrecordedAdmissionIsNeverSent(t *testing.T) {
	for _, outcome := range []db.AdmitOutcome{db.AdmitOverLimit, db.AdmitPrincipalOverLimit, db.AdmitOrgOverLimit, db.AdmitIncomparable, db.AdmitOutcome(200)} {
		bridge, node, tracking := newBridgeFixture(t)
		bridge.tracking.store = outcomeTracking{trackingStore: tracking.runtime, outcome: outcome}
		if _, err := newSignedTransfer(t, 0).submit(t, bridge, uuid.NewString(), uuid.NewString()); err == nil {
			t.Fatalf("outcome %d accepted", outcome)
		}
		if node.calls.Load() != 0 {
			t.Fatalf("outcome %d: an unrecorded transaction was sent", outcome)
		}
	}
}
