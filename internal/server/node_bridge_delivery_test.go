package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
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
