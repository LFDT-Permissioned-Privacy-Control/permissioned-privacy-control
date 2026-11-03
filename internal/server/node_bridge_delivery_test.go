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
