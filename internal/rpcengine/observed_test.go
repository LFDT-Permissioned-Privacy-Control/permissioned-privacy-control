package rpcengine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"privacy-proxy/internal/policycore"
)

func TestObservedClosedClassificationAndOwnedMetadata(t *testing.T) {
	for _, code := range []policycore.DenialCode{policycore.DenialInvalidFacts, policycore.DenialInvalidContext, policycore.DenialNoFrames, "", "future"} {
		if nativeClass(policycore.Decision{Code: code}) != EvaluationFailedCompletion {
			t.Fatal("invalid evidence is ordinary denial", code)
		}
	}
	for _, code := range []policycore.DenialCode{policycore.DenialNoMatchingRule, policycore.DenialOwnership, policycore.DenialValue, policycore.DenialArgumentConstraint, policycore.DenialMalformedCalldata, policycore.DenialCaller, policycore.DenialDepth, policycore.DenialUnsupportedCreate, policycore.DenialOperationalClaim} {
		if nativeClass(policycore.Decision{Code: code}) != DeniedCompletion {
			t.Fatal("ordinary denial changed", code)
		}
	}
	if nativeClass(policycore.Decision{Allowed: true}) != SuccessfulCompletion || nativeClass(policycore.Decision{Allowed: true, Code: policycore.DenialOwnership}) != EvaluationFailedCompletion {
		t.Fatal("contradictory decision allowed")
	}
	e, other := &Engine{}, &Engine{}
	r := e.CallObserved(context.Background(), "", "", []byte(`{"method":"other"}`))
	m, err := r.MetadataFor(e)
	if err != nil || m.Class != InvalidCompletion || m.Method != InvalidRPCRequest || m.ActorID != "" || m.RPCErrorCode == nil || *m.RPCErrorCode != -32600 {
		t.Fatal(m, err)
	}
	*m.RPCErrorCode = 0
	again, _ := r.MetadataFor(e)
	if *again.RPCErrorCode != -32600 {
		t.Fatal("mutable error metadata")
	}
	if _, err := r.MetadataFor(other); err == nil {
		t.Fatal("foreign result accepted")
	}
	if _, err := r.MarshalResponseFor(other); err == nil {
		t.Fatal("foreign output accepted")
	}
	if _, err := r.MarshalRecordingFailureFor(other); err == nil {
		t.Fatal("foreign fallback accepted")
	}
	if err := r.RequireDeliverable(context.Background(), e); err == nil {
		t.Fatal("unmounted engine deliverable")
	}
}

func TestObservedSealedPreflightCanonicalIDAndClosedData(t *testing.T) {
	e := &Engine{}
	// The strict parser legitimately expands each literal '<' to six JSON bytes.
	input := `{"jsonrpc":"2.0","id":"` + strings.Repeat("<", MaxRequestBytes-200) + `","method":"unsupported","params":[]}`
	r := e.CallObserved(context.Background(), "", "", []byte(input))
	if len(r.response.ID) < 5<<20 || r.PreflightFor(e) != nil {
		t.Fatal("legitimate expanded ID rejected", len(r.response.ID))
	}
	b, err := r.MarshalResponseFor(e)
	if err != nil || len(b) > MaxObservedResponseBytes || !json.Valid(b) {
		t.Fatal(len(b), err)
	}
	// Marshal uses sealed ID directly; no public detached Response/ID exists.
	r.response.Error.Data = map[string]any{"arbitrary": strings.Repeat("x", 1024)}
	if r.PreflightFor(e) == nil {
		t.Fatal("unknown Data branch accepted")
	}
	r.response.Error.Data = strings.Repeat("a", MaxObservedResponseBytes)
	if r.PreflightFor(e) == nil {
		t.Fatal("oversized scalar accepted")
	}
	r.response.Error.Data = nil
	r.phase = broadcastEffect
	r.signedHash = "0x" + strings.Repeat("a", 64)
	fallback, err := r.MarshalRecordingFailureFor(e)
	if err != nil || !strings.Contains(string(fallback), `"code":-32004`) || !strings.Contains(string(fallback), r.signedHash) {
		t.Fatal("uncertain submission lost original hash", err)
	}
	r.phase = admissionEffect
	fallback, err = r.MarshalRecordingFailureFor(e)
	if err != nil || strings.Contains(string(fallback), "transactionHash") {
		t.Fatal("claimed broadcast before attempt", err)
	}
}

func TestObservedRawCanonicalIDAndNoProtectedUnauthenticatedBranch(t *testing.T) {
	e := &Engine{}
	input := `{"jsonrpc":"2.0","id":"` + strings.Repeat("<", MaxRawRequestBytes-200) + `","method":"unsupported","params":[]}`
	r := e.SubmitRawObserved(context.Background(), "", "", []byte(input))
	if len(r.response.ID) < 11<<20 || r.PreflightFor(e) != nil {
		t.Fatal("near-limit canonical raw ID", len(r.response.ID))
	}
	raw, err := r.MarshalResponseFor(e)
	if err != nil || len(raw) > MaxObservedResponseBytes {
		t.Fatal(err, len(raw))
	}
	r.response.Error.Code = 3
	r.response.Error.Message = "execution reverted"
	r.response.Error.Data = "0xdead"
	if r.PreflightFor(e) == nil {
		t.Fatal("protected Data allowed without original View")
	}
}

func TestObservedFinishPreservesSelectedBroadcastOutcome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, class := range []CompletionClass{SuccessfulCompletion, UnconfirmedCompletion} {
		r := &OperationResult{owner: &Engine{}, phase: broadcastEffect, metadata: OperationMetadata{Class: class}}
		out := responseError(nil, -32004, "submission outcome unknown")
		if class == SuccessfulCompletion {
			value := "0x"
			out = Response{JSONRPC: "2.0", ID: json.RawMessage("null"), Result: &value}
		}
		r.finish(ctx, out)
		if r.metadata.Class != class {
			t.Fatal("post-broadcast result rewritten", class, r.metadata.Class)
		}
		if r.RequireDeliverable(ctx, r.owner) == nil {
			t.Fatal("cancelled protected delivery permitted")
		}
	}
	r := &OperationResult{metadata: OperationMetadata{Class: DeniedCompletion}}
	r.finish(ctx, responseError(nil, -32001, "not authorized"))
	if r.metadata.Class != UnavailableCompletion {
		t.Fatal("pre-effect cancellation priority changed")
	}
}
