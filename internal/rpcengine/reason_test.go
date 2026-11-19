package rpcengine

import (
	"context"
	"testing"

	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/policycore"
)

func TestRecordedReasonsKeepPolicyCodesClosedAndFinalOutcomePrecedence(t *testing.T) {
	for _, code := range []policycore.DenialCode{policycore.DenialNoMatchingRule, policycore.DenialArgumentConstraint, policycore.DenialMalformedCalldata, policycore.DenialOwnership, policycore.DenialValue, policycore.DenialDepth, policycore.DenialUnsupportedCreate, policycore.DenialCaller, policycore.DenialOperationalClaim, policycore.DenialNoFrames, policycore.DenialInvalidContext, policycore.DenialInvalidFacts} {
		d := policycore.Decision{Code: code, Reason: "private frame, address and policy text"}
		if got := policyReason(d); !activityreasondata.Known(got) || !validCapturedReason(nativeClass(d), got) {
			t.Fatal("known decision lost exact diagnostic", code, got)
		}
	}
	if policyReason(policycore.Decision{Code: "no_matching_rule:secret"}) != "" || policyReason(policycore.Decision{Allowed: true, Code: policycore.DenialOwnership}) != "" {
		t.Fatal("invented/contradictory policy diagnostic")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, class := range []CompletionClass{SuccessfulCompletion, UnconfirmedCompletion} {
		why := activityreasondata.Code("")
		if class == UnconfirmedCompletion {
			why = activityreasondata.SubmissionOutcomeUnknown
		}
		r := &OperationResult{owner: &Engine{}, phase: broadcastEffect, metadata: OperationMetadata{Class: class, Reason: why}}
		r.finish(ctx, responseError(nil, -32004, "submission outcome unknown"))
		if r.metadata.Class != class || r.metadata.Reason != why {
			t.Fatal("cancellation rewrote the selected broadcast outcome", r.metadata)
		}
	}
	r := &OperationResult{owner: &Engine{}, metadata: OperationMetadata{Class: DeniedCompletion, Reason: activityreasondata.SenderNotLinked}}
	r.finish(ctx, denied(nil))
	if r.metadata.Class != UnavailableCompletion || r.metadata.Reason != activityreasondata.RequestCancelled {
		t.Fatal("stale reason survived cancellation", r.metadata)
	}
	r.metadata.Class, r.metadata.Reason = SuccessfulCompletion, activityreasondata.MethodNotAllowed
	if _, err := r.MetadataFor(r.owner); err == nil {
		t.Fatal("owned metadata accepted an inconsistent named reason")
	}
	r.metadata.Class, r.metadata.Reason = DeniedCompletion, activityreasondata.Code("raw private error")
	if _, err := r.MetadataFor(r.owner); err == nil {
		t.Fatal("owned metadata accepted arbitrary text")
	}
}
