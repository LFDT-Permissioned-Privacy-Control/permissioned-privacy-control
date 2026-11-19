package activityreasondata

import "testing"

func TestClosedRecordedReasonOutcomeContract(t *testing.T) {
	outcomes := []string{"success", "invalid", "unauthenticated", "denied", "evaluation-failed", "unavailable", "unconfirmed"}
	groups := map[string][]Code{
		"invalid":           {InvalidRequestShape},
		"unauthenticated":   {AuthRequired, CredentialsExpired},
		"denied":            {MethodNotAllowed, SenderNotLinked, AccessDenied, ComplianceBlocked, DeployClaimRequired, TraceAccessDenied, PolicyNoMatchingRule, PolicyArgumentConstraint, PolicyMalformedCalldata, PolicyOwnership, PolicyValueConstraint, PolicyDepthConstraint, PolicyUnsupportedCreate, PolicyCallerConstraint, PolicyOperationalClaim},
		"unavailable":       {ExecutionUnavailable, TracingUnavailable, RequestCancelled},
		"unconfirmed":       {SubmissionOutcomeUnknown},
		"evaluation-failed": {PolicyNoFramesObserved, PolicyInvalidContext, PolicyInvalidFacts},
	}
	for expected, codes := range groups {
		for _, code := range codes {
			if !Known(code) || len(code) > 64 {
				t.Fatal("missing or unbounded compiled code", code)
			}
			for _, outcome := range outcomes {
				if AllowedOutcome(code, outcome) != (outcome == expected) {
					t.Fatal("reason/outcome mismatch accepted", code, outcome)
				}
			}
		}
	}
	for _, outcome := range outcomes {
		if !Known(NotRecorded) || !AllowedOutcome(NotRecorded, outcome) {
			t.Fatal("unclassified completion rejected", outcome)
		}
	}
	for _, code := range []Code{"", "policy_unknown", "sender_not_linked\nprivate", "cross_org", "rate_limited", "state_override_not_allowed"} {
		if Known(code) {
			t.Fatal("unknown diagnostic accepted", code)
		}
		for _, outcome := range outcomes {
			if AllowedOutcome(code, outcome) {
				t.Fatal("unknown diagnostic/outcome accepted", code, outcome)
			}
		}
	}
	if AllowedOutcome(NotRecorded, "future") || AllowedOutcome(NotRecorded, "") {
		t.Fatal("unknown outcome accepted")
	}
}
