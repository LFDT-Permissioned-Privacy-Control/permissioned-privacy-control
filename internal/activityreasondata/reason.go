// Package activityreasondata defines bounded recorded diagnostics only. Codes
// confer no permission and carry no arbitrary error text or request data.
package activityreasondata

type Code string

const (
	NotRecorded              Code = "not_recorded"
	InvalidRequestShape      Code = "invalid_request_shape"
	AuthRequired             Code = "auth_required"
	CredentialsExpired       Code = "credentials_expired"
	MethodNotAllowed         Code = "method_not_allowed"
	SenderNotLinked          Code = "sender_not_linked"
	AccessDenied             Code = "access_denied"
	ComplianceBlocked        Code = "compliance_blocked"
	DeployClaimRequired      Code = "deploy_claim_required"
	TraceAccessDenied        Code = "trace_access_denied"
	ExecutionUnavailable     Code = "execution_unavailable"
	TracingUnavailable       Code = "tracing_unavailable"
	RequestCancelled         Code = "request_cancelled"
	SubmissionOutcomeUnknown Code = "submission_outcome_unknown"
	PolicyNoMatchingRule     Code = "policy_no_matching_rule"
	PolicyArgumentConstraint Code = "policy_argument_constraint"
	PolicyMalformedCalldata  Code = "policy_malformed_calldata"
	PolicyOwnership          Code = "policy_ownership"
	PolicyValueConstraint    Code = "policy_value_constraint"
	PolicyDepthConstraint    Code = "policy_depth_constraint"
	PolicyUnsupportedCreate  Code = "policy_unsupported_create"
	PolicyCallerConstraint   Code = "policy_caller_constraint"
	PolicyOperationalClaim   Code = "policy_operational_claim"
	PolicyNoFramesObserved   Code = "policy_no_frames_observed"
	PolicyInvalidContext     Code = "policy_invalid_context"
	PolicyInvalidFacts       Code = "policy_invalid_facts"
)

func classifiedOutcome(code Code) string {
	switch code {
	case InvalidRequestShape:
		return "invalid"
	case AuthRequired, CredentialsExpired:
		return "unauthenticated"
	case MethodNotAllowed, SenderNotLinked, AccessDenied, ComplianceBlocked, DeployClaimRequired, TraceAccessDenied,
		PolicyNoMatchingRule, PolicyArgumentConstraint, PolicyMalformedCalldata, PolicyOwnership, PolicyValueConstraint,
		PolicyDepthConstraint, PolicyUnsupportedCreate, PolicyCallerConstraint, PolicyOperationalClaim:
		return "denied"
	case ExecutionUnavailable, TracingUnavailable, RequestCancelled:
		return "unavailable"
	case SubmissionOutcomeUnknown:
		return "unconfirmed"
	case PolicyNoFramesObserved, PolicyInvalidContext, PolicyInvalidFacts:
		return "evaluation-failed"
	default:
		return ""
	}
}

// Known rejects the zero value and every unclassified/prefix-like string.
func Known(code Code) bool { return code == NotRecorded || classifiedOutcome(code) != "" }

// AllowedOutcome validates the recorded pair. Empty trusted input is normalized
// by the recorder, never accepted in a durable v2 payload. Success has no named
// diagnostic; not_recorded remains valid for all seven completion outcomes.
func AllowedOutcome(code Code, outcome string) bool {
	switch outcome {
	case "success", "invalid", "unauthenticated", "denied", "evaluation-failed", "unavailable", "unconfirmed":
		return code == NotRecorded || classifiedOutcome(code) == outcome
	default:
		return false
	}
}
