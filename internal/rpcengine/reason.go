package rpcengine

import (
	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/policycore"
)

// Recorded reasons are private diagnostics from the selected trusted branch.
// They never change an ordinary RPC response or supply permission authority.
func capturedReason(why []activityreasondata.Code) activityreasondata.Code {
	if len(why) == 1 {
		return why[0]
	}
	return ""
}

func validCapturedReason(class CompletionClass, why activityreasondata.Code) bool {
	if why == "" {
		return true // unclassified trusted input; recorder writes not_recorded
	}
	var outcome string
	switch class {
	case InvalidCompletion:
		outcome = "invalid"
	case UnauthenticatedCompletion:
		outcome = "unauthenticated"
	case DeniedCompletion:
		outcome = "denied"
	case EvaluationFailedCompletion:
		outcome = "evaluation-failed"
	case UnavailableCompletion:
		outcome = "unavailable"
	case UnconfirmedCompletion:
		outcome = "unconfirmed"
	case SuccessfulCompletion:
		outcome = "success"
	}
	return activityreasondata.AllowedOutcome(why, outcome)
}

func policyReason(d policycore.Decision) activityreasondata.Code {
	if d.Allowed {
		return ""
	}
	switch d.Code {
	case policycore.DenialNoMatchingRule:
		return activityreasondata.PolicyNoMatchingRule
	case policycore.DenialArgumentConstraint:
		return activityreasondata.PolicyArgumentConstraint
	case policycore.DenialMalformedCalldata:
		return activityreasondata.PolicyMalformedCalldata
	case policycore.DenialNoFrames:
		return activityreasondata.PolicyNoFramesObserved
	case policycore.DenialInvalidContext:
		return activityreasondata.PolicyInvalidContext
	case policycore.DenialOwnership:
		return activityreasondata.PolicyOwnership
	case policycore.DenialValue:
		return activityreasondata.PolicyValueConstraint
	case policycore.DenialDepth:
		return activityreasondata.PolicyDepthConstraint
	case policycore.DenialUnsupportedCreate:
		return activityreasondata.PolicyUnsupportedCreate
	case policycore.DenialCaller:
		return activityreasondata.PolicyCallerConstraint
	case policycore.DenialOperationalClaim:
		return activityreasondata.PolicyOperationalClaim
	case policycore.DenialInvalidFacts:
		return activityreasondata.PolicyInvalidFacts
	}
	return ""
}

func (r *OperationResult) decision(d policycore.Decision) {
	if r != nil {
		r.class(nativeClass(d))
		r.metadata.Reason = policyReason(d)
	}
}

// A few retained profiles deliberately use a coarser completion class. Keep
// that existing class and omit a diagnostic whose typed pair would conflict.
func compatiblePolicyReason(d policycore.Decision, class CompletionClass) activityreasondata.Code {
	why := policyReason(d)
	if validCapturedReason(class, why) {
		return why
	}
	return ""
}
