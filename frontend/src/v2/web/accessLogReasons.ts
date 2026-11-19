const reasons = {
  not_recorded: ['Not recorded', null],
  invalid_request_shape: ['Invalid request shape', 'invalid'],
  auth_required: ['Authentication required', 'unauthenticated'],
  credentials_expired: ['Credentials expired', 'unauthenticated'],
  method_not_allowed: ['Method not allowed', 'denied'],
  sender_not_linked: ['Wallet not linked', 'denied'],
  access_denied: ['Access denied', 'denied'],
  compliance_blocked: ['Compliance blocked', 'denied'],
  deploy_claim_required: ['Deploy claim required', 'denied'],
  trace_access_denied: ['Trace access denied', 'denied'],
  execution_unavailable: ['Execution unavailable', 'unavailable'],
  tracing_unavailable: ['Tracing unavailable', 'unavailable'],
  request_cancelled: ['Request cancelled', 'unavailable'],
  submission_outcome_unknown: ['Submission outcome unknown', 'unconfirmed'],
  policy_no_matching_rule: ['No matching policy rule', 'denied'],
  policy_argument_constraint: ['Argument rule not satisfied', 'denied'],
  policy_malformed_calldata: ['Malformed call data', 'denied'],
  policy_ownership: ['Ownership rule not satisfied', 'denied'],
  policy_value_constraint: ['Value rule not satisfied', 'denied'],
  policy_depth_constraint: ['Call depth rule not satisfied', 'denied'],
  policy_unsupported_create: ['Unsupported contract creation', 'denied'],
  policy_caller_constraint: ['Caller rule not satisfied', 'denied'],
  policy_operational_claim: ['Required operational claim missing', 'denied'],
  policy_no_frames_observed: ['Execution frames unavailable', 'evaluation-failed'],
  policy_invalid_context: ['Invalid evaluation context', 'evaluation-failed'],
  policy_invalid_facts: ['Invalid execution evidence', 'evaluation-failed'],
} as const

export type AccessLogReason = keyof typeof reasons
const outcomes = ['success', 'invalid', 'unauthenticated', 'denied', 'evaluation-failed', 'unavailable', 'unconfirmed']
export function validReasonOutcome(value: unknown, outcome: string): value is AccessLogReason {
  if (typeof value !== 'string' || !Object.prototype.hasOwnProperty.call(reasons, value) || !outcomes.includes(outcome)) return false
  const expected = reasons[value as AccessLogReason][1]
  return expected === null || expected === outcome
}
export function logReasonLabel(value: AccessLogReason): string { return reasons[value][0] }
