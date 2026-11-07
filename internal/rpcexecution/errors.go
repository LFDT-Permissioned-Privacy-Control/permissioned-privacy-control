// Package rpcexecution acquires one bounded, anchored execution from a trusted
// node. Node honesty and fork qualification are explicit deployment inputs.
package rpcexecution

type ErrorCode string

const (
	InvalidCall         ErrorCode = "invalid_call"
	InvalidBinding      ErrorCode = "invalid_node_binding"
	NodeFailure         ErrorCode = "node_unavailable"
	InvalidEvidence     ErrorCode = "invalid_execution_evidence"
	UnsupportedEvidence ErrorCode = "unsupported_execution_evidence"
	EvidenceLimit       ErrorCode = "execution_evidence_limit"
	RootScopeDenied     ErrorCode = "root_scope_denied"
)

// Error carries only a stable safe category, never node text or credentials.
type Error struct{ Code ErrorCode }

func (e *Error) Error() string     { return string(e.Code) }
func failure(code ErrorCode) error { return &Error{Code: code} }
