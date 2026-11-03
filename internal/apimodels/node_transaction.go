package apimodels

import "privacy-proxy/internal/nodepolicy"

// NodeTransactionProgress is the owner's view of a transaction submitted in
// Reth policy mode. Only included, reverted and dropped are final; pending,
// provisional and renewal_stopped can still change.
type NodeTransactionProgress struct {
	TransactionHash string `json:"transaction_hash"`
	ContextID       string `json:"context_id"`
	// Status: pending (waiting for inclusion; OPS keeps it deliverable),
	// provisional (in a block that is not final yet), renewal_stopped (OPS will
	// not renew it; it may still settle), included or reverted (in a finalized
	// block; final), dropped (a finalized transaction used its nonce; final).
	Status    string                       `json:"status" enums:"pending,provisional,renewal_stopped,included,reverted,dropped"`
	Execution *nodepolicy.ExecutionOutcome `json:"execution,omitempty"`
	// Reconciled: the status is final and OPS bookkeeping for it is committed.
	Reconciled bool `json:"reconciled"`
	// ReconciliationNote: why renewal stopped (for example max_age,
	// principal_banned, compliance_denied, nonce_conflict), nonce_consumed for
	// dropped, or effects_not_applied.
	ReconciliationNote string `json:"reconciliation_note,omitempty"`
}
