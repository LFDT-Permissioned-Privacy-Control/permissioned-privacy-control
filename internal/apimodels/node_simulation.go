package apimodels

type NodeSimulationRequest struct {
	PrincipalID         string `json:"principalId,omitempty"`
	CandidateRevisionID string `json:"candidateRevisionId,omitempty"`
	Method              string `json:"method"`
	Params              []any  `json:"params"`
	DryRun              bool   `json:"dryRun"`
}

// NodeOwnershipRecoveryRequest names a finalized deployment transaction.
type NodeOwnershipRecoveryRequest struct {
	TransactionHash string `json:"transactionHash"`
}

// NodeOwnershipRecoveryResponse reports the contracts registered from the
// node's finalized evidence.
type NodeOwnershipRecoveryResponse struct {
	TransactionHash string `json:"transactionHash"`
	// Registered: the ownership effect was applied by this call (false when it
	// had already been applied, for example by normal reconciliation).
	Registered bool `json:"registered"`
	// Conflicts counts created addresses another organization already owns;
	// they were not registered.
	Conflicts int `json:"conflicts"`
}
