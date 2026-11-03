package nodepolicy

import (
	"context"
	"encoding/json"
)

type CreatedContract struct {
	Address     string `json:"address"`
	OrgID       string `json:"org_id"`
	PrincipalID string `json:"principal_id"`
}
type ExecutionOutcome struct {
	Status               string            `json:"status"`
	FactsVersion         uint64            `json:"facts_version"`
	BlockHash            *string           `json:"block_hash"`
	BlockNumber          *uint64           `json:"block_number"`
	Finalized            bool              `json:"finalized"`
	FinalizedBlockHash   *string           `json:"finalized_block_hash"`
	FinalizedBlockNumber *uint64           `json:"finalized_block_number"`
	ReasonCode           string            `json:"reason_code"`
	Created              []CreatedContract `json:"created"`
}
type TransactionStatus struct {
	TransactionHash string           `json:"transaction_hash"`
	PrincipalID     string           `json:"principal_id"`
	OrgID           string           `json:"org_id"`
	ContextID       string           `json:"context_id"`
	Execution       ExecutionOutcome `json:"execution"`
	BootID          string           `json:"boot_id"`
}

func (c *Client) TransactionStatus(ctx context.Context, hash string) (TransactionStatus, error) {
	if !hexField(hash, 32) {
		return TransactionStatus{}, ErrIdentity
	}
	raw, err := c.call(ctx, "ops_transactionStatus", []any{hash})
	if err != nil {
		return TransactionStatus{}, err
	}
	var status TransactionStatus
	if err := decodeStrict(raw, &status); err != nil {
		return TransactionStatus{}, ErrNodeResponse
	}
	if status.TransactionHash != hash || !identifier(status.PrincipalID) || !identifier(status.OrgID) || !identifier(status.ContextID) || !ValidBootID(status.BootID) {
		return TransactionStatus{}, ErrNodeResponse
	}
	if err := status.Validate(); err != nil {
		return TransactionStatus{}, err
	}
	return status, nil
}

func (status TransactionStatus) Validate() error {
	if !hexField(status.TransactionHash, 32) || !identifier(status.PrincipalID) || !identifier(status.OrgID) || !identifier(status.ContextID) {
		return ErrNodeResponse
	}
	outcome := status.Execution
	if (outcome.FinalizedBlockHash == nil) != (outcome.FinalizedBlockNumber == nil) || (outcome.FinalizedBlockHash != nil && !hexField(*outcome.FinalizedBlockHash, 32)) {
		return ErrNodeResponse
	}
	if outcome.Created == nil || len(outcome.Created) > 128 || len(outcome.ReasonCode) > 128 {
		return ErrNodeResponse
	}
	switch outcome.Status {
	case "included", "reverted":
		if outcome.BlockHash == nil || !hexField(*outcome.BlockHash, 32) || outcome.BlockNumber == nil || outcome.FactsVersion == 0 {
			return ErrNodeResponse
		}
		if outcome.Status == "reverted" && len(outcome.Created) > 0 {
			return ErrNodeResponse
		}
		if outcome.Finalized && (outcome.FinalizedBlockNumber == nil || *outcome.FinalizedBlockNumber < *outcome.BlockNumber || (*outcome.FinalizedBlockNumber == *outcome.BlockNumber && *outcome.FinalizedBlockHash != *outcome.BlockHash)) {
			return ErrNodeResponse
		}
	case "pending", "denied", "expired":
		if outcome.Finalized || outcome.BlockHash != nil || outcome.BlockNumber != nil || len(outcome.Created) > 0 {
			return ErrNodeResponse
		}
	default:
		return ErrNodeResponse
	}
	seen := map[string]bool{}
	for _, created := range outcome.Created {
		if !hexField(created.Address, 20) || created.OrgID != status.OrgID || created.PrincipalID != status.PrincipalID || seen[created.Address] {
			return ErrNodeResponse
		}
		seen[created.Address] = true
	}
	return nil
}

// MaxStatusBatch bounds one ops_transactionStatuses call.
const MaxStatusBatch = 256

// FinalizedHead is the node's effective finalized block (final and written).
type FinalizedHead struct {
	Number    uint64 `json:"number"`
	Hash      string `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

// BatchedStatus is one entry of a batched status answer: the single-call
// status (with the batch's boot id) and, for a transaction not included,
// whether the node's pool holds it.
type BatchedStatus struct {
	Status TransactionStatus
	Pooled bool
}

// TransactionStatusBatch is the answer of ops_transactionStatuses: one entry
// per requested hash in request order, nil for a hash the node does not know.
type TransactionStatusBatch struct {
	BootID         string
	Finalized      *FinalizedHead
	CanonicalEpoch uint64
	Statuses       []*BatchedStatus
}

type batchEntryWire struct {
	TransactionHash string           `json:"transaction_hash"`
	PrincipalID     string           `json:"principal_id"`
	OrgID           string           `json:"org_id"`
	ContextID       string           `json:"context_id"`
	Execution       ExecutionOutcome `json:"execution"`
	Pooled          bool             `json:"pooled"`
}

type batchWire struct {
	BootID         string          `json:"boot_id"`
	Finalized      *FinalizedHead  `json:"finalized"`
	CanonicalEpoch uint64          `json:"canonical_epoch"`
	Statuses       json.RawMessage `json:"statuses"` // entries may be null
}

// TransactionStatuses polls up to MaxStatusBatch hashes in one call (plan
// §4.5 option A). Call it only for a node that advertises
// CapabilityTransactionStatuses. Every entry is validated like a single
// answer and must name the hash requested at its position.
func (c *Client) TransactionStatuses(ctx context.Context, hashes []string) (TransactionStatusBatch, error) {
	if len(hashes) == 0 || len(hashes) > MaxStatusBatch {
		return TransactionStatusBatch{}, ErrIdentity
	}
	for _, hash := range hashes {
		if !hexField(hash, 32) {
			return TransactionStatusBatch{}, ErrIdentity
		}
	}
	raw, err := c.call(ctx, "ops_transactionStatuses", []any{hashes})
	if err != nil {
		return TransactionStatusBatch{}, err
	}
	var wire batchWire
	var entries []json.RawMessage
	if err := decodeStrict(raw, &wire); err != nil || !ValidBootID(wire.BootID) || json.Unmarshal(wire.Statuses, &entries) != nil || len(entries) != len(hashes) {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	if f := wire.Finalized; f != nil && (!hexField(f.Hash, 32) || f.Timestamp <= 0) {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	out := TransactionStatusBatch{BootID: wire.BootID, Finalized: wire.Finalized, CanonicalEpoch: wire.CanonicalEpoch, Statuses: make([]*BatchedStatus, len(hashes))}
	for i, entry := range entries {
		if string(entry) == "null" {
			continue
		}
		var e batchEntryWire
		if err := decodeStrict(entry, &e); err != nil || e.TransactionHash != hashes[i] {
			return TransactionStatusBatch{}, ErrNodeResponse
		}
		status := TransactionStatus{TransactionHash: e.TransactionHash, PrincipalID: e.PrincipalID, OrgID: e.OrgID, ContextID: e.ContextID, Execution: e.Execution, BootID: wire.BootID}
		if err := status.Validate(); err != nil {
			return TransactionStatusBatch{}, err
		}
		if e.Pooled && status.Execution.Status != "pending" && status.Execution.Status != "denied" && status.Execution.Status != "expired" {
			return TransactionStatusBatch{}, ErrNodeResponse
		}
		out.Statuses[i] = &BatchedStatus{Status: status, Pooled: e.Pooled}
	}
	return out, nil
}
