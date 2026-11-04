package nodepolicy

import (
	"context"
	"encoding/json"
	"fmt"
)

// ErrInvalidStatus: the node's answer for one transaction is not a valid
// status (it wraps ErrNodeResponse). In a batched answer it is that entry's
// error only; the other entries stand.
var ErrInvalidStatus = fmt.Errorf("%w: invalid transaction status", ErrNodeResponse)

// MaxCreatedContracts bounds the contracts one transaction's status may
// report. It is the node's own bound: the node evaluates at most MAX_CHECKS
// (128) policy-checked frames per transaction, calls and creates together,
// and refuses the whole transaction at the next one, so an included
// transaction never created more (node/reth/src/policy.rs; pinned by
// TestCreatedContractsBoundIsTheNodesFrameLimit). A longer list is a protocol
// violation, never truncated.
const MaxCreatedContracts = 128

// maxBlockNumber is the largest block number OPS stores (BIGINT).
const maxBlockNumber = 1<<63 - 1

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
	if !ValidBootID(status.BootID) {
		return TransactionStatus{}, ErrNodeResponse
	}
	if status.TransactionHash != hash {
		return TransactionStatus{}, ErrInvalidStatus
	}
	if err := status.Validate(); err != nil {
		return TransactionStatus{}, err
	}
	return status, nil
}

// Validate checks one status answer; a failure is ErrInvalidStatus.
func (status TransactionStatus) Validate() error {
	if !hexField(status.TransactionHash, 32) || !identifier(status.PrincipalID) || !identifier(status.OrgID) || !identifier(status.ContextID) {
		return ErrInvalidStatus
	}
	outcome := status.Execution
	if (outcome.FinalizedBlockHash == nil) != (outcome.FinalizedBlockNumber == nil) || (outcome.FinalizedBlockHash != nil && !hexField(*outcome.FinalizedBlockHash, 32)) {
		return ErrInvalidStatus
	}
	// Block numbers are stored as BIGINT: a larger one would fail the whole
	// batch it is written in, so it is this answer's fault alone.
	if (outcome.BlockNumber != nil && *outcome.BlockNumber > maxBlockNumber) || (outcome.FinalizedBlockNumber != nil && *outcome.FinalizedBlockNumber > maxBlockNumber) {
		return ErrInvalidStatus
	}
	if outcome.Created == nil || len(outcome.Created) > MaxCreatedContracts || len(outcome.ReasonCode) > 128 {
		return ErrInvalidStatus
	}
	switch outcome.Status {
	case "included", "reverted":
		if outcome.BlockHash == nil || !hexField(*outcome.BlockHash, 32) || outcome.BlockNumber == nil || outcome.FactsVersion == 0 {
			return ErrInvalidStatus
		}
		if outcome.Status == "reverted" && len(outcome.Created) > 0 {
			return ErrInvalidStatus
		}
		if outcome.Finalized && (outcome.FinalizedBlockNumber == nil || *outcome.FinalizedBlockNumber < *outcome.BlockNumber || (*outcome.FinalizedBlockNumber == *outcome.BlockNumber && *outcome.FinalizedBlockHash != *outcome.BlockHash)) {
			return ErrInvalidStatus
		}
	case "pending", "denied", "expired":
		if outcome.Finalized || outcome.BlockHash != nil || outcome.BlockNumber != nil || len(outcome.Created) > 0 {
			return ErrInvalidStatus
		}
	default:
		return ErrInvalidStatus
	}
	seen := map[string]bool{}
	for _, created := range outcome.Created {
		if !hexField(created.Address, 20) || created.OrgID != status.OrgID || created.PrincipalID != status.PrincipalID || seen[created.Address] {
			return ErrInvalidStatus
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
// whether the node's pool holds it. Err (ErrInvalidStatus) is set instead
// when the node's entry for this hash was not a valid answer; Status and
// Pooled are then empty, and only this hash is affected.
type BatchedStatus struct {
	Status TransactionStatus
	Pooled bool
	Err    error
}

// TransactionStatusBatch is the answer of ops_transactionStatuses: one entry
// per requested hash in request order. A nil entry is no answer for that hash
// in this call (unknown, a failed lookup, a block that left the chain while
// the answer was prepared, or the node's per-call budget): never evidence of
// absence; an entry with Err is an invalid answer for that hash alone.
// Finalized is nil while finality is unknown or only genesis is final.
type TransactionStatusBatch struct {
	BootID         string
	Finalized      *FinalizedHead
	CanonicalEpoch uint64
	Statuses       []*BatchedStatus
	// With TransactionEvidence only: Receipts[i] reports whether a canonical
	// block holds hash i (nil: the lookup failed); SenderNonces[j] is sender
	// j's account nonce after the Finalized block (nil when Finalized is nil
	// or that state could not be read).
	Receipts     []*bool
	SenderNonces []uint64
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

// evidenceWire is the answer with the senders parameter: two more fields,
// both required (sender_nonces may be null).
type evidenceWire struct {
	batchWire
	Receipts     json.RawMessage  `json:"receipts"`      // entries may be null
	SenderNonces *json.RawMessage `json:"sender_nonces"` // required, may be null
}

// TransactionStatuses polls up to MaxStatusBatch hashes in one call (plan
// §4.5 option A). Call it only for a node that advertises
// CapabilityTransactionStatuses. Every entry is validated like a single
// answer and must name the hash requested at its position.
func (c *Client) TransactionStatuses(ctx context.Context, hashes []string) (TransactionStatusBatch, error) {
	if !validBatch(hashes, 32) {
		return TransactionStatusBatch{}, ErrIdentity
	}
	raw, err := c.call(ctx, "ops_transactionStatuses", []any{hashes})
	if err != nil {
		return TransactionStatusBatch{}, err
	}
	var wire batchWire
	if err := decodeStrict(raw, &wire); err != nil {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	return decodeBatch(wire, hashes)
}

// TransactionEvidence is ops_transactionStatuses with the senders parameter:
// the statuses plus, read at the answer's finalized block, whether a
// canonical block holds each hash and each sender's account nonce (plan
// §4.8.1 dropped evidence, from the private node itself). Senders are 1 to
// MaxStatusBatch lowercase addresses.
func (c *Client) TransactionEvidence(ctx context.Context, hashes, senders []string) (TransactionStatusBatch, error) {
	if !validBatch(hashes, 32) || !validBatch(senders, 20) {
		return TransactionStatusBatch{}, ErrIdentity
	}
	raw, err := c.call(ctx, "ops_transactionStatuses", []any{hashes, senders})
	if err != nil {
		return TransactionStatusBatch{}, err
	}
	var wire evidenceWire
	var receipts []*bool
	// decodeStrict has checked that both fields are present.
	if err := decodeStrict(raw, &wire); err != nil || json.Unmarshal(wire.Receipts, &receipts) != nil || len(receipts) != len(hashes) {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	out, err := decodeBatch(wire.batchWire, hashes)
	if err != nil {
		return TransactionStatusBatch{}, err
	}
	out.Receipts = receipts
	if wire.SenderNonces != nil {
		var nonces []*uint64 // a null entry is a protocol error, never 0
		if out.Finalized == nil || json.Unmarshal(*wire.SenderNonces, &nonces) != nil || len(nonces) != len(senders) {
			return TransactionStatusBatch{}, ErrNodeResponse
		}
		out.SenderNonces = make([]uint64, len(nonces))
		for i, n := range nonces {
			if n == nil {
				return TransactionStatusBatch{}, ErrNodeResponse
			}
			out.SenderNonces[i] = *n
		}
	}
	return out, nil
}

// validBatch reports 1..MaxStatusBatch lowercase 0x-hex values of size bytes.
func validBatch(values []string, size int) bool {
	if len(values) == 0 || len(values) > MaxStatusBatch {
		return false
	}
	for _, v := range values {
		if !hexField(v, size) {
			return false
		}
	}
	return true
}

func decodeBatch(wire batchWire, hashes []string) (TransactionStatusBatch, error) {
	var entries []json.RawMessage
	if !ValidBootID(wire.BootID) || json.Unmarshal(wire.Statuses, &entries) != nil || len(entries) != len(hashes) {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	// Only a block above genesis is ever reported final (genesis: null).
	if f := wire.Finalized; f != nil && (!hexField(f.Hash, 32) || f.Number == 0 || f.Number > maxBlockNumber || f.Timestamp <= 0) {
		return TransactionStatusBatch{}, ErrNodeResponse
	}
	out := TransactionStatusBatch{BootID: wire.BootID, Finalized: wire.Finalized, CanonicalEpoch: wire.CanonicalEpoch, Statuses: make([]*BatchedStatus, len(hashes))}
	// Entries are decoded one by one: an invalid one is an error for its hash
	// only, never for the transactions answered with it.
	for i, entry := range entries {
		if string(entry) == "null" {
			continue
		}
		status, pooled, err := decodeBatchEntry(entry, hashes[i], wire.BootID)
		if err != nil {
			out.Statuses[i] = &BatchedStatus{Err: err}
			continue
		}
		out.Statuses[i] = &BatchedStatus{Status: status, Pooled: pooled}
	}
	return out, nil
}

// decodeBatchEntry decodes and validates one batched entry for hash; any
// failure is ErrInvalidStatus.
func decodeBatchEntry(entry json.RawMessage, hash, bootID string) (TransactionStatus, bool, error) {
	var e batchEntryWire
	if err := decodeStrict(entry, &e); err != nil || e.TransactionHash != hash {
		return TransactionStatus{}, false, ErrInvalidStatus
	}
	status := TransactionStatus{TransactionHash: e.TransactionHash, PrincipalID: e.PrincipalID, OrgID: e.OrgID, ContextID: e.ContextID, Execution: e.Execution, BootID: bootID}
	if err := status.Validate(); err != nil {
		return TransactionStatus{}, false, ErrInvalidStatus
	}
	if e.Pooled && status.Execution.Status != "pending" && status.Execution.Status != "denied" && status.Execution.Status != "expired" {
		return TransactionStatus{}, false, ErrInvalidStatus
	}
	return status, e.Pooled, nil
}
