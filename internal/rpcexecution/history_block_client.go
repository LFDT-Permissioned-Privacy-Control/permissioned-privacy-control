package rpcexecution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/networkidentity"
)

// HistoryBlockClient is a raw included-history source. It owns no policy,
// account directory, admission grant, indexer, database or response renderer.
type HistoryBlockClient struct {
	transport  Transport
	source     creationfacts.Source
	credential Credential
	limits     HistoryBlockLimits
}

func NewHistoryBlockClient(transport Transport, source creationfacts.Source, credential Credential, l HistoryBlockLimits) (*HistoryBlockClient, error) {
	if !l.valid() {
		return nil, failure(InvalidBinding)
	}
	key, e := (networkidentity.Binding{Environment: source.Network.Environment, ChainID: source.Network.ChainID, GenesisHash: source.Network.Genesis.Hex(), DeploymentID: source.Network.Deployment}).Key()
	if e != nil || creationfacts.Digest(key) != source.Network.Key {
		return nil, failure(InvalidBinding)
	}
	if _, e := NewHeaderClient(transport, source, credential, HeaderLimits{l.Timeout, 1, 16 << 10}); e != nil {
		return nil, e
	}
	return &HistoryBlockClient{transport, source, credential, l}, nil
}
func (c *HistoryBlockClient) Source() creationfacts.Source {
	if c == nil {
		return creationfacts.Source{}
	}
	return c.source
}

// AcquireBlock counts all ten possible physical requests and raw response bytes
// under one child deadline. The selected hash is finally checked by NUMBER.
func (c *HistoryBlockClient) AcquireBlock(ctx context.Context, selector HistoryBlockSelector) (*HistoryBlockObservation, error) {
	if ctx == nil {
		return nil, failure(InvalidCall)
	}
	deadline, _ := ctx.Deadline()
	return c.acquireBlockWithin(ctx, selector, deadline, ctx.Done())
}

// Only the ordinary-history owner uses this private composition hook. It keeps
// the original operation fence when its bounded acquisition child is canceled;
// public standalone AcquireBlock retains its original caller semantics.
func (c *HistoryBlockClient) acquireBlockWithin(ctx context.Context, selector HistoryBlockSelector, callerDeadline time.Time, callerDone <-chan struct{}) (*HistoryBlockObservation, error) {
	if c == nil || ctx == nil || !c.limits.valid() || !selector.valid() {
		return nil, failure(InvalidCall)
	}
	ctx, cancel := context.WithTimeout(ctx, c.limits.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	budget := &namespaceWireBudget{base: c.transport, remaining: c.limits.MaxTotalWireBytes, maxCalls: c.limits.MaxRequests}
	headers, e := NewHeaderClient(budget, c.source, c.credential, HeaderLimits{c.limits.Timeout, 1, 16 << 10})
	if e != nil {
		return nil, e
	}
	q := HeaderQuery{Hash: selector.hash}
	if selector.kind == 1 {
		q = HeaderQuery{NumberOrTag: fmt.Sprintf("0x%x", selector.number)}
	}
	before, e := headers.Read(ctx, []HeaderQuery{q})
	if e != nil {
		return nil, namespaceBudgetError(budget, e)
	}
	if !before.Synced() || len(before.headers) != 1 {
		return nil, failure(InvalidEvidence)
	}
	h := before.headers[0]
	raw, e := headers.wire.rpcBounded(ctx, "eth_getBlockByHash", []any{h.Hash.Hex(), true}, c.limits.MaxBlockBytes)
	if e != nil {
		return nil, namespaceBudgetError(budget, e)
	}
	b, charge, e := decodeHistoryBlock(raw, h, c.limits, c.source.Network.ChainID)
	if e != nil {
		return nil, e
	}
	// decodeHistoryBlock retains normalized owned values, never this wire or its
	// parser maps. Release this stage before acquiring the receipt response.
	raw = nil
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	raw, e = headers.wire.rpcBounded(ctx, "eth_getBlockReceipts", []any{h.Hash.Hex()}, c.limits.MaxReceiptSetBytes)
	if e != nil {
		return nil, namespaceBudgetError(budget, e)
	}
	if e = decodeHistoryReceipts(raw, b, c.limits, charge); e != nil {
		return nil, e
	}
	raw = nil
	after, e := headers.Read(ctx, []HeaderQuery{{NumberOrTag: fmt.Sprintf("0x%x", h.Number)}})
	if e != nil {
		return nil, namespaceBudgetError(budget, e)
	}
	if !after.Synced() || len(after.headers) != 1 || after.headers[0] != h || ctx.Err() != nil {
		return nil, failure(InvalidEvidence)
	}
	b.owner, b.source, b.selector = c, c.source, selector
	b.originalDone, b.originalDeadline = callerDone, callerDeadline
	b.digest, e = historyObservationDigest(b)
	if e != nil || ctx.Err() != nil {
		return nil, failure(InvalidEvidence)
	}
	return b, nil
}

func decodeHistoryBlock(raw []byte, wanted creationfacts.Header, l HistoryBlockLimits, chain string) (*HistoryBlockObservation, int, error) {
	if int64(len(raw)) > l.MaxBlockBytes {
		return nil, 0, failure(EvidenceLimit)
	}
	if e := historyJSONShape(raw, l, false); e != nil {
		return nil, 0, e
	}
	f, e := nullableRawObject(raw, 32, map[string]bool{"baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true, "excessBlobGas": true, "parentBeaconBlockRoot": true, "requestsHash": true, "totalDifficulty": true, "size": true, "blockAccessListHash": true, "slotNumber": true})
	if e != nil {
		return nil, 0, e
	}
	txs, ok := f["transactions"]
	if !ok {
		return nil, 0, failure(InvalidEvidence)
	}
	delete(f, "transactions")
	uncles, ok := f["uncles"]
	if !ok {
		return nil, 0, failure(InvalidEvidence)
	}
	delete(f, "uncles")
	withdrawals, hasWithdrawals := f["withdrawals"]
	delete(f, "withdrawals")
	headerRaw, e := json.Marshal(f)
	if e != nil {
		return nil, 0, failure(InvalidEvidence)
	}
	h, e := decodeQualifiedHeader(headerRaw)
	if e != nil || h != wanted {
		return nil, 0, failure(InvalidEvidence)
	}
	var header types.Header
	if json.Unmarshal(headerRaw, &header) != nil {
		return nil, 0, failure(InvalidEvidence)
	}
	b := &HistoryBlockObservation{header: &header, uncles: []common.Hash{}}
	if raw, ok := f["size"]; ok {
		b.sizePresence = HistoryNull
		if !historyNull(raw) {
			b.reportedSize, e = includedQuantity(raw, 64)
			if e != nil {
				return nil, 0, e
			}
			b.sizePresence = HistoryPresent
		}
	}
	if raw, ok := f["totalDifficulty"]; ok {
		b.tdPresence = HistoryNull
		if !historyNull(raw) {
			b.totalDifficulty, e = historyBig(raw)
			if e != nil {
				return nil, 0, e
			}
			b.tdPresence = HistoryPresent
		}
	}
	charge := 1024 + len(header.Extra)
	e = includedArray(uncles, 8192, func(raw json.RawMessage) error {
		v, e := includedData(raw, 32)
		if e != nil {
			return e
		}
		b.uncles = append(b.uncles, common.BytesToHash(v))
		charge += 32
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	if hasWithdrawals {
		b.withdrawals = []*types.Withdrawal{}
		if header.WithdrawalsHash == nil {
			return nil, 0, failure(InvalidEvidence)
		}
		e = includedArray(withdrawals, 8192, func(raw json.RawMessage) error {
			f, e := closedRawObject(raw, 4)
			if e != nil || len(f) != 4 {
				return failure(InvalidEvidence)
			}
			for _, k := range []string{"index", "validatorIndex", "amount"} {
				if _, e := includedQuantity(f[k], 64); e != nil {
					return e
				}
			}
			if _, e := includedData(f["address"], 20); e != nil {
				return e
			}
			var w types.Withdrawal
			if json.Unmarshal(raw, &w) != nil {
				return failure(InvalidEvidence)
			}
			b.withdrawals = append(b.withdrawals, &w)
			charge += 64
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
	} else if header.WithdrawalsHash != nil {
		return nil, 0, failure(InvalidEvidence)
	}
	seen := map[common.Hash]bool{}
	e = includedArray(txs, l.MaxTransactions, func(raw json.RawMessage) error {
		pos := includedPosition{Hash: h.Hash, Number: h.Number, Index: uint32(len(b.transactions)), Timestamp: h.Timestamp, TimestampKnown: true}
		t, n, e := decodeHistoryTransaction(raw, pos, chain, &header, l)
		if e != nil {
			return e
		}
		if seen[t.Hash()] {
			return failure(InvalidEvidence)
		}
		seen[t.Hash()] = true
		charge += n
		if charge > l.MaxObservationBytes {
			return failure(EvidenceLimit)
		}
		b.transactions = append(b.transactions, t)
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	if charge > l.MaxObservationBytes {
		return nil, 0, failure(EvidenceLimit)
	}
	return b, charge, nil
}

func historyOriginalFence(b *HistoryBlockObservation) error {
	select {
	case <-b.originalDone:
		return failure(NodeFailure)
	default:
	}
	if !b.originalDeadline.IsZero() && !time.Now().Before(b.originalDeadline) {
		return failure(NodeFailure)
	}
	return nil
}

// Recheck does not replay a block body. A new caller cannot reset the original
// cancellation/deadline fence, and lower selected time/wire/attempt caps apply.
func (c *HistoryBlockClient) Recheck(ctx context.Context, b *HistoryBlockObservation) error {
	if c == nil || ctx == nil || !b.valid() || b.owner != c || b.source != c.source || !c.limits.valid() {
		return failure(InvalidBinding)
	}
	if e := historyOriginalFence(b); e != nil {
		return e
	}
	timeout := min(c.limits.Timeout, 5*time.Second)
	deadline := time.Now().Add(timeout)
	if !b.originalDeadline.IsZero() && b.originalDeadline.Before(deadline) {
		deadline = b.originalDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	if b.originalDone != nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-b.originalDone:
				cancel()
			case <-ctx.Done():
			}
		}()
		defer func() { cancel(); <-done }()
	} else {
		defer cancel()
	}
	if ctx.Err() != nil {
		return failure(NodeFailure)
	}
	budget := &namespaceWireBudget{base: c.transport, remaining: min(c.limits.MaxTotalWireBytes, int64(64<<10)), maxCalls: min(c.limits.MaxRequests, 4)}
	headers, e := NewHeaderClient(budget, c.source, c.credential, HeaderLimits{timeout, 1, 16 << 10})
	if e != nil {
		return e
	}
	result, e := headers.Read(ctx, []HeaderQuery{{NumberOrTag: fmt.Sprintf("0x%x", b.header.Number.Uint64())}})
	if e != nil {
		return namespaceBudgetError(budget, e)
	}
	h := creationfacts.Header{Number: b.header.Number.Uint64(), Hash: b.header.Hash(), Parent: b.header.ParentHash, Timestamp: b.header.Time}
	if !result.Synced() || len(result.headers) != 1 || result.headers[0] != h || ctx.Err() != nil {
		return failure(InvalidEvidence)
	}
	return historyOriginalFence(b)
}

func historyObservationDigest(b *HistoryBlockObservation) (common.Hash, error) {
	h := sha256.New()
	encode := json.NewEncoder(h)
	header, e := rlp.EncodeToBytes(b.header)
	if e != nil {
		return common.Hash{}, e
	}
	if e = encode.Encode(struct {
		Domain          string
		Source          creationfacts.Digest
		Kind            uint8
		Number          uint64
		Hash            common.Hash
		Header          []byte
		Uncles          []common.Hash
		Withdrawals     []*types.Withdrawal
		ReportedSize    uint64
		SizePresence    HistoryFieldPresence
		TotalDifficulty *big.Int
		TDPresence      HistoryFieldPresence
	}{Domain: "ops-history-block/v1", Source: b.source.Digest(), Kind: b.selector.kind, Number: b.selector.number, Hash: b.selector.hash, Header: header, Uncles: b.uncles, Withdrawals: b.withdrawals, ReportedSize: b.reportedSize, SizePresence: b.sizePresence, TotalDifficulty: b.totalDifficulty, TDPresence: b.tdPresence}); e != nil {
		return common.Hash{}, e
	}
	for i, t := range b.transactions {
		r := b.receipts[i]
		v := struct {
			Signed          []byte
			From            common.Address
			Status          *uint8
			Root            *common.Hash
			Gas, Cumulative uint64
			Price           *big.Int
			BlobGas         uint64
			BlobPrice       *big.Int
			Contract        *common.Address
			Logs            []HistoryLog
			Bloom           types.Bloom
		}{Signed: t.signed, From: t.from, Gas: r.gasUsed, Cumulative: r.cumulativeGasUsed, Price: r.effectiveGasPrice, BlobGas: r.blobGasUsed, BlobPrice: r.blobGasPrice, Logs: r.logs, Bloom: r.bloom}
		if r.statusPresent {
			v.Status = &r.status
		}
		if r.postStatePresent {
			v.Root = &r.postState
		}
		if r.contractPresent {
			v.Contract = &r.contractAddress
		}
		if e = encode.Encode(v); e != nil {
			return common.Hash{}, e
		}
	}
	return common.BytesToHash(h.Sum(nil)), nil
}
