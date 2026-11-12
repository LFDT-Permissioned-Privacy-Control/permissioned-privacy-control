package rpcexecution

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

// IncludedHistoryBatch is a fixed ordinary Explorer acquisition. It has no
// C2/whole-block conversion and never accepts caller-supplied transaction facts.
// Its single budget includes all reads and every later final recheck.
type IncludedHistoryBatch struct {
	owner     *HistoryReadClient
	staged    *HistoryReadObservation // private header/typed-data staging only; never a valid public observation
	requested []common.Hash
	anchor    *HistoryHeader
	anchors   []HistoryHeader
	digest    common.Hash
}

func (c *HistoryReadClient) AcquireIncludedBatch(ctx context.Context, hashes []common.Hash, anchor *HistoryHeader, fence HistoryOperationFence, reserved int) (*IncludedHistoryBatch, error) {
	return c.AcquireExplorerBatch(ctx, hashes, anchor, nil, fence, reserved)
}

// AcquireExplorerBatch also qualifies a bounded set of retained block headers.
// Header anchors are expected identities, not trusted header contents; the same
// selected node supplies and canonically rechecks every full typed header.
func (c *HistoryReadClient) AcquireExplorerBatch(ctx context.Context, hashes []common.Hash, anchor *HistoryHeader, anchors []HistoryHeader, fence HistoryOperationFence, reserved int) (*IncludedHistoryBatch, error) {

	if c == nil || len(hashes) > min(64, c.limits.MaxParents) || len(anchors) > min(64, c.limits.MaxHeaders-1) {
		return nil, failure(EvidenceLimit)
	}
	if reserved < 0 || reserved > c.limits.MaxChargedBytes {
		return nil, failure(EvidenceLimit)
	}
	bound, cancel, err := fence.bind(ctx, c.limits.Timeout)
	if err != nil {
		return nil, err
	}
	defer cancel()
	budget := &historyReadBudget{base: c.transport, limits: c.limits}
	if err = budget.reserveOwned(reserved + 1024 + 64*len(hashes)); err != nil {
		return nil, err
	}
	// This carrier has no owner/query/digest, so it cannot pass the ordinary
	// public observation validity check or be promoted to a canonical block.
	o := &HistoryReadObservation{source: c.source, fence: fence, budget: budget, headers: map[common.Hash]*types.Header{}, canonical: map[uint64]common.Hash{}}
	b := &IncludedHistoryBatch{owner: c, staged: o, requested: append([]common.Hash{}, hashes...)}
	for _, a := range anchors {
		if a.Hash == (common.Hash{}) || a.Number > 1<<63-1 {
			return nil, failure(InvalidCall)
		}
		b.anchors = append(b.anchors, HistoryHeader{Number: a.Number, Hash: a.Hash})
	}
	if anchor != nil {
		copy := *anchor
		copy.BaseFeePerGas = historyBigCopy(anchor.BaseFeePerGas)
		b.anchor = &copy
	}
	seen := map[common.Hash]bool{}
	for _, hash := range hashes {
		if hash == (common.Hash{}) || seen[hash] {
			return nil, failure(InvalidCall)
		}
		seen[hash] = true
	}
	if err = c.checkNetwork(bound, budget); err != nil {
		return nil, err
	}
	items := make([]historyRPCItem, 0, len(hashes))
	for _, hash := range hashes {
		items = append(items, historyRPCItem{"eth_getTransactionByHash", []any{hash.Hex()}, int64(c.limits.Block.MaxTransactionBytes)})
	}
	var raw []json.RawMessage
	if len(items) > 0 {
		raw, err = c.batch(bound, budget, items)
		if err != nil {
			return nil, err
		}
	}
	locations := make([]HistoryLocation, len(hashes))
	numbers := map[uint64]bool{}
	if anchor != nil {
		numbers[anchor.Number] = true
	}
	for _, a := range b.anchors {
		numbers[a.Number] = true
	}
	for i, value := range raw {
		if historyNull(value) {
			return nil, failure(InvalidEvidence)
		}
		location, pending, err := decodeHistoryLocation(value, false)
		if err != nil || pending {
			return nil, failure(InvalidEvidence)
		}
		locations[i] = location
		numbers[location.BlockNumber] = true
	}
	ordered := make([]uint64, 0, len(numbers))
	for n := range numbers {
		ordered = append(ordered, n)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) > c.limits.MaxHeaders {
		return nil, failure(EvidenceLimit)
	}
	items = items[:0]
	for _, n := range ordered {
		items = append(items, historyRPCItem{"eth_getHeaderByNumber", []any{historyNumber(n)}, 16 << 10})
	}
	byNumber := map[uint64]*types.Header{}
	if len(items) > 0 {
		headers, err := c.batch(bound, budget, items)
		if err != nil {
			return nil, err
		}
		for i, value := range headers {
			qualified, err := decodeQualifiedHeader(value)
			if err != nil || qualified.Number != ordered[i] {
				return nil, failure(InvalidEvidence)
			}
			var header types.Header
			if json.Unmarshal(value, &header) != nil {
				return nil, failure(InvalidEvidence)
			}
			if err = c.addHeader(o, &header, true); err != nil {
				return nil, err
			}
			byNumber[qualified.Number] = &header
		}
	}
	if anchor != nil {
		h := byNumber[anchor.Number]
		if h == nil || h.Hash() != anchor.Hash {
			return nil, failure(InvalidEvidence)
		}
	}
	for _, a := range b.anchors {
		h := byNumber[a.Number]
		if h == nil || h.Hash() != a.Hash {
			return nil, failure(InvalidEvidence)
		}
	}
	for i, value := range raw {
		loc := locations[i]
		header := byNumber[loc.BlockNumber]
		if header == nil || header.Hash() != loc.BlockHash {
			return nil, failure(InvalidEvidence)
		}
		if err = historyJSONShape(value, c.limits.Block, false); err != nil {
			return nil, err
		}
		pos := includedPosition{Hash: loc.BlockHash, Number: loc.BlockNumber, Index: loc.TransactionIndex, Timestamp: header.Time, TimestampKnown: true}
		tx, n, err := decodeHistoryTransaction(value, pos, c.source.Network.ChainID, header, c.limits.Block)
		if err != nil || tx.Hash() != hashes[i] {
			return nil, failure(InvalidEvidence)
		}
		if err = budget.reserveOwned(n + 128); err != nil {
			return nil, err
		}
		price, err := historyEffectivePrice(tx, header.BaseFee)
		if err != nil {
			return nil, err
		}
		o.transactions = append(o.transactions, LocatedHistoryTransaction{tx, loc, price})
	}
	raw = nil
	items = items[:0]
	for _, hash := range hashes {
		items = append(items, historyRPCItem{"eth_getTransactionReceipt", []any{hash.Hex()}, int64(c.limits.Block.MaxReceiptBytes)})
	}
	if len(items) > 0 {
		raw, err = c.batch(bound, budget, items)
		if err != nil {
			return nil, err
		}
	}
	for i, value := range raw {
		if historyNull(value) {
			return nil, failure(InvalidEvidence)
		}
		t := o.transactions[i]
		header := byNumber[t.Location.BlockNumber]
		pos := includedPosition{Hash: t.Location.BlockHash, Number: t.Location.BlockNumber, Index: t.Location.TransactionIndex, Timestamp: header.Time, TimestampKnown: true}
		receipt, n, err := decodeSparseHistoryReceipt(value, t.Transaction, pos, header, c.limits.Block)
		if err != nil {
			return nil, err
		}
		if len(receipt.logs) > c.limits.MaxLogs-len(o.logs) {
			return nil, failure(EvidenceLimit)
		}
		if err = budget.reserveOwned(n + 64 + 96*len(receipt.logs)); err != nil {
			return nil, err
		}
		o.receipts = append(o.receipts, LocatedHistoryReceipt{receipt, t.Transaction.Hash(), t.Location})
		for _, log := range receipt.logs {
			o.logs = append(o.logs, LocatedHistoryLog{log, t.Transaction.Hash(), t.Location, false})
		}
	}
	if err = c.checkObservation(bound, o); err != nil {
		return nil, err
	}
	if !fence.live() || bound.Err() != nil {
		return nil, failure(NodeFailure)
	}
	b.digest, err = b.computeDigest()
	if err != nil {
		return nil, err
	}
	return b, nil
}
func (b *IncludedHistoryBatch) computeDigest() (common.Hash, error) {
	if b == nil || b.owner == nil || b.staged == nil {
		return common.Hash{}, failure(InvalidBinding)
	}
	// The inner digest is typed-data integrity only: its carrier deliberately has
	// no public owner/query. The outer domain binds the fixed batch purpose/set.
	data, err := historyReadDigest(b.staged)
	if err != nil {
		return common.Hash{}, err
	}
	raw, err := json.Marshal(struct {
		Domain  string
		Hashes  []common.Hash
		Anchor  *HistoryHeader
		Anchors []HistoryHeader
		Data    common.Hash
	}{"ops-explorer-included-batch/v1", b.requested, b.anchor, b.anchors, data})
	if err != nil {
		return common.Hash{}, err
	}
	return common.Hash(sha256.Sum256(raw)), nil
}
func (b *IncludedHistoryBatch) Recheck(ctx context.Context) error {
	if b == nil || b.owner == nil || b.digest == (common.Hash{}) {
		return failure(InvalidBinding)
	}
	got, err := b.computeDigest()
	if err != nil || got != b.digest {
		return failure(InvalidEvidence)
	}
	bound, cancel, err := b.staged.fence.bind(ctx, min(5*time.Second, b.owner.limits.Timeout))
	if err != nil {
		return err
	}
	defer cancel()
	if err = b.owner.checkObservation(bound, b.staged); err != nil {
		return err
	}
	if !b.staged.fence.live() || bound.Err() != nil {
		return failure(NodeFailure)
	}
	return nil
}
func (b *IncludedHistoryBatch) Transactions() []LocatedHistoryTransaction {
	if b == nil || b.digest == (common.Hash{}) {
		return nil
	}
	out := append([]LocatedHistoryTransaction{}, b.staged.transactions...)
	for i := range out {
		out[i].GasPrice = historyBigCopy(out[i].GasPrice)
	}
	return out
}
func (b *IncludedHistoryBatch) Receipts() []LocatedHistoryReceipt {
	if b == nil || b.digest == (common.Hash{}) {
		return nil
	}
	return append([]LocatedHistoryReceipt{}, b.staged.receipts...)
}
func (b *IncludedHistoryBatch) Logs() []LocatedHistoryLog {
	if b == nil || b.digest == (common.Hash{}) {
		return nil
	}
	out := append([]LocatedHistoryLog{}, b.staged.logs...)
	for i := range out {
		out[i].Log.Data = append([]byte{}, out[i].Log.Data...)
		out[i].Log.Topics = append([]common.Hash{}, out[i].Log.Topics...)
	}
	return out
}
func (b *IncludedHistoryBatch) ReserveWorkingBytes(n int) error {
	if b == nil || b.digest == (common.Hash{}) || !b.staged.fence.live() {
		return failure(InvalidBinding)
	}
	return b.staged.budget.reserveOwned(n)
}
func (b *IncludedHistoryBatch) RemainingWorkingBytes() int {
	if b == nil || b.digest == (common.Hash{}) {
		return 0
	}
	b.staged.budget.mu.Lock()
	defer b.staged.budget.mu.Unlock()
	return b.staged.budget.limits.MaxChargedBytes - b.staged.budget.charged
}

// Header returns a detached full typed header already acquired under this batch.
func (b *IncludedHistoryBatch) Header(number uint64, hash common.Hash) (*types.Header, bool) {
	if b == nil || b.digest == (common.Hash{}) || b.staged.canonical[number] != hash {
		return nil, false
	}
	h, ok := b.staged.headers[hash]
	if !ok {
		return nil, false
	}
	return types.CopyHeader(h), true
}
