package rpcexecution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

func (c *HistoryReadClient) Acquire(ctx context.Context, q HistoryReadQuery) (*HistoryReadObservation, error) {
	if c == nil || ctx == nil {
		return nil, failure(InvalidCall)
	}
	d := time.Now().Add(c.limits.Timeout)
	if earlier, ok := ctx.Deadline(); ok {
		d = minTime(d, earlier)
	}
	return c.AcquireWithin(ctx, q, HistoryOperationFence{d, ctx.Done()})
}
func (c *HistoryReadClient) AcquireWithin(parent context.Context, q HistoryReadQuery, fence HistoryOperationFence) (*HistoryReadObservation, error) {
	return c.acquireReservedWithin(parent, q, fence, 0)
}

// AcquireReservedWithin precharges captured owning facts before node I/O. The
// lower-only reservation grants nothing and cannot enlarge selected limits.
func (c *HistoryReadClient) AcquireReservedWithin(parent context.Context, q HistoryReadQuery, fence HistoryOperationFence, reservedWorkingBytes int) (*HistoryReadObservation, error) {
	return c.acquireReservedWithin(parent, q, fence, reservedWorkingBytes)
}
func (c *HistoryReadClient) acquireReservedWithin(parent context.Context, q HistoryReadQuery, fence HistoryOperationFence, reservedWorkingBytes int) (*HistoryReadObservation, error) {
	if c == nil || !q.validFor(c.limits) {
		return nil, failure(InvalidCall)
	}
	ctx, cancel, err := fence.bind(parent, c.limits.Timeout)
	if err != nil {
		return nil, err
	}
	defer cancel()
	b := &historyReadBudget{base: c.transport, limits: c.limits}
	if reservedWorkingBytes < 0 || reservedWorkingBytes > c.limits.MaxChargedBytes {
		return nil, failure(EvidenceLimit)
	}
	if err = b.reserveOwned(reservedWorkingBytes + len(q.encoded) + 1024); err != nil {
		return nil, err
	}
	o := &HistoryReadObservation{owner: c, source: c.source, query: q, kind: HistoryLocated, fence: fence, budget: b, headers: map[common.Hash]*types.Header{}, canonical: map[uint64]common.Hash{}}
	if err = c.checkNetwork(ctx, b); err != nil {
		return nil, err
	}
	switch q.method {
	case HistoryBlockByHash, HistoryBlockByNumber, HistoryBlockCountByHash, HistoryBlockCountByNumber, HistoryBlockReceipts:
		err = c.acquireReadBlock(ctx, o)
	case HistoryTransactionByHash, HistoryTransactionReceipt, HistoryTransactionByHashIndex, HistoryTransactionByNumberIndex:
		err = c.acquireReadTransaction(ctx, o)
	case HistoryLogs:
		err = c.acquireReadLogs(ctx, o)
	default:
		err = failure(InvalidCall)
	}
	if err != nil {
		return nil, err
	}
	if err = c.checkObservation(ctx, o); err != nil {
		return nil, err
	}
	if !fence.live() || ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	o.digest, err = historyReadDigest(o)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	return o, nil
}

func (c *HistoryReadClient) Recheck(parent context.Context, o *HistoryReadObservation) error {
	if c == nil || !o.valid() || o.owner != c || o.source != c.source {
		return failure(InvalidBinding)
	}
	d, err := historyReadDigest(o)
	if err != nil || d != o.digest {
		return failure(InvalidEvidence)
	}
	ctx, cancel, err := o.fence.bind(parent, min(c.limits.Timeout, 5*time.Second))
	if err != nil {
		return err
	}
	defer cancel()
	if err = c.checkObservation(ctx, o); err != nil {
		return err
	}
	if !o.fence.live() || ctx.Err() != nil {
		return failure(NodeFailure)
	}
	return nil
}

func (c *HistoryReadClient) checkNetwork(ctx context.Context, b *historyReadBudget) error {
	r, err := c.batch(ctx, b, []historyRPCItem{{"eth_chainId", []any{}, 4096}, {"eth_getHeaderByNumber", []any{"0x0"}, 16 << 10}, {"eth_syncing", []any{}, 4096}})
	if err != nil {
		return err
	}
	n, err := historyBig(r[0])
	if err != nil || n.String() != c.source.Network.ChainID {
		return failure(InvalidEvidence)
	}
	h, err := decodeQualifiedHeader(r[1])
	if err != nil || h.Number != 0 || h.Hash != c.source.Network.Genesis {
		return failure(InvalidEvidence)
	}
	synced, err := decodeHeaderSync(r[2])
	if err != nil || !synced {
		return failure(InvalidEvidence)
	}
	return nil
}
func (c *HistoryReadClient) checkObservation(ctx context.Context, o *HistoryReadObservation) error {
	if err := c.checkNetwork(ctx, o.budget); err != nil {
		return err
	}
	// The original finite selected population is rechecked, never a moving
	// latest/pending query or an attempt to make absent rows into completeness.
	hashes := make([]common.Hash, 0, len(o.headers))
	for hash := range o.headers {
		hashes = append(hashes, hash)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i].Hex() < hashes[j].Hex() })
	for start := 0; start < len(hashes); start += c.limits.MaxBatchItems {
		end := min(start+c.limits.MaxBatchItems, len(hashes))
		items := make([]historyRPCItem, 0, end-start)
		for _, hash := range hashes[start:end] {
			h := o.headers[hash]
			method, selector := "eth_getHeaderByHash", hash.Hex()
			if canonical, ok := o.canonical[h.Number.Uint64()]; ok {
				if canonical != hash {
					return failure(InvalidEvidence)
				}
				method, selector = "eth_getHeaderByNumber", historyNumber(h.Number.Uint64())
			}
			items = append(items, historyRPCItem{method, []any{selector}, 16 << 10})
		}
		r, err := c.batch(ctx, o.budget, items)
		if err != nil {
			return err
		}
		for i, raw := range r {
			got, err := decodeQualifiedHeader(raw)
			want := o.headers[hashes[start+i]]
			if err != nil || got.Hash != want.Hash() || got.Number != want.Number.Uint64() {
				return failure(InvalidEvidence)
			}
		}
	}
	return nil
}
func (c *HistoryReadClient) addHeader(o *HistoryReadObservation, h *types.Header, canonical bool) error {
	hash := h.Hash()
	if _, found := o.headers[hash]; !found {
		if len(o.headers) >= c.limits.MaxHeaders {
			return failure(EvidenceLimit)
		}
		if err := o.budget.reserveOwned(1536 + len(h.Extra)); err != nil {
			return err
		}
		o.headers[hash] = h
	}
	if canonical {
		n := h.Number.Uint64()
		if previous, found := o.canonical[n]; found && previous != hash {
			return failure(InvalidEvidence)
		}
		o.canonical[n] = hash
	}
	return nil
}
func (c *HistoryReadClient) readHeader(ctx context.Context, o *HistoryReadObservation, selector any, byHash bool) (*types.Header, error) {
	method := "eth_getHeaderByNumber"
	if byHash {
		method = "eth_getHeaderByHash"
	}
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{method, []any{selector}, 16 << 10}})
	if err != nil {
		return nil, err
	}
	if historyNull(r[0]) {
		return nil, nil
	}
	qualified, err := decodeQualifiedHeader(r[0])
	if err != nil {
		return nil, err
	}
	if byHash {
		if selector != qualified.Hash.Hex() {
			return nil, failure(InvalidEvidence)
		}
	} else if s, ok := selector.(string); ok && len(s) > 2 && s[:2] == "0x" {
		n, ok := quantity(s, 64)
		if !ok || n.Uint64() != qualified.Number {
			return nil, failure(InvalidEvidence)
		}
	}
	var h types.Header
	if json.Unmarshal(r[0], &h) != nil {
		return nil, failure(InvalidEvidence)
	}
	return &h, nil
}
func historyBlockTag(b StateBlockMetadata) any {
	switch b.Kind {
	case StateNumber:
		return historyNumber(b.Number)
	case StateHash:
		return b.Hash.Hex()
	case StateLatest:
		return "latest"
	case StateSafe:
		return "safe"
	case StateFinalized:
		return "finalized"
	case StatePending:
		return "pending"
	case StateEarliest:
		return "earliest"
	}
	return nil
}
func (c *HistoryReadClient) acquireReadBlock(ctx context.Context, o *HistoryReadObservation) error {
	q := o.query
	if q.block.Kind == StatePending {
		return c.acquirePendingBlock(ctx, o)
	}
	byHash := q.block.Kind == StateHash
	h, err := c.readHeader(ctx, o, historyBlockTag(q.block), byHash)
	if err != nil {
		return err
	}
	if h == nil {
		o.kind = HistoryNotFound
		return nil
	}
	canonical := !byHash || q.block.RequireCanonical
	if err = c.addHeader(o, h, canonical); err != nil {
		return err
	}
	blockLimits, err := c.blockReadLimits(o)
	if err != nil {
		return err
	}
	if canonical {
		// Keep CB1's exact complete-population validation and original fence;
		// its private transport spends this SAME operation's physical/item/wire
		// budget, including every network and final canonical probe.
		client, err := NewHistoryBlockClient(historySingleTransport{o.budget}, c.source, c.credential, blockLimits)
		if err != nil {
			return err
		}
		selector, err := HistoryBlockHash(h.Hash())
		if err != nil {
			return err
		}
		o.block, err = client.acquireBlockWithin(ctx, selector, o.fence.Deadline, o.fence.Done)
		if err != nil {
			return c.budgetError(o.budget, err)
		}
		o.kind = HistoryCanonical
	} else {
		r, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getBlockByHash", []any{h.Hash().Hex(), true}, blockLimits.MaxBlockBytes}})
		if err != nil {
			return err
		}
		wanted := creationfacts.Header{Number: h.Number.Uint64(), Hash: h.Hash(), Parent: h.ParentHash, Timestamp: h.Time}
		b, charge, err := decodeHistoryBlock(r[0], wanted, blockLimits, c.source.Network.ChainID)
		if err != nil {
			return err
		}
		r = nil
		r, err = c.batch(ctx, o.budget, []historyRPCItem{{"eth_getBlockReceipts", []any{h.Hash().Hex()}, blockLimits.MaxReceiptSetBytes}})
		if err != nil {
			return err
		}
		if err = decodeHistoryReceipts(r[0], b, blockLimits, charge); err != nil {
			return err
		}
		r = nil
		b.source = c.source
		o.block = b
		o.kind = HistoryLocated
	}
	if err = o.budget.reserveOwned(historyReadBlockCharge(o.block)); err != nil {
		return err
	}
	for i, t := range o.block.transactions {
		location := historyIncludedLocation(includedPosition{Hash: h.Hash(), Number: h.Number.Uint64(), Index: uint32(i)})
		price, err := historyEffectivePrice(t, h.BaseFee)
		if err != nil {
			return err
		}
		o.transactions = append(o.transactions, LocatedHistoryTransaction{t, location, price})
		r := o.block.receipts[i]
		o.receipts = append(o.receipts, LocatedHistoryReceipt{r, t.Hash(), location})
		for _, log := range r.logs {
			o.logs = append(o.logs, LocatedHistoryLog{log, t.Hash(), location, false})
		}
	}
	return nil
}

// blockReadLimits is selected before any complete block model is decoded.
// H1's location/log wrappers cost at most the original CB1 normalized charge:
// +1024 header, +128/transaction, +64/receipt and +96/log, against CB1's
// >=1024, >=512, 512 and >=128 respectively. Reserving half the remaining
// allowance for CB1 therefore bounds the complete composed model before its
// later exact charge. This is a logical retained-data bound, not Go heap/RSS.
func (c *HistoryReadClient) blockReadLimits(o *HistoryReadObservation) (HistoryBlockLimits, error) {
	l := c.limits.Block
	l.MaxBlockBytes = min(l.MaxBlockBytes, c.limits.MaxResultBytes)
	l.MaxReceiptSetBytes = min(l.MaxReceiptSetBytes, c.limits.MaxResultBytes)
	l.MaxTransactionBytes = min(l.MaxTransactionBytes, int(c.limits.MaxResultBytes))
	l.MaxReceiptBytes = min(l.MaxReceiptBytes, int(c.limits.MaxResultBytes))
	o.budget.mu.Lock()
	remaining := o.budget.limits.MaxChargedBytes - o.budget.charged
	o.budget.mu.Unlock()
	l.MaxObservationBytes = min(l.MaxObservationBytes, remaining/2)
	if !l.valid() {
		return HistoryBlockLimits{}, failure(EvidenceLimit)
	}
	return l, nil
}

func historyReadBlockCharge(b *HistoryBlockObservation) int {
	n := 2048 + len(b.header.Extra) + len(b.uncles)*32 + len(b.withdrawals)*64
	for _, t := range b.transactions {
		n += historyTransactionCharge(t) + 128
	}
	for _, r := range b.receipts {
		n += 512 + 64
		for _, l := range r.logs {
			n += 128 + len(l.Data) + len(l.Topics)*32 + 96
		}
	}
	return n
}
func historyTransactionCharge(t HistoryTransaction) int {
	n := 512 + len(t.signed) + len(t.tx.Data())
	for _, a := range t.tx.AccessList() {
		n += 20 + 32*len(a.StorageKeys)
	}
	return n + 32*len(t.tx.BlobHashes()) + 160*len(t.tx.SetCodeAuthorizations())
}
func historyIncludedLocation(p includedPosition) HistoryLocation {
	return HistoryLocation{p.Hash, p.Number, p.Index, true, true, true}
}

func (c *HistoryReadClient) acquireReadTransaction(ctx context.Context, o *HistoryReadObservation) error {
	q := o.query
	if q.method == HistoryTransactionByNumberIndex && q.block.Kind == StatePending {
		return c.acquirePendingBlock(ctx, o)
	}
	method, params := q.method.String(), q.params
	canonical := q.method == HistoryTransactionByNumberIndex && q.block.Kind != StatePending
	var selected *types.Header
	if canonical {
		var err error
		selected, err = c.readHeader(ctx, o, historyBlockTag(q.block), false)
		if err != nil {
			return err
		}
		if selected == nil {
			o.kind = HistoryNotFound
			return nil
		}
		params = []any{historyNumber(selected.Number.Uint64()), fmt.Sprintf("0x%x", q.index)}
	}
	if q.method == HistoryTransactionReceipt {
		method = "eth_getTransactionByHash"
		params = []any{q.hash.Hex()}
	}
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{method, params, int64(c.limits.Block.MaxTransactionBytes)}})
	if err != nil {
		return err
	}
	if historyNull(r[0]) {
		if q.method == HistoryTransactionReceipt {
			rr, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getTransactionReceipt", []any{q.hash.Hex()}, int64(c.limits.Block.MaxReceiptBytes)}})
			if err != nil {
				return err
			}
			if !historyNull(rr[0]) {
				return failure(InvalidEvidence)
			}
		}
		o.kind = HistoryNotFound
		return nil
	}
	location, pending, err := decodeHistoryLocation(r[0], false)
	if err != nil {
		return err
	}
	if pending {
		if q.method == HistoryTransactionReceipt {
			rr, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getTransactionReceipt", []any{q.hash.Hex()}, int64(c.limits.Block.MaxReceiptBytes)}})
			if err != nil {
				return err
			}
			if !historyNull(rr[0]) {
				return failure(UnsupportedEvidence)
			}
			o.kind = HistoryNotFound
			return nil
		}
		if q.method == HistoryTransactionByHashIndex || canonical {
			return failure(InvalidEvidence)
		}
		o.kind = HistoryPending
	}
	var h *types.Header
	if !pending {
		h = selected
		if h == nil || h.Hash() != location.BlockHash {
			h, err = c.readHeader(ctx, o, location.BlockHash.Hex(), true)
			if err != nil {
				return err
			}
			if h == nil {
				return failure(InvalidEvidence)
			}
		}
		if h.Number.Uint64() != location.BlockNumber || selected != nil && selected.Hash() != location.BlockHash {
			return failure(InvalidEvidence)
		}
		if q.method == HistoryTransactionByHashIndex && location.BlockHash != q.hash || (q.method == HistoryTransactionByHashIndex || q.method == HistoryTransactionByNumberIndex) && uint64(location.TransactionIndex) != q.index {
			return failure(InvalidEvidence)
		}
		if err = c.addHeader(o, h, canonical); err != nil {
			return err
		}
		if canonical {
			o.kind = HistoryCanonical
		}
	}
	if err = historyJSONShape(r[0], c.limits.Block, false); err != nil {
		return err
	}
	pos := includedPosition{Hash: location.BlockHash, Number: location.BlockNumber, Index: location.TransactionIndex}
	t, n, err := decodeHistoryTransactionValue(r[0], pos, c.source.Network.ChainID, h, c.limits.Block, pending)
	if err != nil {
		return err
	}
	if (q.method == HistoryTransactionByHash || q.method == HistoryTransactionReceipt) && t.Hash() != q.hash {
		return failure(InvalidEvidence)
	}
	if err = o.budget.reserveOwned(n + 128); err != nil {
		return err
	}
	price := t.tx.GasFeeCap()
	if h != nil {
		price, err = historyEffectivePrice(t, h.BaseFee)
		if err != nil {
			return err
		}
	}
	o.transactions = append(o.transactions, LocatedHistoryTransaction{t, location, historyBigCopy(price)})
	if !pending && q.method == HistoryTransactionReceipt {
		if err = c.acquireParentReceipt(ctx, o, t, location, h, false); err != nil {
			return err
		}
	}
	if q.method == HistoryTransactionReceipt && len(o.receipts) == 0 {
		o.kind = HistoryNotFound
		o.transactions = nil
	}
	return nil
}

func decodeHistoryLocation(raw []byte, body bool) (HistoryLocation, bool, error) {
	f, err := nullableRawObject(raw, 32, map[string]bool{"to": true, "gasPrice": true, "chainId": true, "maxFeePerGas": true, "maxPriorityFeePerGas": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "blockTimestamp": true})
	if err != nil {
		return HistoryLocation{}, false, err
	}
	p, err := decodeIncludedPosition(f)
	if err == nil {
		return historyIncludedLocation(p), false, nil
	}
	if !errors.Is(err, ErrNotIncluded) {
		return HistoryLocation{}, false, err
	}
	return HistoryLocation{}, true, nil
}
func (c *HistoryReadClient) acquireParentReceipt(ctx context.Context, o *HistoryReadObservation, t HistoryTransaction, location HistoryLocation, h *types.Header, allowMissing bool) error {
	r, err := c.batch(ctx, o.budget, []historyRPCItem{{"eth_getTransactionReceipt", []any{t.Hash().Hex()}, int64(c.limits.Block.MaxReceiptBytes)}})
	if err != nil {
		return err
	}
	if historyNull(r[0]) {
		if allowMissing {
			return nil
		}
		return failure(InvalidEvidence)
	}
	receipt, n, err := decodeStandaloneHistoryReceipt(r[0], t, location, h, c.limits.Block)
	if err != nil {
		return err
	}
	if err = o.budget.reserveOwned(n + 64); err != nil {
		return err
	}
	o.receipts = append(o.receipts, LocatedHistoryReceipt{receipt, t.Hash(), location})
	for _, log := range receipt.logs {
		o.logs = append(o.logs, LocatedHistoryLog{log, t.Hash(), location, false})
	}
	return nil
}
func decodeStandaloneHistoryReceipt(raw []byte, t HistoryTransaction, location HistoryLocation, h *types.Header, l HistoryBlockLimits) (HistoryReceipt, int, error) {
	pos := includedPosition{Hash: location.BlockHash, Number: location.BlockNumber, Index: location.TransactionIndex, Timestamp: h.Time, TimestampKnown: true}
	return decodeSparseHistoryReceipt(raw, t, pos, h, l)
}
