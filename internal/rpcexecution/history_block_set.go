package rpcexecution

import (
	"context"
	"fmt"
	"time"
)

// HistoryBlockSetLimits bounds one shared before/body/after acquisition. The
// member client's decoding limits still apply. Its standalone ten-call budget
// is not multiplied or silently replaced: a lowered standalone call budget
// cannot admit this composition. Total wire and ownership limits are bounded
// by BOTH these set limits and the member's original limits.
type HistoryBlockSetLimits struct {
	Timeout             time.Duration
	MaxBlocks           int
	MaxRequests         int
	MaxTotalWireBytes   int64
	MaxObservationBytes int
}

func DefaultHistoryBlockSetLimits() HistoryBlockSetLimits {
	return HistoryBlockSetLimits{5 * time.Second, 128, 518, 17 << 20, 16 << 20}
}

func (l HistoryBlockSetLimits) valid() bool {
	m := DefaultHistoryBlockSetLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxBlocks > 0 && l.MaxBlocks <= m.MaxBlocks &&
		l.MaxRequests > 0 && l.MaxRequests <= m.MaxRequests && l.MaxTotalWireBytes > 0 && l.MaxTotalWireBytes <= m.MaxTotalWireBytes &&
		l.MaxObservationBytes > 0 && l.MaxObservationBytes <= m.MaxObservationBytes
}

// AcquireBlockSetWithin preserves selector order and returns a validated prefix
// if capacity is exhausted BEFORE starting another body. The whole read fails
// on malformed/unavailable evidence, a body overflow, cancellation or a reorg.
// Every supplied number has already spent its before-header work, including an
// unconsumed suffix; the caller must not refund or reacquire that work.
// Members retain the ORIGINAL fence, not this temporary acquisition context.
func (c *HistoryBlockClient) AcquireBlockSetWithin(parent context.Context, numbers []uint64, fence HistoryOperationFence, l HistoryBlockSetLimits) ([]*HistoryBlockObservation, error) {
	if c == nil || !c.limits.valid() || !l.valid() || len(numbers) == 0 || len(numbers) > l.MaxBlocks {
		return nil, failure(InvalidCall)
	}
	queries := make([]HeaderQuery, len(numbers))
	seen := make(map[uint64]bool, len(numbers))
	for i, number := range numbers {
		if _, err := HistoryBlockNumber(number); err != nil || seen[number] {
			return nil, failure(InvalidCall)
		}
		seen[number] = true
		queries[i] = HeaderQuery{NumberOrTag: fmt.Sprintf("0x%x", number)}
	}
	// Admission happens before transport dispatch. Lowered member limits never
	// become fresh per-member credits when entering this shared operation.
	if c.limits.MaxRequests < DefaultHistoryBlockLimits().MaxRequests || l.MaxRequests < 4*len(numbers)+6 {
		return nil, failure(EvidenceLimit)
	}
	wireLimit := min(l.MaxTotalWireBytes, c.limits.MaxTotalWireBytes)
	ownedLimit := min(l.MaxObservationBytes, c.limits.MaxObservationBytes)
	postWire := int64((len(numbers)+1)*(16<<10) + 2*(4<<10))
	if wireLimit <= 2*postWire+2048 || ownedLimit < 512*len(numbers)+1024 {
		return nil, failure(EvidenceLimit)
	}
	ctx, cancel, err := fence.bind(parent, min(l.Timeout, c.limits.Timeout))
	if err != nil {
		return nil, err
	}
	defer cancel()
	deadline, _ := ctx.Deadline()
	postTime := min(500*time.Millisecond, time.Until(deadline)/4)
	bodyCtx, bodyCancel := context.WithDeadline(ctx, deadline.Add(-postTime))
	defer bodyCancel()
	budget := &namespaceWireBudget{base: c.transport, remaining: wireLimit, maxCalls: l.MaxRequests}
	headers, err := NewHeaderClient(budget, c.source, c.credential, HeaderLimits{Timeout: min(l.Timeout, c.limits.Timeout), MaxQueries: l.MaxBlocks, MaxHeaderBytes: 16 << 10})
	if err != nil {
		return nil, err
	}
	before, err := headers.Read(bodyCtx, queries)
	if err != nil {
		return nil, namespaceBudgetError(budget, err)
	}
	if !before.Synced() || len(before.headers) != len(numbers) {
		return nil, failure(InvalidEvidence)
	}
	blocks := make([]*HistoryBlockObservation, 0, len(numbers))
	owned := 512 * len(numbers) // bounded header and member-reference work
	for _, header := range before.headers {
		available := budget.remaining - postWire
		if available < 2048 || ownedLimit-owned < 1024 || !time.Now().Before(deadline.Add(-postTime)) {
			break
		}
		limits := c.limits
		limits.MaxObservationBytes = min(limits.MaxObservationBytes, ownedLimit-owned)
		// Both body envelopes, including each reader's overflow probe, must fit
		// below the post-header reserve before either body request is sent.
		limits.MaxBlockBytes = min(limits.MaxBlockBytes, available/2-1)
		limits.MaxReceiptSetBytes = min(limits.MaxReceiptSetBytes, available/2-1)
		block, err := c.readBody(bodyCtx, headers, header, limits)
		if err != nil {
			return nil, namespaceBudgetError(budget, err)
		}
		owned += block.ownedBytes
		blocks = append(blocks, block)
	}
	if len(blocks) == 0 {
		return nil, failure(EvidenceLimit)
	}
	after, err := headers.Read(ctx, queries[:len(blocks)])
	if err != nil {
		return nil, namespaceBudgetError(budget, err)
	}
	if !after.Synced() || len(after.headers) != len(blocks) || ctx.Err() != nil || !fence.live() {
		return nil, failure(InvalidEvidence)
	}
	for i, block := range blocks {
		if after.headers[i] != before.headers[i] {
			return nil, failure(InvalidEvidence)
		}
		selector, _ := HistoryBlockNumber(numbers[i])
		if _, err = c.finishBody(ctx, block, selector, fence.Deadline, fence.Done); err != nil {
			return nil, err
		}
	}
	if ctx.Err() != nil || !fence.live() {
		return nil, failure(NodeFailure)
	}
	return blocks, nil
}
