package rpcexecution

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
)

func (c *Client) AcquireMinedEnvelope(ctx context.Context, wanted common.Hash, l MinedTraceLimits) (*MinedEnvelope, error) {
	if c == nil || ctx == nil || !c.selected || !c.networkBound || c.binding.Profile != SimulationCallProfileID || wanted == (common.Hash{}) || !l.valid() {
		return nil, failure(InvalidBinding)
	}
	originalDone := ctx.Done()
	deadline := time.Now().Add(l.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	bounded, cancel, err := minedContext(ctx, deadline, originalDone)
	if err != nil {
		return nil, err
	}
	defer cancel()
	budget := &minedWireBudget{base: c.transport, remaining: l.MaxResponseBytes, maxCalls: l.MaxRequests}
	selected := *c
	selected.transport = budget
	selected.limits = l.Execution
	if err := minedNetwork(bounded, &selected); err != nil {
		return nil, err
	}
	raw, err := selected.rpcResultBounded(bounded, "eth_getTransactionByHash", []any{wanted.Hex()}, int64(l.historyLimits().MaxTransactionBytes), true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, ErrNotIncluded
	}
	if err := historyJSONShape(raw, l.historyLimits(), false); err != nil {
		return nil, err
	}
	fields, err := nullableRawObject(raw, 32, map[string]bool{"to": true, "blockHash": true, "blockNumber": true, "transactionIndex": true, "gasPrice": true, "maxFeePerGas": true, "maxPriorityFeePerGas": true, "chainId": true})
	if err != nil {
		return nil, err
	}
	pos, err := decodeIncludedPosition(fields)
	if err != nil {
		return nil, err
	}
	block, err := selected.rpcBounded(bounded, "eth_getBlockByHash", []any{pos.Hash.Hex(), false}, l.historyLimits().MaxBlockBytes)
	if err != nil {
		return nil, err
	}
	full, h, count, err := decodeMinedBlock(block, pos, wanted, l.historyLimits())
	if err != nil || h.Timestamp < c.binding.PragueStartInclusive || h.Timestamp >= c.binding.PragueEndExclusive {
		return nil, failure(InvalidEvidence)
	}
	tx, _, err := decodeHistoryTransaction(raw, pos, c.binding.ChainID, full, l.historyLimits())
	if err != nil || tx.Hash() != wanted {
		return nil, failure(InvalidEvidence)
	}
	if tx.Type() == 4 {
		return nil, failure(UnsupportedEvidence)
	}
	raw, err = selected.rpcResultBounded(bounded, "eth_getTransactionReceipt", []any{wanted.Hex()}, int64(l.historyLimits().MaxReceiptBytes), true)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, ErrNotIncluded
	}
	pos.Timestamp, pos.TimestampKnown = h.Timestamp, true
	receipt, _, err := decodeSparseHistoryReceipt(raw, tx, pos, full, l.historyLimits())
	if err != nil || !receipt.statusPresent {
		return nil, failure(InvalidEvidence)
	}
	if err := minedCanonical(bounded, &selected, h); err != nil {
		return nil, err
	}
	if bounded.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &MinedEnvelope{source: &selected, budget: budget, limits: l, transaction: tx, header: h, index: pos.Index, count: count, success: receipt.status == 1, deadline: deadline, done: originalDone, traceAttempt: &atomic.Bool{}}, nil
}

func (p *MinedEnvelope) AcquireTrace(ctx context.Context, topOnly bool) (*MinedExecution, error) {
	if p == nil || p.source == nil || p.budget == nil || p.traceAttempt == nil || !p.traceAttempt.CompareAndSwap(false, true) {
		return nil, failure(InvalidBinding)
	}
	ctx, cancel, err := minedContext(ctx, p.deadline, p.done)
	if err != nil {
		return nil, err
	}
	defer cancel()
	config := map[string]any{"tracer": "muxTracer", "tracerConfig": map[string]any{"callTracer": map[string]any{"onlyTopCall": topOnly, "withLog": false}, "prestateTracer": map[string]any{"diffMode": false, "disableCode": false, "disableStorage": true, "includeEmpty": true}, "flatCallTracer": map[string]any{"includePrecompiles": true}}}
	raw, err := p.source.rpcBounded(ctx, "debug_traceTransaction", []any{p.transaction.Hash().Hex(), config}, p.limits.Execution.MaxMuxBytes)
	if err != nil {
		return nil, err
	}
	parts, err := closedRawObject(raw, 3)
	if err != nil || len(parts) != 3 || parts["callTracer"] == nil || parts["prestateTracer"] == nil || parts["flatCallTracer"] == nil {
		return nil, failure(InvalidEvidence)
	}
	// Release the original MUX and context child before tree/code construction.
	raw = nil
	if err := validateMinedTraceContext(parts["flatCallTracer"], p); err != nil {
		return nil, err
	}
	delete(parts, "flatCallTracer")
	tx := p.transaction
	expected := executionfacts.ExpectedRoot{Kind: executionfacts.Call, From: tx.From(), Input: tx.Input(), Value: tx.Value()}
	if to, ok := tx.To(); ok {
		expected.To = executionfacts.Address{Value: to, Known: true}
	} else {
		expected.Kind = executionfacts.Create
		expected.CreatedAddress = executionfacts.Address{Value: crypto.CreateAddress(tx.From(), tx.Nonce()), Known: true}
	}
	tree, err := executionfacts.Parse(parts["callTracer"], expected, executionfacts.GethLifecycleWithLogsProfile(), p.limits.Execution.Trace)
	if err != nil {
		return nil, failure(InvalidEvidence)
	}
	records := tree.Records()
	if len(records) == 0 || topOnly && len(records) != 1 || (!records[0].Failed()) != p.success {
		return nil, failure(InvalidEvidence)
	}
	codes, total, err := decodePrestate(parts["prestateTracer"], p.limits.Execution)
	if err != nil {
		return nil, err
	}
	for _, c := range codes {
		if c.Delegated() {
			return nil, failure(UnsupportedEvidence)
		}
	}
	if expected.Kind == executionfacts.Create {
		sender, ok := codes[tx.From()]
		if !ok || !sender.nonceKnown || sender.nonce != tx.Nonce() {
			return nil, failure(InvalidEvidence)
		}
	}
	ensure := func(a common.Address, needNonce bool) (CodeInfo, error) {
		c, ok := codes[a]
		if !ok && precompile(a) && !needNonce {
			c = CodeInfo{hash: crypto.Keccak256Hash(nil), precompile: true}
			codes[a] = c
			return c, nil
		}
		if !ok || needNonce && !c.nonceKnown {
			return CodeInfo{}, failure(UnsupportedEvidence)
		}
		if c.Delegated() {
			return CodeInfo{}, failure(UnsupportedEvidence)
		}
		return c, nil
	}
	timeline, err := buildTimeline(ctx, records, &total, p.limits.Execution, ensure)
	if err != nil {
		return nil, err
	}
	if err := minedCanonical(ctx, p.source, p.header); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return &MinedExecution{envelope: p, topOnly: topOnly, tree: tree, codes: codes, timeline: timeline, child: parts["callTracer"]}, nil
}

// RequireEvaluationCurrent runs after current-association SQL and before native
// evaluation. Delivery reserves remain unavailable to this bounded stage.
func (e *MinedExecution) RequireEvaluationCurrent(ctx context.Context, observer creationfacts.Header) error {
	if !e.valid() {
		return failure(InvalidEvidence)
	}
	p := e.envelope
	p.budget.advance(1)
	if err := minedCanonical(ctx, p.source, p.header); err != nil {
		return err
	}
	if observer != (creationfacts.Header{}) && !minedHeaderMatches(p.header, observer) {
		return minedCanonical(ctx, p.source, observer)
	}
	return ctx.Err()
}
