package rpcexecution

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

// Physical attempts and response envelopes share one budget through both
// stages and delivery. Reserve the final checks before any expensive trace.
type minedWireBudget struct {
	mu                     sync.Mutex
	base                   Transport
	remaining              int64
	calls, maxCalls, phase int
}

func (b *minedWireBudget) advance(phase int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if phase > b.phase {
		b.phase = phase
	}
}
func (b *minedWireBudget) RoundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	reserve, reserveBytes := 7, int64(128<<10)
	if b.phase == 1 {
		reserve, reserveBytes = 5, 96<<10
	}
	if b.phase == 2 {
		reserve, reserveBytes = 0, 0
	}
	if b.calls >= b.maxCalls-reserve || b.remaining <= reserveBytes {
		b.mu.Unlock()
		return nil, failure(EvidenceLimit)
	}
	b.calls++
	b.mu.Unlock()
	rsp, err := b.base.RoundTrip(r)
	if err != nil || rsp == nil || rsp.Body == nil {
		return rsp, err
	}
	owned := *rsp
	owned.Body = &minedCountedBody{rsp.Body, b}
	return &owned, nil
}

type minedCountedBody struct {
	body   io.ReadCloser
	budget *minedWireBudget
}

func (b *minedCountedBody) Read(p []byte) (int, error) {
	b.budget.mu.Lock()
	left := b.budget.remaining
	b.budget.mu.Unlock()
	if left < 0 {
		return 0, failure(EvidenceLimit)
	}
	if int64(len(p)) > left+1 {
		p = p[:left+1]
	}
	n, err := b.body.Read(p)
	b.budget.mu.Lock()
	b.budget.remaining -= int64(n)
	over := b.budget.remaining < 0
	b.budget.mu.Unlock()
	if over {
		return n, failure(EvidenceLimit)
	}
	return n, err
}
func (b *minedCountedBody) Close() error { return b.body.Close() }

func minedContext(parent context.Context, deadline time.Time, done <-chan struct{}) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || !time.Now().Before(deadline) {
		return nil, nil, failure(NodeFailure)
	}
	select {
	case <-done:
		return nil, nil, failure(NodeFailure)
	default:
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	if done == nil {
		return ctx, cancel, nil
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, func() { cancel(); <-stopped }, nil
}
func minedNetwork(ctx context.Context, c *Client) error {
	if c == nil || !c.selected || !c.networkBound {
		return failure(InvalidBinding)
	}
	if err := c.RequireBoundNetwork(ctx); err != nil {
		return err
	}
	raw, err := c.rpcBounded(ctx, "eth_syncing", []any{}, 4<<10)
	if err != nil {
		return err
	}
	synced, err := decodeHeaderSync(raw)
	if err != nil || !synced {
		return failure(InvalidEvidence)
	}
	return ctx.Err()
}
func minedCanonical(ctx context.Context, c *Client, h creationfacts.Header) error {
	if c == nil || !h.Valid() || ctx.Err() != nil {
		return failure(InvalidBinding)
	}
	raw, err := c.rpcBounded(ctx, "eth_getHeaderByNumber", []any{"0x" + strconv.FormatUint(h.Number, 16)}, 16<<10)
	if err != nil {
		return err
	}
	actual, err := decodeQualifiedHeader(raw)
	if err != nil || actual != h {
		return failure(InvalidEvidence)
	}
	return ctx.Err()
}

func decodeMinedBlock(raw []byte, pos includedPosition, wanted common.Hash, l HistoryBlockLimits) (*types.Header, creationfacts.Header, uint32, error) {
	zero := creationfacts.Header{}
	if int64(len(raw)) > l.MaxBlockBytes {
		return nil, zero, 0, failure(EvidenceLimit)
	}
	f, err := nullableRawObject(raw, 40, map[string]bool{"baseFeePerGas": true, "withdrawalsRoot": true, "blobGasUsed": true, "excessBlobGas": true, "parentBeaconBlockRoot": true, "requestsHash": true, "totalDifficulty": true, "size": true, "blockAccessListHash": true, "slotNumber": true})
	if err != nil {
		return nil, zero, 0, err
	}
	list, ok := f["transactions"]
	if !ok {
		return nil, zero, 0, failure(InvalidEvidence)
	}
	delete(f, "transactions")
	count, seen := uint32(0), false
	err = includedArray(list, l.MaxTransactions, func(raw json.RawMessage) error {
		b, err := includedData(raw, 32)
		if err != nil {
			return err
		}
		h := common.BytesToHash(b)
		if h == (common.Hash{}) || h == wanted && (seen || count != pos.Index) || count == pos.Index && h != wanted {
			return failure(InvalidEvidence)
		}
		if h == wanted {
			seen = true
		}
		count++
		return nil
	})
	if err != nil || !seen {
		return nil, zero, 0, failure(InvalidEvidence)
	}
	for _, name := range []string{"uncles", "withdrawals"} {
		if v, ok := f[name]; ok {
			if err := includedArray(v, 8192, func(json.RawMessage) error { return nil }); err != nil {
				return nil, zero, 0, err
			}
			delete(f, name)
		}
	}
	headerRaw, err := json.Marshal(f)
	if err != nil {
		return nil, zero, 0, failure(InvalidEvidence)
	}
	h, err := decodeQualifiedHeader(headerRaw)
	if err != nil || h.Hash != pos.Hash || h.Number != pos.Number || pos.TimestampKnown && h.Timestamp != pos.Timestamp {
		return nil, zero, 0, failure(InvalidEvidence)
	}
	var full types.Header
	if json.Unmarshal(headerRaw, &full) != nil || full.Hash() != h.Hash {
		return nil, zero, 0, failure(InvalidEvidence)
	}
	return &full, h, count, nil
}
