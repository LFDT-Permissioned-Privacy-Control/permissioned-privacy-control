package rpcexecution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"privacy-proxy/internal/creationfacts"
)

// HistoryOperationFence carries values from the original owning request, not
// a temporary acquisition context or a caller's authentication/body values.
type HistoryOperationFence struct {
	Deadline time.Time
	Done     <-chan struct{}
}

func (f HistoryOperationFence) live() bool {
	if f.Deadline.IsZero() || !time.Now().Before(f.Deadline) {
		return false
	}
	select {
	case <-f.Done:
		return false
	default:
		return true
	}
}
func (f HistoryOperationFence) bind(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil || !f.live() {
		return nil, nil, failure(NodeFailure)
	}
	deadline := minTime(f.Deadline, time.Now().Add(timeout))
	ctx, cancel := context.WithDeadline(parent, deadline)
	if f.Done != nil {
		go func() {
			select {
			case <-f.Done:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel, nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// This one budget is shared by direct/batched acquisition, CB1 composition,
// metadata reservation and all final probes. No stage restarts its counters.
type historyReadBudget struct {
	mu                       sync.Mutex
	base                     Transport
	limits                   HistoryReadLimits
	physical, items, charged int
	wire                     int64
	exceeded                 bool
}

func (b *historyReadBudget) reserveItems(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limits.MaxRPCItems-b.items {
		b.exceeded = true
		return failure(EvidenceLimit)
	}
	b.items += n
	return nil
}
func (b *historyReadBudget) reserveOwned(n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > b.limits.MaxChargedBytes-b.charged {
		b.exceeded = true
		return failure(EvidenceLimit)
	}
	b.charged += n
	return nil
}
func (b *historyReadBudget) RoundTrip(r *http.Request) (*http.Response, error) {
	b.mu.Lock()
	if b.physical >= b.limits.MaxHTTPAttempts || b.wire >= b.limits.MaxWireBytes {
		b.exceeded = true
		b.mu.Unlock()
		return nil, failure(EvidenceLimit)
	}
	b.physical++
	b.mu.Unlock()
	response, err := b.base.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	copy := *response
	copy.Body = &historyReadCountedBody{body: response.Body, budget: b}
	return &copy, nil
}

type historyReadCountedBody struct {
	body   io.ReadCloser
	budget *historyReadBudget
}

func (r *historyReadCountedBody) Read(p []byte) (int, error) {
	b := r.budget
	b.mu.Lock()
	left := b.limits.MaxWireBytes - b.wire
	if left < 0 {
		b.mu.Unlock()
		return 0, failure(EvidenceLimit)
	}
	if int64(len(p)) > left+1 {
		p = p[:left+1]
	}
	// Serialize body reads with the shared wire counter. Even an accidental
	// concurrent consumer cannot spend the same remaining bytes twice.
	n, err := r.body.Read(p)
	b.wire += int64(n)
	if b.wire > b.limits.MaxWireBytes {
		b.exceeded = true
		err = failure(EvidenceLimit)
	}
	b.mu.Unlock()
	return n, err
}
func (r *historyReadCountedBody) Close() error { return r.body.Close() }

type historySingleTransport struct{ budget *historyReadBudget }

// CB1 counts a complete single-response envelope against its selected limit.
// Keep that conservative convention when composed under a lower outer result
// ceiling, including CB1's fixed network/header probes.
type historyReadLimitedBody struct {
	body   io.ReadCloser
	budget *historyReadBudget
	left   int64
}

func (r *historyReadLimitedBody) Read(p []byte) (int, error) {
	if r.left < 0 {
		return 0, failure(EvidenceLimit)
	}
	if int64(len(p)) > r.left+1 {
		p = p[:r.left+1]
	}
	n, err := r.body.Read(p)
	r.left -= int64(n)
	if r.left < 0 {
		r.budget.mu.Lock()
		r.budget.exceeded = true
		r.budget.mu.Unlock()
		err = failure(EvidenceLimit)
	}
	return n, err
}
func (r *historyReadLimitedBody) Close() error { return r.body.Close() }

func (t historySingleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.budget.reserveItems(1); err != nil {
		return nil, err
	}
	response, err := t.budget.RoundTrip(r)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	copy := *response
	copy.Body = &historyReadLimitedBody{body: response.Body, budget: t.budget, left: t.budget.limits.MaxResultBytes}
	return &copy, nil
}

type historyRPCItem struct {
	method   string
	params   []any
	maxBytes int64
}
type HistoryReadClient struct {
	transport  Transport
	source     creationfacts.Source
	credential Credential
	limits     HistoryReadLimits
}

func NewHistoryReadClient(transport Transport, source creationfacts.Source, credential Credential, limits HistoryReadLimits) (*HistoryReadClient, error) {
	if !limits.valid() {
		return nil, failure(InvalidBinding)
	}
	if _, err := NewHistoryBlockClient(transport, source, credential, limits.Block); err != nil {
		return nil, err
	}
	return &HistoryReadClient{transport, source, credential, limits}, nil
}
func (c *HistoryReadClient) Source() creationfacts.Source {
	if c == nil {
		return creationfacts.Source{}
	}
	return c.source
}
func (c *HistoryReadClient) Bounds() HistoryReadLimits {
	if c == nil {
		return HistoryReadLimits{}
	}
	return c.limits
}

// batch is private fixed-method acquisition, never user-selected passthrough.
// A duplicate/missing/error item invalidates the WHOLE response. Returned wire
// fragments are consumed by typed decoders and never exposed as response bytes.
func (c *HistoryReadClient) batch(ctx context.Context, budget *historyReadBudget, items []historyRPCItem) ([]json.RawMessage, error) {
	if c == nil || ctx == nil || budget == nil || len(items) == 0 || len(items) > c.limits.MaxRPCItems {
		return nil, failure(InvalidCall)
	}
	// A selected lower batch ceiling changes physical grouping, not supported
	// fixed methods. All groups spend the original budget; a later failure
	// discards every staged result and cannot publish a partial population.
	if len(items) > c.limits.MaxBatchItems {
		var out []json.RawMessage
		for start := 0; start < len(items); start += c.limits.MaxBatchItems {
			end := min(start+c.limits.MaxBatchItems, len(items))
			part, err := c.batch(ctx, budget, items[start:end])
			if err != nil {
				return nil, err
			}
			out = append(out, part...)
		}
		return out, nil
	}
	if err := budget.reserveItems(len(items)); err != nil {
		return nil, err
	}
	type request struct {
		JSONRPC string `json:"jsonrpc"`
		ID      string `json:"id"`
		Method  string `json:"method"`
		Params  []any  `json:"params"`
	}
	requests := make([]request, len(items))
	expected := map[string]int{}
	effective := make([]int64, len(items))
	// The array punctuation and each bounded response envelope are charged before
	// reading. A small selected item cannot consume the full operation wire cap.
	bodyLimit := int64(2 + len(items))
	maxEnvelope := int64(0)
	for i, item := range items {
		if item.method == "" || item.maxBytes <= 0 {
			return nil, failure(InvalidCall)
		}
		effective[i] = min(item.maxBytes, c.limits.MaxResultBytes)
		envelope := effective[i] + 4096
		bodyLimit += envelope
		maxEnvelope = max(maxEnvelope, envelope)
		id := "h1:" + strconv.Itoa(i)
		requests[i] = request{"2.0", id, item.method, item.params}
		expected[id] = i
	}
	raw, err := json.Marshal(requests)
	if err != nil {
		return nil, failure(InvalidCall)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.source.URL, bytes.NewReader(raw))
	if err != nil {
		return nil, failure(NodeFailure)
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	if c.credential.Header != "" {
		req.Header.Set(c.credential.Header, c.credential.Value)
	}
	response, err := budget.RoundTrip(req)
	if err != nil {
		return nil, c.budgetError(budget, err)
	}
	if response == nil || response.Body == nil {
		return nil, failure(NodeFailure)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, failure(NodeFailure)
	}
	// The operation wire counter remains shared across all stages. This smaller
	// body limit is conjunctive and bounds parser input before per-ID decoding.
	bodyLimit = min(bodyLimit, c.limits.MaxWireBytes)
	raw, err = io.ReadAll(io.LimitReader(response.Body, bodyLimit+1))
	if err != nil {
		return nil, c.budgetError(budget, err)
	}
	if int64(len(raw)) > bodyLimit {
		return nil, failure(EvidenceLimit)
	}
	out := make([]json.RawMessage, len(items))
	seen := make([]bool, len(items))
	count := 0
	err = includedArray(raw, len(items), func(message json.RawMessage) error {
		count++
		// Envelope metadata cannot consume the entire wire ceiling before its
		// fixed ID/version are checked. Result-specific bounds follow the ID.
		if int64(len(message)) > maxEnvelope {
			return failure(EvidenceLimit)
		}
		fields, err := nullableRawObject(message, 4, map[string]bool{"result": true})
		if err != nil {
			return err
		}
		for field := range fields {
			if field != "jsonrpc" && field != "id" && field != "result" && field != "error" {
				return failure(InvalidEvidence)
			}
		}
		var id, version string
		if len(fields["id"]) > 32 || len(fields["jsonrpc"]) > 32 {
			return failure(InvalidEvidence)
		}
		if json.Unmarshal(fields["id"], &id) != nil || json.Unmarshal(fields["jsonrpc"], &version) != nil || version != "2.0" {
			return failure(InvalidEvidence)
		}
		i, known := expected[id]
		if !known || seen[i] {
			return failure(InvalidEvidence)
		}
		seen[i] = true
		result, present := fields["result"]
		if _, bad := fields["error"]; bad {
			return failure(NodeFailure)
		}
		if !present {
			return failure(InvalidEvidence)
		}
		if int64(len(result)) > effective[i] {
			return failure(EvidenceLimit)
		}
		out[i] = result
		return nil
	})
	if err != nil {
		return nil, err
	}
	if count != len(items) {
		return nil, failure(InvalidEvidence)
	}
	if ctx.Err() != nil {
		return nil, failure(NodeFailure)
	}
	return out, nil
}
func (c *HistoryReadClient) budgetError(b *historyReadBudget, err error) error {
	b.mu.Lock()
	exceeded := b.exceeded
	b.mu.Unlock()
	if exceeded {
		return failure(EvidenceLimit)
	}
	return failure(NodeFailure)
}

func historyNumber(n uint64) string { return fmt.Sprintf("0x%x", n) }
