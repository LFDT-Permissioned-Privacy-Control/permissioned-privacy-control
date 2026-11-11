package rpcexecution

import (
	"bytes"
	"context"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/networkidentity"
)

const MinedClientTraceProfileID = "geth-prague-mined-client-trace/v1"

// MinedTraceLimits apply to both acquisition stages and the final source
// checkpoint. They do not change simulation or protected-send profiles.
type MinedTraceLimits struct {
	Timeout                                                                                   time.Duration
	MaxRequests                                                                               int
	MaxResponseBytes                                                                          int64
	MaxTransactionBytes, MaxSignedBytes, MaxReceiptBytes                                      int
	MaxBlockBytes                                                                             int64
	MaxBlockTransactions, MaxReceiptLogs, MaxAccessEntries, MaxStorageKeys, MaxAuthorizations int
	Execution                                                                                 Limits
}

func DefaultMinedTraceLimits() MinedTraceLimits {
	h := DefaultHistoryBlockLimits()
	return MinedTraceLimits{Timeout: 15 * time.Second, MaxRequests: 24, MaxResponseBytes: 32 << 20, MaxTransactionBytes: h.MaxTransactionBytes, MaxSignedBytes: h.MaxSignedBytes, MaxReceiptBytes: h.MaxReceiptBytes, MaxBlockBytes: h.MaxBlockBytes, MaxBlockTransactions: h.MaxTransactions, MaxReceiptLogs: h.MaxLogs, MaxAccessEntries: h.MaxAccessEntries, MaxStorageKeys: h.MaxStorageKeys, MaxAuthorizations: h.MaxAuthorizations, Execution: DefaultLimits()}
}
func (l MinedTraceLimits) historyLimits() HistoryBlockLimits {
	h := DefaultHistoryBlockLimits()
	h.MaxTransactionBytes, h.MaxSignedBytes, h.MaxReceiptBytes = l.MaxTransactionBytes, l.MaxSignedBytes, l.MaxReceiptBytes
	h.MaxBlockBytes, h.MaxTransactions, h.MaxLogs = l.MaxBlockBytes, l.MaxBlockTransactions, l.MaxReceiptLogs
	h.MaxAccessEntries, h.MaxStorageKeys, h.MaxAuthorizations = l.MaxAccessEntries, l.MaxStorageKeys, l.MaxAuthorizations
	return h
}
func (l MinedTraceLimits) Valid() bool { return l.valid() }
func (l MinedTraceLimits) valid() bool {
	d := DefaultMinedTraceLimits()
	return l.Timeout > 0 && l.Timeout <= d.Timeout && l.MaxRequests >= 16 && l.MaxRequests <= d.MaxRequests && l.MaxResponseBytes > 0 && l.MaxResponseBytes <= d.MaxResponseBytes && l.historyLimits().valid() && lifecycleLimits(l.Execution)
}

// MinedEnvelope is a genuine included signed-history observation. Its source,
// ordinal and receipt cannot be supplied by an RPC caller or substituted
// between stages. A shared attempt bit also survives a copied envelope value.
type MinedEnvelope struct {
	source       *Client
	budget       *minedWireBudget
	limits       MinedTraceLimits
	transaction  HistoryTransaction
	header       creationfacts.Header
	index, count uint32
	success      bool
	deadline     time.Time
	done         <-chan struct{}
	traceAttempt *atomic.Bool
}

func (e *MinedEnvelope) Transaction() HistoryTransaction {
	if e == nil {
		return HistoryTransaction{}
	}
	return e.transaction
}
func (e *MinedEnvelope) Inclusion() (creationfacts.Header, uint32, uint32) {
	if e == nil {
		return creationfacts.Header{}, 0, 0
	}
	return e.header, e.index, e.count
}
func (e *MinedEnvelope) Successful() bool { return e != nil && e.success }

type MinedExecution struct {
	envelope *MinedEnvelope
	topOnly  bool
	tree     *executionfacts.Tree
	codes    map[common.Address]CodeInfo
	timeline *codeTimeline
	child    []byte
}

func (e *MinedExecution) valid() bool {
	return e != nil && e.envelope != nil && e.envelope.source != nil && e.envelope.traceAttempt != nil && e.envelope.traceAttempt.Load() && e.tree != nil && e.timeline != nil
}
func (e *MinedExecution) Purpose() string {
	if !e.valid() {
		return ""
	}
	return MinedClientTraceProfileID
}
func (e *MinedExecution) TopOnly() bool { return e.valid() && e.topOnly }
func (e *MinedExecution) TransactionHash() common.Hash {
	if !e.valid() {
		return common.Hash{}
	}
	return e.envelope.transaction.Hash()
}
func (e *MinedExecution) VerifiedSigner() common.Address {
	if !e.valid() {
		return common.Address{}
	}
	return e.envelope.transaction.From()
}
func (e *MinedExecution) Transaction() HistoryTransaction {
	if !e.valid() {
		return HistoryTransaction{}
	}
	return e.envelope.transaction
}
func (e *MinedExecution) InclusionIndex() uint32 {
	if !e.valid() {
		return 0
	}
	return e.envelope.index
}
func (e *MinedExecution) Anchor() Anchor {
	if !e.valid() {
		return Anchor{}
	}
	h, s := e.envelope.header, e.envelope.source
	return Anchor{Hash: h.Hash, Number: h.Number, Timestamp: h.Timestamp, ChainID: s.binding.ChainID, Profile: MinedClientTraceProfileID, OrganizationID: s.binding.OrganizationID}
}
func (e *MinedExecution) Tree() *executionfacts.Tree {
	if !e.valid() {
		return nil
	}
	return e.tree
}
func (e *MinedExecution) Code(a common.Address) (CodeInfo, bool) {
	if !e.valid() {
		return CodeInfo{}, false
	}
	c, ok := e.codes[a]
	return c, ok
}
func (e *MinedExecution) RecordCount() int {
	if !e.valid() {
		return 0
	}
	return len(e.timeline.frames)
}
func (e *MinedExecution) QualificationWork() uint64 {
	if !e.valid() {
		return 0
	}
	return e.timeline.work
}
func (e *MinedExecution) FrameCode(i int) (CodeInfo, bool) {
	if !e.valid() {
		return CodeInfo{}, false
	}
	return timelineFrame(e.timeline, i)
}
func (e *MinedExecution) RuntimeCodeAt(i int, a common.Address) (CodeInfo, bool) {
	if !e.valid() {
		return CodeInfo{}, false
	}
	return timelineRuntime(e.timeline, e.codes, i, a)
}
func (e *MinedExecution) CreationContext(i int) (CreationContext, bool) {
	if !e.valid() {
		return CreationContext{}, false
	}
	return timelineCreation(e.timeline, i)
}
func (e *MinedExecution) CallTraceJSON() ([]byte, error) {
	if !e.valid() || len(e.child) == 0 || len(e.child) > 8<<20 {
		return nil, failure(InvalidEvidence)
	}
	return bytes.Clone(e.child), nil
}

// The delivery object deliberately retains no envelope, transaction, tree,
// prestate, code or acquisition child context.
type MinedTraceCheckpoint struct {
	source *Client
	budget *minedWireBudget
	header creationfacts.Header
	hash   common.Hash
	index  uint32
}

func (e *MinedExecution) DeliveryCheckpoint() (*MinedTraceCheckpoint, error) {
	if !e.valid() {
		return nil, failure(InvalidEvidence)
	}
	p := e.envelope
	return &MinedTraceCheckpoint{p.source, p.budget, p.header, p.transaction.Hash(), p.index}, nil
}
func (p *MinedTraceCheckpoint) BoundNetwork() (networkidentity.Binding, bool) {
	if p == nil || p.source == nil {
		return networkidentity.Binding{}, false
	}
	return p.source.BoundNetwork()
}
func (p *MinedTraceCheckpoint) RequireCurrent(ctx context.Context, observer creationfacts.Header) error {
	if p == nil || p.source == nil || p.budget == nil || !p.header.Valid() || p.hash == (common.Hash{}) || ctx == nil {
		return failure(InvalidBinding)
	}
	p.budget.advance(2)
	if err := minedNetwork(ctx, p.source); err != nil {
		return err
	}
	if err := minedCanonical(ctx, p.source, p.header); err != nil {
		return err
	}
	if observer != (creationfacts.Header{}) && observer != p.header {
		if err := minedCanonical(ctx, p.source, observer); err != nil {
			return err
		}
	}
	return ctx.Err()
}
