package rpcexecution

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

type HistoryReadKind uint8

const (
	HistoryNotFound HistoryReadKind = iota + 1
	HistoryCanonical
	HistoryLocated
	HistoryPending
)

// HistoryLocation is the node's explicit location, not an inclusion proof.
// Pending tuples keep their actual independent null/present fields. Ordinary
// Located observations have no C2 ROOT/TxCount/consensus conversion.
type HistoryLocation struct {
	BlockHash                                common.Hash
	BlockNumber                              uint64
	TransactionIndex                         uint32
	HashPresent, NumberPresent, IndexPresent bool
}

type LocatedHistoryTransaction struct {
	Transaction HistoryTransaction
	Location    HistoryLocation
	GasPrice    *big.Int
}

// SignedFieldsJSON serializes the owned verified typed signed envelope. It
// contains no node response bytes, location, from, policy or grant. A serving
// owner adds its actual location/from only after its own admission decision.
func (t HistoryTransaction) SignedFieldsJSON() ([]byte, error) {
	if t.tx == nil {
		return nil, failure(InvalidEvidence)
	}
	return t.tx.MarshalJSON()
}

type LocatedHistoryReceipt struct {
	Receipt         HistoryReceipt
	TransactionHash common.Hash
	Location        HistoryLocation
}
type LocatedHistoryLog struct {
	Log             HistoryLog
	TransactionHash common.Hash
	Location        HistoryLocation
	Removed         bool
}

// PendingHistoryBlock deliberately has no canonical hash accessor. Present
// fields retain actual node metadata; normalized Header is an owned typed
// parsing container, with its hash/nonce/miner presence recorded separately.
type PendingHistoryBlock struct {
	Header                                  *types.Header
	Hash                                    common.Hash
	HashPresent, NoncePresent, MinerPresent bool
	Uncles                                  []common.Hash
	Withdrawals                             []*types.Withdrawal
	ReportedSize                            uint64
	SizePresence                            HistoryFieldPresence
	TotalDifficulty                         *big.Int
	TDPresence                              HistoryFieldPresence
}

// LocatedHistoryBlock is a detached data view. It cannot be passed to CB1's
// Recheck or used as a canonical block/C2 authority token.
type LocatedHistoryBlock struct {
	Header          *types.Header
	Uncles          []common.Hash
	Withdrawals     []*types.Withdrawal
	ReportedSize    uint64
	SizePresence    HistoryFieldPresence
	TotalDifficulty *big.Int
	TDPresence      HistoryFieldPresence
}

type HistoryReadObservation struct {
	owner        *HistoryReadClient
	source       creationfacts.Source
	query        HistoryReadQuery
	kind         HistoryReadKind
	fence        HistoryOperationFence
	budget       *historyReadBudget
	transactions []LocatedHistoryTransaction
	receipts     []LocatedHistoryReceipt
	logs         []LocatedHistoryLog
	block        *HistoryBlockObservation
	pending      *PendingHistoryBlock
	headers      map[common.Hash]*types.Header
	canonical    map[uint64]common.Hash
	digest       common.Hash
}

func (o *HistoryReadObservation) valid() bool {
	return o != nil && o.owner != nil && o.budget != nil && o.kind >= HistoryNotFound && o.kind <= HistoryPending && o.digest != (common.Hash{})
}
func (o *HistoryReadObservation) Kind() HistoryReadKind {
	if !o.valid() {
		return 0
	}
	return o.kind
}
func (o *HistoryReadObservation) Source() creationfacts.Source {
	if !o.valid() {
		return creationfacts.Source{}
	}
	return o.source
}
func (o *HistoryReadObservation) Digest() common.Hash {
	if !o.valid() {
		return common.Hash{}
	}
	return o.digest
}

// ReserveWorkingBytes charges an owning renderer's bounded metadata/matcher
// working set before its copies/parsing. It grants no source/authorization
// fact, never refunds a prior reservation, and never resets transport counters.
func (o *HistoryReadObservation) ReserveWorkingBytes(n int) error {
	if !o.valid() || !o.fence.live() {
		return failure(InvalidBinding)
	}
	return o.budget.reserveOwned(n)
}
func (o *HistoryReadObservation) RemainingWorkingBytes() int {
	if !o.valid() || !o.fence.live() {
		return 0
	}
	o.budget.mu.Lock()
	defer o.budget.mu.Unlock()
	return o.budget.limits.MaxChargedBytes - o.budget.charged
}
func (o *HistoryReadObservation) HasLogs() bool {
	if !o.valid() {
		return false
	}
	if len(o.logs) > 0 {
		return true
	}
	for _, r := range o.receipts {
		if len(r.Receipt.logs) > 0 {
			return true
		}
	}
	return false
}

// RenderWorkingBytes is a conservative pre-copy allowance for detached model
// slices, hex projections and the final JSON value. It counts variable signed
// payloads (including access/authorization lists), every receipt log and the
// direct log population. It is a logical work bound, not a heap/RSS promise.
func (o *HistoryReadObservation) RenderWorkingBytes() int {
	if !o.valid() {
		return 0
	}
	n := 16 << 10
	for _, t := range o.transactions {
		n += 2048 + 6*len(t.Transaction.signed)
	}
	for _, r := range o.receipts {
		n += 2048
		for _, l := range r.Receipt.logs {
			n += 1024 + 4*len(l.Data) + 256*len(l.Topics)
		}
	}
	for _, l := range o.logs {
		n += 1024 + 4*len(l.Log.Data) + 256*len(l.Log.Topics)
	}
	return n
}
func (o *HistoryReadObservation) Transactions() []LocatedHistoryTransaction {
	if !o.valid() {
		return nil
	}
	out := append([]LocatedHistoryTransaction{}, o.transactions...)
	for i := range out {
		out[i].GasPrice = historyBigCopy(out[i].GasPrice)
	}
	return out
}
func (o *HistoryReadObservation) Receipts() []LocatedHistoryReceipt {
	if !o.valid() {
		return nil
	}
	// HistoryReceipt exposes mutable values only through detached getters.
	return append([]LocatedHistoryReceipt{}, o.receipts...)
}
func (o *HistoryReadObservation) Logs() []LocatedHistoryLog {
	if !o.valid() {
		return nil
	}
	out := append([]LocatedHistoryLog{}, o.logs...)
	for i := range out {
		out[i].Log.Data = bytes.Clone(out[i].Log.Data)
		out[i].Log.Topics = append([]common.Hash{}, out[i].Log.Topics...)
	}
	return out
}
func (o *HistoryReadObservation) Block() (*HistoryBlockObservation, bool) {
	if !o.valid() || o.kind != HistoryCanonical || o.block == nil || !o.block.valid() {
		return nil, false
	}
	return o.block, true
}
func (o *HistoryReadObservation) BlockData() (LocatedHistoryBlock, bool) {
	if !o.valid() || o.block == nil {
		return LocatedHistoryBlock{}, false
	}
	b := o.block
	return LocatedHistoryBlock{types.CopyHeader(b.header), append([]common.Hash{}, b.uncles...), copyHistoryWithdrawals(b.withdrawals), b.reportedSize, b.sizePresence, historyBigCopy(b.totalDifficulty), b.tdPresence}, true
}
func copyHistoryWithdrawals(in []*types.Withdrawal) []*types.Withdrawal {
	if in == nil {
		return nil
	}
	out := make([]*types.Withdrawal, len(in))
	for i, v := range in {
		copy := *v
		out[i] = &copy
	}
	return out
}
func (o *HistoryReadObservation) PendingBlock() (PendingHistoryBlock, bool) {
	if !o.valid() || o.pending == nil {
		return PendingHistoryBlock{}, false
	}
	p := *o.pending
	p.Header = types.CopyHeader(p.Header)
	p.Uncles = append([]common.Hash{}, p.Uncles...)
	p.Withdrawals = copyHistoryWithdrawals(p.Withdrawals)
	p.TotalDifficulty = historyBigCopy(p.TotalDifficulty)
	return p, true
}

func historyReadDigest(o *HistoryReadObservation) (common.Hash, error) {
	h := sha256.New()
	enc := json.NewEncoder(h)
	if err := enc.Encode(struct {
		Domain string
		Source creationfacts.Digest
		Query  [32]byte
		Kind   HistoryReadKind
	}{"ops-history-read/v1", o.source.Digest(), o.query.digest, o.kind}); err != nil {
		return common.Hash{}, err
	}
	if o.block != nil {
		d, err := historyObservationDigest(o.block)
		if err != nil {
			return common.Hash{}, err
		}
		if err = enc.Encode(d); err != nil {
			return common.Hash{}, err
		}
	}
	if err := enc.Encode(o.pending); err != nil {
		return common.Hash{}, err
	}
	for _, t := range o.transactions {
		if err := enc.Encode(struct {
			Signed   []byte
			From     common.Address
			Location HistoryLocation
			GasPrice *big.Int
		}{t.Transaction.signed, t.Transaction.from, t.Location, t.GasPrice}); err != nil {
			return common.Hash{}, err
		}
	}
	// Receipt fields are private: encode every retained field explicitly, including
	// status/root and blob/contract presence and all typed log metadata.
	for _, v := range o.receipts {
		r := v.Receipt
		if err := enc.Encode(struct {
			Location        HistoryLocation
			Hash            common.Hash
			Status          uint8
			StatusPresent   bool
			Root            common.Hash
			RootPresent     bool
			Gas, Cumulative uint64
			Price           *big.Int
			BlobGas         uint64
			BlobPrice       *big.Int
			Contract        common.Address
			ContractPresent bool
			Bloom           types.Bloom
			Logs            []HistoryLog
		}{v.Location, v.TransactionHash, r.status, r.statusPresent, r.postState, r.postStatePresent, r.gasUsed, r.cumulativeGasUsed, r.effectiveGasPrice, r.blobGasUsed, r.blobGasPrice, r.contractAddress, r.contractPresent, r.bloom, r.logs}); err != nil {
			return common.Hash{}, err
		}
	}
	if err := enc.Encode(o.logs); err != nil {
		return common.Hash{}, err
	}
	// encoding/json sorts map keys. These headers are complete typed hash-bound
	// values; canonical number/hash obligations have their own explicit map.
	if err := enc.Encode(o.headers); err != nil {
		return common.Hash{}, err
	}
	if err := enc.Encode(o.canonical); err != nil {
		return common.Hash{}, err
	}
	return common.BytesToHash(h.Sum(nil)), nil
}
