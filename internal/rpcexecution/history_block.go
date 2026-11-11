package rpcexecution

import (
	"bytes"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

// HistoryBlockSelector selects included history, never pending or a moving tag.
type HistoryBlockSelector struct {
	kind   uint8
	number uint64
	hash   common.Hash
}

func HistoryBlockNumber(n uint64) (HistoryBlockSelector, error) {
	if n > math.MaxInt64 {
		return HistoryBlockSelector{}, failure(InvalidCall)
	}
	return HistoryBlockSelector{kind: 1, number: n}, nil
}
func HistoryBlockHash(h common.Hash) (HistoryBlockSelector, error) {
	if h == (common.Hash{}) {
		return HistoryBlockSelector{}, failure(InvalidCall)
	}
	return HistoryBlockSelector{kind: 2, hash: h}, nil
}
func (s HistoryBlockSelector) valid() bool {
	return s.kind == 1 && s.number <= math.MaxInt64 && s.hash == (common.Hash{}) || s.kind == 2 && s.hash != (common.Hash{}) && s.number == 0
}

// All ceilings are conjunctive, and can only be lowered. MaxObservationBytes
// charges normalized payload, not Go heap or copies made by detached getters.
type HistoryBlockLimits struct {
	Timeout                                              time.Duration
	MaxRequests, MaxTransactions, MaxLogs                int
	MaxBlockBytes, MaxReceiptSetBytes, MaxTotalWireBytes int64
	MaxTransactionBytes, MaxSignedBytes, MaxReceiptBytes int
	MaxAccessEntries, MaxStorageKeys, MaxAuthorizations  int
	MaxObservationBytes                                  int
}

func DefaultHistoryBlockLimits() HistoryBlockLimits {
	return HistoryBlockLimits{10 * time.Second, 10, 10000, 20000, 8 << 20, 8 << 20, 17 << 20, 2 << 20, 512 << 10, 2 << 20, 4096, 65536, 4096, 16 << 20}
}
func (l HistoryBlockLimits) valid() bool {
	m := DefaultHistoryBlockLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout &&
		l.MaxRequests > 0 && l.MaxRequests <= m.MaxRequests && l.MaxTransactions > 0 && l.MaxTransactions <= m.MaxTransactions && l.MaxLogs > 0 && l.MaxLogs <= m.MaxLogs &&
		l.MaxBlockBytes > 0 && l.MaxBlockBytes <= m.MaxBlockBytes && l.MaxReceiptSetBytes > 0 && l.MaxReceiptSetBytes <= m.MaxReceiptSetBytes && l.MaxTotalWireBytes > 0 && l.MaxTotalWireBytes <= m.MaxTotalWireBytes &&
		l.MaxTransactionBytes > 0 && l.MaxTransactionBytes <= m.MaxTransactionBytes && l.MaxSignedBytes > 0 && l.MaxSignedBytes <= m.MaxSignedBytes && l.MaxReceiptBytes > 0 && l.MaxReceiptBytes <= m.MaxReceiptBytes &&
		l.MaxAccessEntries > 0 && l.MaxAccessEntries <= m.MaxAccessEntries && l.MaxStorageKeys > 0 && l.MaxStorageKeys <= m.MaxStorageKeys && l.MaxAuthorizations > 0 && l.MaxAuthorizations <= m.MaxAuthorizations && l.MaxObservationBytes > 0 && l.MaxObservationBytes <= m.MaxObservationBytes
}

type HistoryHeader struct {
	Number, Timestamp, GasLimit, GasUsed             uint64
	Hash, ParentHash, TransactionsRoot, ReceiptsRoot common.Hash
	BaseFeePerGas                                    *big.Int
}

// HistoryBlockObservation belongs to its acquiring client. It records one full
// node-returned block population, not consensus, authorization or a C2 view.
// The caller fence keeps no context values, request, auth state or child ctx.
type HistoryBlockObservation struct {
	owner            *HistoryBlockClient
	source           creationfacts.Source
	selector         HistoryBlockSelector
	header           *types.Header
	transactions     []HistoryTransaction
	receipts         []HistoryReceipt
	uncles           []common.Hash
	withdrawals      []*types.Withdrawal
	reportedSize     uint64
	sizePresence     HistoryFieldPresence
	totalDifficulty  *big.Int
	tdPresence       HistoryFieldPresence
	digest           common.Hash
	originalDone     <-chan struct{}
	originalDeadline time.Time
}

// HistoryFieldPresence preserves optional node metadata, including explicit
// null versus omission. It supplies no inferred size or total difficulty.
type HistoryFieldPresence uint8

const (
	HistoryAbsent HistoryFieldPresence = iota
	HistoryNull
	HistoryPresent
)

// EthereumHeader returns a detached typed header, never an authorization or a
// ready-to-publish RPC response. Serving applies its own privacy/rendering rules.
func (b *HistoryBlockObservation) EthereumHeader() *types.Header {
	if !b.valid() {
		return nil
	}
	return types.CopyHeader(b.header)
}
func (b *HistoryBlockObservation) Uncles() []common.Hash {
	if !b.valid() {
		return nil
	}
	out := make([]common.Hash, len(b.uncles))
	copy(out, b.uncles)
	return out
}
func (b *HistoryBlockObservation) Withdrawals() []*types.Withdrawal {
	if !b.valid() || b.withdrawals == nil {
		return nil
	}
	out := make([]*types.Withdrawal, len(b.withdrawals))
	for i, v := range b.withdrawals {
		copy := *v
		out[i] = &copy
	}
	return out
}
func (b *HistoryBlockObservation) ReportedSize() (uint64, HistoryFieldPresence) {
	if !b.valid() {
		return 0, HistoryAbsent
	}
	return b.reportedSize, b.sizePresence
}
func (b *HistoryBlockObservation) TotalDifficulty() (*big.Int, HistoryFieldPresence) {
	if !b.valid() {
		return nil, HistoryAbsent
	}
	return historyBigCopy(b.totalDifficulty), b.tdPresence
}

func (b *HistoryBlockObservation) valid() bool {
	return b != nil && b.owner != nil && b.header != nil && b.digest != (common.Hash{})
}
func (b *HistoryBlockObservation) Source() creationfacts.Source {
	if !b.valid() {
		return creationfacts.Source{}
	}
	return b.source
}
func (b *HistoryBlockObservation) Selector() HistoryBlockSelector {
	if !b.valid() {
		return HistoryBlockSelector{}
	}
	return b.selector
}
func (b *HistoryBlockObservation) Header() HistoryHeader {
	if !b.valid() {
		return HistoryHeader{}
	}
	h := b.header
	return HistoryHeader{h.Number.Uint64(), h.Time, h.GasLimit, h.GasUsed, h.Hash(), h.ParentHash, h.TxHash, h.ReceiptHash, historyBigCopy(h.BaseFee)}
}
func (b *HistoryBlockObservation) TransactionCount() uint32 {
	if !b.valid() {
		return 0
	}
	return uint32(len(b.transactions))
}
func (b *HistoryBlockObservation) Transaction(i uint32) (HistoryTransaction, bool) {
	if !b.valid() || uint64(i) >= uint64(len(b.transactions)) {
		return HistoryTransaction{}, false
	}
	return b.transactions[i], true
}
func (b *HistoryBlockObservation) Receipt(i uint32) (HistoryReceipt, bool) {
	if !b.valid() || uint64(i) >= uint64(len(b.receipts)) {
		return HistoryReceipt{}, false
	}
	return b.receipts[i], true
}
func (b *HistoryBlockObservation) Digest() common.Hash {
	if !b.valid() {
		return common.Hash{}
	}
	return b.digest
}

// HistoryTransaction has no conversion to admission VerifiedTransaction. Types
// 3/4 and unprotected legacy here never expand protected send admission.
type HistoryTransaction struct {
	tx     *types.Transaction
	from   common.Address
	signed []byte
}

func (t HistoryTransaction) Hash() common.Hash {
	if t.tx == nil {
		return common.Hash{}
	}
	return t.tx.Hash()
}
func (t HistoryTransaction) From() common.Address { return t.from }
func (t HistoryTransaction) To() (common.Address, bool) {
	if t.tx == nil || t.tx.To() == nil {
		return common.Address{}, false
	}
	return *t.tx.To(), true
}
func (t HistoryTransaction) Type() uint8 {
	if t.tx == nil {
		return 0
	}
	return t.tx.Type()
}
func (t HistoryTransaction) Nonce() uint64 {
	if t.tx == nil {
		return 0
	}
	return t.tx.Nonce()
}
func (t HistoryTransaction) GasLimit() uint64 {
	if t.tx == nil {
		return 0
	}
	return t.tx.Gas()
}
func (t HistoryTransaction) Value() *big.Int {
	if t.tx == nil {
		return nil
	}
	return historyBigCopy(t.tx.Value())
}
func (t HistoryTransaction) Input() []byte {
	if t.tx == nil {
		return nil
	}
	return bytes.Clone(t.tx.Data())
}
func (t HistoryTransaction) SignedBytes() []byte { return bytes.Clone(t.signed) }

type HistorySignedFees struct {
	Protected                                                            bool
	ChainID                                                              *big.Int
	LegacyGasPrice, MaxFeePerGas, MaxPriorityFeePerGas, MaxFeePerBlobGas *big.Int
}

func (t HistoryTransaction) Fees() HistorySignedFees {
	if t.tx == nil {
		return HistorySignedFees{}
	}
	f := HistorySignedFees{Protected: t.tx.Protected(), ChainID: historyBigCopy(t.tx.ChainId())}
	if t.Type() < 2 {
		f.LegacyGasPrice = historyBigCopy(t.tx.GasPrice())
	} else {
		f.MaxFeePerGas, f.MaxPriorityFeePerGas = historyBigCopy(t.tx.GasFeeCap()), historyBigCopy(t.tx.GasTipCap())
	}
	if t.Type() == 3 {
		f.MaxFeePerBlobGas = historyBigCopy(t.tx.BlobGasFeeCap())
	}
	return f
}
func (t HistoryTransaction) AccessList() types.AccessList {
	if t.tx == nil {
		return nil
	}
	a := t.tx.AccessList()
	out := make(types.AccessList, len(a))
	for i, v := range a {
		out[i] = types.AccessTuple{Address: v.Address, StorageKeys: append([]common.Hash(nil), v.StorageKeys...)}
	}
	return out
}
func (t HistoryTransaction) BlobHashes() []common.Hash {
	if t.tx == nil {
		return nil
	}
	return append([]common.Hash(nil), t.tx.BlobHashes()...)
}
func (t HistoryTransaction) Authorizations() []types.SetCodeAuthorization {
	if t.tx == nil {
		return nil
	}
	return append([]types.SetCodeAuthorization(nil), t.tx.SetCodeAuthorizations()...)
}

type HistoryReceipt struct {
	status                     uint8
	statusPresent              bool
	postState                  common.Hash
	postStatePresent           bool
	gasUsed, cumulativeGasUsed uint64
	effectiveGasPrice          *big.Int
	blobGasUsed                uint64
	blobGasPrice               *big.Int
	contractAddress            common.Address
	contractPresent            bool
	logs                       []HistoryLog
	bloom                      types.Bloom
}

func (r HistoryReceipt) Status() (uint8, bool)              { return r.status, r.statusPresent }
func (r HistoryReceipt) PostStateRoot() (common.Hash, bool) { return r.postState, r.postStatePresent }
func (r HistoryReceipt) GasUsed() uint64                    { return r.gasUsed }
func (r HistoryReceipt) CumulativeGasUsed() uint64          { return r.cumulativeGasUsed }
func (r HistoryReceipt) EffectiveGasPrice() *big.Int        { return historyBigCopy(r.effectiveGasPrice) }
func (r HistoryReceipt) BlobGas() (uint64, *big.Int, bool) {
	return r.blobGasUsed, historyBigCopy(r.blobGasPrice), r.blobGasPrice != nil
}
func (r HistoryReceipt) ContractAddress() (common.Address, bool) {
	return r.contractAddress, r.contractPresent
}

type HistoryLog struct {
	Address                    common.Address
	Topics                     []common.Hash
	Data                       []byte
	TransactionIndex, LogIndex uint32
}

func (r HistoryReceipt) Logs() []HistoryLog {
	out := make([]HistoryLog, len(r.logs))
	for i, v := range r.logs {
		out[i] = v
		out[i].Data = bytes.Clone(v.Data)
		out[i].Topics = append([]common.Hash(nil), v.Topics...)
	}
	return out
}
func historyBigCopy(n *big.Int) *big.Int {
	if n == nil {
		return nil
	}
	return new(big.Int).Set(n)
}
