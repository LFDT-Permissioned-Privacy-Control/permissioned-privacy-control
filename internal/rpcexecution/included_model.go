package rpcexecution

import (
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/transactioninput"
)

const IncludedProfileID = "reth-prague-included-creations/v1"

var ErrNotIncluded = errors.New("transaction is not included")

type IncludedLimits struct {
	Timeout                                                          time.Duration
	MaxRequests                                                      int
	MaxTransactionBytes, MaxReceiptBytes, MaxBlockBytes, MaxMuxBytes int64
	MaxCodeBytes, MaxTotalCodeBytes, MaxSurvivors, MaxWork           int
	Trace                                                            executionfacts.Limits
}

func DefaultIncludedLimits() IncludedLimits {
	return IncludedLimits{Timeout: 15 * time.Second, MaxRequests: 2060, MaxTransactionBytes: 2 << 20, MaxReceiptBytes: 2 << 20, MaxBlockBytes: 8 << 20, MaxMuxBytes: 16 << 20, MaxCodeBytes: 1 << 20, MaxTotalCodeBytes: 8 << 20, MaxSurvivors: 2048, MaxWork: 2000000, Trace: executionfacts.DefaultLimits()}
}
func (l IncludedLimits) valid() bool {
	m := DefaultIncludedLimits()
	t, d := l.Trace, m.Trace
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxRequests > 0 && l.MaxRequests <= m.MaxRequests && l.MaxTransactionBytes > 0 && l.MaxTransactionBytes <= m.MaxTransactionBytes && l.MaxReceiptBytes > 0 && l.MaxReceiptBytes <= m.MaxReceiptBytes && l.MaxBlockBytes > 0 && l.MaxBlockBytes <= m.MaxBlockBytes && l.MaxMuxBytes > 0 && l.MaxMuxBytes <= m.MaxMuxBytes && l.MaxCodeBytes > 0 && l.MaxCodeBytes <= m.MaxCodeBytes && l.MaxTotalCodeBytes > 0 && l.MaxTotalCodeBytes <= m.MaxTotalCodeBytes && l.MaxSurvivors > 0 && l.MaxSurvivors <= m.MaxSurvivors && l.MaxWork > 0 && l.MaxWork <= m.MaxWork && t.MaxRawBytes > 0 && t.MaxRawBytes <= d.MaxRawBytes && t.MaxRecords > 0 && t.MaxRecords <= d.MaxRecords && t.MaxDepth >= 0 && t.MaxDepth <= d.MaxDepth && t.MaxInputBytes > 0 && t.MaxInputBytes <= d.MaxInputBytes && t.MaxAggregateInputBytes > 0 && t.MaxAggregateInputBytes <= d.MaxAggregateInputBytes && t.MaxTextBytes > 0 && t.MaxTextBytes <= d.MaxTextBytes && t.MaxLogs > 0 && t.MaxLogs <= d.MaxLogs && t.MaxAggregateLogBytes > 0 && t.MaxAggregateLogBytes <= d.MaxAggregateLogBytes
}

// IncludedCreationRecord contains transaction-index creation metadata. Caller
// and raw Creator are distinct. Parent is the nearest actual CREATE ordinal,
// not a preflight ordinal and not necessarily an ordinary surviving birth.
type IncludedCreationRecord struct {
	Record, Parent, Depth            int
	Kind                             string
	Address, Creator, Caller         common.Address
	AddressKnown, CallerKnown        bool
	InputHash                        common.Hash
	Value                            string
	OutputHash                       common.Hash
	OutputLength                     int
	Failed, AncestorFailed, Survives bool
}
type IncludedSelfRecord struct {
	Record, Parent, Depth  int
	Source, Beneficiary    common.Address
	BeneficiaryKnown       bool
	Value                  string
	Failed, AncestorFailed bool
}
type IncludedCreationProof struct {
	source      creationfacts.Source
	transaction transactioninput.VerifiedTransaction
	header      creationfacts.Header
	index       uint32
	success     bool
	creations   []IncludedCreationRecord
	self        []IncludedSelfRecord
	digest      common.Hash
}

func (p *IncludedCreationProof) Source() creationfacts.Source {
	if p == nil {
		return creationfacts.Source{}
	}
	return p.source
}
func (p *IncludedCreationProof) Transaction() transactioninput.VerifiedTransaction {
	if p == nil {
		return transactioninput.VerifiedTransaction{}
	}
	return p.transaction
}
func (p *IncludedCreationProof) Inclusion() (creationfacts.Header, uint32) {
	if p == nil {
		return creationfacts.Header{}, 0
	}
	return p.header, p.index
}
func (p *IncludedCreationProof) Successful() bool { return p != nil && p.success }
func (p *IncludedCreationProof) Creations() []IncludedCreationRecord {
	if p == nil {
		return nil
	}
	return append([]IncludedCreationRecord{}, p.creations...)
}
func (p *IncludedCreationProof) SelfDestructs() []IncludedSelfRecord {
	if p == nil {
		return nil
	}
	return append([]IncludedSelfRecord{}, p.self...)
}
func (p *IncludedCreationProof) Digest() common.Hash {
	if p == nil {
		return common.Hash{}
	}
	return p.digest
}
