package rpcexecution

import (
	"math"
	"time"

	"privacy-proxy/internal/executionfacts"
	"privacy-proxy/internal/policybundle"
)

const NodeProfileID = policybundle.RuntimeNodeEvidenceProfileID
const MaxCallBytes = 1 << 20

type Limits struct {
	Trace                  executionfacts.Limits
	MaxMuxBytes            int64
	MaxPrestateAccounts    int
	MaxCodeBytesPerAccount int
	MaxTotalCodeBytes      int
	MaxAnchoredCodeLookups int
	AcquisitionTimeout     time.Duration
}

func DefaultLimits() Limits {
	return Limits{Trace: executionfacts.DefaultLimits(), MaxMuxBytes: 16 << 20,
		MaxPrestateAccounts: 8192, MaxCodeBytesPerAccount: 1 << 20,
		MaxTotalCodeBytes: 8 << 20, MaxAnchoredCodeLookups: 256,
		AcquisitionTimeout: 10 * time.Second}
}

func (l Limits) valid() bool {
	t := l.Trace
	return l.MaxMuxBytes > 0 && l.MaxMuxBytes < math.MaxInt64 &&
		l.MaxPrestateAccounts > 0 && l.MaxCodeBytesPerAccount > 0 &&
		l.MaxTotalCodeBytes > 0 && l.MaxAnchoredCodeLookups > 0 && l.AcquisitionTimeout > 0 &&
		t.MaxRawBytes > 0 && t.MaxRecords > 0 && t.MaxDepth >= 0 && t.MaxDepth <= 256 &&
		t.MaxInputBytes > 0 && t.MaxAggregateInputBytes > 0 && t.MaxTextBytes > 0 &&
		t.MaxLogs > 0 && t.MaxAggregateLogBytes > 0
}
