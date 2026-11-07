// Package executionfacts validates a bounded callTracer tree from a trusted
// node. It preserves execution evidence; it does not establish node honesty,
// resolve ownership or executed-code provenance, or authorize a transaction.
package executionfacts

// ProfileID identifies the exact callTracer schema and semantics this parser
// accepts. Other tracer formats require explicit qualification.
const ProfileID = "geth-callTracer/v1"
const WithLogsProfileID = "geth-callTracer-with-logs/v1"
const LifecycleWithLogsProfileID = "geth-callTracer-lifecycle-with-logs/v1"

// Profile is selected by the runtime, never by a request or node response.
type Profile struct{ id string }

func GethCallTracerProfile() Profile         { return Profile{ProfileID} }
func GethCallTracerWithLogsProfile() Profile { return Profile{WithLogsProfileID} }
func GethLifecycleWithLogsProfile() Profile  { return Profile{LifecycleWithLogsProfileID} }

func (p Profile) valid() bool { return p.id == ProfileID || p.withLogs() }
func (p Profile) withLogs() bool {
	return p.id == WithLogsProfileID || p.id == LifecycleWithLogsProfileID
}

type Kind string

const (
	Call         Kind = "CALL"
	StaticCall   Kind = "STATICCALL"
	DelegateCall Kind = "DELEGATECALL"
	CallCode     Kind = "CALLCODE"
	Create       Kind = "CREATE"
	Create2      Kind = "CREATE2"
	SelfDestruct Kind = "SELFDESTRUCT"
)

func (k Kind) valid() bool {
	switch k {
	case Call, StaticCall, DelegateCall, CallCode, Create, Create2, SelfDestruct:
		return true
	}
	return false
}

func (k Kind) creation() bool { return k == Create || k == Create2 }

// Limits are explicit engineering budgets, not throughput guarantees.
type Limits struct {
	MaxRawBytes            int
	MaxRecords             int
	MaxDepth               int // Root depth is zero.
	MaxInputBytes          int
	MaxAggregateInputBytes int
	MaxTextBytes           int // Per error/revertReason string.
	MaxLogs                int
	MaxAggregateLogBytes   int
}

func DefaultLimits() Limits {
	return Limits{MaxRawBytes: 8 << 20, MaxRecords: 4096, MaxDepth: 256,
		MaxInputBytes: 1 << 20, MaxAggregateInputBytes: 4 << 20, MaxTextBytes: 4096,
		MaxLogs: 4096, MaxAggregateLogBytes: 1 << 20}
}

func (l Limits) valid() bool {
	return l.MaxRawBytes > 0 && l.MaxRecords > 0 && l.MaxDepth >= 0 && l.MaxDepth <= 256 &&
		l.MaxInputBytes > 0 && l.MaxAggregateInputBytes > 0 && l.MaxTextBytes > 0 &&
		l.MaxLogs > 0 && l.MaxAggregateLogBytes > 0
}
