package explorerquery

import "context"

type ProtectedSelection struct {
	Expected              Metadata
	ReadAt                *Anchor
	DatasetEpoch          string
	RunFloor              *uint64
	Targets               [][20]byte
	FromTime, ThroughTime uint64
	// Without ReadAt, ThroughNumber is an upper bound narrowed to the producer's
	// committed anchor. The consumer must qualify that anchor against its trusted
	// node before reading candidates. A pinned read keeps its range and anchor.
	FromNumber, ThroughNumber uint64
}

type ProtectedPosition struct {
	Number uint64
	Index  uint32
	Hash   [32]byte
}
type ProtectedRow struct {
	Position  ProtectedPosition
	Timestamp uint64
	From      [20]byte
	To        *[20]byte
}
type ProtectedDestinations struct {
	Addresses   [][20]byte
	First, Last *uint64
}
type ProtectedWitness struct {
	Address [20]byte
	Row     ProtectedRow
}

// Intervals are half-open (block, transaction-index) ranges from the qualified
// namespace pass. Creation coordinates identify the original ROOT only.
type ProtectedInterval struct {
	Address      [20]byte
	FromNumber   uint64
	FromIndex    uint32
	BeforeNumber uint64
	BeforeIndex  uint32
}
type ProtectedCreation struct {
	Address  [20]byte
	Position ProtectedPosition
}
type ProtectedPredicate struct {
	Intervals []ProtectedInterval
	Creations []ProtectedCreation
}
type ProtectedTransactionQuery struct {
	Address *[20]byte
	Hash    *[32]byte
	After   *ProtectedPosition
	Limit   uint16
}

// ProtectedSource supplies bounded chain facts only. Policy, canonical node
// qualification and final delivery authority remain with the consumer.
type ProtectedSource interface {
	Metadata() Metadata
	BeginProtected(context.Context, ProtectedSelection) (ProtectedRead, error)
}

type ProtectedSnapshot struct {
	ReadAt       Anchor
	DatasetEpoch string
	RunFloor     uint64
}

type ProtectedRead interface {
	Snapshot() ProtectedSnapshot
	ReadDestinations(context.Context) (ProtectedDestinations, error)
	ReadWitnesses(context.Context, ProtectedPredicate) ([]ProtectedWitness, error)
	ReadTransactions(context.Context, ProtectedPredicate, ProtectedTransactionQuery) ([]ProtectedRow, bool, error)
	Recheck(context.Context) error
	Close()
}
