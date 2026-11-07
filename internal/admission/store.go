package admission

import (
	"context"
	"github.com/ethereum/go-ethereum/common"
	"time"
)

// Store owns only operational facts. Its callbacks are trusted service code;
// no callback can select SQL, tables, configuration or another actor's scope.
type Store interface {
	WithRawTransaction(context.Context, Scope, func(RawTx) (CommitKind, error)) (CommitReceipt, error)
	WithReadOnly(context.Context, Scope, func(ReadTx) error) error
	CreateRecord(context.Context, Digest, ExpectedState, Record, func(*Record) error) (Record, error)
	GetRecord(context.Context, Digest, ExpectedState, string, string) (Record, error)
	ListRecords(context.Context, Digest, ExpectedState, string, Position, int) ([]Record, error)
	DeleteUnused(context.Context, Digest, ExpectedState, string, string, func() error) (bool, error)
	ListEvents(context.Context, Digest, ExpectedState, string, EventPosition, int) ([]Event, error)
}
type ReadTx interface {
	BoundRecord(TransferQuery) (Record, bool, error)
	FindUnused(TransferQuery, time.Time) (Record, bool, error)
}
type RawTx interface {
	ReadTx
	ClaimUnused(TransferQuery, time.Time) (Record, bool, error)
	AppendEvent(Event) (int64, error)
	GetOrigin() (Origin, bool, error)
	PutOrigin(Origin) (bool, error)
	PutWitness(Witness) error
	GetShare() (Share, bool, error)
	PutShare(Share) error
}

func equalToken(a, b *common.Address) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}
