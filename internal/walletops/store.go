package walletops

import (
	"context"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// Store is a trusted operational boundary. Callbacks complete before commit;
// a successful return means COMMIT succeeded, not that an HTTP client received it.
type Store interface {
	WithActorTransaction(context.Context, Namespace, ExpectedState, string, func(ActorTx) error) error
	LoadActive(context.Context, Namespace, ExpectedState, string, int) ([]OwnershipFact, error)
	ResolveActiveActors(context.Context, Namespace, ExpectedState, common.Address, int) ([]string, error)
}
type ActorTx interface {
	DeleteExpiredChallenges(time.Time, int) error
	CountChallenges() (int, error)
	InsertChallenge(Challenge) error
	TakeChallenge([32]byte, common.Address, time.Time) (Challenge, bool, error)
	CountLinkRows() (int, error)
	GetLink(common.Address) (Link, bool, error)
	InsertOwnership(Link) (bool, error)
	Revoke(common.Address, time.Time) (bool, bool, error)
}
type ENSMetadata struct {
	Name           string
	ForwardAddress common.Address
}
type ENSResolver interface {
	Lookup(context.Context, common.Address) (ENSMetadata, error)
}
type AuditEvent struct {
	Actor, Address, Action string
	At                     time.Time
}

// AuditSink is borrowed from assembly. Nonblocking post-commit delivery may
// drop on nil/full; assembly must not close it while handlers are running.
type AuditSink chan<- AuditEvent
