package admission

import (
	"context"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/creationfacts"
)

type CreationOriginBinding struct{ Actor, Organization string }
type CaptureNeed uint8

const (
	NeedCapture CaptureNeed = iota + 1
	NoEligible
)

// CaptureCommitBinding is trusted service output after matching an opaque
// positive gate result. Its fields are not independently a permission mint.
type CaptureCommitBinding struct {
	ObserverEpoch, CaptureEpoch string
	SourceSet                   creationfacts.Digest
}

func (b CaptureCommitBinding) Valid() bool {
	return ValidUUID(b.ObserverEpoch) && ValidUUID(b.CaptureEpoch) && b.SourceSet != (creationfacts.Digest{})
}

// CreationCoveredStore is a new exact capability; legacy Store/ReadTx and old
// journal writers do not accidentally activate covered authority production.
type CreationCoveredStore interface {
	CreationIntentStore
	CreationCoveredSchemaVersion() int
	ReadOriginBinding(context.Context, Digest, ExpectedState, common.Hash) (CreationOriginBinding, bool, error)
	WithCoveredRawTransaction(context.Context, Scope, CaptureCommitBinding, func(RawTx) (CommitKind, error)) (CommitReceipt, error)
}
type CoveredCreationRawTx interface {
	CreationRawTx
	PutCoveredCreationIntent(CreationIntent, creationfacts.CoverageRecord) (CreationIntentReceipt, error)
}
