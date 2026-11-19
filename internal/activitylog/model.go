// Package activitylog records bounded completion metadata through the existing
// durable audit buffer and generic sealer. It does not authenticate principals
// or prove how many requests executed outside the sealed SQL population.
package activitylog

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"privacy-proxy/internal/activityreasondata"
	"privacy-proxy/internal/audit/buffer"
	"privacy-proxy/internal/audit/sealer"
	"privacy-proxy/internal/networkidentity"
)

type Digest [32]byte
type Outcome string

const (
	Success           Outcome = "success"
	Invalid           Outcome = "invalid"
	Unauthenticated   Outcome = "unauthenticated"
	Denied            Outcome = "denied"
	EvaluationFailed  Outcome = "evaluation-failed"
	Unavailable       Outcome = "unavailable"
	Unconfirmed       Outcome = "unconfirmed"
	MaxEncodedBytes           = 2048
	MaxBatchBytes             = 1 << 20
	MaxObservedMicros int64   = 253402300799999999
)

var (
	ErrInvalid     = errors.New("invalid activity metadata")
	ErrUnavailable = errors.New("activity recording unavailable")
	ErrConflict    = errors.New("activity source conflict")
	ErrTooBroad    = errors.New("activity scope too broad")
	ErrQuarantined = errors.New("activity spool requires offline recovery")
)

// LegacyFormat pins the unchanged original v1 wire family.
func LegacyFormat() Digest { return Digest(sha256.Sum256([]byte("ops.activity.sealed-metadata/v1"))) }

// Format identifies the closed dual-read v1/v2 stream profile. Individual
// payloads retain their original version and canonical bytes; new writes use v2.
func Format() Digest { return Digest(sha256.Sum256([]byte("ops.activity.sealed-metadata/v1-v2"))) }

// Completion is trusted operational input from the same accepted Core request.
// It is not an HTTP DTO, principal proof or permission capability.
type Completion struct {
	ActorID, DataOrganizationID string
	PolicyDigest                Digest
	Method, TrustedIP           string
	HTTPStatus                  uint16
	RPCErrorCode                *int32
	Outcome                     Outcome
	Reason                      activityreasondata.Code
}

// Envelope is the normalized closed v1/v2 shape. The codec requires c in v2
// and forbids it in v1; omitempty preserves v1 serialization byte-for-byte.
// Only e is nullable.
// b is supplied by the actual buffer sequence at seal time, never the caller.
type Envelope struct {
	Version        uint8                   `json:"v"`
	Kind           uint8                   `json:"k"`
	Network        string                  `json:"n"`
	Generation     string                  `json:"g"`
	Configuration  string                  `json:"x"`
	ProducerID     string                  `json:"p"`
	RunID          string                  `json:"r"`
	RecordID       string                  `json:"q"`
	Ordinal        string                  `json:"o"`
	ObservedMicros int64                   `json:"t"`
	ActorID        string                  `json:"a"`
	DataOrg        string                  `json:"d"`
	Policy         string                  `json:"z"`
	Method         string                  `json:"m"`
	IP             string                  `json:"i"`
	HTTP           uint16                  `json:"h"`
	RPCError       *int32                  `json:"e"`
	Outcome        string                  `json:"u"`
	Status         uint16                  `json:"s"`
	Reason         activityreasondata.Code `json:"c,omitempty"`
	BufferSeq      string                  `json:"b"`
}

type Limits struct {
	InFlight, BufferedEntries int
	BufferedBytes             int64
	SealBatch                 int
}

func DefaultLimits() Limits { return Limits{256, 65536, 128 << 20, 512} }
func (l Limits) Valid() bool {
	return l.InFlight > 0 && l.InFlight <= 256 && l.BufferedEntries > 0 && l.BufferedEntries <= 65536 && l.BufferedBytes >= MaxEncodedBytes && l.BufferedBytes <= 128<<20 && l.SealBatch > 0 && l.SealBatch <= 512
}

type StoreMetadata struct {
	NetworkKey            Digest
	SourceID, Generation  string
	Configuration, Format Digest
}
type RunRequest struct {
	ProducerID, RunID string
	AllocatedThrough  uint64
}
type RunBinding struct {
	Metadata              StoreMetadata
	ProducerID, RunID     string
	RangeIndex, Base, Top uint64
}

type Store interface {
	Metadata() StoreMetadata
	StartRun(context.Context, RunRequest) (RunStore, error)
}
type RunStore interface {
	Binding() RunBinding
	HighWater(context.Context) (uint64, error)
	RangeHighWater(context.Context, uint64) (uint64, error)
	Verify(context.Context, []buffer.Entry) ([]sealer.Verdict, error)
	SealOne(context.Context, uint64, []byte) error
	SealBatch(context.Context, []buffer.Entry) error
	Settle(context.Context, uint64, []buffer.Entry) (uint64, error)
}
type Config struct {
	Network                                  networkidentity.Binding
	SourceID, ProducerID, ExpectedGeneration string
	Configuration                            Digest
	Methods                                  []string
	Clock                                    func() time.Time
	BufferDirectory                          string
	Limits                                   Limits
}
