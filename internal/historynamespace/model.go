// Package historynamespace describes immutable historical contract namespaces.
// It supplies no current permission, Actor association or complete history source.
package historynamespace

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"time"

	"privacy-proxy/internal/networkidentity"
)

const ModelID = "prague-ordinary-runtime/v1"
const ArtifactAPIVersion = "ops.history-namespace/v1"
const MaxRuntimeBytes = 1 << 20
const MaxArtifactBytes = 4 << 20
const MaxStatements = 4096
const MaxCheckpointAddresses = 128

var (
	ErrInvalid     = errors.New("invalid historical namespace metadata")
	ErrUnavailable = errors.New("historical namespace unavailable")
	ErrTooBroad    = errors.New("historical namespace bound exceeded")
	ErrConflict    = errors.New("historical namespace conflict")
)

type Digest [32]byte
type Hash [32]byte
type Address [20]byte

func (d Digest) String() string                { return "sha256:" + hex.EncodeToString(d[:]) }
func (h Hash) String() string                  { return "0x" + hex.EncodeToString(h[:]) }
func (a Address) String() string               { return "0x" + hex.EncodeToString(a[:]) }
func (d Digest) MarshalText() ([]byte, error)  { return []byte(d.String()), nil }
func (h Hash) MarshalText() ([]byte, error)    { return []byte(h.String()), nil }
func (a Address) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

func fixedJSON(raw []byte, prefix string, size int) ([]byte, error) {
	var text string
	if len(raw) != len(prefix)+2*size+2 || json.Unmarshal(raw, &text) != nil || !strings.HasPrefix(text, prefix) {
		return nil, ErrInvalid
	}
	b, err := hex.DecodeString(text[len(prefix):])
	if err != nil || len(b) != size || prefix+hex.EncodeToString(b) != text {
		return nil, ErrInvalid
	}
	return b, nil
}
func (d *Digest) UnmarshalJSON(raw []byte) error {
	b, err := fixedJSON(raw, "sha256:", len(d))
	if err == nil {
		copy(d[:], b)
	}
	return err
}
func (h *Hash) UnmarshalJSON(raw []byte) error {
	b, err := fixedJSON(raw, "0x", len(h))
	if err == nil {
		copy(h[:], b)
	}
	return err
}
func (a *Address) UnmarshalJSON(raw []byte) error {
	b, err := fixedJSON(raw, "0x", len(a))
	if err == nil {
		copy(a[:], b)
	}
	return err
}

func uuidBytes(text string) ([16]byte, error) {
	var out [16]byte
	if len(text) != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-' {
		return out, ErrInvalid
	}
	b, err := hex.DecodeString(strings.ReplaceAll(text, "-", ""))
	if err != nil || len(b) != 16 || hex.EncodeToString(b) != strings.ReplaceAll(text, "-", "") {
		return out, ErrInvalid
	}
	copy(out[:], b)
	if out == ([16]byte{}) {
		return out, ErrInvalid
	}
	return out, nil
}
func UUID(text string) bool { _, err := uuidBytes(text); return err == nil }

// Label is an original or explicitly transferred data namespace, never an
// Actor's organization membership or a current Git permission owner.
type Label struct {
	Kind           string  `json:"kind"`
	OrganizationID *string `json:"organizationId,omitempty" optional:"true"`
}

func (l Label) Valid() bool {
	return l.Kind == "org" && l.OrganizationID != nil && UUID(*l.OrganizationID) || l.Kind == "public" && l.OrganizationID == nil
}
func (l Label) Equal(other Label) bool {
	return l.Kind == other.Kind && ((l.OrganizationID == nil && other.OrganizationID == nil) ||
		(l.OrganizationID != nil && other.OrganizationID != nil && *l.OrganizationID == *other.OrganizationID))
}
func (l Label) Detached() Label {
	if l.OrganizationID != nil {
		id := *l.OrganizationID
		l.OrganizationID = &id
	}
	return l
}

// ModelEra is an approved continuous semantic-model boundary. A checkpoint
// cannot discover this boundary or extend it to an unsupported future fork.
type ModelEra struct {
	EntryNumber           uint64 `json:"entryNumber"`
	EntryHash             Hash   `json:"entryHash"`
	EntryTimestamp        uint64 `json:"entryTimestamp"`
	EndTimestampExclusive uint64 `json:"endTimestampExclusive"`
}

func (e ModelEra) Valid() bool {
	return e.EntryNumber <= math.MaxInt64 && e.EntryHash != (Hash{}) && e.EntryTimestamp <= math.MaxInt64 && e.EndTimestampExclusive <= math.MaxInt64 && e.EndTimestampExclusive > e.EntryTimestamp
}

// Cut is a boundary before ordered transaction Index. Index zero is block
// start; actual TxCount is block end. Shape alone does not prove that count.
type Cut struct {
	Number uint64 `json:"number"`
	Hash   Hash   `json:"hash"`
	Index  uint32 `json:"index"`
}

func (c Cut) Valid() bool { return c.Number <= math.MaxInt64 && c.Hash != (Hash{}) }
func CompareCuts(a, b Cut) int {
	if a.Number < b.Number || a.Number == b.Number && a.Index < b.Index {
		return -1
	}
	if a.Number > b.Number || a.Index > b.Index {
		return 1
	}
	return 0
}

type BirthCoordinate struct {
	Number          uint64 `json:"number"`
	Hash            Hash   `json:"hash"`
	TransactionHash Hash   `json:"transactionHash"`
	Index           uint32 `json:"index"`
	Record          uint32 `json:"record"`
}

func (b BirthCoordinate) Valid() bool {
	return b.Number <= math.MaxInt64 && b.Hash != (Hash{}) && b.TransactionHash != (Hash{}) && b.Record < 4096
}

type PhysicalStart struct {
	Kind  string           `json:"kind"`
	Birth *BirthCoordinate `json:"birth,omitempty" optional:"true"`
}

func (p PhysicalStart) Valid(era ModelEra) bool {
	return era.Valid() && (p.Kind == "preexisting" && p.Birth == nil ||
		p.Kind == "born" && p.Birth != nil && p.Birth.Valid() && p.Birth.Number >= era.EntryNumber && (p.Birth.Number != era.EntryNumber || p.Birth.Hash == era.EntryHash))
}
func (p PhysicalStart) Detached() PhysicalStart {
	if p.Birth != nil {
		birth := *p.Birth
		p.Birth = &birth
	}
	return p
}

// PragueSegmentKey excludes label and evidence clocks so equivalent later
// proofs cannot create a second transfer chain for the same persistent runtime.
func PragueSegmentKey(network Digest, address Address, runtime Hash, length uint32) (Digest, error) {
	if network == (Digest{}) || runtime == (Hash{}) || length == 0 || length > MaxRuntimeBytes {
		return Digest{}, ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("ops-history-prague-segment/v1\x00"))
	h.Write(network[:])
	h.Write(address[:])
	h.Write(runtime[:])
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], length)
	h.Write(size[:])
	binary.BigEndian.PutUint32(size[:], uint32(len(ModelID)))
	h.Write(size[:])
	h.Write([]byte(ModelID))
	var result Digest
	copy(result[:], h.Sum(nil))
	return result, nil
}

func PreEraSegmentKey(network Digest, address Address, lifetimeID string) (Digest, error) {
	id, err := uuidBytes(lifetimeID)
	if err != nil || network == (Digest{}) {
		return Digest{}, ErrInvalid
	}
	h := sha256.New()
	h.Write([]byte("ops-history-legacy-segment/v1\x00"))
	h.Write(network[:])
	h.Write(address[:])
	h.Write(id[:])
	var result Digest
	copy(result[:], h.Sum(nil))
	return result, nil
}

type CapacityLimits struct {
	Lifetimes, Transfers, Cohorts, RevokedCohorts int64
	LifetimesPerAddress, TransfersPerSegment      int
}

func DefaultCapacityLimits() CapacityLimits {
	return CapacityLimits{1000000, 1000000, 10000, 10000, 32, 64}
}
func (l CapacityLimits) Valid() bool {
	m := DefaultCapacityLimits()
	return l.Lifetimes > 0 && l.Lifetimes <= m.Lifetimes && l.Transfers > 0 && l.Transfers <= m.Transfers &&
		l.Cohorts > 0 && l.Cohorts <= m.Cohorts && l.RevokedCohorts > 0 && l.RevokedCohorts <= m.RevokedCohorts &&
		l.LifetimesPerAddress > 0 && l.LifetimesPerAddress <= m.LifetimesPerAddress && l.TransfersPerSegment > 0 && l.TransfersPerSegment <= m.TransfersPerSegment
}

// OfflineTimeout checks the numeric bound before time.Duration multiplication.
func OfflineTimeout(seconds int64) (time.Duration, error) {
	if seconds < 1 || seconds > 30*60 {
		return 0, ErrInvalid
	}
	return time.Duration(seconds) * time.Second, nil
}

func NetworkKey(binding networkidentity.Binding) (Digest, error) {
	key, err := binding.Key()
	return Digest(key), err
}

func semanticDigest(domain string, value any) (Digest, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return Digest{}, ErrInvalid
	}
	return semanticDigestBytes(domain, raw), nil
}

// semanticDigestBytes shares the exact domain+NUL+canonical JSON framing.
// Callers pass only bytes just produced by the owned canonical encoder.
func semanticDigestBytes(domain string, raw []byte) Digest {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(raw)
	var d Digest
	copy(d[:], h.Sum(nil))
	return d
}

func compareDigest(a, b Digest) int { return bytes.Compare(a[:], b[:]) }
