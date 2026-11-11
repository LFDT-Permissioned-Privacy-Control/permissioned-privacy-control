package creationfacts

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

const CurrentAddressProfile = "ops-current-a2-association/v1"

type AddressReadLimits struct {
	Timeout                 time.Duration
	MaxCandidates, MaxBytes int
}

func DefaultAddressReadLimits() AddressReadLimits {
	return AddressReadLimits{250 * time.Millisecond, 64, 256 << 10}
}
func (l AddressReadLimits) Valid() bool {
	d := DefaultAddressReadLimits()
	return l.Timeout > 0 && l.Timeout <= d.Timeout && l.MaxCandidates > 0 && l.MaxCandidates <= d.MaxCandidates && l.MaxBytes > 0 && l.MaxBytes <= d.MaxBytes
}

// AddressReadBinding is independently selected startup metadata. Original
// capture coverage is retained separately and can precede this generation.
type AddressReadBinding struct {
	Network              Network
	State                State
	SourceSet, Reference Digest
	Profile              string
	Limits               AddressReadLimits
}

func (b AddressReadBinding) Valid() bool {
	return b.Network.Valid() && b.State.Valid() && b.SourceSet != (Digest{}) && b.Reference != (Digest{}) && b.Profile == CurrentAddressProfile && b.Limits.Valid()
}

// The nonzero-size identity distinguishes actual borrowed reader instances.
// It identifies provenance, not permission or an external attestation.
type AddressReaderIdentity struct{ marker byte }

func NewAddressReaderIdentity() *AddressReaderIdentity { return &AddressReaderIdentity{1} }
func (i *AddressReaderIdentity) Valid() bool           { return i != nil && i.marker == 1 }

type AddressReaderMetadata struct {
	Binding  AddressReadBinding
	Identity *AddressReaderIdentity
}
type CurrentAddressReader interface {
	Metadata() AddressReaderMetadata
	ReadAddressAssociations(context.Context, common.Address) (*AddressAssociations, error)
	RecheckAddressAssociations(context.Context, *AddressAssociations) error
}

// AddressAssociation is a projection of already-published A2 evidence. The
// trusted adapter checks row/reference equality and current canonicality before
// construction; these values alone cannot grant a method, group or target.
type AddressAssociation struct {
	Namespace, Kind, WalletActor                 string
	Address, Creator                             common.Address
	CreationKind                                 string
	Record                                       int
	Index                                        uint32
	Inclusion                                    Header
	TransactionHash, OutputHash, Proof           common.Hash
	OutputLength                                 int
	Seed, Plan, Manifest, Runtime, Qualification Digest
	PlannedEntry                                 int
	Branch                                       uint8
	OriginalProfile                              string
	OriginalAnchor                               Header
	OriginalCoverage                             CoverageRecord
}

func addressActor(v string) bool {
	if len(v) != len("ops:p1:")+43 || v[:len("ops:p1:")] != "ops:p1:" {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(v[len("ops:p1:"):])
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == v[len("ops:p1:"):]
}
func (r AddressAssociation) valid(target common.Address, network Digest) bool {
	if r.Address != target || !UUID(r.Namespace) || r.Kind != "WALLET" && r.Kind != "FACTORY" ||
		r.Kind == "WALLET" && !addressActor(r.WalletActor) || r.Kind == "FACTORY" && r.WalletActor != "" ||
		r.CreationKind != "CREATE" && r.CreationKind != "CREATE2" || r.Record < 0 || r.Record > 4095 ||
		!r.Inclusion.Valid() || r.TransactionHash == (common.Hash{}) || r.OutputHash == (common.Hash{}) || r.Proof == (common.Hash{}) || r.OutputLength < 1 || r.OutputLength > 1<<20 ||
		r.Seed == (Digest{}) || r.Plan == (Digest{}) || r.Manifest == (Digest{}) || r.Runtime == (Digest{}) || r.Qualification == (Digest{}) || r.PlannedEntry < 0 || r.PlannedEntry >= 128 || r.Branch < 1 || r.Branch > 8 ||
		r.OriginalProfile != "geth-prague-lifecycle-signed/v1" && r.OriginalProfile != "geth-prague-lifecycle-guard/v1" || !r.OriginalAnchor.Valid() || r.OriginalAnchor.Number >= r.Inclusion.Number {
		return false
	}
	c := r.OriginalCoverage
	if _, err := c.Canonical(); err != nil || c.Network != network || c.HighWater.Number > r.OriginalAnchor.Number || c.Latest.Number < r.OriginalAnchor.Number || c.HighWater.Number == r.OriginalAnchor.Number && c.HighWater.Hash != r.OriginalAnchor.Hash {
		return false
	}
	// ValidUntil describes the ORIGINAL bounded capture. Never compare it to
	// now, or require its original latest header to reach the later birth.
	return true
}

// AddressAssociations deliberately has no Complete, Unregistered or Public bit.
// An empty pass is lack of positive association, never a permission fallback.
type AddressAssociations struct {
	owner          *AddressReaderIdentity
	binding        AddressReadBinding
	target         common.Address
	observerEpoch  string
	reorgEpoch     int64
	observerHead   Header
	digest         Digest
	rows           []AddressAssociation
	candidateBytes int
}

// NewAddressAssociations compiles bounded trusted-adapter observations, not an
// externally supplied permission verdict. SQL/node provenance remains in TCB.
func NewAddressAssociations(owner *AddressReaderIdentity, binding AddressReadBinding, target common.Address, observerEpoch string, reorgEpoch int64, observerHead Header, rows []AddressAssociation) (*AddressAssociations, error) {
	if !owner.Valid() || !binding.Valid() || !UUID(observerEpoch) || reorgEpoch < 0 || !observerHead.Valid() || observerHead.Parent != (common.Hash{}) || observerHead.Timestamp != 0 || len(rows) > binding.Limits.MaxCandidates {
		return nil, ErrInvalid
	}
	owned := slices.Clone(rows)
	encoded := make([][]byte, len(owned))
	bytesUsed := 0
	for i, row := range owned {
		if !row.valid(target, binding.Network.Key) || row.Inclusion.Number > observerHead.Number || row.Inclusion.Number == observerHead.Number && row.Inclusion.Hash != observerHead.Hash {
			return nil, ErrInvalid
		}
		raw, err := json.Marshal(row)
		if err != nil || len(raw) > binding.Limits.MaxBytes-bytesUsed {
			return nil, ErrInvalid
		}
		bytesUsed += len(raw)
		encoded[i] = raw
	}
	order := make([]int, len(owned))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(i, j int) bool { return bytes.Compare(encoded[order[i]], encoded[order[j]]) < 0 })
	rowsOut := make([]AddressAssociation, len(owned))
	canonical := make([]json.RawMessage, len(owned))
	for i, index := range order {
		if i > 0 && bytes.Equal(encoded[index], canonical[i-1]) {
			return nil, ErrInvalid
		}
		rowsOut[i], canonical[i] = owned[index], encoded[index]
	}
	raw, err := json.Marshal(struct {
		Binding AddressReadBinding
		Target  common.Address
		Rows    []json.RawMessage
	}{binding, target, canonical})
	if err != nil {
		return nil, ErrInvalid
	}
	return &AddressAssociations{owner, binding, target, observerEpoch, reorgEpoch, observerHead, Hash("ops-current-address-candidates/v1", raw), rowsOut, bytesUsed}, nil
}

// AddressReadStamp identifies one original observer/reorg generation. A caller
// joining several point observations must not combine different generations.
type AddressReadStamp struct {
	ObserverEpoch string
	ReorgEpoch    int64
}

func (p *AddressAssociations) ObservationStamp() AddressReadStamp {
	if p == nil {
		return AddressReadStamp{}
	}
	return AddressReadStamp{p.observerEpoch, p.reorgEpoch}
}

// CandidateBytes counts canonical candidate evidence, not total process memory.
func (p *AddressAssociations) CandidateBytes() int {
	if p == nil {
		return 0
	}
	return p.candidateBytes
}
func (p *AddressAssociations) ValidateFor(owner *AddressReaderIdentity, binding AddressReadBinding, target common.Address) error {
	if p == nil || !owner.Valid() || p.owner != owner || p.binding != binding || p.target != target || p.digest == (Digest{}) || !UUID(p.observerEpoch) || p.reorgEpoch < 0 || !p.observerHead.Valid() || len(p.rows) > binding.Limits.MaxCandidates {
		return ErrInvalid
	}
	return nil
}

// ObserverHead retains only the number/hash from the same original adapter
// read. Parent/Timestamp are zero; this does not claim a full stored header.
// The facts digest deliberately excludes this separately owned provenance so
// ordinary append-only observer progress can pass SameCurrent.
func (p *AddressAssociations) ObserverHead() Header {
	if p == nil {
		return Header{}
	}
	return p.observerHead
}
func (p *AddressAssociations) Candidates() []AddressAssociation {
	if p == nil {
		return nil
	}
	return slices.Clone(p.rows)
}
func (p *AddressAssociations) Target() common.Address {
	if p == nil {
		return common.Address{}
	}
	return p.target
}
func (p *AddressAssociations) SameCurrent(other *AddressAssociations) bool {
	return p != nil && other != nil && p.owner == other.owner && p.binding == other.binding && p.target == other.target && p.observerEpoch == other.observerEpoch && p.reorgEpoch == other.reorgEpoch && p.digest == other.digest
}
