package historyfacts

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/admission"
	"privacy-proxy/internal/networkidentity"
)

const ShareSchemaProfile = "ops-admission-v3-readonly-shares/v1"
const MaxShareHashes = 1024

type ShareBinding struct {
	Network       networkidentity.Binding
	State         admission.ExpectedState
	SchemaProfile string
}

func (b ShareBinding) Valid() bool {
	_, err := b.Network.Key()
	return err == nil && b.State.Valid() && b.SchemaProfile == ShareSchemaProfile
}

// ReaderIdentity distinguishes actual instances. It is not an attestation of
// database rows. Only a trusted admitted-share adapter constructs passes.
type ReaderIdentity struct{ marker byte }

func NewReaderIdentity() *ReaderIdentity { return &ReaderIdentity{1} }
func (i *ReaderIdentity) valid() bool    { return i != nil && i.marker == 1 }

type ShareMetadata struct {
	Binding  ShareBinding
	Mode     string
	Identity *ReaderIdentity
}
type ShareReader interface {
	Metadata() ShareMetadata
	Read(context.Context, ShareQuery) (*SharePass, error)
	Recheck(context.Context, *SharePass) error
}
type ShareQuery struct {
	Hashes   []common.Hash
	fence    Fence
	maxBytes int
}

func (q ShareQuery) ByteLimit() int {
	if q.maxBytes == 0 {
		return MaxChargedBytes
	}
	return q.maxBytes
}

// OperationFence uses the original owning operation when available, rather
// than retaining the temporary acquisition child passed to an adapter.
func (q ShareQuery) OperationFence(ctx context.Context) (Fence, error) {
	if !q.fence.deadline.IsZero() {
		if q.fence.Check() != nil {
			return Fence{}, ErrUnavailable
		}
		return q.fence, nil
	}
	return NewFence(ctx, MaxOperationTime)
}

// NormalizeShareQuery bounds before copying and fixes one canonical exact set.
func NormalizeShareQuery(q ShareQuery) (ShareQuery, error) {
	if len(q.Hashes) > MaxShareHashes {
		return ShareQuery{}, ErrTooBroad
	}
	if q.maxBytes < 0 || q.maxBytes > MaxChargedBytes {
		return ShareQuery{}, ErrInvalid
	}
	hashes := slices.Clone(q.Hashes)
	sort.Slice(hashes, func(i, j int) bool { return bytes.Compare(hashes[i][:], hashes[j][:]) < 0 })
	for i, h := range hashes {
		if h == (common.Hash{}) || i > 0 && hashes[i-1] == h {
			return ShareQuery{}, ErrInvalid
		}
	}
	return ShareQuery{Hashes: hashes, fence: q.fence, maxBytes: q.maxBytes}, nil
}

type SharePass struct {
	owner   *ReaderIdentity
	binding ShareBinding
	query   ShareQuery
	rows    map[common.Hash]admission.Share
	digest  admission.Digest
	charged int
	fence   Fence
}

// NewSharePass compiles bounded trusted adapter output AFTER known COMMIT.
// Every queried hash not in rows is explicitly absent in that snapshot.
func NewSharePass(owner *ReaderIdentity, b ShareBinding, q ShareQuery, rows []admission.Share, fence Fence) (*SharePass, error) {
	q, err := NormalizeShareQuery(q)
	if err != nil || !owner.valid() || !b.Valid() || fence.Check() != nil || len(rows) > len(q.Hashes) {
		return nil, ErrInvalid
	}
	key, _ := b.Network.Key()
	charged := 256 + 64*len(q.Hashes)
	if charged > q.ByteLimit() {
		return nil, ErrTooBroad
	}
	p := &SharePass{owner: owner, binding: b, query: q, rows: make(map[common.Hash]admission.Share, len(rows)), fence: fence, charged: charged}
	for _, s := range rows {
		if !s.Valid() || s.DeclaredAt.Year() < 1 || s.DeclaredAt.Year() > 9999 || s.Witness.WalletEvidenceAt.Year() < 1 || s.Witness.WalletEvidenceAt.Year() > 9999 || s.Network != admission.Digest(key) || !slices.Contains(q.Hashes, s.Hash) {
			return nil, ErrUnavailable
		}
		if _, exists := p.rows[s.Hash]; exists {
			return nil, ErrUnavailable
		}
		p.charged += 512 + len(s.Actor) + len(s.Organization) + 32*len(s.Recipients)
		for _, actor := range s.Recipients {
			p.charged += len(actor)
		}
		if p.charged > q.ByteLimit() {
			return nil, ErrTooBroad
		}
		s.Recipients = slices.Clone(s.Recipients)
		s.DeclaredAt = s.DeclaredAt.UTC()
		s.Witness.WalletEvidenceAt = s.Witness.WalletEvidenceAt.UTC()
		p.rows[s.Hash] = s
	}
	p.digest = p.computeDigest()
	if fence.Check() != nil {
		return nil, ErrUnavailable
	}
	return p, nil
}
func (p *SharePass) Share(hash common.Hash) (admission.Share, bool) {
	if p == nil {
		return admission.Share{}, false
	}
	s, ok := p.rows[hash]
	s.Recipients = slices.Clone(s.Recipients)
	return s, ok
}
func (p *SharePass) ChargedBytes() int {
	if p == nil {
		return 0
	}
	return p.charged
}
func (p *SharePass) Query() ShareQuery {
	if p == nil {
		return ShareQuery{}
	}
	return ShareQuery{Hashes: slices.Clone(p.query.Hashes), fence: p.fence, maxBytes: p.query.maxBytes}
}
func (p *SharePass) ValidateFor(owner *ReaderIdentity, b ShareBinding) error {
	if p == nil || !owner.valid() || p.owner != owner || p.binding != b || p.fence.Check() != nil || p.digest != p.computeDigest() {
		return ErrUnavailable
	}
	return p.fence.Check()
}
func (p *SharePass) Bind(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if p == nil {
		return nil, nil, ErrInvalid
	}
	return p.fence.Bind(ctx)
}

// SamePositives permits new listings only for a subsequent request. An
// originally positive row must still be exactly the original immutable row.
func (p *SharePass) SamePositives(current *SharePass) bool {
	if p == nil || current == nil || p.owner != current.owner || p.binding != current.binding || !slices.Equal(p.query.Hashes, current.query.Hashes) {
		return false
	}
	for hash, old := range p.rows {
		now, ok := current.rows[hash]
		if !ok || shareDigest(old) != shareDigest(now) {
			return false
		}
	}
	return true
}
func shareDigest(s admission.Share) admission.Digest {
	// Fixed Go struct encoding is deterministic; there are no maps or pointers.
	raw, _ := json.Marshal(s)
	return admission.HashParts("ops-history-share-row/v1", raw)
}
func (p *SharePass) computeDigest() admission.Digest {
	parts := [][]byte{[]byte(p.binding.Network.Environment), []byte(p.binding.Network.ChainID), []byte(p.binding.Network.GenesisHash), []byte(p.binding.Network.DeploymentID), []byte(p.binding.State.Generation), p.binding.State.Coverage[:], []byte(p.binding.SchemaProfile)}
	for _, hash := range p.query.Hashes {
		parts = append(parts, hash[:])
		s, ok := p.rows[hash]
		if !ok {
			parts = append(parts, []byte{0})
		} else {
			d := shareDigest(s)
			parts = append(parts, []byte{1}, d[:])
		}
	}
	return admission.HashParts("ops-history-share-pass/v1", parts...)
}
