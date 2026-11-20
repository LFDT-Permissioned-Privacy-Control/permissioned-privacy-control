package explorerquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"
)

type CurrentCountSelector struct {
	Family                   Family
	Addresses                []string
	Token, TokenType, Search string
	From, Through            *uint64
}
type CurrentCountQuery struct {
	Selectors []CurrentCountSelector
	Read      Query
}

func (q CurrentCountQuery) Digest() [32]byte { b, _ := json.Marshal(q); return sha256.Sum256(b) }

type CurrentCountData struct {
	Counts                []uint64
	ObservedAt            time.Time
	Upper                 Anchor
	DatasetEpoch          string
	RunFloor, HistoryFrom uint64
}
type CurrentCountSource interface {
	ReadCurrentCounts(context.Context, CurrentCountQuery) (*CurrentCountPass, error)
	RecheckCurrentCounts(context.Context, *CurrentCountPass) error
}
type CurrentCountPass struct {
	metadata Metadata
	query    CurrentCountQuery
	data     CurrentCountData
	digest   [32]byte
	charged  int
	state    any
}

func NewCurrentCountPass(m Metadata, q CurrentCountQuery, d CurrentCountData, charged int, state any) (*CurrentCountPass, error) {
	if !m.Binding.Valid() || !m.Identity.Valid() || m.Mode != Mode || q.Read.Fence.Check() != nil || state == nil || charged < 0 || charged > 16<<20 || len(q.Selectors) < 1 || len(q.Selectors) > 25 || len(q.Selectors) != len(d.Counts) || d.ObservedAt.IsZero() || !ValidDatasetEpoch(d.DatasetEpoch) || !ValidHash(d.Upper.Hash) || d.RunFloor > d.Upper.Number || d.HistoryFrom > d.Upper.Number {
		return nil, ErrInvalid
	}
	// Detached canonical copies keep the pass immutable to its caller.
	raw, _ := json.Marshal(q)
	var copied CurrentCountQuery
	if json.Unmarshal(raw, &copied) != nil {
		return nil, ErrInvalid
	}
	copied.Read.Fence = q.Read.Fence
	copied.Read.Budget = q.Read.Budget
	d.Counts = append([]uint64{}, d.Counts...)
	p := &CurrentCountPass{m, copied, d, [32]byte{}, charged, state}
	p.digest = p.compute()
	return p, nil
}
func (p *CurrentCountPass) compute() [32]byte {
	b, _ := json.Marshal(struct {
		Metadata Binding
		Query    CurrentCountQuery
		Data     CurrentCountData
	}{p.metadata.Binding, p.query, p.data})
	return sha256.Sum256(b)
}
func (p *CurrentCountPass) ValidateFor(m Metadata) error {
	if p == nil || p.metadata != m || p.query.Read.Fence.Check() != nil || p.compute() != p.digest {
		return ErrUnavailable
	}
	return nil
}
func (p *CurrentCountPass) StateFor(i *ReaderIdentity) (any, error) {
	if p == nil || p.metadata.Identity != i {
		return nil, ErrUnavailable
	}
	return p.state, nil
}
func (p *CurrentCountPass) Data() CurrentCountData {
	if p == nil {
		return CurrentCountData{}
	}
	d := p.data
	d.Counts = append([]uint64{}, d.Counts...)
	return d
}
func (p *CurrentCountPass) ChargedBytes() int {
	if p == nil {
		return 0
	}
	return p.charged
}
func (p *CurrentCountPass) QueryDigest() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.query.Digest()
}
func (p *CurrentCountPass) Close() {
	if p != nil {
		if c, ok := p.state.(interface{ Close() }); ok {
			c.Close()
		}
	}
}

func (p *CurrentCountPass) Deadline() time.Time {
	if p == nil {
		return time.Time{}
	}
	return p.query.Read.Deadline()
}
