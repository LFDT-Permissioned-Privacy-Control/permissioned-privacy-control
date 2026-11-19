package explorerquery

import (
	"context"
	"crypto/sha256"
	"encoding/json"
)

type Record struct {
	Source   string
	Family   Family
	Key      string
	Position Position
	JSON     json.RawMessage
}
type Data struct {
	Upper                 *Anchor
	Rows                  []Record
	Context               []Record
	Exhausted             bool
	Next                  *Position
	DatasetEpoch          string
	RunFloor, HistoryFrom uint64
	EndedAt, Consistency  string
}
type Source interface {
	Metadata() Metadata
	ReadCohort(context.Context, Query) (*ReadPass, error)
	Recheck(context.Context, *ReadPass) error
}
type ReadPass struct {
	metadata Metadata
	query    Query
	data     Data
	digest   [32]byte
	charged  int
	state    any
}

// NewReadPass is for a trusted fixed-purpose transport adapter after a complete
// service observation. It grants no permission and cannot certify all-chain completeness.
func NewReadPass(m Metadata, q Query, d Data, charged int, state any) (*ReadPass, error) {
	q, err := Normalize(q)
	if err != nil || !m.Binding.Valid() || !m.Identity.Valid() || m.Mode != Mode || q.Fence.Check() != nil || !ValidDatasetEpoch(d.DatasetEpoch) || q.DatasetEpoch != d.DatasetEpoch || q.RunFloor == nil || *q.RunFloor != d.RunFloor || q.Upper == nil || d.Upper == nil || *q.Upper != *d.Upper || d.RunFloor > d.Upper.Number || d.Exhausted != (d.Next == nil) || state == nil || charged < 0 || charged > 16<<20 || len(d.Rows) > q.RawLimit+1 || len(d.Rows)+len(d.Context) > 20000 {
		return nil, ErrInvalid
	}
	for _, rows := range [][]Record{d.Rows, d.Context} {
		for _, r := range rows {
			if len(r.Key) > 512 || len(r.JSON) > 2<<20 || !json.Valid(r.JSON) {
				return nil, ErrInvalid
			}
		}
	}
	p := &ReadPass{metadata: m, query: q, data: d, charged: charged, state: state}
	p.digest = p.computeDigest()
	return p, nil
}
func (p *ReadPass) computeDigest() [32]byte {
	raw, _ := json.Marshal(struct {
		Domain  string
		Binding Binding
		Query   Query
		Data    Data
	}{"ops-explorer-live-index-cohort/v1", p.metadata.Binding, p.query, p.data})
	return sha256.Sum256(raw)
}
func (p *ReadPass) ValidateFor(m Metadata) error {
	if p == nil || p.metadata != m || p.query.Fence.Check() != nil || p.digest != p.computeDigest() {
		return ErrUnavailable
	}
	return nil
}
func (p *ReadPass) StateFor(identity *ReaderIdentity) (any, error) {
	if p == nil || p.metadata.Identity != identity {
		return nil, ErrUnavailable
	}
	return p.state, nil
}
func (p *ReadPass) Query() Query {
	if p == nil {
		return Query{}
	}
	q, _ := Normalize(p.query)
	return q
}
func (p *ReadPass) Digest() [32]byte {
	if p == nil {
		return [32]byte{}
	}
	return p.digest
}
func (p *ReadPass) ChargedBytes() int {
	if p == nil {
		return 0
	}
	return p.charged
}
func (p *ReadPass) Data() Data {
	if p == nil {
		return Data{}
	}
	d := p.data
	if d.Next != nil {
		v := *d.Next
		d.Next = &v
	}
	if d.Upper != nil {
		c := *d.Upper
		d.Upper = &c
	}
	clone := func(in []Record) []Record {
		out := append([]Record{}, in...)
		for i := range out {
			out[i].JSON = append(json.RawMessage{}, out[i].JSON...)
		}
		return out
	}
	d.Rows = clone(d.Rows)
	d.Context = clone(d.Context)
	return d
}

func (p *ReadPass) Upper() *Anchor {
	if p == nil || p.data.Upper == nil {
		return nil
	}
	copy := *p.data.Upper
	return &copy
}

// Close releases an operational source's short-lived read purpose. It grants
// no authority and is harmless for detached test adapters without resources.
func (p *ReadPass) Close() {
	if p != nil {
		if state, ok := p.state.(interface{ Close() }); ok {
			state.Close()
		}
	}
}

func (p *ReadPass) DatasetEpoch() string {
	if p == nil {
		return ""
	}
	return p.data.DatasetEpoch
}
func (p *ReadPass) RunFloor() uint64 {
	if p == nil {
		return 0
	}
	return p.data.RunFloor
}
