package explorerindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	q "privacy-proxy/internal/explorerquery"
)

type currentCountState struct {
	mu        sync.Mutex
	owner     *Reader
	pass      *q.CurrentCountPass
	query     q.CurrentCountQuery
	operation *operation
	closed    bool
}

func (s *currentCountState) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.operation.Close()
}
func countSelector(s q.CurrentCountSelector) (*pb.CurrentCountSelector, error) {
	if len(s.Addresses) > 4096 {
		return nil, ErrTooBroad
	}
	a := &pb.AddressSet{Addresses: make([][]byte, len(s.Addresses))}
	for i, v := range s.Addresses {
		b, e := unhex(v, 20)
		if e != nil || i > 0 && bytes.Compare(a.Addresses[i-1], b) >= 0 {
			return nil, ErrInvalid
		}
		a.Addresses[i] = b
	}
	switch s.Family {
	case q.Addresses:
		if s.Token != "" || s.TokenType != "" || s.Search != "" || s.From != nil || s.Through != nil {
			return nil, ErrInvalid
		}
		return &pb.CurrentCountSelector{Value: &pb.CurrentCountSelector_Addresses{Addresses: &pb.CurrentAddresses{Addresses: a}}}, nil
	case q.Tokens:
		return &pb.CurrentCountSelector{Value: &pb.CurrentCountSelector_Tokens{Tokens: &pb.CurrentTokens{Addresses: a, TokenType: s.TokenType, Search: s.Search, BlockRange: &pb.BlockRange{FromBlock: s.From, ToBlock: s.Through}}}}, nil
	case q.Holders:
		b, e := unhex(s.Token, 20)
		if e != nil {
			return nil, e
		}
		return &pb.CurrentCountSelector{Value: &pb.CurrentCountSelector_Holders{Holders: &pb.CurrentHolders{TokenAddress: b, Addresses: a}}}, nil
	default:
		return nil, ErrInvalid
	}
}
func (r *Reader) ReadCurrentCounts(ctx context.Context, query q.CurrentCountQuery) (*q.CurrentCountPass, error) {
	if len(query.Selectors) < 1 || len(query.Selectors) > 25 {
		return nil, ErrInvalid
	}
	bound, cancel, e := query.Read.Bind(ctx)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer cancel()
	if !r.valid() {
		return nil, ErrUnavailable
	}
	sourceFence, e := query.Read.Fence.Shortened(time.Now().Add(r.limits.Timeout))
	if e != nil {
		return nil, ErrUnavailable
	}
	o := &operation{owner: r, fence: sourceFence, budget: query.Read.Budget}
	query.Read.Fence = sourceFence
	state := &currentCountState{owner: r, query: query, operation: o}
	complete := false
	defer func() {
		if !complete {
			state.Close()
		}
	}()
	if query.Read.Upper != nil {
		h, e := unhex(query.Read.Upper.Hash, 32)
		if e != nil || query.Read.RunFloor == nil || !canonicalEpoch(query.Read.DatasetEpoch) {
			return nil, ErrInvalid
		}
		o.read = &pb.ReadContext{ReadAt: &pb.ReadAt{BlockNumber: query.Read.Upper.Number, BlockHash: h}, ExpectDatasetEpoch: query.Read.DatasetEpoch, ExpectedRunFloor: query.Read.RunFloor}
	}
	if _, e = o.chain(bound); e != nil {
		return nil, e
	}
	req := &pb.BatchCountCurrentRequest{Read: clonedRead(o.read)}
	work := 0
	for _, s := range query.Selectors {
		x, e := countSelector(s)
		if e != nil {
			return nil, e
		}
		work += len(s.Addresses)
		if work > 20000 {
			return nil, ErrTooBroad
		}
		req.Selectors = append(req.Selectors, x)
	}
	if e = o.chargeRows(work); e != nil {
		return nil, e
	}
	started := time.Now()
	reply, e := o.call(bound, req, func(c context.Context) (proto.Message, error) { return r.client.BatchCountCurrent(c, req) })
	if e != nil {
		return nil, rpcError(e)
	}
	v := reply.(*pb.BatchCountCurrentResponse)
	if e = o.page(v.Page, pb.Consistency_CONSISTENCY_CURRENT); e != nil {
		return nil, e
	}
	if len(v.Counts) != len(req.Selectors) || v.ObservedAt == nil || v.ObservedAt.CheckValid() != nil || v.ObservedAt.AsTime().Before(started.Add(-time.Second)) || v.ObservedAt.AsTime().After(time.Now().Add(time.Second)) {
		return nil, ErrUnavailable
	}
	d := q.CurrentCountData{ObservedAt: v.ObservedAt.AsTime(), Upper: q.Anchor{Number: v.Page.ReadAt.BlockNumber, Hash: hexBytes(v.Page.ReadAt.BlockHash)}, DatasetEpoch: v.Page.DatasetEpoch, RunFloor: v.Page.RunFloorBlock, HistoryFrom: v.Page.HistoryFromBlock}
	for i, x := range v.Counts {
		raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(req.Selectors[i])
		digest := sha256.Sum256(raw)
		if x == nil || !bytes.Equal(x.SelectorDigest, digest[:]) || x.Count > uint64(len(query.Selectors[i].Addresses)) {
			return nil, ErrUnavailable
		}
		d.Counts = append(d.Counts, x.Count)
	}
	pass, e := q.NewCurrentCountPass(r.metadata, query, d, o.charged, state)
	if e != nil {
		return nil, e
	}
	state.pass = pass
	complete = true
	return pass, nil
}
func (r *Reader) RecheckCurrentCounts(ctx context.Context, p *q.CurrentCountPass) error {
	if !r.valid() || p.ValidateFor(r.metadata) != nil {
		return ErrUnavailable
	}
	raw, e := p.StateFor(r.metadata.Identity)
	if e != nil {
		return e
	}
	s, ok := raw.(*currentCountState)
	if !ok || s.owner != r || s.pass != p {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	bound, cancel, e := s.query.Read.Bind(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer cancel()
	current, e := s.operation.chain(bound)
	if e != nil {
		return e
	}
	if current.Page.HistoryFromBlock != p.Data().HistoryFrom {
		return ErrConflict
	}
	return p.ValidateFor(r.metadata)
}
