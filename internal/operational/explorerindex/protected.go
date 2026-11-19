package explorerindex

import (
	"bytes"
	"context"
	"crypto/sha256"
	"google.golang.org/protobuf/proto"
	"math"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	q "privacy-proxy/internal/explorerquery"
	"slices"
	"sync"
)

type ProtectedSelection = q.ProtectedSelection
type ProtectedPosition = q.ProtectedPosition
type ProtectedRow = q.ProtectedRow
type ProtectedDestinations = q.ProtectedDestinations
type ProtectedWitness = q.ProtectedWitness
type ProtectedInterval = q.ProtectedInterval
type ProtectedCreation = q.ProtectedCreation
type ProtectedPredicate = q.ProtectedPredicate
type ProtectedTransactionQuery = q.ProtectedTransactionQuery
type protectedRead struct {
	mu                            sync.Mutex
	owner                         *Reader
	metadata                      q.Metadata
	selection                     q.ProtectedSelection
	operation                     *operation
	destinations                  *q.ProtectedDestinations
	destinationDigest             [32]byte
	lastDestinationDigest         [32]byte
	witnessed, transacted, closed bool
}

func (r *Reader) BeginProtected(ctx context.Context, s q.ProtectedSelection) (q.ProtectedRead, error) {
	if !r.valid() || s.Expected != r.metadata || len(s.Targets) > 4096 || s.FromTime > s.ThroughTime || s.ThroughTime > 253402300799 || s.FromNumber > s.ThroughNumber || s.ThroughNumber >= math.MaxInt64 {
		return nil, ErrInvalid
	}
	for i, a := range s.Targets {
		if i > 0 && bytes.Compare(s.Targets[i-1][:], a[:]) >= 0 {
			return nil, ErrInvalid
		}
	}
	o, e := r.newOperation(ctx)
	if e != nil {
		return nil, e
	}
	if s.ReadAt != nil {
		b, e := unhex(s.ReadAt.Hash, 32)
		if e != nil {
			return nil, e
		}
		o.read = &pb.ReadContext{ReadAt: &pb.ReadAt{BlockNumber: s.ReadAt.Number, BlockHash: b}, ExpectDatasetEpoch: s.DatasetEpoch, ExpectedRunFloor: s.RunFloor}
	}
	if _, e = o.chain(ctx); e != nil {
		o.Close()
		return nil, e
	}
	if s.ThroughNumber > o.read.ReadAt.BlockNumber {
		if s.ReadAt != nil {
			o.Close()
			return nil, ErrUnavailable
		}
		s.ThroughNumber = o.read.ReadAt.BlockNumber
	}
	if s.ReadAt == nil && (o.read.ReadAt.BlockNumber > s.ThroughNumber || s.ThroughNumber < s.FromNumber) {
		o.Close()
		return nil, ErrUnavailable
	}
	s.Targets = slices.Clone(s.Targets)
	return &protectedRead{owner: r, metadata: r.metadata, selection: s, operation: o}, nil
}
func (p *protectedRead) Snapshot() q.ProtectedSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return q.ProtectedSnapshot{ReadAt: q.Anchor{Number: p.operation.read.ReadAt.BlockNumber, Hash: hexBytes(p.operation.read.ReadAt.BlockHash)}, DatasetEpoch: p.operation.read.ExpectDatasetEpoch, RunFloor: *p.operation.read.ExpectedRunFloor}
}
func (p *protectedRead) valid() bool {
	return p != nil && !p.closed && p.owner.valid() && p.metadata == p.owner.Metadata() && p.operation.fence.Check() == nil
}
func (p *protectedRead) Close() {
	if p != nil {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.closed = true
		p.operation.Close()
	}
}
func (p *protectedRead) targets() *pb.AddressSet {
	out := &pb.AddressSet{Addresses: make([][]byte, len(p.selection.Targets))}
	for i, a := range p.selection.Targets {
		out.Addresses[i] = bytes.Clone(a[:])
	}
	return out
}
func (p *protectedRead) rangeFilter() *pb.TransactionFilter {
	return &pb.TransactionFilter{AnyParty: p.targets(), BlockRange: &pb.BlockRange{FromBlock: proto.Uint64(p.selection.FromNumber), ToBlock: proto.Uint64(p.selection.ThroughNumber)}, TimeRange: &pb.TimeRange{FromTimestamp: proto.Uint64(p.selection.FromTime), ToTimestamp: proto.Uint64(p.selection.ThroughTime)}}
}
func (p *protectedRead) counterparties(ctx context.Context) (q.ProtectedDestinations, error) {
	req := &pb.ListCounterpartiesRequest{Read: clonedRead(p.operation.read), Targets: p.targets(), BlockRange: p.rangeFilter().BlockRange, TimeRange: p.rangeFilter().TimeRange}
	r, e := p.operation.call(ctx, req, func(c context.Context) (proto.Message, error) { return p.owner.client.ListCounterparties(c, req) })
	if e != nil {
		return q.ProtectedDestinations{}, rpcError(e)
	}
	v := r.(*pb.ListCounterpartiesResponse)
	if e = p.operation.page(v.Page, pb.Consistency_CONSISTENCY_CURRENT); e != nil {
		return q.ProtectedDestinations{}, e
	}
	if v.Page.NextStartAfter != nil || len(v.Counterparties) > 4096 || (v.FirstBlock == nil) != (v.LastBlock == nil) {
		return q.ProtectedDestinations{}, ErrUnavailable
	}
	if e := p.operation.chargeRows(len(v.Counterparties)); e != nil {
		return q.ProtectedDestinations{}, e
	}
	out := q.ProtectedDestinations{Addresses: make([][20]byte, len(v.Counterparties))}
	for i, c := range v.Counterparties {
		if c == nil || c.Key == nil || !address(c.Key.Address) || i > 0 && bytes.Compare(v.Counterparties[i-1].Key.Address, c.Key.Address) >= 0 {
			return out, ErrUnavailable
		}
		if c.FirstBlock > c.LastBlock || c.FirstBlock < p.selection.FromNumber || c.LastBlock > p.selection.ThroughNumber {
			return out, ErrUnavailable
		}
		copy(out.Addresses[i][:], c.Key.Address)
	}
	if v.FirstBlock != nil {
		if *v.FirstBlock > *v.LastBlock || *v.FirstBlock < p.selection.FromNumber || *v.LastBlock > p.selection.ThroughNumber {
			return out, ErrUnavailable
		}
		a, b := *v.FirstBlock, *v.LastBlock
		out.First = &a
		out.Last = &b
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(v)
	if err != nil {
		return out, ErrUnavailable
	}
	p.lastDestinationDigest = sha256.Sum256(wire)
	return out, nil
}
func (p *protectedRead) ReadDestinations(ctx context.Context) (q.ProtectedDestinations, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.destinations != nil {
		return q.ProtectedDestinations{}, ErrInvalid
	}
	v, e := p.counterparties(ctx)
	if e != nil {
		return v, e
	}
	p.destinationDigest = p.lastDestinationDigest
	copy := v
	copy.Addresses = slices.Clone(v.Addresses)
	p.destinations = &copy
	return v, nil
}
func (p *protectedRead) predicate(v q.ProtectedPredicate) (*pb.DestinationPredicates, error) {
	if p.destinations == nil || len(v.Intervals) > 16384 || len(v.Creations) > 16384-len(v.Intervals) {
		return nil, ErrInvalid
	}
	if e := p.operation.retain((len(v.Intervals)+len(v.Creations))*128 + 128); e != nil {
		return nil, e
	}
	selected := func(a [20]byte) bool {
		_, ok := slices.BinarySearchFunc(p.destinations.Addresses, a, func(a, b [20]byte) int { return bytes.Compare(a[:], b[:]) })
		return ok
	}
	out := &pb.DestinationPredicates{}
	for _, i := range v.Intervals {
		if !selected(i.Address) || i.FromNumber < p.selection.FromNumber || i.BeforeNumber > p.selection.ThroughNumber+1 || i.FromNumber > i.BeforeNumber || i.FromNumber == i.BeforeNumber && i.FromIndex >= i.BeforeIndex {
			return nil, ErrInvalid
		}
		out.Intervals = append(out.Intervals, &pb.DestinationInterval{ToAddress: bytes.Clone(i.Address[:]), From: &pb.TransactionPosition{BlockNumber: i.FromNumber, TransactionIndex: i.FromIndex}, To: &pb.TransactionPosition{BlockNumber: i.BeforeNumber, TransactionIndex: i.BeforeIndex}})
	}
	for _, c := range v.Creations {
		if !selected(c.Address) || c.Position.Hash == ([32]byte{}) || c.Position.Number < p.selection.FromNumber || c.Position.Number > p.selection.ThroughNumber {
			return nil, ErrInvalid
		}
		out.Creations = append(out.Creations, &pb.ExactCreation{Transaction: &pb.TransactionKey{BlockNumber: c.Position.Number, TransactionIndex: c.Position.Index, Hash: bytes.Clone(c.Position.Hash[:])}})
	}
	return out, nil
}
func protectedRow(v *pb.Transaction, s q.ProtectedSelection) (q.ProtectedRow, error) {
	if _, e := txRecord(v); e != nil {
		return q.ProtectedRow{}, e
	}
	if v.Key.BlockNumber < s.FromNumber || v.Key.BlockNumber > s.ThroughNumber || v.BlockTimestamp < s.FromTime || v.BlockTimestamp > s.ThroughTime {
		return q.ProtectedRow{}, ErrUnavailable
	}
	out := q.ProtectedRow{Position: q.ProtectedPosition{Number: v.Key.BlockNumber, Index: v.Key.TransactionIndex}, Timestamp: v.BlockTimestamp}
	copy(out.Position.Hash[:], v.Key.Hash)
	copy(out.From[:], v.From)
	if v.To != nil {
		a := [20]byte{}
		copy(a[:], v.To)
		out.To = &a
	}
	return out, nil
}

// The retained parent does not carry a block hash: it is qualified against the
// actual node's complete typed transaction/receipt/header by protectedsource.
func (p *protectedRead) ReadWitnesses(ctx context.Context, v q.ProtectedPredicate) ([]q.ProtectedWitness, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.witnessed {
		return nil, ErrInvalid
	}
	pred, e := p.predicate(v)
	if e != nil {
		return nil, e
	}
	filter := p.rangeFilter()
	filter.Destinations = pred
	req := &pb.BatchFirstActivityRequest{Read: clonedRead(p.operation.read), Targets: p.targets(), Filter: filter}
	r, e := p.operation.call(ctx, req, func(c context.Context) (proto.Message, error) { return p.owner.client.BatchFirstActivity(c, req) })
	if e != nil {
		return nil, rpcError(e)
	}
	x := r.(*pb.BatchFirstActivityResponse)
	if x.Page == nil || x.Page.NextStartAfter != nil {
		return nil, ErrUnavailable
	}
	if e = p.operation.page(x.Page, pb.Consistency_CONSISTENCY_SNAPSHOT); e != nil {
		return nil, e
	}
	if len(x.Activities) != len(p.selection.Targets) {
		return nil, ErrUnavailable
	}
	if e := p.operation.chargeRows(len(x.Activities)); e != nil {
		return nil, e
	}
	out := []q.ProtectedWitness{}
	for i, a := range x.Activities {
		if a == nil || !bytes.Equal(a.Target, p.selection.Targets[i][:]) {
			return nil, ErrUnavailable
		}
		if a.Transaction == nil {
			continue
		}
		row, e := protectedRow(a.Transaction, p.selection)
		if e != nil {
			return nil, e
		}
		if row.From != p.selection.Targets[i] && (row.To == nil || *row.To != p.selection.Targets[i]) {
			return nil, ErrUnavailable
		}
		out = append(out, q.ProtectedWitness{Address: p.selection.Targets[i], Row: row})
	}
	p.witnessed = true
	return out, nil
}
func (p *protectedRead) ReadTransactions(ctx context.Context, v q.ProtectedPredicate, query q.ProtectedTransactionQuery) ([]q.ProtectedRow, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.transacted || query.Limit < 1 || query.Limit > 100 || query.Hash != nil && (query.After != nil || query.Limit != 1) {
		return nil, false, ErrInvalid
	}
	pred, e := p.predicate(v)
	if e != nil {
		return nil, false, e
	}
	filter := p.rangeFilter()
	filter.Destinations = pred
	if query.Address != nil {
		found := slices.Contains(p.selection.Targets, *query.Address)
		if !found {
			return nil, false, ErrInvalid
		}
		filter.AnyParty = &pb.AddressSet{Addresses: [][]byte{query.Address[:]}}
	}
	if query.Hash != nil {
		filter.TransactionHash = bytes.Clone(query.Hash[:])
	}
	var after *pb.Key
	if query.After != nil {
		after = &pb.Key{Value: &pb.Key_Transaction{Transaction: &pb.TransactionKey{BlockNumber: query.After.Number, TransactionIndex: query.After.Index, Hash: bytes.Clone(query.After.Hash[:])}}}
	}
	for {
		req := &pb.ListTransactionsRequest{Read: clonedRead(p.operation.read), Page: &pb.PageRequest{PageSize: int32(query.Limit), Order: pb.Order_ORDER_ASCENDING, StartAfter: after}, Filter: filter}
		r, e := p.operation.call(ctx, req, func(c context.Context) (proto.Message, error) { return p.owner.client.ListTransactions(c, req) })
		if e != nil {
			return nil, false, rpcError(e)
		}
		x := r.(*pb.ListTransactionsResponse)
		if e = p.operation.page(x.Page, pb.Consistency_CONSISTENCY_SNAPSHOT); e != nil {
			return nil, false, e
		}
		if len(x.Transactions) > int(query.Limit) {
			return nil, false, ErrUnavailable
		}
		if e := p.operation.chargeRows(len(x.Transactions)); e != nil {
			return nil, false, e
		}
		out := make([]q.ProtectedRow, 0, len(x.Transactions))
		for _, tx := range x.Transactions {
			row, e := protectedRow(tx, p.selection)
			if e != nil {
				return nil, false, e
			}
			out = append(out, row)
		}
		if len(out) == 0 && x.Page.NextStartAfter != nil {
			if proto.Equal(after, x.Page.NextStartAfter) {
				return nil, false, ErrUnavailable
			}
			after = proto.Clone(x.Page.NextStartAfter).(*pb.Key)
			continue
		}
		p.transacted = true
		return out, x.Page.NextStartAfter == nil, nil
	}
}
func (p *protectedRead) Recheck(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.valid() || p.destinations == nil {
		return ErrUnavailable
	}
	if _, e := p.operation.chain(ctx); e != nil {
		return e
	}
	_, e := p.counterparties(ctx)
	if e != nil {
		return e
	}
	if p.lastDestinationDigest != p.destinationDigest {
		return ErrConflict
	}
	return nil
}
