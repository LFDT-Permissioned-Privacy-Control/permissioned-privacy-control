package explorerindex

import (
	"context"
	"encoding/json"
	"errors"
	"google.golang.org/protobuf/proto"
	pb "privacy-proxy/gen/go/chain_indexer/v2"
	"privacy-proxy/internal/admissionsharedata"
	q "privacy-proxy/internal/explorerquery"
	"strings"
	"sync"
	"time"
)

type cohortState struct {
	mu        sync.Mutex
	owner     *Reader
	pass      *q.ReadPass
	query     q.Query
	operation *operation
	closed    bool
}

func (s *cohortState) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; s.operation.Close() }
func addrSet(s string) *pb.AddressSet {
	if s == "" {
		return nil
	}
	a, _ := unhex(s, 20)
	return &pb.AddressSet{Addresses: [][]byte{a}}
}
func hashSet(s string) *pb.HashSet {
	if s == "" {
		return nil
	}
	a, _ := unhex(s, 32)
	return &pb.HashSet{Hashes: [][]byte{a}}
}
func blockRange(v q.Query) *pb.BlockRange {
	if v.Block != nil {
		return &pb.BlockRange{FromBlock: v.Block, ToBlock: v.Block}
	}
	if v.From == nil && v.Through == nil {
		return nil
	}
	return &pb.BlockRange{FromBlock: v.From, ToBlock: v.Through}
}
func hashFilter(s string) []byte {
	if s == "" {
		return nil
	}
	b, _ := unhex(s, 32)
	return b
}
func expectedConsistency(f q.Family) pb.Consistency {
	switch f {
	case q.Tokens, q.Contracts, q.Addresses, q.Balances, q.Holders, q.Search:
		return pb.Consistency_CONSISTENCY_CURRENT
	default:
		return pb.Consistency_CONSISTENCY_SNAPSHOT
	}
}
func pageData(p *pb.PageInfo, f q.Family) (q.Data, error) {
	d := q.Data{Upper: &q.Anchor{Number: p.ReadAt.BlockNumber, Hash: hexBytes(p.ReadAt.BlockHash)}, DatasetEpoch: p.DatasetEpoch, RunFloor: p.RunFloorBlock, HistoryFrom: p.HistoryFromBlock, EndedAt: p.EndedAt.String(), Consistency: strings.TrimPrefix(p.Consistency.String(), "CONSISTENCY_"), Exhausted: p.NextStartAfter == nil}
	if p.NextStartAfter != nil {
		k, e := keyRead(f, p.NextStartAfter)
		if e != nil {
			return d, e
		}
		d.Next = &k
	}
	return d, nil
}
func (o *operation) list(ctx context.Context, v q.Query, page *pb.PageRequest) (*pb.PageInfo, []q.Record, error) {
	var info *pb.PageInfo
	rows := []q.Record{}
	add := func(r q.Record, e error) error {
		if e != nil {
			return e
		}
		if e := o.chargeRows(1); e != nil {
			return e
		}
		if e = o.retain(len(r.JSON) + len(r.Key) + 256); e != nil {
			return e
		}
		rows = append(rows, r)
		return nil
	}
	call := func(req proto.Message, fn func(context.Context) (proto.Message, error)) (proto.Message, error) {
		r, e := o.call(ctx, req, fn)
		if e != nil {
			return nil, rpcError(e)
		}
		return r, nil
	}
	read := clonedRead(o.read)
	switch v.Family {
	case q.Blocks:
		if v.Hash != "" || v.Block != nil {
			req := &pb.GetBlockRequest{Read: read}
			if v.Hash != "" {
				req.Selector = &pb.GetBlockRequest_Hash{Hash: hashFilter(v.Hash)}
			} else {
				req.Selector = &pb.GetBlockRequest_Number{Number: *v.Block}
			}
			r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.GetBlock(c, req) })
			if e != nil {
				return nil, nil, e
			}
			x := r.(*pb.GetBlockResponse)
			if x.Source != pb.Source_SOURCE_INDEXER && x.Source != pb.Source_SOURCE_NODE {
				return nil, nil, ErrUnavailable
			}
			info = x.Page
			if e = add(blockRecord(x.Block)); e != nil {
				return nil, nil, e
			}
			rows[len(rows)-1].Source = strings.TrimPrefix(x.Source.String(), "SOURCE_")
		} else {
			req := &pb.ListBlocksRequest{Read: read, Page: page, BlockRange: blockRange(v)}
			r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListBlocks(c, req) })
			if e != nil {
				return nil, nil, e
			}
			x := r.(*pb.ListBlocksResponse)
			info = x.Page
			for _, b := range x.Blocks {
				if e = add(blockRecord(b)); e != nil {
					return nil, nil, e
				}
			}
		}
	case q.Transactions:
		if v.Hash != "" {
			req := &pb.GetTransactionRequest{Read: read, Hash: hashFilter(v.Hash)}
			r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.GetTransaction(c, req) })
			if e != nil {
				return nil, nil, e
			}
			x := r.(*pb.GetTransactionResponse)
			info = x.Page
			if x.Source != pb.Source_SOURCE_INDEXER && x.Source != pb.Source_SOURCE_NODE {
				return nil, nil, ErrUnavailable
			}
			if e = add(txRecord(x.Transaction)); e != nil {
				return nil, nil, e
			}
			rows[len(rows)-1].Source = strings.TrimPrefix(x.Source.String(), "SOURCE_")
		} else {
			req := &pb.ListTransactionsRequest{Read: read, Page: page, Filter: &pb.TransactionFilter{AnyParty: addrSet(v.Address), BlockRange: blockRange(v)}}
			r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListTransactions(c, req) })
			if e != nil {
				return nil, nil, e
			}
			x := r.(*pb.ListTransactionsResponse)
			info = x.Page
			for _, b := range x.Transactions {
				if e = add(txRecord(b)); e != nil {
					return nil, nil, e
				}
			}
		}
	case q.Logs:
		req := &pb.ListLogsRequest{Read: read, Page: page, Filter: &pb.LogFilter{Addresses: addrSet(v.Address), Topic0: hashSet(v.Topic0), BlockRange: blockRange(v), TransactionHash: hashFilter(v.Hash), BlockNumber: v.Block}}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListLogs(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListLogsResponse)
		info = x.Page
		for _, b := range x.Logs {
			if e = add(logRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Transfers:
		req := &pb.ListTokenTransfersRequest{Read: read, Page: page, Filter: &pb.TransferFilter{AnyParty: addrSet(v.Address), Tokens: addrSet(v.Token), BlockRange: blockRange(v), TransactionHash: hashFilter(v.Hash), BlockNumber: v.Block}}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListTokenTransfers(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListTokenTransfersResponse)
		info = x.Page
		for _, b := range x.Transfers {
			if e = add(transferRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Internals:
		req := &pb.ListInternalTransactionsRequest{Read: read, Page: page, Filter: &pb.InternalFilter{AnyParty: addrSet(v.Address), BlockRange: blockRange(v), TransactionHash: hashFilter(v.Hash), BlockNumber: v.Block}}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListInternalTransactions(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListInternalTransactionsResponse)
		info = x.Page
		for _, b := range x.InternalTransactions {
			if e = add(internalRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Tokens:
		req := &pb.ListTokensRequest{Read: read, Page: page, Addresses: addrSet(v.Address), Search: v.Search, BlockRange: blockRange(v)}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListTokens(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListTokensResponse)
		info = x.Page
		for _, b := range x.Tokens {
			if e = add(tokenRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Contracts:
		req := &pb.ListContractsRequest{Read: read, Page: page, Addresses: addrSet(v.Address), BlockRange: blockRange(v)}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListContracts(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListContractsResponse)
		info = x.Page
		for _, b := range x.Contracts {
			if e = add(contractRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Addresses:
		req := &pb.ListAddressesRequest{Read: read, Page: page, Addresses: addrSet(v.Address)}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListAddresses(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListAddressesResponse)
		info = x.Page
		for _, b := range x.Addresses {
			if e = add(addressRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Balances:
		req := &pb.ListBalancesRequest{Read: read, Page: page, Addresses: addrSet(v.Address), Tokens: addrSet(v.Token)}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListBalances(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListBalancesResponse)
		info = x.Page
		for _, b := range x.Balances {
			if e = add(balanceRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Holders:
		req := &pb.ListHoldersRequest{Read: read, Page: page, TokenAddress: func() []byte { b, _ := unhex(v.Token, 20); return b }(), Addresses: addrSet(v.Address)}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.ListHolders(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.ListHoldersResponse)
		info = x.Page
		for _, b := range x.Holders {
			if e = add(holderRecord(b)); e != nil {
				return nil, nil, e
			}
		}
	case q.Search:
		req := &pb.SearchRequest{Read: read, Page: page, Query: v.Search}
		r, e := call(req, func(c context.Context) (proto.Message, error) { return o.owner.client.Search(c, req) })
		if e != nil {
			return nil, nil, e
		}
		x := r.(*pb.SearchResponse)
		info = x.Page
		for _, b := range x.Results {
			if b == nil || b.Key == nil {
				return nil, nil, ErrUnavailable
			}
			kind := strings.ToLower(strings.TrimPrefix(b.Key.Kind.String(), "SEARCH_KIND_"))
			if e = add(record(q.Search, &pb.Key{Value: &pb.Key_Search{Search: b.Key}}, map[string]any{"kind": kind, "value": hexBytes(b.Key.Identity)})); e != nil {
				return nil, nil, e
			}
		}
	default:
		return nil, nil, ErrInvalid
	}
	if e := o.page(info, expectedConsistency(v.Family)); e != nil {
		return nil, nil, e
	}
	if (v.Family == q.Blocks && (v.Hash != "" || v.Block != nil) || v.Family == q.Transactions && v.Hash != "") && info.NextStartAfter != nil {
		return nil, nil, ErrUnavailable
	}
	if expectedConsistency(v.Family) == pb.Consistency_CONSISTENCY_SNAPSHOT {
		for _, r := range rows {
			if r.Position.Block > info.ReadAt.BlockNumber || r.Source != "NODE" && r.Position.Block < max(info.RunFloorBlock, info.HistoryFromBlock) {
				return nil, nil, ErrUnavailable
			}
		}
	}
	if len(rows) > int(page.PageSize) && !(v.Hash != "" || v.Block != nil && v.Family == q.Blocks) {
		return nil, nil, ErrUnavailable
	}
	return info, rows, nil
}
func (o *operation) context(ctx context.Context, rows []q.Record) ([]q.Record, error) {
	hashes := [][]byte{}
	seen := map[string]bool{}
	for _, r := range rows {
		var f map[string]json.RawMessage
		if json.Unmarshal(r.JSON, &f) != nil {
			return nil, ErrUnavailable
		}
		key := "tx_hash"
		if r.Family == q.Transactions {
			key = "hash"
		}
		if r.Family == q.Search {
			var k string
			_ = json.Unmarshal(f["kind"], &k)
			if k == "transaction" {
				key = "value"
			}
		}
		var h string
		_ = json.Unmarshal(f[key], &h)
		if h != "" && !seen[h] {
			b, e := unhex(h, 32)
			if e != nil {
				return nil, e
			}
			seen[h] = true
			hashes = append(hashes, b)
		}
	}
	if len(hashes) == 0 {
		return nil, nil
	}
	if len(hashes) > 256 {
		return nil, ErrTooBroad
	}
	req := &pb.BatchGetTransactionsRequest{Read: clonedRead(o.read), Hashes: hashes}
	reply, err := o.call(ctx, req, func(c context.Context) (proto.Message, error) { return o.owner.client.BatchGetTransactions(c, req) })
	out := []q.Record{}
	add := func(r q.Record, e error) error {
		if e != nil {
			return e
		}
		if e := o.chargeRows(1); e != nil {
			return e
		}
		if e = o.retain(len(r.JSON) + len(r.Key) + 256); e != nil {
			return e
		}
		out = append(out, r)
		return nil
	}
	if err == nil {
		x := reply.(*pb.BatchGetTransactionsResponse)
		if x.Page == nil || x.Page.NextStartAfter != nil {
			return nil, ErrUnavailable
		}
		if e := o.page(x.Page, pb.Consistency_CONSISTENCY_SNAPSHOT); e != nil {
			return nil, e
		}
		if len(x.Transactions) != len(hashes) {
			return nil, ErrUnavailable
		}
		for i, b := range x.Transactions {
			if b == nil || b.Transaction == nil || b.Transaction.Key == nil || !bytesEqual(b.Transaction.Key.Hash, hashes[i]) {
				return nil, ErrUnavailable
			}
			if e := add(txRecord(b.Transaction)); e != nil {
				return nil, e
			}
			for _, v := range b.Logs {
				if e := add(logRecord(v)); e != nil {
					return nil, e
				}
			}
			for _, v := range b.Transfers {
				if e := add(transferRecord(v)); e != nil {
					return nil, e
				}
			}
			for _, v := range b.InternalTransactions {
				if e := add(internalRecord(v)); e != nil {
					return nil, e
				}
			}
		}
		return out, nil
	}
	if Reason(err) != "CHILD_LIST_TOO_LARGE" {
		return nil, rpcError(err)
	}
	// Reachable parent-only lookup, then bounded separately paged children. No
	// partial capped bundle is used and every call shares the original ledger.
	for _, h := range hashes {
		parent := &pb.GetTransactionRequest{Read: clonedRead(o.read), Hash: h}
		r, e := o.call(ctx, parent, func(c context.Context) (proto.Message, error) { return o.owner.client.GetTransaction(c, parent) })
		if e != nil {
			return nil, rpcError(e)
		}
		p := r.(*pb.GetTransactionResponse)
		if e = o.page(p.Page, pb.Consistency_CONSISTENCY_SNAPSHOT); e != nil {
			return nil, e
		}
		if p.Transaction == nil || p.Transaction.Key == nil || !bytesEqual(p.Transaction.Key.Hash, h) {
			return nil, ErrUnavailable
		}
		if e = add(txRecord(p.Transaction)); e != nil {
			return nil, e
		}
		families := []q.Family{}
		if len(rows) > 0 && (rows[0].Family == q.Transactions || rows[0].Family == q.Search) {
			families = []q.Family{q.Transfers}
		}
		for _, family := range families {
			child := q.Query{Family: family, Hash: hexBytes(h), RawLimit: 100}
			var after *pb.Key
			for {
				pg, rs, e := o.list(ctx, child, &pb.PageRequest{PageSize: 100, StartAfter: after})
				if e != nil {
					return nil, e
				}
				for _, v := range rs {
					out = append(out, v)
				}
				if pg.NextStartAfter == nil {
					break
				}
				if proto.Equal(after, pg.NextStartAfter) {
					return nil, ErrUnavailable
				}
				after = proto.Clone(pg.NextStartAfter).(*pb.Key)
			}
		}
	}
	return out, nil
}
func bytesEqual(a, b []byte) bool { return string(a) == string(b) }
func (r *Reader) ReadCohort(ctx context.Context, v q.Query) (*q.ReadPass, error) {
	normalized, e := q.Normalize(v)
	if e != nil {
		return nil, e
	}
	bound, cancel, e := normalized.Bind(ctx)
	if e != nil {
		return nil, ErrUnavailable
	}
	defer cancel()
	o, e := r.newOperation(ctx)
	if e != nil {
		return nil, e
	}
	// The local indexed deadline also bounds later node qualification and delivery.
	if normalized.Deadline().Before(func() time.Time { d, _ := o.fence.Original(); return d }()) {
		f, e := admissionsharedata.NewFence(ctx, time.Until(normalized.Deadline()))
		if e != nil {
			return nil, ErrUnavailable
		}
		o.fence = f
	}
	state := &cohortState{owner: r, operation: o}
	complete := false
	defer func() {
		if !complete {
			state.Close()
		}
	}()
	if normalized.Upper != nil {
		if normalized.DatasetEpoch == "" || normalized.RunFloor == nil {
			return nil, ErrInvalid
		}
		h, e := unhex(normalized.Upper.Hash, 32)
		if e != nil {
			return nil, e
		}
		o.read = &pb.ReadContext{ReadAt: &pb.ReadAt{BlockNumber: normalized.Upper.Number, BlockHash: h}, ExpectDatasetEpoch: normalized.DatasetEpoch, ExpectedRunFloor: normalized.RunFloor}
	}
	chain, e := o.chain(bound)
	if e != nil {
		return nil, e
	}
	var data q.Data
	if v.Family == q.Sync || v.Family == q.Progress {
		data, _ = pageData(chain.Page, v.Family)
		raw, _ := json.Marshal(map[string]any{"id": 1, "last_indexed_block": decimal(chain.LatestIndexed), "is_syncing": chain.IsSyncing, "max_fetched_block": decimal(chain.LatestIndexed), "min_fetched_block": decimal(chain.LowestIndexed), "backfill_complete": chain.BackfillComplete})
		data.Rows = []q.Record{{Family: v.Family, Key: "1", JSON: raw}}
		if v.Family == q.Sync {
			data.Context = []q.Record{{Family: q.Progress, Key: "1", JSON: raw}}
		}
	} else {
		key, e := keyWire(normalized.Family, normalized.After)
		if e != nil {
			return nil, e
		}
		page, rows, e := o.list(bound, normalized, &pb.PageRequest{PageSize: int32(min(100, normalized.RawLimit)), StartAfter: key})
		if e != nil {
			if errors.Is(e, ErrNotFound) {
				data, _ = pageData(chain.Page, v.Family)
			} else {
				return nil, e
			}
		} else {
			data, e = pageData(page, v.Family)
			if e != nil {
				return nil, e
			}
			data.Rows = rows
		}
		// A pruned NODE parent point is already complete parent/receipt data.
		// Its indexed child bundle is absent by definition; asking for it would
		// incorrectly turn a successful authorized node point into NOT_FOUND.
		if !(normalized.Family == q.Transactions && len(data.Rows) == 1 && data.Rows[0].Source == "NODE") {
			data.Context, e = o.context(bound, data.Rows)
			if e != nil {
				return nil, e
			}
		}
	}
	normalized.Upper = data.Upper
	normalized.DatasetEpoch = data.DatasetEpoch
	floor := data.RunFloor
	normalized.RunFloor = &floor
	state.query = normalized
	normalized.Fence = o.fence
	pass, e := q.NewReadPass(r.metadata, normalized, data, o.charged, state)
	if e != nil {
		return nil, e
	}
	state.pass = pass
	complete = true
	return pass, nil
}
func (r *Reader) Recheck(ctx context.Context, pass *q.ReadPass) error {
	if !r.valid() || pass.ValidateFor(r.metadata) != nil {
		return ErrUnavailable
	}
	raw, e := pass.StateFor(r.metadata.Identity)
	if e != nil {
		return e
	}
	s, ok := raw.(*cohortState)
	if !ok || s.owner != r || s.pass != pass {
		return ErrUnavailable
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrUnavailable
	}
	bound, cancel, e := s.query.Bind(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer cancel()
	_, e = s.operation.chain(bound)
	if e != nil {
		return e
	}
	return pass.ValidateFor(r.metadata)
}
