package rpcengine

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"privacy-proxy/internal/explorerquery"
	wire "privacy-proxy/internal/explorerv2data"
	"privacy-proxy/internal/historyfacts"
	"privacy-proxy/internal/rpcexecution"
)

type explorerCurrentCountEvidence struct {
	pass    *explorerquery.CurrentCountPass
	current *historyfacts.Current
	batch   *rpcexecution.IncludedHistoryBatch
}

func (p *explorerCurrentCountEvidence) recheck(ctx context.Context, e *ExplorerEngine) error {
	source, ok := e.config.Index.(explorerquery.CurrentCountSource)
	if !ok || p.pass.ValidateFor(e.metadata) != nil || source.RecheckCurrentCounts(ctx, p.pass) != nil || p.batch.Recheck(ctx) != nil || p.current.Recheck(ctx) != nil || p.current.RequireLive(ctx) != nil {
		return errExplorer
	}
	return nil
}
func wantsExplorerCounts(label string) bool {
	switch label {
	case "explorer.stats", "explorer.tokens", "explorer.token", "explorer.accounts", "explorer.address_stats", "explorer.blocks", "explorer.block_number", "explorer.block_hash":
		return true
	}
	return false
}
func unavailableCount(consistency string) wire.ScopedCount {
	return wire.ScopedCount{Status: "unavailable", Population: "ORDINARY_VISIBLE_ROWS", Consistency: consistency, Coverage: func() string {
		if consistency == "CURRENT" {
			return "current"
		}
		return "scan_limited"
	}()}
}
func exactCurrentCount(n uint64, observed time.Time) wire.ScopedCount {
	value := decimal(n)
	stamp := observed.UTC().Format(time.RFC3339Nano)
	return wire.ScopedCount{Status: "exact", Value: &value, Population: "ORDINARY_VISIBLE_ROWS", Consistency: "CURRENT", Coverage: "current", ObservedAt: &stamp}
}

type countTarget struct {
	address string
	counts  wire.Counts
	block   *explorerquery.Anchor
}

func (e *ExplorerEngine) currentCountBatch(ctx context.Context, r *ExplorerOperationResult, scope *historyfacts.Current, selectors []explorerquery.CurrentCountSelector) []wire.ScopedCount {
	out := make([]wire.ScopedCount, len(selectors))
	for i := range out {
		out[i] = unavailableCount("CURRENT")
	}
	source, ok := e.config.Index.(explorerquery.CurrentCountSource)
	if !ok || len(selectors) == 0 || scope == nil || !r.canCountMore() {
		return out
	}
	data := r.pass.Data()
	floor := data.RunFloor
	fence, err := scope.OperationFence().Shortened(r.countStarted.Add(5 * time.Second))
	if err != nil {
		return out
	}
	query := explorerquery.CurrentCountQuery{Selectors: selectors, Read: explorerquery.Query{Family: explorerquery.Addresses, RawLimit: 1, Upper: data.Upper, DatasetEpoch: data.DatasetEpoch, RunFloor: &floor, Fence: fence, Budget: r.readBudget}}
	acquire, cancel, ok := r.optionalCountContext(ctx, true)
	if !ok {
		return out
	}
	defer cancel()
	pass, err := source.ReadCurrentCounts(acquire, query)
	if err != nil {
		return out
	}
	keep := false
	defer func() {
		if !keep {
			pass.Close()
		}
	}()
	if pass.ValidateFor(e.metadata) != nil || pass.QueryDigest() != query.Digest() {
		return out
	}
	sample := pass.Data()
	client := e.config.History.clients[HistoryBindingKey{scope.Organization(), scope.CredentialRef()}]
	if client == nil {
		return out
	}
	d, done := scope.OriginalFence()
	d = minTimeExplorer(d, r.countDeadline())
	batch, err := client.AcquireExplorerBatchShared(acquire, nil, &rpcexecution.HistoryHeader{Number: sample.Upper.Number, Hash: common.HexToHash(sample.Upper.Hash)}, nil, rpcexecution.HistoryOperationFence{Deadline: d, Done: done}, pass.ChargedBytes(), r.nodeBudget)
	if err != nil {
		return out
	}
	for i, n := range sample.Counts {
		out[i] = exactCurrentCount(n, sample.ObservedAt)
	}
	r.currentCounts = append(r.currentCounts, &explorerCurrentCountEvidence{pass, scope, batch})
	keep = true
	return out
}
func minTimeExplorer(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (r *ExplorerOperationResult) countDeadline() time.Time {
	deadline := r.countStarted.Add(5 * time.Second)
	if r.current != nil {
		d, _ := r.current.OriginalFence()
		deadline = minTimeExplorer(deadline, d)
	}
	if r.pass != nil {
		deadline = minTimeExplorer(deadline, r.pass.Query().Deadline())
	}
	if r.batch != nil {
		deadline = minTimeExplorer(deadline, r.batch.Deadline())
	}
	for _, p := range r.countPages {
		if p.pass != nil {
			deadline = minTimeExplorer(deadline, p.pass.Query().Deadline())
		}
		if p.batch != nil {
			deadline = minTimeExplorer(deadline, p.batch.Deadline())
		}
	}
	for _, p := range r.currentCounts {
		deadline = minTimeExplorer(deadline, p.pass.Deadline())
		deadline = minTimeExplorer(deadline, p.batch.Deadline())
	}
	return deadline
}
func (r *ExplorerOperationResult) optionalCountContext(ctx context.Context, acquire bool) (context.Context, context.CancelFunc, bool) {
	hard := r.countDeadline()
	remaining := time.Until(hard)
	if remaining < 200*time.Millisecond {
		return nil, nil, false
	}
	deadline := hard.Add(-max(100*time.Millisecond, remaining/2))
	if acquire {
		deadline = minTimeExplorer(deadline, r.countStarted.Add(2*time.Second))
	}
	if !time.Now().Before(deadline) {
		return nil, nil, false
	}
	child, cancel := context.WithDeadline(ctx, deadline)
	return child, cancel, true
}
func (r *ExplorerOperationResult) canCountMore() bool {
	if r.readBudget == nil || time.Since(r.countStarted) >= 2*time.Second || time.Until(r.countDeadline()) < 200*time.Millisecond {
		return false
	}
	return r.readBudget.CanAcquire(len(r.countPages)+len(r.currentCounts)+1) && r.nodeBudget.CanAcquire(len(r.countPages)+len(r.currentCounts)+1)
}

// enrichExplorerCounts borrows original authority. Optional failures never turn
// a permitted ordinary page into invented zero or a raw indexer count.
func (e *ExplorerEngine) enrichExplorerCounts(ctx context.Context, r *ExplorerOperationResult) {
	if r.payload == nil || r.pass == nil || len(r.body) > MaxExplorerResponseBytes-(256<<10) {
		return
	}
	var tokens, accounts, blocks []countTarget
	data := r.pass.Data()
	blockTargets := map[uint64]bool{}
	visit := func(value any) any {
		switch item := value.(type) {
		case wire.Block:
			item.Counts = wire.Counts{"transactions": unavailableCount("SNAPSHOT")}
			n, err := explorerNumber(string(item.Number))
			if err != nil {
				return item
			}
			count := item.Counts["transactions"]
			count.Range = &wire.CountRange{FromBlock: item.Number, ThroughBlock: item.Number, HeadHash: item.Hash}
			if n < data.HistoryFrom {
				count.Coverage = "history_pruned"
			} else if n < data.RunFloor || item.Source != "INDEXER" {
				count.Coverage = "index_floor"
			}
			item.Counts["transactions"] = count
			if item.Source == "INDEXER" && data.Upper != nil && n >= max(data.HistoryFrom, data.RunFloor) && n <= data.Upper.Number && len(blocks) < 25 && !blockTargets[n] {
				if _, ok := r.batch.Header(n, common.HexToHash(item.Hash)); ok {
					blockTargets[n] = true
					blocks = append(blocks, countTarget{counts: item.Counts, block: &explorerquery.Anchor{Number: n, Hash: item.Hash}})
				}
			}
			return item
		case wire.Token:
			item.Counts = wire.Counts{"holders": unavailableCount("CURRENT"), "tokenTransfers": unavailableCount("SNAPSHOT")}
			tokens = append(tokens, countTarget{address: item.Address, counts: item.Counts})
			return item
		case wire.AddressStats:
			item.Counts = wire.Counts{"transactions": unavailableCount("SNAPSHOT"), "tokenTransfers": unavailableCount("SNAPSHOT"), "internalTransactions": unavailableCount("SNAPSHOT")}
			accounts = append(accounts, countTarget{address: item.Address, counts: item.Counts})
			return item
		}
		return value
	}
	var stats *wire.ChainStats
	switch payload := r.payload.(type) {
	case wire.Page[any]:
		for i, item := range payload.Items {
			payload.Items[i] = visit(item)
		}
		r.payload = payload
	case wire.Token:
		r.payload = visit(payload)
	case wire.Block:
		r.payload = visit(payload)
	case wire.AddressStats:
		r.payload = visit(payload)
	case wire.ChainStats:
		payload.Counts = wire.Counts{"transactions": unavailableCount("SNAPSHOT"), "accounts": unavailableCount("CURRENT"), "tokens": unavailableCount("CURRENT"), "blocks": unavailableCount("SNAPSHOT")}
		stats = &payload
		r.payload = payload
	}
	full, fullErr := r.current.FullAddressSet(4096)
	addresses := make([]string, len(full))
	for i, a := range full {
		addresses[i] = strings.ToLower(a.Hex())
	}
	if fullErr == nil {
		if len(tokens) > 0 {
			if scope, err := r.current.ForMethod("eth_getLogs"); err == nil {
				selectors := make([]explorerquery.CurrentCountSelector, len(tokens))
				for i, t := range tokens {
					selectors[i] = explorerquery.CurrentCountSelector{Family: explorerquery.Holders, Addresses: addresses, Token: t.address}
				}
				values := e.currentCountBatch(ctx, r, scope, selectors)
				for i, v := range values {
					tokens[i].counts["holders"] = v
				}
			}
		}
		if stats != nil {
			for _, metric := range []struct {
				name, method string
				family       explorerquery.Family
			}{{"accounts", "eth_getTransactionByHash", explorerquery.Addresses}, {"tokens", "eth_getLogs", explorerquery.Tokens}} {
				if scope, err := r.current.ForMethod(metric.method); err == nil {
					value := e.currentCountBatch(ctx, r, scope, []explorerquery.CurrentCountSelector{{Family: metric.family, Addresses: addresses}})
					stats.Counts[metric.name] = value[0]
				}
			}
		}
	}
	if len(accounts) > 0 {
		e.countHistory(ctx, r, accounts, "transactions", "eth_getTransactionByHash", "/addresses/"+accounts[0].address+"/transactions", explorerquery.Transactions, false)
		e.countHistory(ctx, r, accounts, "tokenTransfers", "eth_getLogs", "/addresses/"+accounts[0].address+"/transfers", explorerquery.Transfers, false)
		e.countHistory(ctx, r, accounts, "internalTransactions", "eth_getTransactionByHash", "/addresses/"+accounts[0].address+"/internal", explorerquery.Internals, false)
	}
	if len(tokens) > 0 {
		e.countHistory(ctx, r, tokens, "tokenTransfers", "eth_getLogs", "/tokens/"+tokens[0].address+"/transfers", explorerquery.Transfers, true)
	}
	if len(blocks) > 0 {
		e.countHistory(ctx, r, blocks, "transactions", "eth_getTransactionByHash", "/blocks/"+string(decimal(blocks[0].block.Number))+"/transactions", explorerquery.Transactions, false)
	}
	if stats != nil {
		targets := []countTarget{{counts: stats.Counts}}
		e.countHistory(ctx, r, targets, "transactions", "eth_getTransactionByHash", "/transactions", explorerquery.Transactions, false)
		e.countHistory(ctx, r, targets, "blocks", "eth_getBlockByNumber", "/blocks", explorerquery.Blocks, false)
		r.payload = *stats
	}
	r.setExactCountFields()
	r.body, _ = json.Marshal(r.payload)
}

func (e *ExplorerEngine) countHistory(ctx context.Context, parent *ExplorerOperationResult, targets []countTarget, metric, method, path string, family explorerquery.Family, byToken bool) {
	if len(targets) == 0 || !parent.canCountMore() {
		return
	}
	scope, err := parent.current.ForMethod(method)
	if err != nil {
		return
	}
	request, err := parseExplorerRequest("/api/v2/explorer"+path, "limit=1000")
	if err != nil {
		return
	}
	request.query.Address = ""
	request.query.Token = ""
	selected := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.address != "" {
			selected = append(selected, target.address)
		}
	}
	sort.Strings(selected)
	if byToken {
		request.query.TokenSet = selected
	} else {
		request.query.AddressSet = selected
	}
	data := parent.pass.Data()
	floor := data.RunFloor
	from := max(data.RunFloor, data.HistoryFrom)
	byBlock := targets[0].block != nil
	var requiredAnchors []rpcexecution.HistoryHeader
	if byBlock {
		if len(targets) > 25 {
			return
		}
		from = targets[0].block.Number
		through := from
		for _, target := range targets {
			if target.block == nil {
				return
			}
			from = min(from, target.block.Number)
			through = max(through, target.block.Number)
			requiredAnchors = append(requiredAnchors, rpcexecution.HistoryHeader{Number: target.block.Number, Hash: common.HexToHash(target.block.Hash)})
		}
		// Parsing a point block route installs Query.Block. A grouped range must
		// clear it, or later selected blocks could falsely become exact zero.
		request.query.Block = nil
		request.query.Hash = ""
		request.query.Through = &through
	}
	request.query.Upper = data.Upper
	request.query.DatasetEpoch = data.DatasetEpoch
	request.query.RunFloor = &floor
	request.query.From = &from
	totals := make([]uint64, len(targets))
	seen := map[string]bool{}
	proofs := []*ExplorerOperationResult{}
	complete := false
	observed := time.Time{}
	defer func() {
		for _, proof := range proofs {
			proof.Close()
		}
	}()
	for parent.canCountMore() {
		page := &ExplorerOperationResult{owner: e, current: scope, request: request, readBudget: parent.readBudget, nodeBudget: parent.nodeBudget, countStarted: parent.countStarted, layoutMatcher: parent.layoutMatcher, countHardDeadline: parent.countDeadline(), countAnchors: requiredAnchors}
		acquire, cancel, ok := parent.optionalCountContext(ctx, true)
		if !ok {
			break
		}
		e.readExplorerPage(acquire, page)
		completed := acquire.Err() == nil
		cancel()
		if !completed {
			page.Close()
			return
		}
		if page.captured.HTTPStatus != 200 || page.pass == nil || page.payload == nil {
			page.Close()
			return
		}
		d := page.pass.Data()
		if d.HistoryFrom != data.HistoryFrom || d.RunFloor != data.RunFloor || d.DatasetEpoch != data.DatasetEpoch || d.Upper == nil || *d.Upper != *data.Upper {
			page.Close()
			return
		}
		renderer, err := newExplorerRender(page, d)
		if err != nil {
			page.Close()
			return
		}
		if observed.IsZero() {
			observed = time.Now().UTC()
		}
		position := page.scanPosition
		for _, row := range d.Rows {
			if position != nil && row.Position == *position { /* included below, then stop */
			}
			key := string(family) + ":" + row.Key
			if seen[key] {
				page.Close()
				return
			}
			seen[key] = true
			fields, err := fieldsOf(row)
			if err != nil {
				page.Close()
				return
			}
			var ok bool
			switch family {
			case explorerquery.Transactions:
				_, ok, err = renderer.transaction(row)
			case explorerquery.Transfers:
				_, ok, err = renderer.transferWire(row)
			case explorerquery.Internals:
				_, ok, err = renderer.internalWire(row)
			case explorerquery.Blocks:
				_, ok, err = renderer.other(row)
			}
			if err != nil {
				page.Close()
				return
			}
			for i, target := range targets {
				if parent.readBudget.Work(1) != nil {
					page.Close()
					return
				}
				matches := target.address == ""
				if byBlock {
					tx, found := renderer.transactions[fields.text("hash")]
					if !found {
						page.Close()
						return
					}
					matches = tx.Location.BlockNumber == target.block.Number
					if matches && strings.ToLower(tx.Location.BlockHash.Hex()) != target.block.Hash {
						page.Close()
						return
					}
				} else if byToken {
					matches = fields.text("token_address") == target.address
				} else if target.address != "" {
					matches = fields.text("from_address") == target.address || fields.text("to_address") == target.address || family == explorerquery.Transactions && fields.text("contract_address") == target.address
				}
				if ok && matches {
					totals[i]++
				}
			}
			if position != nil && row.Position == *position {
				break
			}
		}
		proofs = append(proofs, page)
		if page.scanExhausted {
			complete = true
			break
		}
		if position == nil || request.query.After != nil && *request.query.After == *position {
			return
		}
		next := *position
		request.query.After = &next
	}
	if len(proofs) == 0 {
		return
	}
	stamp := observed.Format(time.RFC3339Nano)
	for i, target := range targets {
		value := decimal(totals[i])
		count := wire.ScopedCount{Status: "at_least", LowerBound: &value, Population: "ORDINARY_VISIBLE_ROWS", Consistency: "SNAPSHOT", ObservedAt: &stamp, Range: &wire.CountRange{FromBlock: decimal(from), ThroughBlock: decimal(data.Upper.Number), HeadHash: data.Upper.Hash}, Coverage: "scan_limited"}
		if byBlock {
			count.Range = &wire.CountRange{FromBlock: decimal(target.block.Number), ThroughBlock: decimal(target.block.Number), HeadHash: target.block.Hash}
		}
		if complete {
			count.Status = "exact"
			count.Value = &value
			count.LowerBound = nil
			count.Coverage = "complete_range"
			if !byBlock && data.HistoryFrom > 0 && data.HistoryFrom >= data.RunFloor {
				count.Coverage = "history_pruned"
			} else if !byBlock && data.RunFloor > 0 {
				count.Coverage = "index_floor"
			}
		}
		target.counts[metric] = count
	}
	parent.countPages = append(parent.countPages, proofs...)
	proofs = nil
}

func (r *ExplorerOperationResult) setExactCountFields() {
	exact := func(c wire.Counts, k string) *wire.Quantity {
		if v, ok := c[k]; ok && v.Status == "exact" {
			return v.Value
		}
		return nil
	}
	apply := func(v any) any {
		switch x := v.(type) {
		case wire.Token:
			x.HolderCount = exact(x.Counts, "holders")
			x.TransferCount = exact(x.Counts, "tokenTransfers")
			return x
		case wire.Block:
			x.TransactionCount = exact(x.Counts, "transactions")
			return x
		case wire.AddressStats:
			x.TxCount = exact(x.Counts, "transactions")
			x.TokenTransferCount = exact(x.Counts, "tokenTransfers")
			x.InternalTxCount = exact(x.Counts, "internalTransactions")
			return x
		case wire.ChainStats:
			x.TotalTransactions = exact(x.Counts, "transactions")
			x.TotalAddresses = exact(x.Counts, "accounts")
			x.TotalTokens = exact(x.Counts, "tokens")
			x.TotalBlocks = exact(x.Counts, "blocks")
			return x
		}
		return v
	}
	if p, ok := r.payload.(wire.Page[any]); ok {
		for i, v := range p.Items {
			p.Items[i] = apply(v)
		}
		r.payload = p
	} else {
		r.payload = apply(r.payload)
	}
}

// PrepareResponseFor resolves optional-proof failure before preparing bytes.
// Original parent authority still fails closed after the recorder append.
func (r *ExplorerOperationResult) PrepareResponseFor(ctx context.Context, e *ExplorerEngine) ([]byte, error) {
	if r == nil || r.owner != e {
		return nil, errExplorer
	}
	if r.readBudget == nil {
		body, err := r.MarshalResponseFor(e)
		if err != nil {
			return nil, err
		}
		if err = r.RequireDeliverable(ctx, e); err != nil {
			return nil, err
		}
		return body, nil
	}
	if r.payload != nil && r.readBudget != nil {
		countCtx, cancel, ok := r.optionalCountContext(ctx, false)
		if !ok {
			r.dropCounts()
		} else {
			if r.checkCountEvidence(countCtx, e) != nil {
				r.dropCounts()
			}
			cancel()
		}
	}
	if err := r.requireBaseDeliverable(ctx, e); err != nil {
		return nil, err
	}
	body, err := r.MarshalResponseFor(e)
	if err != nil {
		return nil, err
	}
	if r.baseProofsLive(ctx, e) != nil {
		return nil, errExplorer
	}
	if r.countProofsLive(ctx, e) != nil {
		r.dropCounts()
		body, err = r.MarshalResponseFor(e)
		if err != nil || r.baseProofsLive(ctx, e) != nil {
			return nil, errExplorer
		}
	}
	return body, nil
}

func (r *ExplorerOperationResult) baseProofsLive(ctx context.Context, e *ExplorerEngine) error {
	if ctx == nil || ctx.Err() != nil || r.current != nil && r.current.RequireLive(ctx) != nil || r.pass != nil && r.pass.ValidateFor(e.metadata) != nil || r.batch != nil && r.batch.RequireLive() != nil {
		return errExplorer
	}
	return nil
}
func (r *ExplorerOperationResult) countProofsLive(ctx context.Context, e *ExplorerEngine) error {
	for _, p := range r.countPages {
		if p.baseProofsLive(ctx, e) != nil {
			return errExplorer
		}
	}
	for _, p := range r.currentCounts {
		if p.pass.ValidateFor(e.metadata) != nil || p.batch.RequireLive() != nil || p.current.RequireLive(ctx) != nil {
			return errExplorer
		}
	}
	return nil
}
func (r *ExplorerOperationResult) checkCountEvidence(ctx context.Context, e *ExplorerEngine) error {
	for _, page := range r.countPages {
		if page.RequireDeliverable(ctx, e) != nil {
			return errExplorer
		}
	}
	for _, p := range r.currentCounts {
		if p.recheck(ctx, e) != nil {
			return errExplorer
		}
	}
	return nil
}
func (r *ExplorerOperationResult) dropCounts() {
	for _, p := range r.countPages {
		p.Close()
	}
	r.countPages = nil
	for _, p := range r.currentCounts {
		p.pass.Close()
		p.batch.Close()
	}
	r.currentCounts = nil
	apply := func(value any) any {
		var counts wire.Counts
		switch x := value.(type) {
		case wire.Token:
			counts = x.Counts
		case wire.Block:
			counts = x.Counts
		case wire.AddressStats:
			counts = x.Counts
		case wire.ChainStats:
			counts = x.Counts
		}
		for k, c := range counts {
			counts[k] = unavailableCount(c.Consistency)
		}
		return value
	}
	if p, ok := r.payload.(wire.Page[any]); ok {
		for i, v := range p.Items {
			p.Items[i] = apply(v)
		}
		r.payload = p
	} else {
		r.payload = apply(r.payload)
	}
	r.setExactCountFields()
	r.body, _ = json.Marshal(r.payload)
}
