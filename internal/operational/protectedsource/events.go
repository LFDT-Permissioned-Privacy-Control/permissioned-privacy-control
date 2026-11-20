package protectedsource

import (
	"context"
	"slices"
	"strconv"

	d "privacy-proxy/internal/disclosuredata"
	p "privacy-proxy/internal/disclosurepolicy"
	x "privacy-proxy/internal/explorerquery"
	h "privacy-proxy/internal/historynamespace"
	r "privacy-proxy/internal/rpcexecution"
)

const maxEventScanLogs = 1024
const maxEventEmitters = 128
const eventFullWorkingBytes = 4 << 20
const eventMetadataWorkingBytes = 1 << 20

// A reservation within the existing owned-work ledger covers scan metadata,
// detached facts, and Full payload/hex copies before any raw getter is called.
// It is an accounting bound, not a claim about process RSS.
type eventPageBudget struct{ work, projection int }

func eventCost(meta r.HistoryLogMetadata, actorBytes int, full bool) (work, projection int, err error) {
	if meta.TopicCount < 0 || meta.TopicCount > 4 || meta.DataBytes < 0 || meta.DataBytes > d.MaxResponseBytes || actorBytes < 0 || actorBytes > d.MaxVariableBytes {
		return 0, 0, d.ErrTooBroad
	}
	work, projection = 2048+3*actorBytes, 2048+2*actorBytes
	if full {
		work += 5*meta.DataBytes + 192*meta.TopicCount
		projection += 3*meta.DataBytes + 132*meta.TopicCount
	}
	return work, projection, nil
}

func (n *nodeRead) reserveEvent(full bool) (*eventPageBudget, error) {
	reserved := eventMetadataWorkingBytes
	if full {
		reserved = eventFullWorkingBytes
	}
	if err := n.retain(reserved); err != nil {
		return nil, err
	}
	return &eventPageBudget{work: reserved - (256 << 10), projection: d.MaxVariableBytes - (64 << 10)}, nil
}

func (b *eventPageBudget) try(meta r.HistoryLogMetadata, actorBytes int, full bool) bool {
	work, projection, err := eventCost(meta, actorBytes, full)
	if err != nil || work > b.work || projection > b.projection {
		return false
	}
	b.work -= work
	b.projection -= projection
	return true
}

type eventScanUnit struct {
	parent int
	log    uint32 // receipt-local offset, never used as the public log ordinal
	meta   r.HistoryLogMetadata
	empty  bool
}

func eventParent(root qualifiedRoot) d.TransactionPosition {
	return d.TransactionPosition{BlockNumber: d.Count(strconv.FormatUint(root.root.Number, 10)), TransactionIndex: root.root.Index, Hash: root.indexed.Position.Hash}
}

func eventAfter(root qualifiedRoot) *d.Position {
	return &d.Position{Kind: d.HistorySource, Events: &d.EventsPosition{Parent: eventParent(root), Mode: "after"}}
}

func eventBoundary(n *nodeRead, root qualifiedRoot, local uint32) (*d.Position, error) {
	receipt, ok := n.blocks[root.root.Number].Receipt(root.root.Index)
	if !ok {
		return nil, d.ErrUnavailable
	}
	if local >= receipt.LogCount() {
		return eventAfter(root), nil
	}
	meta, ok := receipt.LogMetadata(local)
	if !ok || meta.TransactionIndex != root.root.Index {
		return nil, d.ErrUnavailable
	}
	ordinal := meta.LogIndex
	return &d.Position{Kind: d.HistorySource, Events: &d.EventsPosition{Parent: eventParent(root), Mode: "pending", NextLogIndex: &ordinal}}, nil
}

// Pending positions name the NEXT real block-global ordinal. Complete CB1
// receipt qualification occurs first, including earlier entries; only new scan
// metadata and new emitters consume this page's bounded work.
func eventStart(n *nodeRead, root qualifiedRoot, after *d.Position) (uint32, error) {
	if after == nil || after.Events.Mode != "pending" {
		return 0, nil
	}
	if eventParent(root) != after.Events.Parent || after.Events.NextLogIndex == nil {
		return 0, d.ErrConflict
	}
	receipt, ok := n.blocks[root.root.Number].Receipt(root.root.Index)
	if !ok || receipt.LogCount() == 0 {
		return 0, d.ErrConflict
	}
	first, ok := receipt.LogMetadata(0)
	if !ok || *after.Events.NextLogIndex < first.LogIndex {
		return 0, d.ErrConflict
	}
	local := *after.Events.NextLogIndex - first.LogIndex
	if local >= receipt.LogCount() {
		return 0, d.ErrConflict
	}
	meta, ok := receipt.LogMetadata(local)
	if !ok || meta.LogIndex != *after.Events.NextLogIndex || meta.TransactionIndex != root.root.Index {
		return 0, d.ErrConflict
	}
	return local, nil
}

func eventUnits(ctx context.Context, n *nodeRead, roots []qualifiedRoot, after *d.Position) ([]eventScanUnit, bool, error) {
	units := make([]eventScanUnit, 0, maxEventScanLogs+100)
	emitters := map[h.Address]bool{}
	scanned := 0
	for i, root := range roots {
		if ctx.Err() != nil {
			return nil, false, d.ErrUnavailable
		}
		receipt, ok := n.blocks[root.root.Number].Receipt(root.root.Index)
		if !ok {
			return nil, false, d.ErrUnavailable
		}
		start, err := eventStart(n, root, after)
		if err != nil {
			return nil, false, err
		}
		if receipt.LogCount() == 0 {
			units = append(units, eventScanUnit{parent: i, empty: true})
			continue
		}
		for local := start; local < receipt.LogCount(); local++ {
			if scanned >= maxEventScanLogs {
				return units, false, nil
			}
			meta, ok := receipt.LogMetadata(local)
			if !ok || meta.TransactionIndex != root.root.Index || meta.TopicCount > 4 || meta.LogIndex > 2147483647 {
				return nil, false, d.ErrUnavailable
			}
			emitter := h.Address(meta.Address)
			if !emitters[emitter] && len(emitters) >= maxEventEmitters {
				return units, false, nil
			}
			emitters[emitter] = true
			scanned++
			units = append(units, eventScanUnit{parent: i, log: local, meta: meta})
		}
	}
	return units, true, nil
}

func (read *snapshot) readEvents(ctx context.Context, predicate x.ProtectedPredicate, actors map[[20]byte][]string, reference d.Digest) error {
	if !d.NativeEventsPlan(read.owner.plan) {
		return d.ErrUnsupported
	}
	full := read.scope.Query.Scope().Level == p.Full
	budget, err := read.node.reserveEvent(full)
	if err != nil {
		return err
	}
	// Wallet identity strings also occur in private facts and must leave room
	// in the shared rendering budget. Never reclaim this charge on filtering.
	for _, wallet := range read.facts.Wallets {
		budget.projection -= len(wallet.ActorID)
	}
	if budget.projection <= 0 {
		return d.ErrTooBroad
	}
	query := x.ProtectedTransactionQuery{Limit: 100}
	pending := read.after != nil && read.after.Events.Mode == "pending"
	if read.after != nil {
		parent := read.after.Events.Parent
		if pending {
			hash := parent.Hash
			query.Hash = &hash
			query.Limit = 1
		} else {
			number, _ := strconv.ParseUint(string(parent.BlockNumber), 10, 63)
			query.After = &x.ProtectedPosition{Number: number, Index: parent.TransactionIndex, Hash: parent.Hash}
		}
	}
	// The protected Indexer contract permits exactly one transaction read.
	rows, indexEnd, err := read.index.ReadTransactions(ctx, predicate, query)
	if err != nil {
		return indexError(err)
	}
	if pending && len(rows) != 1 {
		return d.ErrConflict
	}
	read.facts.Events = []d.EventFact{}
	if len(rows) == 0 {
		if !indexEnd {
			return d.ErrUnavailable
		}
		read.facts.End = true
		return nil
	}
	roots, err := read.node.qualify(ctx, rows, false)
	if err != nil {
		return err
	}
	if len(roots) == 0 {
		return d.ErrTooBroad
	}
	if len(roots) < len(rows) {
		indexEnd = false
	}
	units, complete, err := eventUnits(ctx, read.node, roots, read.after)
	if err != nil {
		return err
	}
	if len(units) == 0 {
		return d.ErrTooBroad
	}
	// Plan the point/root and emitter support together before any support I/O.
	// A smaller prefix is a capacity choice, never permission to skip a bad row.
	count := len(units)
	var plan *eventNamespacePlan
	for attempt := 0; attempt < 12; attempt++ {
		emitters := make([]h.Address, 0, min(count, maxEventEmitters))
		for _, unit := range units[:count] {
			if !unit.empty {
				emitters = append(emitters, h.Address(unit.meta.Address))
			}
		}
		slices.SortFunc(emitters, func(a, b h.Address) int {
			for i := range a {
				if a[i] < b[i] {
					return -1
				}
				if a[i] > b[i] {
					return 1
				}
			}
			return 0
		})
		emitters = slices.Compact(emitters)
		plan, err = read.namespace.planEvents(ctx, roots[:units[count-1].parent+1], emitters)
		if err != nil {
			return err
		}
		if read.node.canSupportMany(plan.pointRequirements, plan.emitterRequirements) {
			break
		}
		if count == 1 || attempt == 11 {
			return d.ErrTooBroad
		}
		count = max(1, count/2)
	}
	if err = read.namespace.acceptEvents(ctx, plan, read.scope.DataOrganizationID); err != nil {
		return err
	}
	limit := int(read.scope.Query.Limit())
	consumed := 0
	var boundary *d.Position
	for _, unit := range units[:count] {
		if ctx.Err() != nil {
			return d.ErrUnavailable
		}
		root := roots[unit.parent]
		if !unit.empty && read.namespace.eventEmitterAllowed(root, h.Address(unit.meta.Address), read.scope.DataOrganizationID) {
			if len(read.facts.Events) >= limit {
				break
			}
			actorBytes := 0
			for _, id := range actors[root.fact.From] {
				actorBytes += len(id)
			}
			if root.fact.To != nil && *root.fact.To != root.fact.From {
				for _, id := range actors[*root.fact.To] {
					actorBytes += len(id)
				}
			}
			if !budget.try(unit.meta, actorBytes, full) {
				if len(read.facts.Events) == 0 {
					return d.ErrTooBroad
				}
				break
			}
			parent, err := transactionFact(read.scope, reference, actors, root.fact)
			if err != nil {
				return err
			}
			parent.Provenance.Kind = d.RetainedEventsPopulation
			event := d.EventFact{Transaction: parent, Emitter: [20]byte(unit.meta.Address), LogIndex: unit.meta.LogIndex}
			if full {
				receipt, _ := read.node.blocks[root.root.Number].Receipt(root.root.Index)
				log, ok := receipt.Log(unit.log)
				if !ok || len(log.Data) != unit.meta.DataBytes || len(log.Topics) != unit.meta.TopicCount {
					return d.ErrUnavailable
				}
				topics := make([][32]byte, len(log.Topics))
				for i, topic := range log.Topics {
					topics[i] = [32]byte(topic)
				}
				data := log.Data
				if data == nil {
					data = []byte{}
				}
				event.Payload = &d.EventPayload{Topics: topics, Data: data}
			}
			read.facts.Events = append(read.facts.Events, event)
		}
		consumed++
		if unit.empty {
			boundary = eventAfter(root)
		} else {
			boundary, err = eventBoundary(read.node, root, unit.log+1)
			if err != nil {
				return err
			}
		}
	}
	if consumed == 0 || boundary == nil {
		return d.ErrTooBroad
	}
	// An exact-hash lookup cannot establish global exhaustion. Completing a
	// pending receipt returns after(parent); the next normal query decides End.
	read.facts.End = !pending && indexEnd && complete && count == len(units) && consumed == count
	if !read.facts.End {
		read.facts.Next = boundary
	}
	return nil
}
