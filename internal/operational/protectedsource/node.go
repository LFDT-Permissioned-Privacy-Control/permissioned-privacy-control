// Package protectedsource assembles operational disclosure reads. Retained
// index enumeration is a named trust input; node/C2 qualification is separate.
package protectedsource

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	c "privacy-proxy/internal/creationfacts"
	d "privacy-proxy/internal/disclosuredata"
	x "privacy-proxy/internal/explorerquery"
	h "privacy-proxy/internal/historynamespace"
	r "privacy-proxy/internal/rpcexecution"
)

// One request may touch at most128 canonical numbers. Shared CB1 sets avoid
// repeated network setup: 7*C+35 physical attempts, including both final passes.
const maxNodeAttempts = 931
const maxNodeBlocks = 128
const maxNodeWire = 32 << 20
const maxNodeOwned = 16 << 20
const finalNodeCalls = 2 * (maxNodeBlocks + 3)
const finalNodeWire = 2 * ((maxNodeBlocks+1)*(16<<10) + 2*(4<<10))
const finalNodeOwned = 256 << 10

// NodeConfig is approved startup assembly for one DataOrg. A disclosure
// recipient never selects the URL, credential or a fallback group credential.
type NodeConfig struct {
	Source     c.Source
	Credential r.Credential
	Transport  r.Transport
}

type nodeRead struct {
	config                            NodeConfig
	wire                              *nodeWire
	headers                           *r.HeaderClient
	owned                             int
	canonical                         map[uint64]h.CanonicalBlock
	blocks                            map[uint64]*r.HistoryBlockObservation
	touched                           map[uint64]bool
	bodyTouched                       map[uint64]bool
	bodySets, headerSets, finalChecks int
	fence                             r.HistoryOperationFence
	acquireDeadline                   time.Time
	finalWindow                       time.Duration
}

type nodeWire struct {
	mu            sync.Mutex
	base          r.Transport
	attempts      int
	remaining     int64
	exceeded      bool
	reservedCalls int
	reservedWire  int64
}
type nodeBody struct {
	body   io.ReadCloser
	budget *nodeWire
}

func (b *nodeWire) RoundTrip(request *http.Request) (*http.Response, error) {
	b.mu.Lock()
	if b.attempts >= maxNodeAttempts-b.reservedCalls || b.remaining <= b.reservedWire || b.exceeded {
		b.exceeded = true
		b.mu.Unlock()
		return nil, d.ErrTooBroad
	}
	b.attempts++
	b.mu.Unlock()
	response, err := b.base.RoundTrip(request)
	if err != nil || response == nil || response.Body == nil {
		return response, err
	}
	copy := *response
	copy.Body = &nodeBody{response.Body, b}
	return &copy, nil
}
func (body *nodeBody) Read(p []byte) (int, error) {
	b := body.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.remaining < b.reservedWire || b.exceeded {
		return 0, d.ErrTooBroad
	}
	// One overflow probe, as in CB1's own bounded wire reader, detects a body
	// exceeding the limit without consuming an unbounded remainder.
	if int64(len(p)) > b.remaining-b.reservedWire+1 {
		p = p[:b.remaining-b.reservedWire+1]
	}
	n, err := body.body.Read(p)
	b.remaining -= int64(n)
	if b.remaining < b.reservedWire {
		b.exceeded = true
		return n, d.ErrTooBroad
	}
	return n, err
}
func (body *nodeBody) Close() error { return body.body.Close() }
func (n *nodeRead) sourceError(err error) error {
	n.wire.mu.Lock()
	exceeded := n.wire.exceeded
	n.wire.mu.Unlock()
	var failure *r.Error
	if exceeded || errors.Is(err, d.ErrTooBroad) || errors.As(err, &failure) && failure.Code == r.EvidenceLimit {
		return d.ErrTooBroad
	}
	return d.ErrUnavailable
}
func newNodeRead(config NodeConfig) (*nodeRead, error) {
	if config.Transport == nil || !config.Source.Valid() || config.Source.Organization == "" || config.Source.Profile != "reth-prague-included-creations/v1" {
		return nil, d.ErrInvalid
	}
	wire := &nodeWire{base: config.Transport, remaining: maxNodeWire}
	headers, err := r.NewHeaderClient(wire, config.Source, config.Credential, r.HeaderLimits{Timeout: 5 * time.Second, MaxQueries: maxNodeBlocks, MaxHeaderBytes: 16 << 10})
	if err != nil {
		return nil, d.ErrInvalid
	}
	return &nodeRead{config: config, wire: wire, headers: headers, canonical: map[uint64]h.CanonicalBlock{}, blocks: map[uint64]*r.HistoryBlockObservation{}, touched: map[uint64]bool{}, bodyTouched: map[uint64]bool{}}, nil
}

func (n *nodeRead) bind(deadline time.Time, done <-chan struct{}) error {
	if !n.fence.Deadline.IsZero() || !deadline.After(time.Now()) {
		return d.ErrUnavailable
	}
	n.fence = r.HistoryOperationFence{Deadline: deadline, Done: done}
	n.finalWindow = min(time.Second, time.Until(deadline)/4)
	n.acquireDeadline = deadline.Add(-2 * n.finalWindow)
	n.wire.reservedCalls, n.wire.reservedWire = finalNodeCalls, finalNodeWire
	return n.retain(finalNodeOwned)
}

// Count work before dispatch. Before-fetched but unconsumed numbers, failed
// bodies and superseded candidate suffixes never return credit.
func (n *nodeRead) touch(numbers []uint64) error {
	if !n.canTouch(numbers) {
		return d.ErrTooBroad
	}
	for _, number := range numbers {
		n.touched[number] = true
	}
	return nil
}
func (n *nodeRead) canTouch(numbers []uint64) bool {
	union := make(map[uint64]bool, len(n.touched)+len(numbers))
	for number := range n.touched {
		union[number] = true
	}
	for _, number := range numbers {
		union[number] = true
	}
	return len(union) <= maxNodeBlocks
}
func (n *nodeRead) retain(bytes int) error {
	if bytes < 0 || bytes > maxNodeOwned-n.owned {
		return d.ErrTooBroad
	}
	n.owned += bytes
	return nil
}

func canonicalHeader(header c.Header) h.CanonicalBlock {
	return h.CanonicalBlock{Number: header.Number, Hash: h.Hash(header.Hash), ParentHash: h.Hash(header.Parent), Timestamp: header.Timestamp}
}
func historyHeader(header r.HistoryHeader, count uint32) h.CanonicalBlock {
	return h.CanonicalBlock{Number: header.Number, Hash: h.Hash(header.Hash), ParentHash: h.Hash(header.ParentHash), Timestamp: header.Timestamp, TxCount: &count}
}
func sameCanonical(a, b h.CanonicalBlock) bool {
	return a.Number == b.Number && a.Hash == b.Hash && a.ParentHash == b.ParentHash && a.Timestamp == b.Timestamp
}
func (n *nodeRead) remember(header h.CanonicalBlock) error {
	if old, ok := n.canonical[header.Number]; ok {
		if !sameCanonical(old, header) || old.TxCount != nil && header.TxCount != nil && *old.TxCount != *header.TxCount {
			return d.ErrConflict
		}
		if old.TxCount != nil {
			return nil
		}
	} else {
		if len(n.canonical) >= maxNodeBlocks {
			return d.ErrTooBroad
		}
		if err := n.retain(128); err != nil {
			return err
		}
	}
	n.canonical[header.Number] = header
	return nil
}

// upper establishes the trusted node ceiling. A continuation chooses
// its authenticated original NUMBER and verifies the actual canonical header.
func (n *nodeRead) upper(ctx context.Context, basis *d.RetainedBasis) (h.CanonicalBlock, error) {
	query := r.HeaderQuery{NumberOrTag: "latest"}
	if basis != nil {
		if !basis.Valid() || basis.NodeSource != d.Digest(n.config.Source.Digest().String()) || basis.NetworkKey != d.Digest(n.config.Source.Network.Key.String()) {
			return h.CanonicalBlock{}, d.ErrConflict
		}
		number, _ := strconv.ParseUint(string(basis.Upper.Number), 10, 63)
		query.NumberOrTag = fmt.Sprintf("0x%x", number)
	}
	batch, err := n.headers.Read(ctx, []r.HeaderQuery{query})
	if err != nil {
		return h.CanonicalBlock{}, n.sourceError(err)
	}
	values := batch.Headers()
	if !batch.Synced() || batch.Source() != n.config.Source || len(values) != 1 {
		return h.CanonicalBlock{}, d.ErrUnavailable
	}
	header := canonicalHeader(values[0])
	if err = n.touch([]uint64{header.Number}); err != nil {
		return h.CanonicalBlock{}, err
	}
	if basis != nil && (basis.Upper.Hash != header.Hash.String() || basis.Upper.ParentHash != header.ParentHash.String() || basis.Upper.Timestamp != d.Count(strconv.FormatUint(header.Timestamp, 10)) || basis.Upper.Transactions != nil) {
		return h.CanonicalBlock{}, d.ErrConflict
	}
	if err = n.remember(header); err != nil {
		return h.CanonicalBlock{}, err
	}
	return header, nil
}

// indexedUpper qualifies the producer's committed anchor against the selected
// live node. Indexer lag narrows the first read; it never changes a continuation
// or supplies trusted parent/timestamp facts on its own.
func (n *nodeRead) indexedUpper(ctx context.Context, anchor x.Anchor) (h.CanonicalBlock, error) {
	if err := n.touch([]uint64{anchor.Number}); err != nil {
		return h.CanonicalBlock{}, err
	}
	// Share network/sync checks across the ceiling and selected header. The
	// unused ceiling supplies no basis facts and need not be retained/rechecked.
	batch, err := n.headers.Read(ctx, []r.HeaderQuery{{NumberOrTag: "latest"}, {NumberOrTag: fmt.Sprintf("0x%x", anchor.Number)}})
	if err != nil {
		return h.CanonicalBlock{}, n.sourceError(err)
	}
	values := batch.Headers()
	if !batch.Synced() || batch.Source() != n.config.Source || len(values) != 2 {
		return h.CanonicalBlock{}, d.ErrUnavailable
	}
	ceiling, header := canonicalHeader(values[0]), canonicalHeader(values[1])
	if err = n.touch([]uint64{ceiling.Number}); err != nil {
		return h.CanonicalBlock{}, err
	}
	if header.Number > ceiling.Number {
		return h.CanonicalBlock{}, d.ErrUnavailable
	}
	if header.Number != anchor.Number || header.Hash.String() != anchor.Hash {
		return h.CanonicalBlock{}, d.ErrConflict
	}
	if err = n.remember(header); err != nil {
		return h.CanonicalBlock{}, err
	}
	return header, nil
}

// acquireSet caches successful opaque CB1 members once. The original operation
// owns calls, wire bytes and decoder ownership across all sets and both checks.
type nodeReserve struct {
	owned int
	wire  int64
	calls int
}

func (n *nodeRead) acquireSet(ctx context.Context, numbers []uint64, reserve nodeReserve, prefix bool) error {
	pending := make([]uint64, 0, len(numbers))
	for _, number := range numbers {
		if n.blocks[number] != nil {
			continue
		}
		if n.bodyTouched[number] {
			if prefix {
				break
			}
			return d.ErrTooBroad
		}
		trial := append(slices.Clone(pending), number)
		if !n.canBodySet(trial, reserve) {
			if prefix {
				break
			}
			return d.ErrTooBroad
		}
		pending = append(pending, number)
	}
	if len(pending) == 0 {
		if prefix && len(numbers) > 0 && n.blocks[numbers[0]] != nil {
			return nil
		}
		for _, number := range numbers {
			if n.blocks[number] == nil {
				return d.ErrTooBroad
			}
		}
		return nil
	}
	if err := n.touch(pending); err != nil {
		return err
	}
	n.bodySets++
	for _, number := range pending {
		n.bodyTouched[number] = true
	}
	limits := r.DefaultHistoryBlockLimits()
	limits.Timeout = 5 * time.Second
	limits.MaxObservationBytes = min(limits.MaxObservationBytes, maxNodeOwned-n.owned-reserve.owned-128*len(pending))
	client, err := r.NewHistoryBlockClient(n.wire, n.config.Source, n.config.Credential, limits)
	if err != nil {
		return d.ErrTooBroad
	}
	setLimits := r.DefaultHistoryBlockSetLimits()
	n.wire.mu.Lock()
	setLimits.MaxRequests = min(setLimits.MaxRequests, maxNodeAttempts-n.wire.attempts-finalNodeCalls-reserve.calls)
	setLimits.MaxTotalWireBytes = min(setLimits.MaxTotalWireBytes, n.wire.remaining-finalNodeWire-reserve.wire)
	n.wire.mu.Unlock()
	setLimits.MaxObservationBytes = limits.MaxObservationBytes
	blocks, err := client.AcquireBlockSetWithin(ctx, pending, n.fence, setLimits)
	if err != nil {
		return n.sourceError(err)
	}
	for _, block := range blocks {
		if block.Source() != n.config.Source || block.Digest() == (common.Hash{}) || block.OwnedBytes() <= 0 {
			return d.ErrUnavailable
		}
		if err = n.retain(block.OwnedBytes()); err != nil {
			return err
		}
		if err = n.remember(historyHeader(block.Header(), block.TransactionCount())); err != nil {
			return err
		}
		n.blocks[block.Header().Number] = block
	}
	if !prefix && len(blocks) != len(pending) {
		return d.ErrTooBroad
	}
	return nil
}

func (n *nodeRead) canBodySet(numbers []uint64, reserve nodeReserve) bool {
	if len(numbers) == 0 {
		return true
	}
	if n.bodySets >= 3 || !n.canTouch(numbers) {
		return false
	}
	n.wire.mu.Lock()
	defer n.wire.mu.Unlock()
	post := int64((len(numbers)+1)*(16<<10) + 2*(4<<10))
	return n.wire.attempts+4*len(numbers)+6 <= maxNodeAttempts-finalNodeCalls-reserve.calls &&
		n.wire.remaining-finalNodeWire-reserve.wire > 2*post+2048 &&
		maxNodeOwned-n.owned-reserve.owned >= len(numbers)*(1024+512+128)
}

func (n *nodeRead) supportNeeds(requirements *h.Requirements) (bodies, headers []uint64, err error) {
	if requirements == nil {
		return nil, nil, d.ErrUnavailable
	}
	return n.supportBlockNeeds(requirements.Blocks())
}
func (n *nodeRead) supportBlockNeeds(blocks []h.BlockRequirement) (bodies, headers []uint64, err error) {
	for _, requirement := range blocks {
		if known, ok := n.canonical[requirement.Number]; ok && (!requirement.NeedTxCount || known.TxCount != nil) {
			continue
		}
		if requirement.NeedTxCount {
			if n.bodyTouched[requirement.Number] {
				return nil, nil, d.ErrTooBroad
			}
			bodies = append(bodies, requirement.Number)
		} else {
			headers = append(headers, requirement.Number)
		}
	}
	return bodies, headers, nil
}

// Merge only acquisition work. Each authority resolver still receives its own
// original opaque Requirements and scope digest after actual support is read.
func supportUnion(requirements ...*h.Requirements) ([]h.BlockRequirement, error) {
	merged := map[uint64]bool{}
	for _, req := range requirements {
		if req == nil {
			return nil, d.ErrUnavailable
		}
		for _, item := range req.Blocks() {
			merged[item.Number] = merged[item.Number] || item.NeedTxCount
		}
	}
	out := make([]h.BlockRequirement, 0, len(merged))
	for number, count := range merged {
		out = append(out, h.BlockRequirement{Number: number, NeedTxCount: count})
	}
	slices.SortFunc(out, func(a, b h.BlockRequirement) int {
		if a.Number < b.Number {
			return -1
		}
		if a.Number > b.Number {
			return 1
		}
		return 0
	})
	return out, nil
}

// Metadata-only planning. Rejected/shrunk prefixes do not dispatch support
// work, and all already spent candidate work stays in the ledger.
func headerReserve(count int) nodeReserve {
	if count == 0 {
		return nodeReserve{}
	}
	return nodeReserve{owned: 512 * count, wire: int64((count+1)*(16<<10) + 2*(4<<10)), calls: count + 3}
}

func (n *nodeRead) canSupport(requirements *h.Requirements) bool {
	if requirements == nil {
		return false
	}
	return n.canSupportBlocks(requirements.Blocks())
}
func (n *nodeRead) canSupportMany(requirements ...*h.Requirements) bool {
	blocks, err := supportUnion(requirements...)
	return err == nil && n.canSupportBlocks(blocks)
}
func (n *nodeRead) canSupportBlocks(blocks []h.BlockRequirement) bool {
	bodies, headers, err := n.supportBlockNeeds(blocks)
	if err != nil || !n.canTouch(append(slices.Clone(bodies), headers...)) || !n.canBodySet(bodies, headerReserve(len(headers))) || len(headers) > 0 && n.headerSets >= 2 {
		return false
	}
	calls := 0
	if len(bodies) > 0 {
		calls += 4*len(bodies) + 6
	}
	if len(headers) > 0 {
		calls += len(headers) + 3
	}
	n.wire.mu.Lock()
	defer n.wire.mu.Unlock()
	reserve := headerReserve(len(headers))
	return n.wire.attempts+calls <= maxNodeAttempts-finalNodeCalls && maxNodeOwned-n.owned >= reserve.owned && n.wire.remaining-finalNodeWire > reserve.wire
}

func (n *nodeRead) supports(ctx context.Context, requirements *h.Requirements) ([]h.CanonicalBlock, error) {
	if err := n.supportsMany(ctx, requirements); err != nil {
		return nil, err
	}
	return n.knownSupport(requirements)
}
func (n *nodeRead) supportsMany(ctx context.Context, requirements ...*h.Requirements) error {
	blocks, err := supportUnion(requirements...)
	if err != nil {
		return err
	}
	if !n.canSupportBlocks(blocks) {
		return d.ErrTooBroad
	}
	bodies, numbers, err := n.supportBlockNeeds(blocks)
	if err != nil {
		return err
	}
	if len(bodies) > 0 {
		if err = n.acquireSet(ctx, bodies, headerReserve(len(numbers)), false); err != nil {
			return err
		}
	}
	if len(numbers) > 0 {
		if err = n.touch(numbers); err != nil {
			return err
		}
		n.headerSets++
		queries := make([]r.HeaderQuery, len(numbers))
		for i, number := range numbers {
			queries[i] = r.HeaderQuery{NumberOrTag: fmt.Sprintf("0x%x", number)}
		}
		batch, err := n.headers.Read(ctx, queries)
		if err != nil {
			return n.sourceError(err)
		}
		if !batch.Synced() || batch.Source() != n.config.Source || len(batch.Headers()) != len(numbers) {
			return d.ErrUnavailable
		}
		for _, header := range batch.Headers() {
			if err = n.remember(canonicalHeader(header)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *nodeRead) knownSupport(requirements *h.Requirements) ([]h.CanonicalBlock, error) {
	blocks := requirements.Blocks()
	out := make([]h.CanonicalBlock, 0, len(blocks))
	for _, requirement := range blocks {
		header, ok := n.canonical[requirement.Number]
		if !ok || requirement.NeedTxCount && header.TxCount == nil {
			return nil, d.ErrUnavailable
		}
		if !requirement.NeedTxCount {
			header.TxCount = nil
		}
		out = append(out, header)
	}
	return out, nil
}

type qualifiedRoot struct {
	indexed x.ProtectedRow
	root    h.Root
	fact    d.TransactionFact
}

func amount(value *big.Int) (d.Amount, error) {
	if value == nil || value.Sign() < 0 || value.BitLen() > 256 {
		return "", d.ErrUnavailable
	}
	return d.Amount(value.String()), nil
}

// qualify uses the cached complete CB1 population. Only capacity checked before
// I/O can shorten an ordered prefix; bad evidence always fails the whole read.
func (n *nodeRead) qualify(ctx context.Context, rows []x.ProtectedRow, full bool) ([]qualifiedRoot, error) {
	if len(rows) > 4096 || full && len(rows) != 1 {
		return nil, d.ErrTooBroad
	}
	if err := n.retain(2048 * len(rows)); err != nil {
		return nil, err
	}
	byNumber := map[uint64][]int{}
	numbers := []uint64{}
	for i, row := range rows {
		if _, ok := byNumber[row.Position.Number]; !ok {
			numbers = append(numbers, row.Position.Number)
		}
		byNumber[row.Position.Number] = append(byNumber[row.Position.Number], i)
	}
	reserve := 0
	if full {
		reserve = 2 << 20
	}
	if len(numbers) > 0 {
		if err := n.acquireSet(ctx, numbers, nodeReserve{owned: reserve}, !full); err != nil {
			return nil, err
		}
	}
	// Only the contiguous input prefix is eligible; an address witness cannot
	// move a later transaction past an unqualified earlier candidate.
	consumed := 0
	for _, row := range rows {
		if n.blocks[row.Position.Number] == nil {
			break
		}
		consumed++
	}
	if len(rows) > 0 && consumed == 0 {
		return nil, d.ErrTooBroad
	}
	rows = rows[:consumed]
	out := make([]qualifiedRoot, len(rows))
	for _, number := range numbers {
		block := n.blocks[number]
		if block == nil {
			break
		}
		header := block.Header()
		for _, index := range byNumber[number] {
			if index >= len(rows) {
				continue
			}
			row := rows[index]
			tx, ok := block.Transaction(row.Position.Index)
			receipt, receiptOK := block.Receipt(row.Position.Index)
			if !ok || !receiptOK || [32]byte(tx.Hash()) != row.Position.Hash || header.Number != row.Position.Number || header.Timestamp != row.Timestamp || [20]byte(tx.From()) != row.From {
				return nil, d.ErrUnavailable
			}
			to, hasTo := tx.To()
			if hasTo != (row.To != nil) || hasTo && [20]byte(to) != *row.To {
				return nil, d.ErrUnavailable
			}
			root := h.Root{Hash: h.Hash(tx.Hash()), BlockHash: h.Hash(header.Hash), Number: header.Number, Index: row.Position.Index, Timestamp: header.Timestamp}
			if hasTo {
				address := h.Address(to)
				root.To = &address
			} else if created, present := receipt.ContractAddress(); present {
				address := h.Address(created)
				root.CreatedAddress = &address
			}
			value, err := amount(tx.Value())
			if err != nil {
				return nil, err
			}
			status, present := receipt.Status()
			if !present {
				return nil, d.ErrUnavailable
			}
			fact := d.TransactionFact{Hash: [32]byte(tx.Hash()), BlockHash: [32]byte(header.Hash), BlockNumber: d.Count(strconv.FormatUint(header.Number, 10)), TransactionIndex: row.Position.Index, BlockTime: int64(header.Timestamp), From: [20]byte(tx.From()), Value: value, GasUsed: d.Count(strconv.FormatUint(receipt.GasUsed(), 10)), Status: status}
			if hasTo {
				address := [20]byte(to)
				fact.To = &address
			}
			if full {
				// Only Full Detail creates input/fee DTO data. Lower List qualifies
				// signed inclusion privately without calling input/signed getters.
				input := tx.Input()
				if len(input) > (1<<20-2)/2 {
					return nil, d.ErrTooBroad
				}
				if err = n.retain(3*len(input) + 2048); err != nil {
					return nil, err
				}
				gasPrice, err := amount(receipt.EffectiveGasPrice())
				if err != nil {
					return nil, err
				}
				detail := &d.TransactionDetailFact{EffectiveGasPrice: gasPrice, GasLimit: d.Count(strconv.FormatUint(tx.GasLimit(), 10)), Nonce: d.Count(strconv.FormatUint(tx.Nonce(), 10)), Type: tx.Type(), Input: "0x" + hex.EncodeToString(input)}
				fees := tx.Fees()
				if tx.Type() < 2 {
					price, err := amount(fees.LegacyGasPrice)
					if err != nil {
						return nil, err
					}
					detail.SignedLegacyGasPrice = &price
				} else {
					cap, err := amount(fees.MaxFeePerGas)
					if err != nil {
						return nil, err
					}
					tip, err := amount(fees.MaxPriorityFeePerGas)
					if err != nil {
						return nil, err
					}
					base, err := amount(header.BaseFeePerGas)
					if err != nil {
						return nil, err
					}
					detail.MaxFeePerGas, detail.MaxPriorityFeePerGas, detail.BlockBaseFeePerGas = &cap, &tip, &base
				}
				if created, present := receipt.ContractAddress(); present {
					address := [20]byte(created)
					detail.ContractAddress = &address
				}
				fact.Full = detail
			}
			out[index] = qualifiedRoot{row, root, fact}
		}
		block = nil
	}
	return out, nil
}

func (n *nodeRead) check(ctx context.Context) error {
	if n.finalChecks >= 2 {
		return d.ErrUnavailable
	}
	n.finalChecks++
	n.wire.mu.Lock()
	n.wire.reservedCalls = (2 - n.finalChecks) * (maxNodeBlocks + 3)
	n.wire.reservedWire = int64((2 - n.finalChecks) * (finalNodeWire / 2))
	n.wire.mu.Unlock()
	numbers := make([]uint64, 0, len(n.canonical))
	for number := range n.canonical {
		numbers = append(numbers, number)
	}
	slices.Sort(numbers)
	queries := make([]r.HeaderQuery, 0, len(numbers))
	for _, number := range numbers {
		queries = append(queries, r.HeaderQuery{NumberOrTag: fmt.Sprintf("0x%x", number)})
	}
	batch, err := n.headers.Read(ctx, queries)
	if err != nil {
		return n.sourceError(err)
	}
	headers := batch.Headers()
	if !batch.Synced() || batch.Source() != n.config.Source || len(headers) != len(numbers) {
		return d.ErrUnavailable
	}
	for i, header := range headers {
		if !sameCanonical(n.canonical[numbers[i]], canonicalHeader(header)) {
			return d.ErrConflict
		}
	}
	return nil
}
