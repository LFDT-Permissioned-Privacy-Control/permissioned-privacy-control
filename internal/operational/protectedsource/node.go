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
	h "privacy-proxy/internal/historynamespace"
	x "privacy-proxy/internal/operational/explorerindex"
	r "privacy-proxy/internal/rpcexecution"
)

const maxNodeAttempts = 64
const maxNodeWire = 32 << 20
const maxNodeOwned = 16 << 20

// NodeConfig is approved startup assembly for one DataOrg. A disclosure
// recipient never selects the URL, credential or a fallback group credential.
type NodeConfig struct {
	Source     c.Source
	Credential r.Credential
	Transport  r.Transport
}

type nodeRead struct {
	config    NodeConfig
	wire      *nodeWire
	headers   *r.HeaderClient
	owned     int
	canonical map[uint64]h.CanonicalBlock
}

type nodeWire struct {
	mu        sync.Mutex
	base      r.Transport
	attempts  int
	remaining int64
	exceeded  bool
}
type nodeBody struct {
	body   io.ReadCloser
	budget *nodeWire
}

func (b *nodeWire) RoundTrip(request *http.Request) (*http.Response, error) {
	b.mu.Lock()
	if b.attempts >= maxNodeAttempts || b.remaining <= 0 || b.exceeded {
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
	if b.remaining < 0 || b.exceeded {
		return 0, d.ErrTooBroad
	}
	// One overflow probe, as in CB1's own bounded wire reader, detects a body
	// exceeding the limit without consuming an unbounded remainder.
	if int64(len(p)) > b.remaining+1 {
		p = p[:b.remaining+1]
	}
	n, err := body.body.Read(p)
	b.remaining -= int64(n)
	if b.remaining < 0 {
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
	headers, err := r.NewHeaderClient(wire, config.Source, config.Credential, r.HeaderLimits{Timeout: 5 * time.Second, MaxQueries: maxNodeAttempts, MaxHeaderBytes: 16 << 10})
	if err != nil {
		return nil, d.ErrInvalid
	}
	return &nodeRead{config: config, wire: wire, headers: headers, canonical: map[uint64]h.CanonicalBlock{}}, nil
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
		if len(n.canonical) >= maxNodeAttempts {
			return d.ErrTooBroad
		}
		if err := n.retain(128); err != nil {
			return err
		}
	}
	n.canonical[header.Number] = header
	return nil
}

// upper is called before the first indexed SQL read. A continuation chooses
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
	if basis != nil && (basis.Upper.Hash != header.Hash.String() || basis.Upper.ParentHash != header.ParentHash.String() || basis.Upper.Timestamp != d.Count(strconv.FormatUint(header.Timestamp, 10)) || basis.Upper.Transactions != nil) {
		return h.CanonicalBlock{}, d.ErrConflict
	}
	if err = n.remember(header); err != nil {
		return h.CanonicalBlock{}, err
	}
	return header, nil
}

func (n *nodeRead) acquire(ctx context.Context, number uint64, reserve int) (*r.HistoryBlockObservation, error) {
	remaining := maxNodeOwned - n.owned - reserve - 128
	if remaining <= 0 {
		return nil, d.ErrTooBroad
	}
	limits := r.DefaultHistoryBlockLimits()
	limits.Timeout = 5 * time.Second
	limits.MaxObservationBytes = min(limits.MaxObservationBytes, remaining)
	client, err := r.NewHistoryBlockClient(n.wire, n.config.Source, n.config.Credential, limits)
	if err != nil {
		return nil, d.ErrInvalid
	}
	selector, err := r.HistoryBlockNumber(number)
	if err != nil {
		return nil, d.ErrUnavailable
	}
	block, err := client.AcquireBlock(ctx, selector)
	if err != nil {
		return nil, n.sourceError(err)
	}
	if block.Source() != n.config.Source || block.Digest() == (common.Hash{}) {
		return nil, d.ErrUnavailable
	}
	if err = n.remember(historyHeader(block.Header(), block.TransactionCount())); err != nil {
		return nil, err
	}
	return block, nil
}

func (n *nodeRead) supports(ctx context.Context, requirements *h.Requirements) ([]h.CanonicalBlock, error) {
	if requirements == nil {
		return nil, d.ErrUnavailable
	}
	blocks := requirements.Blocks()
	if len(blocks) > maxNodeAttempts {
		return nil, d.ErrTooBroad
	}
	queries := []r.HeaderQuery{}
	for _, requirement := range blocks {
		if known, ok := n.canonical[requirement.Number]; ok && (!requirement.NeedTxCount || known.TxCount != nil) {
			continue
		}
		if requirement.NeedTxCount {
			_, err := n.acquire(ctx, requirement.Number, 128)
			if err != nil {
				return nil, err
			}
			// Only minimal actual header/count remains; the full block is dropped.
		} else {
			queries = append(queries, r.HeaderQuery{NumberOrTag: fmt.Sprintf("0x%x", requirement.Number)})
		}
	}
	if len(queries) > 0 {
		batch, err := n.headers.Read(ctx, queries)
		if err != nil {
			return nil, n.sourceError(err)
		}
		if !batch.Synced() || batch.Source() != n.config.Source {
			return nil, d.ErrUnavailable
		}
		for _, header := range batch.Headers() {
			if err = n.remember(canonicalHeader(header)); err != nil {
				return nil, err
			}
		}
	}
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

// qualify acquires each needed block once within this phase. Support blocks
// dropped earlier may be acquired again, under the SAME physical/wire limits.
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
	slices.Sort(numbers)
	out := make([]qualifiedRoot, len(rows))
	for _, number := range numbers {
		reserve := 0
		if full {
			reserve = 2 << 20
		}
		block, err := n.acquire(ctx, number, reserve)
		if err != nil {
			return nil, err
		}
		header := block.Header()
		for _, index := range byNumber[number] {
			row := rows[index]
			tx, ok := block.Transaction(row.Position.Index)
			receipt, receiptOK := block.Receipt(row.Position.Index)
			if !ok || !receiptOK || [32]byte(tx.Hash()) != row.Position.Hash || [32]byte(header.Hash) != row.BlockHash || header.Number != row.Position.Number || header.Timestamp != row.Timestamp || [20]byte(tx.From()) != row.From {
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
