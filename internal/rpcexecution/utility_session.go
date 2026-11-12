package rpcexecution

import (
	"context"
	"encoding/json"
	"math/big"
	"sort"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"privacy-proxy/internal/creationfacts"
)

type UtilityLimits struct {
	MaxProbes, MaxRequests int
	MaxResponseBytes       int64
}

func DefaultUtilityLimits() UtilityLimits { return UtilityLimits{32, 256, 128 << 20} }
func (l UtilityLimits) Valid() bool {
	d := DefaultUtilityLimits()
	return l.MaxProbes > 0 && l.MaxProbes <= d.MaxProbes && l.MaxRequests >= 16 && l.MaxRequests <= d.MaxRequests && l.MaxResponseBytes > 0 && l.MaxResponseBytes <= d.MaxResponseBytes
}

// UtilitySession owns one selected source and fixed hash across every actual
// estimation/access-list execution. It supplies evidence, never a policy verdict.
type UtilitySession struct {
	client *Client
	budget *minedWireBudget
	call   Call
	block  BlockSelector
	header creationfacts.Header
	cap    uint64
	limits UtilityLimits
	probes int
}

func (c *Client) NewUtilitySession(ctx context.Context, call Call, block BlockSelector, l UtilityLimits) (*UtilitySession, error) {
	if c == nil || !c.selected || !c.networkBound || c.binding.Profile != SimulationCallProfileID || call.wire == nil || call.signedInput || !l.Valid() || ctx == nil || block.selector == "" {
		return nil, failure(InvalidBinding)
	}
	budget := &minedWireBudget{base: c.transport, remaining: l.MaxResponseBytes, maxCalls: l.MaxRequests}
	owned := *c
	owned.transport = budget
	if err := owned.RequireBoundNetwork(ctx); err != nil {
		return nil, err
	}
	method := "eth_getHeaderByNumber"
	if block.hash {
		method = "eth_getHeaderByHash"
	}
	raw, err := owned.rpcBounded(ctx, method, []any{block.selector}, 16<<10)
	if err != nil {
		return nil, err
	}
	h, err := decodeQualifiedHeader(raw)
	if err != nil {
		return nil, err
	}
	if block.hash && h.Hash.Hex() != block.selector || h.Timestamp < c.binding.PragueStartInclusive || h.Timestamp >= c.binding.PragueEndExclusive {
		return nil, failure(InvalidEvidence)
	}
	if block.historical && !block.hash {
		n, _ := quantity(block.selector, 64)
		if n == nil || n.Uint64() != h.Number {
			return nil, failure(InvalidEvidence)
		}
	}
	var full types.Header
	if json.Unmarshal(raw, &full) != nil || full.Hash() != h.Hash || full.GasLimit < 21000 {
		return nil, failure(InvalidEvidence)
	}
	cap := full.GasLimit
	if value, ok := call.wire["gas"].(string); ok {
		n, _ := quantity(value, 64)
		if n == nil || n.Sign() == 0 {
			return nil, failure(InvalidCall)
		}
		if n.Uint64() < cap {
			cap = n.Uint64()
		}
	}
	fee := new(big.Int)
	for _, field := range []string{"gasPrice", "maxFeePerGas"} {
		if text, ok := call.wire[field].(string); ok {
			fee, _ = quantity(text, 256)
		}
	}
	if fee.Sign() > 0 || call.value.Sign() > 0 {
		raw, err := owned.rpcBounded(ctx, "eth_getBalance", []any{call.from.Hex(), map[string]any{"blockHash": h.Hash.Hex(), "requireCanonical": false}}, 1024)
		if err != nil {
			return nil, err
		}
		var text string
		if json.Unmarshal(raw, &text) != nil {
			return nil, failure(InvalidEvidence)
		}
		balance, ok := quantity(text, 256)
		if !ok || balance.Cmp(call.value) < 0 {
			return nil, failure(InvalidEvidence)
		}
		if fee.Sign() > 0 {
			allowance := new(big.Int).Div(new(big.Int).Sub(balance, call.value), fee)
			if allowance.IsUint64() && allowance.Uint64() < cap {
				cap = allowance.Uint64()
			}
		}
	}
	if cap < 21000 {
		return nil, failure(InvalidCall)
	}
	selected := BlockSelector{selector: h.Hash.Hex(), hash: true, canonical: block.canonical, historical: true}
	return &UtilitySession{client: &owned, budget: budget, call: call, block: selected, header: h, cap: cap, limits: l}, nil
}
func (s *UtilitySession) GasCap() uint64 {
	if s == nil {
		return 0
	}
	return s.cap
}
func (s *UtilitySession) Probe(ctx context.Context, gas uint64, access *types.AccessList, collect bool, scope RootCreationScopeCheck) (*CallExecution, error) {
	if s == nil || s.client == nil || gas < 21000 || gas > s.cap || s.probes >= s.limits.MaxProbes {
		return nil, failure(EvidenceLimit)
	}
	s.probes++
	call := s.call
	call.wire = s.call.Object()
	call.wire["gas"] = "0x" + strconv.FormatUint(gas, 16)
	if access != nil {
		entries := []any{}
		for _, entry := range *access {
			keys := []any{}
			for _, key := range entry.StorageKeys {
				keys = append(keys, key.Hex())
			}
			entries = append(entries, map[string]any{"address": entry.Address.Hex(), "storageKeys": keys})
		}
		call.wire["accessList"] = entries
		if call.wire["type"] == "0x0" {
			delete(call.wire, "type")
		}
	}
	return s.client.acquireScopedProfileOptions(ctx, call, s.block, nil, true, scope, collect)
}

// UtilityCheckpoint drops the call, all probe executions and access-slot values.
type UtilityCheckpoint struct {
	client *Client
	budget *minedWireBudget
	header creationfacts.Header
}

func (s *UtilitySession) DeliveryCheckpoint() *UtilityCheckpoint {
	if s == nil {
		return nil
	}
	return &UtilityCheckpoint{s.client, s.budget, s.header}
}
func (p *UtilityCheckpoint) Client() *Client {
	if p == nil {
		return nil
	}
	return p.client
}
func (p *UtilityCheckpoint) RequireCurrent(ctx context.Context, observer creationfacts.Header) error {
	if p == nil || p.client == nil || p.budget == nil {
		return failure(InvalidBinding)
	}
	p.budget.advance(2)
	if err := p.client.RequireBoundNetwork(ctx); err != nil {
		return err
	}
	if err := minedCanonical(ctx, p.client, p.header); err != nil {
		return err
	}
	if observer != (creationfacts.Header{}) && !minedHeaderMatches(p.header, observer) {
		return minedCanonical(ctx, p.client, observer)
	}
	return ctx.Err()
}

func (e *CallExecution) AccessList() (types.AccessList, error) {
	if e == nil || e.signed || !e.accessCaptured {
		return nil, failure(InvalidEvidence)
	}
	out := make(types.AccessList, len(e.access))
	for i, x := range e.access {
		out[i] = types.AccessTuple{Address: x.Address, StorageKeys: append([]common.Hash{}, x.StorageKeys...)}
	}
	return out, nil
}
func accessFromPrestate(raw []byte) (types.AccessList, error) {
	fields, err := closedRawObject(raw, 8192)
	if err != nil {
		return nil, err
	}
	out := types.AccessList{}
	slots := 0
	for name, value := range fields {
		a, ok := address(name)
		if !ok {
			return nil, failure(InvalidEvidence)
		}
		entry := types.AccessTuple{Address: a, StorageKeys: []common.Hash{}}
		account, err := closedRawObject(value, 5)
		if err != nil {
			return nil, err
		}
		if storage, ok := account["storage"]; ok {
			m, err := closedRawObject(storage, 65536)
			if err != nil {
				return nil, err
			}
			for key := range m {
				b, ok := data(key)
				if !ok || len(b) != 32 {
					return nil, failure(InvalidEvidence)
				}
				slots++
				if slots > 65536 {
					return nil, failure(EvidenceLimit)
				}
				entry.StorageKeys = append(entry.StorageKeys, common.BytesToHash(b))
			}
		}
		sort.Slice(entry.StorageKeys, func(i, j int) bool { return entry.StorageKeys[i].Cmp(entry.StorageKeys[j]) < 0 })
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address.Cmp(out[j].Address) < 0 })
	return out, nil
}
