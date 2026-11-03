package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// nodeChainReader reads the node's public chain state (NODE_URL), the
// evidence the lease keeper needs beyond the private status call (plan
// §4.8.1): a signer's nonce and transactions' receipts at a finalized block,
// and whether the node still holds a transaction at all (pool or chain).
type nodeChainReader interface {
	// DroppedEvidence reads, in one request (one backend), the block at the
	// finalized height and hash the private node reported, the signer's nonce
	// at exactly that block (by hash, EIP-1898), and whether each hash has a
	// canonical receipt. A backend that does not hold that block answers
	// errNodeChain: evidence that is unavailable is never evidence of absence.
	DroppedEvidence(ctx context.Context, number uint64, hash, signer string, hashes []string) (nonce uint64, receipts map[string]bool, err error)
	// Known reports, per hash, whether the node's pool or chain holds it.
	Known(ctx context.Context, hashes []string) (map[string]bool, error)
}

// errNodeChain: the public node RPC did not answer usably. Evidence that is
// unavailable is never taken as evidence of absence.
var errNodeChain = errors.New("node chain state unavailable")

// rpcChain implements nodeChainReader over JSON-RPC batches.
type rpcChain struct {
	forward func(ctx context.Context, body []byte) ([]byte, int, error)
}

// maxChainBatch bounds one JSON-RPC batch to the public node.
const maxChainBatch = 256

type chainCall struct {
	method string
	params []any
}

// batch sends calls in batches and returns each call's raw result (JSON null
// for "not found"); any error, missing or duplicated answer fails the whole
// read.
func (c rpcChain) batch(ctx context.Context, calls []chainCall) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, len(calls))
	for start := 0; start < len(calls); start += maxChainBatch {
		chunk := calls[start:min(start+maxChainBatch, len(calls))]
		requests := make([]map[string]any, len(chunk))
		for i, call := range chunk {
			requests[i] = map[string]any{"jsonrpc": "2.0", "id": start + i, "method": call.method, "params": call.params}
		}
		body, err := json.Marshal(requests)
		if err != nil {
			return nil, err
		}
		raw, status, err := c.forward(ctx, body)
		if err != nil || status != http.StatusOK {
			return nil, errNodeChain
		}
		var replies []struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal(bytes.TrimSpace(raw), &replies) != nil || len(replies) != len(chunk) {
			return nil, errNodeChain
		}
		seen := map[int]bool{}
		for _, reply := range replies {
			if reply.ID == nil || *reply.ID < start || *reply.ID >= start+len(chunk) || seen[*reply.ID] || (len(reply.Error) > 0 && string(reply.Error) != "null") || len(reply.Result) == 0 {
				return nil, errNodeChain
			}
			seen[*reply.ID] = true
			out[*reply.ID] = reply.Result
		}
	}
	return out, nil
}

func hexQuantity(raw json.RawMessage) (uint64, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || !strings.HasPrefix(s, "0x") || len(s) < 3 {
		return 0, errNodeChain
	}
	return strconv.ParseUint(s[2:], 16, 64)
}

func (c rpcChain) DroppedEvidence(ctx context.Context, number uint64, hash, signer string, hashes []string) (uint64, map[string]bool, error) {
	if len(hashes) == 0 || len(hashes) > maxChainBatch-2 {
		return 0, nil, errNodeChain
	}
	calls := []chainCall{
		{"eth_getBlockByNumber", []any{fmt.Sprintf("0x%x", number), false}},
		{"eth_getTransactionCount", []any{signer, map[string]any{"blockHash": hash}}},
	}
	for _, h := range hashes {
		calls = append(calls, chainCall{"eth_getTransactionReceipt", []any{h}})
	}
	results, err := c.batch(ctx, calls)
	if err != nil {
		return 0, nil, err
	}
	var block struct {
		Number string `json:"number"`
		Hash   string `json:"hash"`
	}
	if json.Unmarshal(results[0], &block) != nil || !strings.EqualFold(block.Hash, hash) {
		return 0, nil, errNodeChain // another chain, or a backend without that block
	}
	if n, err := hexQuantity(json.RawMessage(strconv.Quote(block.Number))); err != nil || n != number {
		return 0, nil, errNodeChain
	}
	nonce, err := hexQuantity(results[1])
	if err != nil {
		return 0, nil, errNodeChain
	}
	receipts := make(map[string]bool, len(hashes))
	for i, h := range hashes {
		receipts[h] = string(bytes.TrimSpace(results[2+i])) != "null"
	}
	return nonce, receipts, nil
}

// presence asks method for every hash and reports which answered non-null.
func (c rpcChain) presence(ctx context.Context, method string, hashes []string) (map[string]bool, error) {
	calls := make([]chainCall, len(hashes))
	for i, hash := range hashes {
		calls[i] = chainCall{method, []any{hash}}
	}
	results, err := c.batch(ctx, calls)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(hashes))
	for i, hash := range hashes {
		out[hash] = string(bytes.TrimSpace(results[i])) != "null"
	}
	return out, nil
}

func (c rpcChain) Known(ctx context.Context, hashes []string) (map[string]bool, error) {
	return c.presence(ctx, "eth_getTransactionByHash", hashes)
}
