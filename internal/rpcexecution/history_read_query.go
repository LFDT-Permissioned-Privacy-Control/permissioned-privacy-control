package rpcexecution

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

type HistoryMethod uint8

const (
	HistoryInvalid HistoryMethod = iota
	HistoryTransactionByHash
	HistoryTransactionReceipt
	HistoryBlockByHash
	HistoryBlockByNumber
	HistoryBlockCountByHash
	HistoryBlockCountByNumber
	HistoryTransactionByHashIndex
	HistoryTransactionByNumberIndex
	HistoryLogs
	HistoryBlockReceipts
)

var historyMethodNames = []string{"", "eth_getTransactionByHash", "eth_getTransactionReceipt", "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getBlockTransactionCountByHash", "eth_getBlockTransactionCountByNumber", "eth_getTransactionByBlockHashAndIndex", "eth_getTransactionByBlockNumberAndIndex", "eth_getLogs", "eth_getBlockReceipts"}

func (m HistoryMethod) String() string {
	if int(m) >= len(historyMethodNames) {
		return ""
	}
	return historyMethodNames[m]
}
func HistoryMethodNamed(s string) (HistoryMethod, bool) {
	for i, name := range historyMethodNames {
		if name == s && i > 0 {
			return HistoryMethod(i), true
		}
	}
	return HistoryInvalid, false
}

type HistoryReadLimits struct {
	Timeout                                                        time.Duration
	MaxParamsBytes                                                 int
	MaxHTTPAttempts, MaxRPCItems, MaxBatchItems                    int
	MaxWireBytes, MaxResultBytes                                   int64
	MaxParents, MaxHeaders, MaxLogs, MaxBlockSpan, MaxChargedBytes int
	Block                                                          HistoryBlockLimits
}

func DefaultHistoryReadLimits() HistoryReadLimits {
	return HistoryReadLimits{20 * time.Second, 128 << 10, 64, 512, 64, 32 << 20, 8 << 20, 512, 256, 20000, 4096, 16 << 20, DefaultHistoryBlockLimits()}
}
func (l HistoryReadLimits) valid() bool {
	m := DefaultHistoryReadLimits()
	return l.Timeout > 0 && l.Timeout <= m.Timeout && l.MaxParamsBytes > 0 && l.MaxParamsBytes <= m.MaxParamsBytes && l.MaxHTTPAttempts > 0 && l.MaxHTTPAttempts <= m.MaxHTTPAttempts && l.MaxRPCItems > 0 && l.MaxRPCItems <= m.MaxRPCItems && l.MaxBatchItems > 0 && l.MaxBatchItems <= m.MaxBatchItems && l.MaxWireBytes > 0 && l.MaxWireBytes <= m.MaxWireBytes && l.MaxResultBytes > 0 && l.MaxResultBytes <= m.MaxResultBytes && l.MaxParents > 0 && l.MaxParents <= m.MaxParents && l.MaxHeaders > 0 && l.MaxHeaders <= m.MaxHeaders && l.MaxLogs > 0 && l.MaxLogs <= m.MaxLogs && l.MaxBlockSpan > 0 && l.MaxBlockSpan <= m.MaxBlockSpan && l.MaxChargedBytes > 0 && l.MaxChargedBytes <= m.MaxChargedBytes && l.Block.valid()
}

type historyLogQuery struct {
	hash      *common.Hash
	from, to  StateBlockMetadata
	addresses []common.Address
	topics    [][]common.Hash
}
type HistoryReadQuery struct {
	method  HistoryMethod
	hash    common.Hash
	block   StateBlockMetadata
	index   uint64
	full    bool
	logs    historyLogQuery
	params  []any
	encoded []byte
	digest  [32]byte
}

func (q HistoryReadQuery) Method() HistoryMethod  { return q.method }
func (q HistoryReadQuery) FullTransactions() bool { return q.full }
func (q HistoryReadQuery) ParamsJSON() []byte     { return bytes.Clone(q.encoded) }
func (q HistoryReadQuery) Digest() [32]byte       { return q.digest }
func (q HistoryReadQuery) validFor(l HistoryReadLimits) bool {
	return l.valid() && q.method.String() != "" && q.params != nil && len(q.encoded) > 0 && len(q.encoded) <= l.MaxParamsBytes
}

func historyHash(v any) (common.Hash, bool) {
	s, ok := v.(string)
	if !ok {
		return common.Hash{}, false
	}
	raw, valid := data(s)
	return common.BytesToHash(raw), valid && len(raw) == 32
}
func historySelector(v any, hashAllowed, objectAllowed bool) (StateBlockMetadata, any, bool) {
	if v == nil {
		return StateBlockMetadata{}, nil, false
	}
	if object, ok := v.(map[string]any); ok {
		if !objectAllowed {
			return StateBlockMetadata{}, nil, false
		}
		h, hasHash := object["blockHash"]
		n, hasNumber := object["blockNumber"]
		if hasHash == hasNumber {
			return StateBlockMetadata{}, nil, false
		}
		value := n
		if hasHash {
			value = h
		}
		meta, wire, valid := historySelector(value, hasHash, false)
		if !valid || hasHash != (meta.Kind == StateHash) {
			return StateBlockMetadata{}, nil, false
		}
		out := map[string]any{}
		if hasHash {
			out["blockHash"] = wire
		} else {
			out["blockNumber"] = wire
		}
		if value, present := object["requireCanonical"]; present {
			flag, ok := value.(bool)
			if !ok {
				return StateBlockMetadata{}, nil, false
			}
			meta.CanonicalWasSupplied = true
			meta.RequireCanonical = flag
			out["requireCanonical"] = flag
		}
		if len(out) != len(object) {
			return StateBlockMetadata{}, nil, false
		}
		meta.InputForm = StateInputObject
		return meta, out, true
	}
	meta, wire, valid := stateBlock(v, true)
	return meta, wire, valid && meta.InputForm == StateInputString && (hashAllowed || meta.Kind != StateHash)
}

// ParseHistoryReadQuery parses only one of the ten closed parameter shapes.
// It does not authenticate, use State's historical-input admin floor, fetch a
// node, infer a ROOT or interpret/convert a JSON-RPC ID.
func ParseHistoryReadQuery(method HistoryMethod, raw json.RawMessage, l HistoryReadLimits) (HistoryReadQuery, error) {
	bad := func() (HistoryReadQuery, error) { return HistoryReadQuery{}, failure(InvalidCall) }
	if !l.valid() || method.String() == "" || len(raw) == 0 || len(raw) > l.MaxParamsBytes {
		return bad()
	}
	v, err := metadataJSONArrays(raw, func(depth int) int {
		if depth == 0 {
			return 2
		}
		if method == HistoryLogs && depth <= 3 {
			return 1024
		}
		return 0
	})
	params, ok := v.([]any)
	if err != nil || !ok {
		return bad()
	}
	q := HistoryReadQuery{method: method}
	owned := []any{}
	switch method {
	case HistoryTransactionByHash, HistoryTransactionReceipt:
		if len(params) != 1 {
			return bad()
		}
		hash, ok := historyHash(params[0])
		if !ok {
			return bad()
		}
		q.hash = hash
		owned = append(owned, strings.ToLower(params[0].(string)))
	case HistoryBlockByHash, HistoryBlockCountByHash, HistoryTransactionByHashIndex:
		want := 1
		if method == HistoryBlockByHash || method == HistoryTransactionByHashIndex {
			want = 2
		}
		if len(params) != want {
			return bad()
		}
		hash, ok := historyHash(params[0])
		if !ok {
			return bad()
		}
		q.hash = hash
		q.block = StateBlockMetadata{Kind: StateHash, Hash: hash, InputForm: StateInputString}
		owned = append(owned, strings.ToLower(params[0].(string)))
	case HistoryBlockByNumber, HistoryBlockCountByNumber, HistoryTransactionByNumberIndex, HistoryBlockReceipts:
		want := 1
		if method == HistoryBlockByNumber || method == HistoryTransactionByNumberIndex {
			want = 2
		}
		if len(params) != want {
			return bad()
		}
		meta, wire, ok := historySelector(params[0], method == HistoryBlockReceipts, method == HistoryBlockReceipts)
		if !ok {
			return bad()
		}
		q.block = meta
		owned = append(owned, wire)
	case HistoryLogs:
		if len(params) != 1 {
			return bad()
		}
		object, ok := params[0].(map[string]any)
		if !ok {
			return bad()
		}
		wire, parsed, ok := historyLogFilter(object)
		if !ok {
			return bad()
		}
		q.logs = parsed
		owned = append(owned, wire)
	default:
		return bad()
	}
	if method == HistoryBlockByHash || method == HistoryBlockByNumber {
		full, ok := params[1].(bool)
		if !ok {
			return bad()
		}
		q.full = full
		owned = append(owned, full)
	}
	if method == HistoryTransactionByHashIndex || method == HistoryTransactionByNumberIndex {
		s, ok := params[1].(string)
		if !ok {
			return bad()
		}
		index, ok := quantity(s, 64)
		if !ok {
			return bad()
		}
		q.index = index.Uint64()
		owned = append(owned, "0x"+index.Text(16))
	}
	q.params = owned
	q.encoded, err = json.Marshal(owned)
	if err != nil || len(q.encoded) > l.MaxParamsBytes {
		return bad()
	}
	q.digest = sha256.Sum256(append([]byte("ops-history-read-query/v1\x00"+method.String()+"\x00"), q.encoded...))
	return q, nil
}

func historyLogFilter(object map[string]any) (map[string]any, historyLogQuery, bool) {
	q := historyLogQuery{from: StateBlockMetadata{Kind: StateLatest}, to: StateBlockMetadata{Kind: StateLatest}}
	out := map[string]any{}
	for key := range object {
		if key != "blockHash" && key != "fromBlock" && key != "toBlock" && key != "address" && key != "topics" {
			return nil, q, false
		}
	}
	if value, present := object["blockHash"]; present && value != nil {
		if object["fromBlock"] != nil {
			return nil, q, false
		}
		if object["toBlock"] != nil {
			return nil, q, false
		}
		hash, ok := historyHash(value)
		if !ok {
			return nil, q, false
		}
		q.hash = &hash
		out["blockHash"] = hash.Hex()
	} else {
		for _, field := range []string{"fromBlock", "toBlock"} {
			value, present := object[field]
			if !present || value == nil {
				out[field] = "latest"
				continue
			}
			meta, wire, ok := historySelector(value, false, false)
			if !ok {
				return nil, q, false
			}
			if field == "fromBlock" {
				q.from = meta
			} else {
				q.to = meta
			}
			out[field] = wire
		}
		if q.from.Kind == StateNumber && q.to.Kind == StateNumber && q.from.Number > q.to.Number {
			return nil, q, false
		}
	}
	if value, present := object["address"]; present && value != nil {
		values := []any{value}
		if array, ok := value.([]any); ok {
			values = array
		}
		if len(values) > 1024 {
			return nil, q, false
		}
		for _, v := range values {
			s, ok := v.(string)
			a, valid := address(s)
			if !ok || !valid {
				return nil, q, false
			}
			q.addresses = append(q.addresses, a)
		}
		sort.Slice(q.addresses, func(i, j int) bool { return bytes.Compare(q.addresses[i][:], q.addresses[j][:]) < 0 })
		q.addresses = slices.Compact(q.addresses)
		wire := make([]string, len(q.addresses))
		for i, a := range q.addresses {
			wire[i] = strings.ToLower(a.Hex())
		}
		out["address"] = wire
	}
	if value, present := object["topics"]; present && value != nil {
		array, ok := value.([]any)
		if !ok || len(array) > 4 {
			return nil, q, false
		}
		wire := make([]any, len(array))
		q.topics = make([][]common.Hash, len(array))
		for i, slot := range array {
			if slot == nil {
				continue
			}
			items := []any{slot}
			if a, ok := slot.([]any); ok {
				items = a
			}
			if len(items) > 1024 {
				return nil, q, false
			}
			wild := false
			for _, item := range items {
				if item == nil {
					wild = true
					continue
				}
				hash, ok := historyHash(item)
				if !ok {
					return nil, q, false
				}
				q.topics[i] = append(q.topics[i], hash)
			}
			if wild || len(items) == 0 {
				q.topics[i] = nil
				continue
			}
			sort.Slice(q.topics[i], func(a, b int) bool { return bytes.Compare(q.topics[i][a][:], q.topics[i][b][:]) < 0 })
			q.topics[i] = slices.Compact(q.topics[i])
			list := make([]string, len(q.topics[i]))
			for j, h := range q.topics[i] {
				list[j] = h.Hex()
			}
			wire[i] = list
		}
		out["topics"] = wire
	}
	return out, q, true
}
