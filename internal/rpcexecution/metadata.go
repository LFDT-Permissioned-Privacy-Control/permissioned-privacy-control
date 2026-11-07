package rpcexecution

import (
	"bytes"
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"time"

	"privacy-proxy/internal/networkidentity"
)

// MetadataMethod is the closed, non-executing metadata surface. Its presence
// supplies no method grant, anonymous access or permission to publish a result.
type MetadataMethod uint8

const (
	InvalidMetadataMethod MetadataMethod = iota
	MetadataAccounts
	MetadataBlockNumber
	MetadataChainID
	MetadataFeeHistory
	MetadataGasPrice
	MetadataMaxPriorityFee
	MetadataSyncing
	MetadataListening
	MetadataPeerCount
	MetadataNetworkVersion
	MetadataClientVersion
	MetadataKeccak
)

var metadataNames = [...]string{"", "eth_accounts", "eth_blockNumber", "eth_chainId", "eth_feeHistory", "eth_gasPrice", "eth_maxPriorityFeePerGas", "eth_syncing", "net_listening", "net_peerCount", "net_version", "web3_clientVersion", "web3_sha3"}

func (m MetadataMethod) String() string {
	if int(m) >= len(metadataNames) {
		return ""
	}
	return metadataNames[m]
}

type MetadataLimits struct {
	Timeout                                       time.Duration
	MaxParamsBytes, MaxResultBytes                int64
	MaxAccounts, MaxHistoryBlocks, MaxPercentiles int
}

func DefaultMetadataLimits() MetadataLimits {
	return MetadataLimits{5 * time.Second, (1 << 20) - 512, 8 << 20, 4096, 1024, 100}
}

func (l MetadataLimits) valid() bool {
	d := DefaultMetadataLimits()
	return l.Timeout > 0 && l.Timeout <= d.Timeout && l.MaxParamsBytes > 0 && l.MaxParamsBytes <= d.MaxParamsBytes && l.MaxResultBytes > 0 && l.MaxResultBytes <= d.MaxResultBytes && l.MaxAccounts > 0 && l.MaxAccounts <= d.MaxAccounts && l.MaxHistoryBlocks > 0 && l.MaxHistoryBlocks <= d.MaxHistoryBlocks && l.MaxPercentiles > 0 && l.MaxPercentiles <= d.MaxPercentiles
}

type MetadataSource struct {
	Network                              networkidentity.Binding
	URL, CredentialRef, CredentialHeader string
	AllowUnauthenticated                 bool
}

// MetadataSourceMetadata describes configured startup facts. In particular a
// local Keccak result supplies no live network observation through this getter.
type MetadataSourceMetadata struct {
	Network                                       networkidentity.Binding
	NetworkKey                                    [32]byte
	URL, CredentialRef, CredentialHeader, Profile string
}

// MetadataQuery owns normalized parameters. It contains no HTTP ID, endpoint or
// credential and cannot select a generic RPC or any execution acquisition path.
type MetadataQuery struct {
	method              MetadataMethod
	params              []any
	inputBytes, encoded int64
	hashInput           []byte
	blocks, percentiles int
}

func (q MetadataQuery) Method() MetadataMethod { return q.method }

func (q MetadataQuery) validFor(l MetadataLimits) bool {
	return l.valid() && q.method.String() != "" && q.params != nil && q.inputBytes >= 0 && q.inputBytes <= l.MaxParamsBytes && q.encoded > 0 && q.encoded <= l.MaxParamsBytes && q.blocks <= l.MaxHistoryBlocks && q.percentiles <= l.MaxPercentiles
}

// ParseMetadataQuery parses parameters only. The later HTTP dispatcher owns
// envelope/notification/alias compatibility and actual request authorization.
func ParseMetadataQuery(method MetadataMethod, raw json.RawMessage, limits MetadataLimits) (MetadataQuery, error) {
	q := MetadataQuery{method: method, inputBytes: int64(len(raw))}
	if !limits.valid() || method.String() == "" || int64(len(raw)) > limits.MaxParamsBytes {
		return MetadataQuery{}, failure(InvalidCall)
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		raw = []byte("[]")
	}
	v, err := metadataJSONArrays(raw, func(depth int) int {
		if depth == 0 {
			switch method {
			case MetadataFeeHistory:
				return 3
			case MetadataKeccak:
				return 1
			}
		}
		if depth == 1 && method == MetadataFeeHistory {
			return limits.MaxPercentiles
		}
		return 0
	})
	if err != nil {
		return MetadataQuery{}, failure(InvalidCall)
	}
	params, ok := v.([]any)
	if !ok {
		return MetadataQuery{}, failure(InvalidCall)
	}
	switch method {
	case MetadataKeccak:
		if len(params) != 1 {
			return MetadataQuery{}, failure(InvalidCall)
		}
		s, ok := params[0].(string)
		if !ok {
			return MetadataQuery{}, failure(InvalidCall)
		}
		q.hashInput, ok = data(s)
		if !ok || int64(len(q.hashInput))*2+6 > limits.MaxParamsBytes {
			return MetadataQuery{}, failure(InvalidCall)
		}
		params[0] = "0x" + strings.ToLower(s[2:])
	case MetadataFeeHistory:
		if len(params) < 2 || len(params) > 3 {
			return MetadataQuery{}, failure(InvalidCall)
		}
		n, ok := metadataBlockCount(params[0], limits.MaxHistoryBlocks)
		if !ok {
			return MetadataQuery{}, failure(InvalidCall)
		}
		block, ok := params[1].(string)
		if !ok || !metadataNewest(block) {
			return MetadataQuery{}, failure(InvalidCall)
		}
		points := []any{}
		if len(params) == 3 && params[2] != nil {
			points, ok = params[2].([]any)
			if !ok {
				return MetadataQuery{}, failure(InvalidCall)
			}
		}
		if len(points) > limits.MaxPercentiles {
			return MetadataQuery{}, failure(InvalidCall)
		}
		last := float64(-1)
		for i, point := range points {
			f, ok := metadataFloat(point)
			if !ok || f < 0 || f > 100 || f <= last {
				return MetadataQuery{}, failure(InvalidCall)
			}
			last, points[i] = f, f
		}
		q.blocks, q.percentiles = n, len(points)
		params = []any{"0x" + strconv.FormatUint(uint64(n), 16), block, points}
	default:
		if len(params) != 0 {
			return MetadataQuery{}, failure(InvalidCall)
		}
	}
	encoded, err := json.Marshal(params)
	q.params, q.encoded = params, int64(len(encoded))
	if err != nil || !q.validFor(limits) {
		return MetadataQuery{}, failure(InvalidCall)
	}
	return q, nil
}

func metadataBlockCount(v any, max int) (int, bool) {
	var text string
	switch x := v.(type) {
	case json.Number:
		text = string(x)
	case string:
		text = x
	default:
		return 0, false
	}
	base := uint64(10)
	if strings.HasPrefix(text, "0x") {
		text, base = text[2:], 16
	}
	if text == "" {
		return 0, false
	}
	var n uint64
	for _, c := range text {
		digit := uint64(99)
		switch {
		case c >= '0' && c <= '9':
			digit = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			digit = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			digit = uint64(c-'A') + 10
		}
		if digit >= base || n > uint64(max)/base || n*base+digit > uint64(max) {
			return 0, false
		}
		n = n*base + digit
	}
	return int(n), true
}

func metadataNewest(s string) bool {
	switch s {
	case "latest", "earliest", "pending", "safe", "finalized":
		return true
	}
	n, ok := quantity(s, 63)
	return ok && n.IsInt64() && s == strings.ToLower(s)
}

func metadataFloat(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok || len(n) > 64 {
		return 0, false
	}
	f, err := strconv.ParseFloat(string(n), 64)
	// Underflow to zero remains a finite float64, like the node's input type.
	return f, (err == nil || f == 0) && !math.IsInf(f, 0) && !math.IsNaN(f)
}
