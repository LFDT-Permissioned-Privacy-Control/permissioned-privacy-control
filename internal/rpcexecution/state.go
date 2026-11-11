package rpcexecution

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// StateMethod is a closed observation surface, not a method or data grant.
type StateMethod uint8

const (
	InvalidStateMethod StateMethod = iota
	StateBalance
	StateCode
	StateStorage
	StateProof
	StateNonce
)

var stateNames = [...]string{"", "eth_getBalance", "eth_getCode", "eth_getStorageAt", "eth_getProof", "eth_getTransactionCount"}

func (m StateMethod) String() string {
	if int(m) >= len(stateNames) {
		return ""
	}
	return stateNames[m]
}

type StateLimits struct {
	Timeout                                   time.Duration
	MaxParamsBytes, MaxResultBytes            int64
	MaxCodeBytes, MaxStorageKeys              int
	MaxProofNodesPerProof, MaxTotalProofNodes int
	MaxProofNodeBytes, MaxTotalProofBytes     int
}

func DefaultStateLimits() StateLimits {
	return StateLimits{5 * time.Second, 128 << 10, 8 << 20, 1 << 20, 1024, 128, 70000, 4096, 4 << 20}
}

func (l StateLimits) valid() bool {
	d := DefaultStateLimits()
	return l.Timeout > 0 && l.Timeout <= d.Timeout &&
		l.MaxParamsBytes > 0 && l.MaxParamsBytes <= d.MaxParamsBytes &&
		l.MaxResultBytes > 0 && l.MaxResultBytes <= d.MaxResultBytes &&
		l.MaxCodeBytes > 0 && l.MaxCodeBytes <= d.MaxCodeBytes &&
		l.MaxStorageKeys > 0 && l.MaxStorageKeys <= d.MaxStorageKeys &&
		l.MaxProofNodesPerProof > 0 && l.MaxProofNodesPerProof <= d.MaxProofNodesPerProof &&
		l.MaxTotalProofNodes > 0 && l.MaxTotalProofNodes <= d.MaxTotalProofNodes &&
		l.MaxProofNodeBytes > 0 && l.MaxProofNodeBytes <= d.MaxProofNodeBytes &&
		l.MaxTotalProofBytes > 0 && l.MaxTotalProofBytes <= d.MaxTotalProofBytes
}

type StateInputForm uint8

const (
	InvalidStateInput StateInputForm = iota
	StateInputOmitted
	StateInputNull
	StateInputString
	StateInputObject
)

type StateBlockKind uint8

const (
	InvalidStateBlock StateBlockKind = iota
	StateLatest
	StatePending
	StateSafe
	StateFinalized
	StateEarliest
	StateNumber
	StateHash
)

// StateBlockMetadata preserves original input classification. HistoricalInput
// describes the legacy input guard, not canonicality or historical ownership.
type StateBlockMetadata struct {
	Kind                 StateBlockKind
	InputForm            StateInputForm
	Number               uint64
	Hash                 common.Hash
	RequireCanonical     bool
	CanonicalWasSupplied bool
}

func (b StateBlockMetadata) HistoricalInput() bool {
	return b.InputForm == StateInputObject || b.Kind == StateNumber || b.Kind == StateHash
}

type StateStorageKey struct {
	Original   string
	Value      common.Hash
	InputBytes int
}

// StateQuery owns both the normalized wire request and the input facts a later
// authorizer needs. Its public accessors never expose mutable internal slices.
type StateQuery struct {
	method     StateMethod
	target     common.Address
	block      StateBlockMetadata
	keys       []StateStorageKey
	params     []any
	encoded    []byte
	inputBytes int64
	digest     [32]byte
}

func (q StateQuery) Method() StateMethod            { return q.method }
func (q StateQuery) Target() common.Address         { return q.target }
func (q StateQuery) Block() StateBlockMetadata      { return q.block }
func (q StateQuery) StorageKeys() []StateStorageKey { return slices.Clone(q.keys) }
func (q StateQuery) ParamsJSON() []byte             { return bytes.Clone(q.encoded) }
func (q StateQuery) Digest() [32]byte               { return q.digest }

func (q StateQuery) validFor(l StateLimits) bool {
	return l.valid() && q.method.String() != "" && q.params != nil &&
		q.inputBytes > 0 && q.inputBytes <= l.MaxParamsBytes && len(q.encoded) > 0 &&
		int64(len(q.encoded)) <= l.MaxParamsBytes && len(q.keys) <= l.MaxStorageKeys
}

// ParseStateQuery parses parameters only; it neither interprets an HTTP ID nor
// authenticates, authorizes, or qualifies a selected state point.
func ParseStateQuery(method StateMethod, raw json.RawMessage, l StateLimits) (StateQuery, error) {
	bad := func() (StateQuery, error) { return StateQuery{}, failure(InvalidCall) }
	if !l.valid() || method.String() == "" || len(raw) == 0 || int64(len(raw)) > l.MaxParamsBytes {
		return bad()
	}
	v, err := metadataJSONArrays(raw, func(depth int) int {
		if depth == 0 {
			return 3
		}
		if method == StateProof && depth == 1 {
			return l.MaxStorageKeys
		}
		return 0
	})
	params, ok := v.([]any)
	if err != nil || !ok {
		return bad()
	}
	blockIndex := 1
	if method == StateStorage || method == StateProof {
		blockIndex = 2
	}
	if len(params) < blockIndex || len(params) > blockIndex+1 {
		return bad()
	}
	addressText, ok := params[0].(string)
	target, addressOK := address(addressText)
	if !ok || !addressOK {
		return bad()
	}
	q := StateQuery{method: method, target: target, inputBytes: int64(len(raw))}
	owned := []any{strings.ToLower(addressText)}
	if method == StateStorage {
		s, ok := params[1].(string)
		key, wire, valid := stateStorageKey(s)
		if !ok || !valid {
			return bad()
		}
		q.keys, owned = []StateStorageKey{key}, append(owned, wire)
	} else if method == StateProof {
		items, ok := params[1].([]any)
		if !ok || len(items) > l.MaxStorageKeys {
			return bad()
		}
		q.keys = make([]StateStorageKey, 0, len(items))
		wires := make([]any, 0, len(items))
		for _, item := range items {
			s, ok := item.(string)
			key, wire, valid := stateStorageKey(s)
			if !ok || !valid {
				return bad()
			}
			q.keys, wires = append(q.keys, key), append(wires, wire)
		}
		owned = append(owned, wires)
	}
	var block any
	provided := len(params) > blockIndex
	if provided {
		block = params[blockIndex]
	}
	meta, wire, valid := stateBlock(block, provided)
	if !valid {
		return bad()
	}
	q.block, q.params = meta, append(owned, wire)
	q.encoded, err = json.Marshal(q.params)
	if err != nil || !q.validFor(l) {
		return bad()
	}
	q.digest = stateQueryDigest(q)
	return q, nil
}

func stateStorageKey(original string) (StateStorageKey, string, bool) {
	text := original
	if strings.HasPrefix(text, "0x") || strings.HasPrefix(text, "0X") {
		text = text[2:]
	}
	if len(text) > 64 {
		return StateStorageKey{}, "", false
	}
	if len(text)%2 != 0 {
		text = "0" + text
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		return StateStorageKey{}, "", false
	}
	key := StateStorageKey{original, common.BytesToHash(raw), len(raw)}
	if len(raw) == 32 {
		return key, "0x" + hex.EncodeToString(raw), true
	}
	return key, "0x" + new(big.Int).SetBytes(raw).Text(16), true
}

func stateBlock(v any, provided bool) (StateBlockMetadata, any, bool) {
	if !provided {
		return StateBlockMetadata{Kind: StateLatest, InputForm: StateInputOmitted}, "latest", true
	}
	if v == nil {
		return StateBlockMetadata{Kind: StateLatest, InputForm: StateInputNull}, "latest", true
	}
	if object, ok := v.(map[string]any); ok {
		hashValue, hasHash := object["blockHash"]
		numberValue, hasNumber := object["blockNumber"]
		if hasHash == hasNumber {
			return StateBlockMetadata{}, nil, false
		}
		value := numberValue
		if hasHash {
			value = hashValue
		}
		meta, wire, valid := stateBlock(value, true)
		if !valid || meta.InputForm != StateInputString || hasHash != (meta.Kind == StateHash) {
			return StateBlockMetadata{}, nil, false
		}
		out := map[string]any{}
		if hasHash {
			out["blockHash"] = wire
		} else {
			out["blockNumber"] = wire
		}
		if canonical, exists := object["requireCanonical"]; exists {
			flag, ok := canonical.(bool)
			if !hasHash || !ok {
				return StateBlockMetadata{}, nil, false
			}
			meta.RequireCanonical, meta.CanonicalWasSupplied = flag, true
			out["requireCanonical"] = flag
		}
		if len(out) != len(object) {
			return StateBlockMetadata{}, nil, false
		}
		meta.InputForm = StateInputObject
		return meta, out, true
	}
	s, ok := v.(string)
	if !ok {
		return StateBlockMetadata{}, nil, false
	}
	meta := StateBlockMetadata{InputForm: StateInputString}
	switch s {
	case "latest":
		meta.Kind = StateLatest
	case "pending":
		meta.Kind = StatePending
	case "safe":
		meta.Kind = StateSafe
	case "finalized":
		meta.Kind = StateFinalized
	case "earliest":
		meta.Kind = StateEarliest
	default:
		if len(s) == 66 {
			raw, valid := data(s)
			if !valid || len(raw) != 32 {
				return StateBlockMetadata{}, nil, false
			}
			meta.Kind, meta.Hash = StateHash, common.BytesToHash(raw)
			return meta, strings.ToLower(s), true
		}
		n, valid := quantity(s, 63)
		if !valid || s != strings.ToLower(s) {
			return StateBlockMetadata{}, nil, false
		}
		meta.Kind, meta.Number = StateNumber, n.Uint64()
	}
	return meta, s, true
}

func stateQueryDigest(q StateQuery) [32]byte {
	h := sha256.New()
	h.Write([]byte("ops-rpc-state-query/v1\x00"))
	h.Write([]byte{byte(q.method), byte(q.block.InputForm)})
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(q.encoded)))
	h.Write(size[:])
	h.Write(q.encoded)
	for _, key := range q.keys {
		binary.BigEndian.PutUint32(size[:], uint32(len(key.Original)))
		h.Write(size[:])
		h.Write([]byte(key.Original))
		h.Write([]byte{byte(key.InputBytes)})
		h.Write(key.Value[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
