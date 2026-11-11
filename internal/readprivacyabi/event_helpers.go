package readprivacyabi

import (
	"encoding/hex"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
	"strings"
)

// isHexValue returns true if s is a 0x-prefixed hex string of non-zero length.
func isHexValue(s string) bool {
	if len(s) < 4 || !strings.HasPrefix(s, "0x") {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// matchesParamSelf checks if the event parameter at the given ABI index
// encodes one of the user's linked addresses.
func matchesParamSelf(
	entry logEntry,
	paramIndex int,
	addrSet map[string]bool,
	parsedEvent *abi.Event,
) bool {
	if parsedEvent == nil {
		// No ABI: fall back to checking topics for address-like values.
		// Indexed param at ABI index i goes to topics[1+indexedOffset].
		// Without ABI we can only check if the index maps to a topic position.
		topicIdx := paramIndex + 1 // rough guess: assume all params up to index are indexed
		if topicIdx < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicIdx], addrSet)
		}
		return false
	}

	if paramIndex < 0 || paramIndex >= len(parsedEvent.Inputs) {
		return false
	}

	input := parsedEvent.Inputs[paramIndex]
	if input.Indexed {
		// Find which topic slot this indexed param occupies.
		// topics[0] = event signature. topics[1..3] = indexed params in order.
		indexedPos := 0
		for i := 0; i < paramIndex; i++ {
			if parsedEvent.Inputs[i].Indexed {
				indexedPos++
			}
		}
		topicSlot := indexedPos + 1
		if topicSlot < len(entry.Topics) {
			return topicMatchesAddr(entry.Topics[topicSlot], addrSet)
		}
		return false
	}

	// Non-indexed param: ABI-decode the data field.
	return dataParamMatchesAddr(entry.Data, parsedEvent, paramIndex, addrSet)
}

// matchesParamCustom checks if the event parameter at the given ABI index
// matches the literal hex value specified in mustBe. The comparison is
// type-aware based on the ABI:
//   - address: 20-byte hex comparison (case-insensitive)
//   - uint256: numeric comparison of hex-encoded big integers
//   - bytes32: direct 32-byte hex comparison
//   - bool:    "0x01" for true, "0x00" for false
//
// For indexed params the raw 32-byte topic is compared directly.
// For non-indexed params the data field is ABI-decoded.
func matchesParamCustom(
	entry logEntry,
	paramIndex int,
	mustBe string,
	parsedEvent *abi.Event,
) bool {
	if parsedEvent == nil {
		// No ABI: fall back to direct topic comparison for indexed params.
		topicIdx := paramIndex + 1
		if topicIdx < len(entry.Topics) {
			return topicMatchesHex(entry.Topics[topicIdx], mustBe)
		}
		return false
	}

	if paramIndex < 0 || paramIndex >= len(parsedEvent.Inputs) {
		return false
	}

	input := parsedEvent.Inputs[paramIndex]
	if input.Indexed {
		topicSlot := indexedTopicSlot(parsedEvent, paramIndex)
		if topicSlot < len(entry.Topics) {
			return topicMatchesHexTyped(entry.Topics[topicSlot], mustBe, input.Type.String())
		}
		return false
	}

	// Non-indexed: ABI-decode the data and compare the value.
	return dataParamMatchesCustom(entry.Data, parsedEvent, paramIndex, mustBe)
}

// indexedTopicSlot returns the topic index (1-based) for an indexed param at
// the given ABI position.
func indexedTopicSlot(parsedEvent *abi.Event, paramIndex int) int {
	indexedPos := 0
	for i := 0; i < paramIndex; i++ {
		if parsedEvent.Inputs[i].Indexed {
			indexedPos++
		}
	}
	return indexedPos + 1
}

// topicMatchesHex compares a 32-byte topic to a hex value with no type info.
// Performs a case-insensitive comparison after zero-padding the mustBe value
// to 32 bytes.
func topicMatchesHex(topic string, mustBe string) bool {
	return topicMatchesHexTyped(topic, mustBe, "")
}

// topicMatchesHexTyped compares a 32-byte topic to a hex value with type awareness.
// For address types, extracts the last 20 bytes and compares. For uint256,
// compares as big integers. For all others, does a direct padded comparison.
func topicMatchesHexTyped(topic string, mustBe string, abiType string) bool {
	t := strings.ToLower(strings.TrimPrefix(topic, "0x"))
	m := strings.ToLower(strings.TrimPrefix(mustBe, "0x"))

	if len(t) != 64 {
		return false
	}

	switch {
	case abiType == "address":
		// Address comparison: compare last 40 hex chars (20 bytes).
		// mustBe can be either a 20-byte address or a 32-byte padded value.
		if len(m) == 40 {
			// Verify topic has zero padding in the first 12 bytes.
			if strings.Trim(t[:24], "0") != "" {
				return false
			}
			return t[24:] == m
		}
		if len(m) == 64 {
			return t == m
		}
		return false

	case strings.HasPrefix(abiType, "uint"):
		// Numeric comparison as big.Int.
		topicInt, ok1 := new(big.Int).SetString(t, 16)
		mustBeInt, ok2 := new(big.Int).SetString(m, 16)
		if !ok1 || !ok2 {
			return false
		}
		return topicInt.Cmp(mustBeInt) == 0

	case abiType == "bool":
		// Normalize: strip leading zeros, then compare.
		topicStripped := strings.TrimLeft(t, "0")
		mustStripped := strings.TrimLeft(m, "0")
		topicBool := topicStripped == "1"
		mustBool := mustStripped == "1"
		topicFalse := topicStripped == ""
		mustFalse := mustStripped == ""
		return (topicBool && mustBool) || (topicFalse && mustFalse)

	default:
		// bytes32, bytes, or unknown: pad mustBe to 64 hex chars (right-pad for
		// bytesN, but indexed topics are always left-padded to 32 bytes).
		// Direct comparison after padding mustBe to 64 chars on the left with zeros.
		if len(m) > 64 {
			return false
		}
		padded := strings.Repeat("0", 64-len(m)) + m
		return t == padded
	}
}

// dataParamMatchesCustom decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex matches the custom mustBe value.
func dataParamMatchesCustom(
	data string,
	parsedEvent *abi.Event,
	paramIndex int,
	mustBe string,
) bool {
	if data == "" || data == "0x" {
		return false
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// Collect non-indexed inputs to determine ABI decode ordering.
	var nonIndexed abi.Arguments
	nonIndexedABIIdx := -1
	niCount := 0
	for i, inp := range parsedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
			if i == paramIndex {
				nonIndexedABIIdx = niCount
			}
			niCount++
		}
	}
	if nonIndexedABIIdx < 0 {
		return false
	}

	values, err := nonIndexed.Unpack(dataBytes)
	if err != nil {
		return false
	}
	if nonIndexedABIIdx >= len(values) {
		return false
	}

	return compareDecodedValue(values[nonIndexedABIIdx], mustBe, parsedEvent.Inputs[paramIndex].Type.String())
}

// compareDecodedValue compares an ABI-decoded Go value against a hex mustBe string.
func compareDecodedValue(decoded interface{}, mustBe string, abiType string) bool {
	m := strings.ToLower(strings.TrimPrefix(mustBe, "0x"))

	switch v := decoded.(type) {
	case common.Address:
		return strings.ToLower(v.Hex()[2:]) == m || (len(m) == 64 && m[24:] == strings.ToLower(v.Hex()[2:]))

	case *big.Int:
		mustBeInt, ok := new(big.Int).SetString(m, 16)
		if !ok {
			return false
		}
		return v.Cmp(mustBeInt) == 0

	case bool:
		// Normalize: strip leading zeros, then compare.
		// "1", "01", "000...001" all mean true. "0", "00", "000...000" all mean false.
		stripped := strings.TrimLeft(m, "0")
		if stripped == "1" {
			return v
		}
		if stripped == "" { // all zeros
			return !v
		}
		return false

	case [32]byte:
		return hex.EncodeToString(v[:]) == m

	default:
		// For other types, encode to hex and compare.
		return false
	}
}

// topicMatchesAddr checks if a 32-byte topic hex string encodes one of the
// user's addresses (zero-padded address format).
func topicMatchesAddr(topic string, addrSet map[string]bool) bool {
	t := strings.ToLower(topic)
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return false
	}
	// Address is last 40 chars, first 24 chars must be zero padding.
	prefix := t[2:26]
	if strings.Trim(prefix, "0") != "" {
		return false
	}
	addr := "0x" + t[26:]
	return addrSet[addr]
}

// dataParamMatchesAddr decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex is an address matching one
// of the user's addresses.
func dataParamMatchesAddr(
	data string,
	parsedEvent *abi.Event,
	paramIndex int,
	addrSet map[string]bool,
) bool {
	if data == "" || data == "0x" {
		return false
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return false
	}

	// Collect non-indexed inputs to determine ABI decode ordering.
	var nonIndexed abi.Arguments
	nonIndexedABIIdx := -1
	niCount := 0
	for i, inp := range parsedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
			if i == paramIndex {
				nonIndexedABIIdx = niCount
			}
			niCount++
		}
	}

	if nonIndexedABIIdx < 0 {
		return false // param is not non-indexed (shouldn't happen, handled above)
	}

	// Attempt ABI unpack.
	values, err := nonIndexed.Unpack(dataBytes)
	if err != nil {
		return false
	}

	if nonIndexedABIIdx >= len(values) {
		return false
	}

	addr, ok := values[nonIndexedABIIdx].(common.Address)
	if !ok {
		return false
	}

	return addrSet[strings.ToLower(addr.Hex())]
}

// eventHasDynamicNonIndexedParam reports whether the event matching
// topic0 in contractABI declares ANY non-indexed parameter of a
// dynamically-sized ABI type (`bytes`, `string`, dynamic arrays — incl.
// fixed-length arrays of dynamic types — or tuples containing any
// dynamic field).
//
// Used by FilterEventLogs (and the explorer's RedactLogs via a mirror)
// to drive the M15 drop gate: dynamic payloads can embed foreign-org
// addresses that the pre-M15 static-slot scanner cannot find. When the
// ABI lookup fails (parse error, no matching event, no ABI provided),
// the function conservatively returns FALSE — at this point the caller
// has already cleared the deny-when-no-ABI gate (RD-875) via an admin
// bypass or visibleTo unlock, so withholding the drop is acceptable.
//
// Indexed params are NEVER considered dynamic for this gate: dynamic
// types appearing as indexed are stored as keccak256 hashes in topics,
// not raw bytes — no address material survives.
func EventHasDynamicNonIndexedParam(contractABI string, topic0 string) bool {
	if contractABI == "" || topic0 == "" {
		return false
	}
	ev := findEventByTopic0(contractABI, topic0)
	if ev == nil {
		return false
	}
	for _, inp := range ev.Inputs {
		if inp.Indexed {
			continue
		}
		if isDynamicABIType(inp.Type) {
			return true
		}
	}
	return false
}

// isDynamicABIType reports whether an abi.Type is dynamically-sized in
// the ABI encoding sense. Mirrors go-ethereum's internal classification:
//   - bytes, string                       — always dynamic
//   - T[] (slice)                         — always dynamic
//   - T[N] (fixed array) where T dynamic  — dynamic
//   - tuple containing any dynamic field  — dynamic
//
// Plain fixed-size types (bytesN, intN, uintN, bool, address, function)
// are static.
func isDynamicABIType(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy, abi.SliceTy:
		return true
	case abi.ArrayTy:
		if t.Elem == nil {
			return false
		}
		return isDynamicABIType(*t.Elem)
	case abi.TupleTy:
		for _, ft := range t.TupleElems {
			if ft != nil && isDynamicABIType(*ft) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// findEventByTopic0 finds the event in a contract ABI that matches the given topic0.
func findEventByTopic0(contractABI string, topic0 string) *abi.Event {
	parsed, err := abi.JSON(strings.NewReader(contractABI))
	if err != nil {
		return nil
	}
	topic0Lower := strings.ToLower(topic0)
	for _, ev := range parsed.Events {
		sig := "0x" + hex.EncodeToString(ev.ID.Bytes())
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			return &ev
		}
	}
	return nil
}

type logEntry struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

func IsDynamicABIType(t abi.Type) bool { return isDynamicABIType(t) }
