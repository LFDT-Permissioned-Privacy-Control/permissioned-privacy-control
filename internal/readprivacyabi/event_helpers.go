package readprivacyabi

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// isHexValue returns true if s is a 0x-prefixed hex string of non-zero length.
func isHexValue(s string) bool {
	if len(s) < 4 || len(s) > 66 || !strings.HasPrefix(s, "0x") {
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
	if paramIndex < 0 {
		return false
	}
	if parsedEvent == nil {
		if paramIndex >= len(entry.Topics)-1 {
			return false
		}
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
	if input.Type.T != abi.AddressTy {
		return false
	}
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

// matchesParamCustom compares only supported static scalar ABI values. Numeric
// literals use the canonical 32-byte ABI word (short positive legacy literals
// may be left-padded). Negative intN values require sign-extended two's-complement
// words; a short 0xff is not silently reinterpreted as int8(-1). Fixed bytes use
// their declared width and right padding, including when indexed.
func matchesParamCustom(
	entry logEntry,
	paramIndex int,
	mustBe string,
	parsedEvent *abi.Event,
) bool {
	if paramIndex < 0 {
		return false
	}
	if parsedEvent == nil {
		if paramIndex >= len(entry.Topics)-1 {
			return false
		}
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

// topicMatchesHex retains the documented empty-ABI legacy fallback: an exact
// raw topic comparison after left padding a positive hex literal. It does not
// claim to identify a parameter type or interpret hashed dynamic values.
func topicMatchesHex(topic string, mustBe string) bool {
	return topicMatchesHexTyped(topic, mustBe, "")
}

func topicMatchesHexTyped(topic, mustBe, abiType string) bool {
	if len(topic) != 66 || !strings.HasPrefix(topic, "0x") {
		return false
	}
	actual, err := hex.DecodeString(topic[2:])
	if err != nil {
		return false
	}
	if abiType == "" {
		literal, ok := scalarLiteralBytes(mustBe)
		if !ok {
			return false
		}
		var expected [32]byte
		copy(expected[32-len(literal):], literal)
		return bytes.Equal(actual, expected[:])
	}
	typ, err := abi.NewType(abiType, "", nil)
	if err != nil || !canonicalScalarWord(actual, typ) {
		return false
	}
	expected, ok := scalarLiteralWord(mustBe, typ)
	return ok && bytes.Equal(actual, expected[:])
}

func scalarLiteralBytes(value string) ([]byte, bool) {
	if len(value) < 4 || len(value) > 66 || !strings.HasPrefix(value, "0x") {
		return nil, false
	}
	decoded, err := hex.DecodeString(value[2:])
	return decoded, err == nil
}

// scalarLiteralWord does no truncation or floating-point conversion. Accept
// existing legacy 32-byte address/fixed-bytes words only with canonical padding.
func scalarLiteralWord(value string, typ abi.Type) ([32]byte, bool) {
	var word [32]byte
	literal, ok := scalarLiteralBytes(value)
	if !ok {
		return word, false
	}
	switch typ.T {
	case abi.FixedBytesTy:
		if typ.Size < 1 || typ.Size > 32 || len(literal) != typ.Size && len(literal) != 32 {
			return word, false
		}
		copy(word[:], literal)
	case abi.AddressTy:
		if len(literal) != 20 && len(literal) != 32 {
			return word, false
		}
		copy(word[32-len(literal):], literal)
	case abi.IntTy, abi.UintTy, abi.BoolTy:
		copy(word[32-len(literal):], literal)
	default:
		return word, false
	}
	return word, canonicalScalarWord(word[:], typ)
}

// go-ethereum represents some int widths as native Go integers and others as
// *big.Int. Enforce every ABI width explicitly, including uint24/int24 etc.
func canonicalScalarWord(word []byte, typ abi.Type) bool {
	if len(word) != 32 {
		return false
	}
	prefixIs := func(end int, value byte) bool {
		for _, b := range word[:end] {
			if b != value {
				return false
			}
		}
		return true
	}
	switch typ.T {
	case abi.AddressTy:
		return prefixIs(12, 0)
	case abi.BoolTy:
		return prefixIs(31, 0) && word[31] <= 1
	case abi.FixedBytesTy:
		if typ.Size < 1 || typ.Size > 32 {
			return false
		}
		for _, b := range word[typ.Size:] {
			if b != 0 {
				return false
			}
		}
		return true
	case abi.UintTy, abi.IntTy:
		if typ.Size < 8 || typ.Size > 256 || typ.Size%8 != 0 {
			return false
		}
		padding := 32 - typ.Size/8
		var sign byte
		if typ.T == abi.IntTy && word[padding]&0x80 != 0 {
			sign = 0xff
		}
		return prefixIs(padding, sign)
	default:
		return false
	}
}

// dataParamMatchesCustom decodes the non-indexed parameters from the log data
// field and checks if the parameter at paramIndex matches the custom mustBe value.
func dataParamMatchesCustom(data string, parsedEvent *abi.Event, paramIndex int, mustBe string) bool {
	value, ok := decodedEventParameter(data, parsedEvent, paramIndex)
	return ok && compareDecodedValue(value, mustBe, parsedEvent.Inputs[paramIndex].Type.String())
}

// Reuse the ABI encoder for the exact decoded Go type; this covers native
// integers and every [N]byte without widening, signed casts or reflect coercion.
func compareDecodedValue(decoded interface{}, mustBe string, abiType string) bool {
	if decoded == nil {
		return false
	}
	if integer, ok := decoded.(*big.Int); ok && integer == nil {
		return false
	}
	typ, err := abi.NewType(abiType, "", nil)
	if err != nil {
		return false
	}
	expected, ok := scalarLiteralWord(mustBe, typ)
	if !ok {
		return false
	}
	actual, err := (abi.Arguments{{Type: typ}}).Pack(decoded)
	return err == nil && canonicalScalarWord(actual, typ) && bytes.Equal(actual, expected[:])
}

// decodedEventParameter requires the original canonical ABI payload. A
// decoded address with nonzero padding or a payload with trailing bytes must
// not satisfy a predicate merely because the decoder ignored those bytes.
func decodedEventParameter(data string, event *abi.Event, paramIndex int) (interface{}, bool) {
	if event == nil || paramIndex < 0 || paramIndex >= len(event.Inputs) || event.Inputs[paramIndex].Indexed {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(data, "0x"), "0X"))
	if err != nil {
		return nil, false
	}
	arguments := event.Inputs.NonIndexed()
	values, err := arguments.Unpack(raw)
	if err != nil {
		return nil, false
	}
	canonical, err := arguments.Pack(values...)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, false
	}
	position := 0
	for i, input := range event.Inputs {
		if input.Indexed {
			continue
		}
		if i == paramIndex {
			if position >= len(values) {
				return nil, false
			}
			return values[position], true
		}
		position++
	}
	return nil, false
}

// topicMatchesAddr checks if a 32-byte topic hex string encodes one of the
// user's addresses (zero-padded address format).
func topicMatchesAddr(topic string, addrSet map[string]bool) bool {
	t := strings.ToLower(topic)
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return false
	}
	if _, err := hex.DecodeString(t[2:]); err != nil {
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
func dataParamMatchesAddr(data string, event *abi.Event, paramIndex int, addrSet map[string]bool) bool {
	if event == nil || paramIndex < 0 || paramIndex >= len(event.Inputs) || event.Inputs[paramIndex].Type.T != abi.AddressTy {
		return false
	}
	value, ok := decodedEventParameter(data, event, paramIndex)
	if !ok {
		return false
	}
	address, ok := value.(common.Address)
	return ok && addrSet[strings.ToLower(address.Hex())]
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
