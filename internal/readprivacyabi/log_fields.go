package readprivacyabi

import (
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"privacy-proxy/internal/explorerdata"
	"reflect"
	"strings"
)

type VisibilityMap = explorerdata.VisibilityMap
type VisibilityLevel = explorerdata.VisibilityLevel
type Log = explorerdata.Log

const (
	VisibilityFull         = explorerdata.VisibilityFull
	VisibilityPseudonymous = explorerdata.VisibilityPseudonymous
	VisibilityRedacted     = explorerdata.VisibilityRedacted
	VisibilityHidden       = explorerdata.VisibilityHidden
)

func CollectLogTopics(l Log) []string {
	if l.Topic0 == nil {
		return nil
	}
	out := []string{*l.Topic0}
	if l.Topic1 == nil {
		return out
	}
	out = append(out, *l.Topic1)
	if l.Topic2 == nil {
		return out
	}
	out = append(out, *l.Topic2)
	if l.Topic3 == nil {
		return out
	}
	out = append(out, *l.Topic3)
	return out
}

func ExtractTopicAddress(topic string) (string, bool) {
	t := strings.ToLower(topic)
	// Topics are 66 chars: "0x" + 64 hex. Address occupies the last 40 chars.
	if len(t) != 66 || !strings.HasPrefix(t, "0x") {
		return "", false
	}
	prefix := t[2:26] // 24 hex chars = 12 zero bytes of padding
	if strings.Trim(prefix, "0") != "" {
		return "", false
	}
	return "0x" + t[26:], true
}

func RedactTopicAddress(addr string, level VisibilityLevel) string {
	switch level {
	case VisibilityFull:
		a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
		return "0x" + strings.Repeat("0", 24) + a
	case VisibilityPseudonymous:
		// GeneratePseudonym returns a human-readable string, not a hex address.
		// We cannot zero-pad it into a valid 32-byte hex topic, so zero the slot instead.
		return "0x" + strings.Repeat("0", 64)
	default: // VisibilityRedacted, VisibilityHidden
		return "0x" + strings.Repeat("0", 64)
	}
}

func RedactLogAddressFields(topics []*string, data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) ([]*string, string) {
	redTopics := make([]*string, len(topics))
	for i, t := range topics {
		redTopics[i] = RedactTopicField(t, visMap)
	}
	redData := RedactLogData(data, contractABI, topic0, visMap)
	return redTopics, redData
}

func ExtractLogAddresses(topics []*string, data string, contractABI json.RawMessage, topic0 *string) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(a string) {
		if _, ok := seen[a]; ok {
			return
		}
		seen[a] = struct{}{}
		out = append(out, a)
	}
	for _, t := range topics {
		if t == nil {
			continue
		}
		if a, ok := ExtractTopicAddress(*t); ok {
			add(a)
		}
	}
	if data != "" && topic0 != nil && len(contractABI) > 0 {
		for _, a := range ExtractDataAddresses(data, contractABI, topic0) {
			add(a)
		}
	}
	return out
}

func RedactTopicField(topic *string, visMap VisibilityMap) *string {
	if topic == nil {
		return nil
	}
	addr, ok := ExtractTopicAddress(*topic)
	if !ok {
		return topic
	}
	level := visMap[addr]
	if level == VisibilityFull {
		return topic
	}
	redacted := RedactTopicAddress(addr, level)
	return &redacted
}

func EventHasDynamicNonIndexedParamJSON(contractABI json.RawMessage, topic0 string) bool {
	if len(contractABI) == 0 || topic0 == "" {
		return false
	}
	parsed, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return false
	}
	topic0Lower := strings.ToLower(topic0)
	var matched *abi.Event
	for _, ev := range parsed.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev
			matched = &ev
			break
		}
	}
	if matched == nil {
		return false
	}
	for _, inp := range matched.Inputs {
		if inp.Indexed {
			continue
		}
		if isDynamicABIType(inp.Type) {
			return true
		}
	}
	return false
}

func ExtractDataAddresses(data string, contractABI json.RawMessage, topic0 *string) []string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return nil
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return nil
	}
	// Find the event matching topic0 (keccak256 of its signature).
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev // capture
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return nil
	}
	// Collect non-indexed inputs in declaration order.
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return nil
	}

	// Decode the hex data.
	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return nil
	}
	// Each non-indexed param occupies a 32-byte slot (for value types).
	if len(dataBytes) < len(nonIndexed)*32 {
		return nil
	}

	var addrs []string
	for i, inp := range nonIndexed {
		if inp.Type.T != abi.AddressTy {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		// Addresses are right-aligned in a 32-byte slot (12 zero bytes of padding on the left).
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := common.BytesToAddress(slot[12:]).Hex()
		addrs = append(addrs, strings.ToLower(addr))
	}
	return addrs
}

func RedactLogData(data string, contractABI json.RawMessage, topic0 *string, visMap VisibilityMap) string {
	if data == "" || len(contractABI) == 0 || topic0 == nil {
		return data
	}
	parsedABI, err := abi.JSON(strings.NewReader(string(contractABI)))
	if err != nil {
		return data
	}
	topic0Lower := strings.ToLower(*topic0)
	var matchedEvent *abi.Event
	for _, ev := range parsedABI.Events {
		sig := "0x" + hex.EncodeToString(crypto.Keccak256([]byte(ev.Sig)))
		if strings.ToLower(sig) == topic0Lower {
			ev := ev
			matchedEvent = &ev
			break
		}
	}
	if matchedEvent == nil {
		return data
	}
	var nonIndexed []abi.Argument
	for _, inp := range matchedEvent.Inputs {
		if !inp.Indexed {
			nonIndexed = append(nonIndexed, inp)
		}
	}
	if len(nonIndexed) == 0 {
		return data
	}

	dataHex := strings.TrimPrefix(data, "0x")
	dataBytes, err := hex.DecodeString(dataHex)
	if err != nil {
		return data
	}
	if len(dataBytes) < len(nonIndexed)*32 {
		return data
	}

	modified := false
	for i, inp := range nonIndexed {
		// M15 / G23 (security audit follow-up to RD-915): pre-fix this
		// loop only scanned slots whose ABI type was AddressTy. A field
		// declared as bytes32 with an address right-aligned in the slot
		// — a common pattern for "addresses passed as bytes32 for
		// historical / cross-contract reasons" — leaked the address
		// verbatim. Now also scan FixedBytesTy slots of size 32 (bytes32):
		// the address pattern (first 12 bytes zero, last 20 = address)
		// is detectable with the same heuristic as AddressTy.
		//
		// Dynamic bytes/string are NOT scanned: the static slot at
		// position i contains the offset into the tail, not the value
		// itself; following the offset would require modelling the full
		// dynamic-encoding layout. Tracked as a follow-up to G23.
		//
		// uint256 / int256 are NOT scanned because legitimate small
		// numeric values (e.g. a uint256 = 123) have the first 12 bytes
		// zero and would false-positive as a hidden address (0x..0007b),
		// silently zeroing event values. Contract authors who encode
		// addresses in uint256 must declare the field as `address`
		// instead — that's an ABI-level signal we honour today.
		eligible := inp.Type.T == abi.AddressTy ||
			(inp.Type.T == abi.FixedBytesTy && inp.Type.Size == 32)
		if !eligible {
			continue
		}
		slot := dataBytes[i*32 : (i+1)*32]
		prefix := slot[:12]
		allZero := true
		for _, b := range prefix {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			continue
		}
		addr := strings.ToLower(common.BytesToAddress(slot[12:]).Hex())
		level := visMap[addr]
		if level == VisibilityFull {
			continue
		}
		// Zero out the entire 32-byte slot.
		for j := i * 32; j < (i+1)*32; j++ {
			dataBytes[j] = 0
		}
		modified = true
	}
	if !modified {
		return data
	}
	prefix := ""
	if strings.HasPrefix(data, "0x") || strings.HasPrefix(data, "0X") {
		prefix = "0x"
	}
	return prefix + hex.EncodeToString(dataBytes)
}

func IsViewerInCalldata(inputData string, viewerAddrs map[string]bool) bool {
	if len(viewerAddrs) == 0 || len(inputData) < 8 {
		return false
	}

	data := strings.ToLower(inputData)
	// Normalize: strip 0x prefix if present so selector is always at [0:8]
	if strings.HasPrefix(data, "0x") {
		data = data[2:]
	}
	if len(data) < 8 {
		return false
	}
	selector := "0x" + data[:8]

	// Each address param is 32 bytes (64 hex chars), zero-padded on the left.
	// Address is in the last 20 bytes: offset 24 hex chars from param start.
	extractAddr := func(offset int) string {
		start := 8 + offset*64 // 8 = selector length after stripping 0x
		end := start + 64
		if len(data) < end {
			return ""
		}
		// Address is last 20 bytes of 32-byte word
		return "0x" + data[start+24:end]
	}

	switch selector {
	// ERC-20
	case "0xa9059cbb": // transfer(address,uint256) — param 0 is recipient
		return viewerAddrs[extractAddr(0)]
	case "0x23b872dd": // transferFrom(address,address,uint256) — params 0,1
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	case "0x095ea7b3": // approve(address,uint256) — param 0 is spender
		return viewerAddrs[extractAddr(0)]
	// ERC-721 (same shape; from/to at params 0,1)
	case "0x42842e0e", "0xb88d4fde":
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	case "0xa22cb465": // setApprovalForAll(address,bool)
		return viewerAddrs[extractAddr(0)]
	// ERC-1155 (from/to at params 0,1)
	case "0xf242432a", "0x2eb2c2d6":
		return viewerAddrs[extractAddr(0)] || viewerAddrs[extractAddr(1)]
	}
	return false
}

func AnyAddressMatches(v any, viewerAddrs map[string]bool) bool {
	switch x := v.(type) {
	case common.Address:
		return viewerAddrs[strings.ToLower(x.Hex())]
	case []common.Address:
		for _, a := range x {
			if viewerAddrs[strings.ToLower(a.Hex())] {
				return true
			}
		}
		return false
	case []any:
		for _, e := range x {
			if AnyAddressMatches(e, viewerAddrs) {
				return true
			}
		}
		return false
	}
	// Fallback via reflect: covers fixed arrays ([N]common.Address) and
	// struct-typed inputs. We walk every exported field / element and
	// recurse.
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Array, reflect.Slice:
		for i := 0; i < rv.Len(); i++ {
			if AnyAddressMatches(rv.Index(i).Interface(), viewerAddrs) {
				return true
			}
		}
	case reflect.Struct:
		for i := 0; i < rv.NumField(); i++ {
			if !rv.Field(i).CanInterface() {
				continue
			}
			if AnyAddressMatches(rv.Field(i).Interface(), viewerAddrs) {
				return true
			}
		}
	}
	return false
}
