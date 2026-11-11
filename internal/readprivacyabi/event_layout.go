package readprivacyabi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

var ErrLayoutTooBroad = errors.New("event layout budget exceeded")

// LayoutLimits bound one operation's approved metadata, not attacker-supplied
// data keys. Its MaxBytes must be reserved from the owning operation BEFORE
// constructing the matcher or obtaining metadata copies. It is a charged byte
// bound, not an exact heap/RSS promise.
type LayoutLimits struct{ MaxBytes, MaxDocuments, MaxEntries, MaxDocumentBytes int }

func DefaultLayoutLimits() LayoutLimits { return LayoutLimits{8 << 20, 128, 8192, 1 << 20} }
func (l LayoutLimits) valid() bool {
	m := DefaultLayoutLimits()
	return l.MaxBytes > 0 && l.MaxBytes <= m.MaxBytes && l.MaxDocuments > 0 && l.MaxDocuments <= m.MaxDocuments && l.MaxEntries > 0 && l.MaxEntries <= m.MaxEntries && l.MaxDocumentBytes > 0 && l.MaxDocumentBytes <= m.MaxDocumentBytes
}

type layoutEvent struct {
	event abi.Event
	raw   json.RawMessage
}
type EventLayouts struct {
	owner   *EventLayoutMatcher
	byTopic map[string][]layoutEvent
}
type EventLayoutMatcher struct {
	limits                    LayoutLimits
	bytes, documents, entries int
	memo                      map[[32]byte]*EventLayouts
	err                       error
}

func NewEventLayoutMatcher(limits LayoutLimits) (*EventLayoutMatcher, error) {
	if !limits.valid() {
		return nil, ErrLayoutTooBroad
	}
	return &EventLayoutMatcher{limits: limits, memo: map[[32]byte]*EventLayouts{}}, nil
}

// ReserveMetadata charges current-registry/grant copies before the owner makes
// them. Retained repeated copies are charged again; there is no refund/reset.
func (m *EventLayoutMatcher) ReserveMetadata(n int) error {
	if m == nil || m.err != nil {
		return ErrLayoutTooBroad
	}
	if n < 0 || n > m.limits.MaxBytes-m.bytes {
		m.err = ErrLayoutTooBroad
		return m.err
	}
	m.bytes += n
	return nil
}

// Match consumes ONLY the original current approved ABI. The bundle loader's
// depth/type/head-slot validation is a caller precondition. Unsupported shapes
// return false; exhaustion is a distinct error, never a successful omitted log.
// The returned detached ONE-event ABI must reach every downstream helper.
func (m *EventLayoutMatcher) Match(approvedABI json.RawMessage, topics []string, data string) (json.RawMessage, bool, error) {
	prepared, err := m.Prepare(approvedABI)
	if err != nil {
		return nil, false, err
	}
	return m.MatchPrepared(prepared, topics, data)
}

// Prepare runs once for an actual current registry entry. The owning consumer
// retains a bounded emitter->handle map, avoiding a large ABI hash per log.
func (m *EventLayoutMatcher) Prepare(approvedABI json.RawMessage) (*EventLayouts, error) {
	if m == nil || !m.limits.valid() || m.err != nil {
		return nil, ErrLayoutTooBroad
	}
	if len(approvedABI) == 0 {
		return &EventLayouts{owner: m}, nil
	}
	if len(approvedABI) > m.limits.MaxDocumentBytes {
		m.err = ErrLayoutTooBroad
		return nil, m.err
	}
	key := sha256.Sum256(approvedABI)
	prepared, known := m.memo[key]
	if !known {
		if m.documents >= m.limits.MaxDocuments {
			m.err = ErrLayoutTooBroad
			return nil, m.err
		}
		// Charge raw-decoder and retained one-event metadata before any copy or
		// reflection parse; number of entries is charged before each decode.
		if err := m.ReserveMetadata(2*len(approvedABI) + 64); err != nil {
			return nil, err
		}
		m.documents++
		byTopic, err := m.parse(approvedABI)
		if err != nil {
			return nil, err
		}
		prepared = &EventLayouts{owner: m, byTopic: byTopic}
		m.memo[key] = prepared
	}
	return prepared, nil
}

func (m *EventLayoutMatcher) MatchPrepared(prepared *EventLayouts, topics []string, data string) (json.RawMessage, bool, error) {
	if m == nil || m.err != nil || prepared == nil || prepared.owner != m {
		return nil, false, ErrLayoutTooBroad
	}
	if len(data) > 2<<20 {
		m.err = ErrLayoutTooBroad
		return nil, false, m.err
	}
	if len(topics) == 0 || len(topics) > 4 {
		return nil, false, nil
	}
	var matched *layoutEvent
	for _, candidate := range prepared.byTopic[strings.ToLower(topics[0])] {
		fits, _ := eventNamesLinked(candidate.event, topics, data, nil)
		if !fits || !indexedWordsCanonical(candidate.event, topics) {
			continue
		}
		if matched != nil {
			return nil, false, nil
		}
		copy := candidate
		matched = &copy
	}
	if matched == nil {
		return nil, false, nil
	}
	// Cover the detached result and its caller's retained string conversion.
	if err := m.ReserveMetadata(2 * len(matched.raw)); err != nil {
		return nil, false, err
	}
	return bytes.Clone(matched.raw), true, nil
}
func (m *EventLayoutMatcher) parse(raw []byte) (map[string][]layoutEvent, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('[') {
		return nil, nil
	}
	out := map[string][]layoutEvent{}
	for d.More() {
		if m.entries >= m.limits.MaxEntries {
			m.err = ErrLayoutTooBroad
			return nil, m.err
		}
		if err := m.ReserveMetadata(128); err != nil {
			return nil, err
		}
		m.entries++
		var entry json.RawMessage
		if d.Decode(&entry) != nil {
			return nil, nil
		}
		var tag struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(entry, &tag) != nil {
			return nil, nil
		}
		if tag.Type != "event" {
			if tag.Type != "function" && tag.Type != "constructor" && tag.Type != "fallback" && tag.Type != "receive" {
				return nil, nil
			}
			continue
		}
		one := make([]byte, 0, len(entry)+2)
		one = append(one, '[')
		one = append(one, entry...)
		one = append(one, ']')
		parsed, err := abi.JSON(bytes.NewReader(one))
		if err != nil || len(parsed.Events) != 1 {
			return nil, nil
		}
		for _, event := range parsed.Events {
			if event.Anonymous {
				continue
			}
			topic := strings.ToLower(event.ID.Hex())
			out[topic] = append(out[topic], layoutEvent{event, one})
		}
	}
	if close, err := d.Token(); err != nil || close != json.Delim(']') {
		return nil, nil
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, nil
	}
	return out, nil
}
func indexedWordsCanonical(event abi.Event, topics []string) bool {
	n := 1
	for _, input := range event.Inputs {
		if !input.Indexed {
			continue
		}
		if n >= len(topics) {
			return false
		}
		word, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(topics[n], "0x"), "0X"))
		n++
		if err != nil || len(word) != 32 {
			return false
		}
		switch input.Type.T {
		case abi.StringTy, abi.BytesTy, abi.SliceTy, abi.ArrayTy, abi.TupleTy:
			// Indexed complex values are hashes, not direct ABI values.
			continue
		case abi.IntTy, abi.UintTy, abi.BoolTy, abi.AddressTy, abi.FixedBytesTy, abi.FunctionTy:
			args := abi.Arguments{{Type: input.Type}}
			values, err := args.Unpack(word)
			if err != nil {
				return false
			}
			packed, err := args.Pack(values...)
			if err != nil || !bytes.Equal(packed, word) {
				return false
			}
		default:
			return false
		}
	}
	return n == len(topics)
}
