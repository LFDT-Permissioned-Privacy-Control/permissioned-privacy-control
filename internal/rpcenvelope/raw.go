package rpcenvelope

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// Limits bound the opt-in raw parser. Legacy ParseEnvelope keeps its original
// encoding/json depth and behavior. Root value depth is one; keys are not values.
type Limits struct{ MaxBytes, MaxDepth, MaxValues int }

func DefaultLimits() Limits { return Limits{1 << 20, 32, 120000} }

func (l Limits) valid() bool {
	d := DefaultLimits()
	return l.MaxBytes > 0 && l.MaxBytes <= d.MaxBytes && l.MaxDepth > 0 && l.MaxDepth <= d.MaxDepth && l.MaxValues > 0 && l.MaxValues <= d.MaxValues
}

// RawEnvelope owns only bounded selected members. It preserves numeric IDs and
// omitted versus null values without decoding parameters into maps or float64.
// The caller separately chooses protocol validity and operation authorization.
type RawEnvelope struct {
	method              string
	id, params, version json.RawMessage
	idPresent           bool
}

func ParseRaw(body []byte, limits Limits) (*RawEnvelope, error) {
	if !limits.valid() || len(body) > limits.MaxBytes {
		return nil, parseError("raw envelope limit")
	}
	if IsBatchRequest(body) {
		return nil, ErrBatchRequest
	}
	if !utf8.Valid(body) || !json.Valid(body) {
		return nil, parseError("malformed JSON")
	}
	members, _, err := scanEnvelopeLimits(body, limits)
	if err != nil {
		return nil, err
	}
	var method, version string
	if raw := members[memberMethod]; raw != nil && json.Unmarshal(raw, &method) != nil {
		return nil, parseError("invalid method type")
	}
	if raw := members[memberJSONRPC]; raw != nil && json.Unmarshal(raw, &version) != nil {
		return nil, parseError("invalid jsonrpc type")
	}
	if raw := members[memberID]; raw != nil {
		// Same type/range acceptance as the legacy API, without replacing the
		// original number by its rounded float64 representation.
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, parseError("invalid id")
		}
		switch value.(type) {
		case nil, string, float64:
		default:
			return nil, parseError("invalid id type")
		}
	}
	if raw := members[memberParams]; raw != nil {
		raw = bytes.TrimSpace(raw)
		if raw[0] != '[' && !bytes.Equal(raw, []byte("null")) {
			return nil, parseError("invalid params type")
		}
	}
	return &RawEnvelope{method: method, id: bytes.Clone(members[memberID]), params: bytes.Clone(members[memberParams]), version: bytes.Clone(members[memberJSONRPC]), idPresent: members[memberID] != nil}, nil
}

func (e *RawEnvelope) Method() string {
	if e == nil {
		return ""
	}
	return e.method
}
func (e *RawEnvelope) IDJSON() (json.RawMessage, bool) {
	if e == nil {
		return nil, false
	}
	return bytes.Clone(e.id), e.idPresent
}
func (e *RawEnvelope) ParamsJSON() json.RawMessage {
	if e == nil {
		return nil
	}
	return bytes.Clone(e.params)
}
func (e *RawEnvelope) VersionJSON() json.RawMessage {
	if e == nil {
		return nil
	}
	return bytes.Clone(e.version)
}
