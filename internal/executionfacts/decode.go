package executionfacts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"strconv"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
)

type wireRecord struct {
	Record
	valuePresent bool
	children     int
	recovered    Address
}

type decoder struct {
	json      *json.Decoder
	limits    Limits
	profile   Profile
	records   []wireRecord
	inputUsed int
	logsUsed  int
	logBytes  int
}

// Parse accepts only the fixed Geth callTracer profiles. It checks the tree
// against independently supplied root inputs and returns no partial tree.
// Parsing is incremental: record/depth/input budgets are checked while reading,
// before appending children or decoding their byte strings.
func Parse(raw []byte, expected ExpectedRoot, profile Profile, limits Limits) (*Tree, error) {
	if !profile.valid() || !limits.valid() || expected.Value == nil || expected.Value.Sign() < 0 || expected.Value.BitLen() > 256 ||
		(expected.Kind != Call && expected.Kind != Create) ||
		(expected.Kind == Call && (!expected.To.Known || expected.CreatedAddress.Known)) ||
		(expected.Kind == Create && expected.To.Known) {
		return nil, fail(InvalidOptions, -1, "options", "invalid limits or independent root inputs")
	}
	if len(raw) > limits.MaxRawBytes || len(expected.Input) > limits.MaxInputBytes {
		return nil, fail(LimitExceeded, -1, "bytes", "raw trace or expected input exceeds budget")
	}
	if !utf8.Valid(raw) {
		return nil, fail(InvalidTrace, -1, "json", "invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	p := decoder{json: d, limits: limits, profile: profile}
	if err := p.node(-1, 0); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, fail(InvalidTrace, -1, "json", "trailing or malformed JSON")
	}
	return buildTree(p.records, expected, profile)
}

func (p *decoder) node(parent, depth int) error {
	index := len(p.records)
	if index >= p.limits.MaxRecords || depth > p.limits.MaxDepth {
		return fail(LimitExceeded, index, "calls", "record or depth budget exceeded")
	}
	token, err := p.json.Token()
	if err != nil || token != json.Delim('{') {
		return fail(InvalidTrace, index, "json", "frame must be an object")
	}
	p.records = append(p.records, wireRecord{})
	w := wireRecord{Record: Record{ParentIndex: parent, Depth: depth}}
	seen := map[string]bool{}
	for p.json.More() {
		keyToken, err := p.json.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok {
			return fail(InvalidTrace, index, "json", "invalid object key")
		}
		if !knownField(key) && !(key == "logs" && p.profile.withLogs()) {
			return fail(InvalidTrace, index, "object", "unsupported field")
		}
		if seen[key] {
			return fail(InvalidTrace, index, key, "duplicate field")
		}
		seen[key] = true
		if key == "logs" {
			logs, err := p.logs(index)
			if err != nil {
				return err
			}
			w.Logs = logs
			continue
		}
		if key == "calls" {
			if err := p.children(index, depth, &w.children); err != nil {
				return err
			}
			continue
		}
		valueToken, err := p.json.Token()
		value, ok := valueToken.(string)
		if err != nil || !ok {
			return fail(InvalidTrace, index, key, "field must be a nonnull string")
		}
		if err := p.scalar(&w, index, key, value); err != nil {
			return err
		}
	}
	if token, err := p.json.Token(); err != nil || token != json.Delim('}') {
		return fail(InvalidTrace, index, "json", "unterminated frame")
	}
	for _, required := range []string{"type", "from", "input", "gas", "gasUsed"} {
		if !seen[required] {
			return fail(InvalidTrace, index, required, "required field missing")
		}
	}
	if !w.Kind.valid() {
		return fail(InvalidTrace, index, "type", "unsupported opcode")
	}
	if !w.To.Known && (!w.Kind.creation() || !w.Failed()) {
		return fail(InvalidTrace, index, "to", "destination may be absent only for failed creation")
	}
	if w.Kind == StaticCall {
		if !w.valuePresent {
			w.Value = new(big.Int) // Defined STATICCALL semantics, not a CALL default.
		}
		if w.Value.Sign() != 0 {
			return fail(InvalidTrace, index, "value", "STATICCALL value must be zero")
		}
	} else if !w.valuePresent {
		return fail(InvalidTrace, index, "value", "explicit value required")
	}
	if w.Kind == SelfDestruct && (len(w.Input) != 0 || w.children != 0) {
		return fail(InvalidTrace, index, "calls", "SELFDESTRUCT is a leaf effect with empty input")
	}
	for _, log := range w.Logs {
		if log.Position > uint64(w.children) {
			return fail(InvalidTrace, index, "logs.position", "position exceeds child count")
		}
	}
	p.records[index] = w
	return nil
}

func knownField(field string) bool {
	switch field {
	case "type", "from", "to", "input", "output", "gas", "gasUsed", "value", "error", "revertReason", "calls":
		return true
	}
	return false
}

func (p *decoder) children(parent, depth int, count *int) error {
	token, err := p.json.Token()
	if err != nil || token != json.Delim('[') {
		return fail(InvalidTrace, parent, "calls", "calls must be a nonnull array")
	}
	for p.json.More() {
		if err := p.node(parent, depth+1); err != nil {
			return err
		}
		*count++
	}
	if token, err := p.json.Token(); err != nil || token != json.Delim(']') {
		return fail(InvalidTrace, parent, "calls", "unterminated calls array")
	}
	return nil
}

func (p *decoder) scalar(w *wireRecord, index int, field, value string) error {
	switch field {
	case "type":
		w.Kind = Kind(value)
	case "from", "to":
		address, ok := parseAddress(value)
		if !ok {
			return fail(InvalidTrace, index, field, "address must contain exactly 20 hex bytes")
		}
		if field == "from" {
			w.From = address
		} else {
			w.To = knownAddress(address)
		}
	case "input", "output":
		budget := p.limits.MaxRawBytes
		if field == "input" {
			budget = min(p.limits.MaxInputBytes, p.limits.MaxAggregateInputBytes-p.inputUsed)
		}
		if len(value) < 2 || value[:2] != "0x" || len(value)%2 != 0 {
			return fail(InvalidTrace, index, field, "byte string must be even-length 0x hex")
		}
		size := (len(value) - 2) / 2
		if size > budget {
			return fail(LimitExceeded, index, field, "byte string exceeds budget")
		}
		decoded, err := hex.DecodeString(value[2:])
		if err != nil {
			return fail(InvalidTrace, index, field, "invalid hex byte string")
		}
		if field == "input" {
			p.inputUsed += size // Checked against the remaining budget before allocation.
			w.Input = decoded
		} else {
			w.Output = decoded
		}
	case "value":
		if !quantity(value, 256) {
			return fail(InvalidTrace, index, field, "value must be a canonical uint256 hex quantity")
		}
		w.Value, _ = new(big.Int).SetString(value[2:], 16)
		w.valuePresent = true
	case "gas", "gasUsed":
		if !quantity(value, 64) {
			return fail(InvalidTrace, index, field, "gas must be a canonical uint64 hex quantity")
		}
		gas, _ := strconv.ParseUint(value[2:], 16, 64)
		if field == "gas" {
			w.Gas = gas
		} else {
			w.GasUsed = gas
		}
	case "error", "revertReason":
		if len(value) > p.limits.MaxTextBytes {
			return fail(LimitExceeded, index, field, "text exceeds budget")
		}
		if field == "error" {
			w.Error = value
		} else {
			w.RevertReason = value
		}
	}
	return nil
}

func quantity(value string, bits int) bool {
	if len(value) < 3 || len(value) > 2+bits/4 || value[:2] != "0x" || (len(value) > 3 && value[2] == '0') {
		return false
	}
	for _, digit := range value[2:] {
		if !(digit >= '0' && digit <= '9') && !(digit >= 'a' && digit <= 'f') {
			return false
		}
	}
	return true
}

func parseAddress(value string) (common.Address, bool) {
	if len(value) != 42 || value[:2] != "0x" {
		return common.Address{}, false
	}
	raw, err := hex.DecodeString(value[2:])
	if err != nil {
		return common.Address{}, false
	}
	return common.BytesToAddress(raw), true
}

func knownAddress(value common.Address) Address { return Address{value, true} }

func buildTree(wire []wireRecord, expected ExpectedRoot, profile Profile) (*Tree, error) {
	if profile.id == LifecycleWithLogsProfileID {
		if err := recoverCreationContexts(wire); err != nil {
			return nil, err
		}
	}
	root := wire[0]
	if root.Kind != expected.Kind || root.From != expected.From || !bytes.Equal(root.Input, expected.Input) || root.Value.Cmp(expected.Value) != 0 ||
		(expected.Kind == Call && root.To != expected.To) ||
		(expected.Kind == Create && root.To.Known && expected.CreatedAddress.Known && root.To != expected.CreatedAddress) {
		return nil, fail(RootMismatch, 0, "root", "trace does not match independent request inputs")
	}
	if root.recovered.Known && expected.CreatedAddress.Known && root.recovered != expected.CreatedAddress {
		return nil, fail(RootMismatch, 0, "root", "child context differs from independent creation destination")
	}
	tree := &Tree{profile: profile.id, records: make([]Record, len(wire))}
	for index, w := range wire {
		r := w.Record
		var parent *Record
		if r.ParentIndex >= 0 {
			parent = &tree.records[r.ParentIndex]
			r.Static = parent.Static
			r.AncestorFailed = parent.AncestorFailed || parent.Failed()
			if parent.StorageAddress.Known && r.From != parent.StorageAddress.Value {
				return nil, fail(InvalidTrace, index, "from", "child source differs from parent context")
			}
		}
		switch r.Kind {
		case Call, StaticCall:
			r.StorageAddress, r.NominalCodeAddress = r.To, r.To
			r.CallerAddress = knownAddress(r.From)
			r.Static = r.Static || r.Kind == StaticCall
		case DelegateCall, CallCode:
			if parent == nil {
				return nil, fail(InvalidTrace, index, "type", "delegated call cannot be a root")
			}
			r.StorageAddress, r.NominalCodeAddress = parent.StorageAddress, r.To
			if r.Kind == DelegateCall {
				r.CallerAddress = parent.CallerAddress
				if r.Value.Cmp(parent.Value) != 0 {
					return nil, fail(InvalidTrace, index, "value", "delegate value differs from inherited value")
				}
			} else {
				r.CallerAddress = parent.StorageAddress
			}
		case Create, Create2:
			tree.requirements.Creation = true
			r.CallerAddress = knownAddress(r.From)
			r.StorageAddress, r.NominalCodeAddress = r.To, r.To
			if !r.To.Known && w.recovered.Known {
				r.StorageAddress, r.NominalCodeAddress = w.recovered, w.recovered
				r.ContextFromChildren = true
			}
			if index == 0 && !r.StorageAddress.Known && expected.CreatedAddress.Known {
				r.StorageAddress, r.NominalCodeAddress = expected.CreatedAddress, expected.CreatedAddress
				r.ContextFromExpected = true
			}
		case SelfDestruct:
			if parent == nil {
				return nil, fail(InvalidTrace, index, "type", "lifecycle effect cannot be a root")
			}
			tree.requirements.Lifecycle = true
			r.StorageAddress, r.CallerAddress = knownAddress(r.From), parent.CallerAddress
		}
		if r.Kind != SelfDestruct {
			tree.requirements.CodeProvenance = true
			if !r.StorageAddress.Known || !r.CallerAddress.Known {
				tree.requirements.UnresolvedExecutionContext = true
			}
		}
		tree.records[index] = r
	}
	return tree, nil
}
