package rpcexecution

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// The result's raw wire value is at most8MiB. Before building collections, this
// one token pass limits values/members to120000 and decoded scalar text to8MiB.
// Together with the existing RPC envelope's owned raw-result copy this bounds
// logical scalar work to16MiB. ResultJSON's caller copy is a separate lifetime.
func metadataJSON(raw []byte) (any, error) {
	return metadataJSONArrays(raw, func(int) int { return 120000 })
}

func metadataJSONArrays(raw []byte, arrayLimit func(int) int) (any, error) {
	return readJSONFieldArrays(raw, func(depth int, _ string) int { return arrayLimit(depth) })
}

// readJSONFieldArrays preserves the shared token and scalar budgets while
// allowing different collection bounds for fields at the same JSON depth.
func readJSONFieldArrays(raw []byte, arrayLimit func(int, string) int) (any, error) {
	if len(raw) > 8<<20 || !utf8.Valid(raw) {
		return nil, failure(EvidenceLimit)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes, text := 0, 0
	var read func(int, string) (any, error)
	read = func(depth int, field string) (any, error) {
		nodes++
		if depth > 32 || nodes > 120000 {
			return nil, failure(EvidenceLimit)
		}
		token, err := d.Token()
		if err != nil {
			return nil, failure(InvalidEvidence)
		}
		switch v := token.(type) {
		case string:
			text += len(v)
		case json.Number:
			text += len(v)
		}
		if text > 8<<20 {
			return nil, failure(EvidenceLimit)
		}
		delim, compound := token.(json.Delim)
		if !compound {
			return token, nil
		}
		switch delim {
		case '[':
			items := []any{}
			for d.More() {
				if len(items) >= arrayLimit(depth, field) {
					return nil, failure(EvidenceLimit)
				}
				v, err := read(depth+1, field)
				if err != nil {
					return nil, err
				}
				items = append(items, v)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, failure(InvalidEvidence)
			}
			return items, nil
		case '{':
			object := map[string]any{}
			folds := map[string]bool{}
			for d.More() {
				if len(object) >= 32 || nodes >= 120000 {
					return nil, failure(EvidenceLimit)
				}
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || folds[strings.ToLower(name)] {
					return nil, failure(InvalidEvidence)
				}
				nodes++
				text += len(name)
				if text > 8<<20 {
					return nil, failure(EvidenceLimit)
				}
				folds[strings.ToLower(name)] = true
				value, err := read(depth+1, name)
				if err != nil {
					return nil, err
				}
				object[name] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, failure(InvalidEvidence)
			}
			return object, nil
		default:
			return nil, failure(InvalidEvidence)
		}
	}
	v, err := read(0, "")
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, failure(InvalidEvidence)
	}
	return v, nil
}
