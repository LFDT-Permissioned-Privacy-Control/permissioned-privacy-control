package disclosurepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"privacy-proxy/internal/strictjson"
)

var ErrInvalid = errors.New("invalid disclosure source or scope")

func strictValue(raw []byte, maximum, depth int) (any, error) {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := strictjson.ReadValue(d, 0, depth)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	return v, nil
}

func Decode(raw []byte, limits Limits) (Source, error) {
	var result Source
	if !limits.Valid() {
		return result, ErrInvalid
	}
	value, err := strictValue(raw, limits.MaxDocumentBytes, limits.MaxJSONDepth)
	if err != nil {
		return result, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return result, ErrInvalid
	}
	rules, ok := object["rules"].([]any)
	if !ok || len(rules) > limits.MaxRules {
		return result, ErrInvalid
	}
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			return result, ErrInvalid
		}
		viewers, _ := rule["viewers"].(map[string]any)
		targets, _ := rule["targets"].(map[string]any)
		addresses, _ := rule["addresses"].(map[string]any)
		for _, field := range []struct {
			value any
			max   int
		}{{viewers["groups"], limits.MaxGroups}, {viewers["actors"], limits.MaxActors}, {targets["actors"], limits.MaxActors}, {addresses["values"], limits.MaxAddresses}, {rule["resources"], 7}} {
			list, ok := field.value.([]any)
			if !ok || len(list) > field.max {
				return result, ErrInvalid
			}
		}
	}
	if err := strictjson.ExactDecode(value, &result); err != nil {
		return Source{}, ErrInvalid
	}
	return result, nil
}

// DecodeScope also validates values and normalizes sets. It is suitable for
// untrusted stored JSON as well as API input; it accepts no omitted/null fields.
func DecodeScope(raw []byte, limits Limits) (Scope, error) {
	if !limits.Valid() {
		return Scope{}, ErrInvalid
	}
	value, err := strictValue(raw, 96<<10, 16)
	if err != nil {
		return Scope{}, err
	}
	var scope Scope
	if err := strictjson.ExactDecode(value, &scope); err != nil {
		return Scope{}, ErrInvalid
	}
	return NormalizeScope(scope, limits)
}
