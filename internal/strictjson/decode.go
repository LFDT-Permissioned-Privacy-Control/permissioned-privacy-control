// Package strictjson parses bounded source JSON without duplicate keys or
// case-insensitive struct aliases. Domain validation belongs to its callers.
package strictjson

import (
	"encoding/json"
	"fmt"
)

// Parse with tokens first: encoding/json alone accepts duplicate keys and
// case-insensitive field aliases, neither of which belongs in reviewed source.
func ReadValue(d *json.Decoder, depth, maxDepth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("document nesting is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid document JSON")
	}
	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("invalid object key")
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			value, err := ReadValue(d, depth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, fmt.Errorf("invalid object")
		}
		return object, nil
	case '[':
		items := []any{}
		for d.More() {
			value, err := ReadValue(d, depth+1, maxDepth)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		if _, err := d.Token(); err != nil {
			return nil, fmt.Errorf("invalid array")
		}
		return items, nil
	default:
		return nil, fmt.Errorf("invalid JSON delimiter")
	}
}
