package quotefeed

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"privacy-proxy/internal/admission"
)

const MaxBodyBytes = 1 << 20

// Bound lexemes before encoding/json allocates decoded keys/numbers. JSON's own
// tokenizer remains responsible for grammar, escapes and primitive types.
func boundedLexemes(raw []byte) bool {
	if len(raw) > MaxBodyBytes || !utf8.Valid(raw) {
		return false
	}
	depth := 0
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '"':
			start := i
			i++
			closed := false
			for i < len(raw) {
				if i-start+1 > 604 {
					return false
				}
				if raw[i] == '"' {
					closed = true
					break
				}
				if raw[i] == '\\' {
					i++
					if i >= len(raw) {
						return false
					}
				}
				i++
			}
			if !closed || i-start+1 > 604 {
				return false
			}
		case '{', '[':
			depth++
			if depth > 8 {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		default:
			if raw[i] == '-' || raw[i] >= '0' && raw[i] <= '9' {
				start := i
				for i+1 < len(raw) {
					c := raw[i+1]
					if c == 'e' || c == 'E' || c == '+' || c == '-' || c == '.' || c >= '0' && c <= '9' {
						i++
					} else {
						break
					}
				}
				if i-start+1 > 128 {
					return false
				}
			}
		}
	}
	return depth == 0
}

func parseBatch(raw []byte, ids, currencies []string, observed time.Time, source string) ([]admission.Quote, error) {
	if observed.IsZero() || len(ids) == 0 || len(ids) > 512 || len(currencies) == 0 || len(currencies) > 5 || !boundedLexemes(raw) {
		return nil, ErrResponse
	}
	allowedIDs := make(map[string]bool, len(ids))
	for _, id := range ids {
		allowedIDs[id] = true
	}
	allowedCurrencies := make(map[string]bool, len(currencies))
	for _, c := range currencies {
		allowedCurrencies[c] = true
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrResponse
	}
	seen := make(map[string]bool, len(ids))
	out := make([]admission.Quote, 0, len(ids)*len(currencies))
	for d.More() {
		if len(seen) >= len(ids) {
			return nil, ErrResponse
		}
		token, err := d.Token()
		id, ok := token.(string)
		if err != nil || !ok || len(id) > 100 || !allowedIDs[id] || seen[id] {
			return nil, ErrResponse
		}
		seen[id] = true
		if token, err := d.Token(); err != nil || token != json.Delim('{') {
			return nil, ErrResponse
		}
		fields := make(map[string]bool, len(currencies)+1)
		prices := make(map[string]float64, len(currencies))
		var asOf int64
		for d.More() {
			if len(fields) >= len(currencies)+1 {
				return nil, ErrResponse
			}
			token, err := d.Token()
			key, ok := token.(string)
			if err != nil || !ok || len(key) > 32 || fields[key] || key != "last_updated_at" && !allowedCurrencies[key] {
				return nil, ErrResponse
			}
			fields[key] = true
			value, err := d.Token()
			if err != nil {
				return nil, ErrResponse
			}
			if value == nil {
				continue
			}
			number, ok := value.(json.Number)
			if !ok || len(number) > 128 {
				return nil, ErrResponse
			}
			if key == "last_updated_at" {
				at, err := strconv.ParseInt(string(number), 10, 64)
				if err != nil || at <= 0 || strconv.FormatInt(at, 10) != string(number) || at > observed.Unix() {
					return nil, ErrResponse
				}
				asOf = at
			} else {
				v, err := strconv.ParseFloat(string(number), 64)
				if err == nil && v > 0 && v < 1e12 && !math.IsInf(v, 0) && !math.IsNaN(v) {
					prices[key] = v
				}
			}
		}
		if token, err := d.Token(); err != nil || token != json.Delim('}') {
			return nil, ErrResponse
		}
		if asOf == 0 {
			continue
		}
		for _, currency := range currencies {
			if value, ok := prices[currency]; ok {
				out = append(out, admission.Quote{ID: id, Currency: currency, Value: value, FetchedAt: observed, ProviderAsOf: time.Unix(asOf, 0).UTC(), SourceID: source})
			}
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrResponse
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrResponse
	}
	return out, nil
}
