package admission

import (
	"math"
	"strconv"
)

// CanonicalFiat preserves the checker's float64 value as its shortest round-trip
// decimal. NUMERIC storage neither adds precision nor imposes cent rounding.
func CanonicalFiat(value float64) (string, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value >= 1e100 {
		return "", ErrInvalid
	}
	if value == 0 {
		return "0", nil
	}
	raw := strconv.FormatFloat(value, 'g', -1, 64)
	if len(raw) > 128 {
		return "", ErrInvalid
	}
	return raw, nil
}
func ParseFiat(raw string) (float64, error) {
	if len(raw) == 0 || len(raw) > 128 {
		return 0, ErrInvalid
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, ErrInvalid
	}
	if _, err := CanonicalFiat(v); err != nil {
		return 0, err
	}
	return v, nil
}
