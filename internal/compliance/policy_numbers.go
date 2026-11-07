package compliance

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
)

func FiniteNonnegative(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) && v >= 0 }

// Threshold columns are NUMERIC(20,2). Reject source values PostgreSQL would
// silently round; multiplying the binary float by 100 would incorrectly reject
// ordinary exact decimal inputs such as 0.29.
func ExactThreshold(v float64) bool {
	if !FiniteNonnegative(v) || v >= 1e18 {
		return false
	}
	text := strconv.FormatFloat(v, 'f', -1, 64)
	point := strings.IndexByte(text, '.')
	return point < 0 || len(text)-point-1 <= 2
}

// Existing compliance runtime models use float64. Preserve the authored decimal
// through their JSON round trip instead of silently accepting more precision
// than those models can carry. Prices remain JSON decimals, not 8-place values;
// only their backing price_fiat integer range is constrained above.
func ValidateWireNumbers(value any) error {
	switch value := value.(type) {
	case json.Number:
		if len(value.String()) > 128 {
			return fmt.Errorf("compliance number exceeds supported decimal precision")
		}
		v, err := value.Float64()
		if err != nil || !FiniteNonnegative(v) {
			return fmt.Errorf("invalid compliance number")
		}
		if v == 0 {
			// Reject underflow without constructing a rational with an attacker-
			// chosen huge exponent. Arbitrarily spelled numeric zero needs no power.
			mantissa := strings.FieldsFunc(value.String(), func(r rune) bool { return r == 'e' || r == 'E' })[0]
			if strings.ContainsAny(mantissa, "123456789") {
				return fmt.Errorf("compliance number exceeds supported decimal precision")
			}
			return nil
		}
		a, ok := new(big.Rat).SetString(value.String())
		b, projected := new(big.Rat).SetString(strconv.FormatFloat(v, 'g', -1, 64))
		if !ok || !projected || a.Cmp(b) != 0 {
			return fmt.Errorf("compliance number exceeds supported decimal precision")
		}
	case map[string]any:
		for _, child := range value {
			if err := ValidateWireNumbers(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range value {
			if err := ValidateWireNumbers(child); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidatePolicySettings(c ComplianceConfig) error {
	if !ExactThreshold(c.ThresholdFiat) || !IsValidCurrency(c.Currency) || (c.UnknownPricePolicy != UnknownPriceAllowed && c.UnknownPricePolicy != UnknownPriceForbidden) || !IsValidEnforcementMode(c.EnforcementMode) {
		return fmt.Errorf("invalid compliance settings")
	}
	return nil
}
