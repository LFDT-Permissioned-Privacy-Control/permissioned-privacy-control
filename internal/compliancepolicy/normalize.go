package compliancepolicy

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"privacy-proxy/internal/compliance"
	"sort"
	"strings"
)

func NormalizeSpec(s *SourceSpec) error {
	if err := compliance.ValidatePolicySettings(compliance.ComplianceConfig{Enabled: s.Settings.Enabled, ThresholdFiat: s.Settings.ThresholdFiat, Currency: s.Settings.Currency, UnknownPricePolicy: compliance.UnknownPricePolicy(s.Settings.UnknownPricePolicy), EnforcementMode: compliance.EnforcementMode(s.Settings.EnforcementMode)}); err != nil {
		return err
	}
	ids, addresses := map[string]bool{}, map[string]bool{}
	for _, row := range s.AddressThresholds {
		if !canonicalUUID(row.ID) || ids[row.ID] || !canonicalAddress(row.Address) || addresses[row.Address] || !compliance.ExactThreshold(row.ThresholdFiat) || len(row.Note) > 4096 {
			return fmt.Errorf("invalid or duplicate address threshold")
		}
		ids[row.ID], addresses[row.Address] = true, true
	}
	addresses = map[string]bool{}
	for _, row := range s.TokenPrices {
		if !canonicalUUID(row.ID) || ids[row.ID] || (row.TokenAddress != "native" && !canonicalAddress(row.TokenAddress)) || addresses[row.TokenAddress] || row.Decimals < 0 || row.Decimals > 255 || len(row.Symbol) == 0 || len(row.Symbol) > 20 || len(row.CoingeckoID) > 100 || strings.TrimSpace(row.CoingeckoID) != row.CoingeckoID {
			return fmt.Errorf("invalid or duplicate token price")
		}
		ids[row.ID], addresses[row.TokenAddress] = true, true
		for currency, price := range row.PricesByCurrency {
			if !compliance.IsValidCurrency(currency) || !compliance.FiniteNonnegative(price) || price >= 1e12 {
				return fmt.Errorf("invalid manual token price")
			}
		}
	}
	sort.Slice(s.AddressThresholds, func(i, j int) bool { return s.AddressThresholds[i].ID < s.AddressThresholds[j].ID })
	sort.Slice(s.TokenPrices, func(i, j int) bool { return s.TokenPrices[i].ID < s.TokenPrices[j].ID })
	return nil
}

func canonicalUUID(s string) bool {
	u, e := uuid.Parse(s)
	return e == nil && u != uuid.Nil && u.String() == s
}
func canonicalAddress(s string) bool {
	return len(s) == 42 && strings.ToLower(s) == s && common.IsHexAddress(s)
}
