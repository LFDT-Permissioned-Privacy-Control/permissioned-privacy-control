package compliance

import (
	"math/big"
	"time"
)

// SupportedCurrency represents a fiat currency code.
type SupportedCurrency string

const (
	CurrencyUSD SupportedCurrency = "usd"
	CurrencyEUR SupportedCurrency = "eur"
	CurrencyCHF SupportedCurrency = "chf"
	CurrencyGBP SupportedCurrency = "gbp"
	CurrencyAED SupportedCurrency = "aed"
)

// ValidCurrencies maps currency codes to their display names.
var ValidCurrencies = map[SupportedCurrency]string{
	CurrencyUSD: "US Dollar",
	CurrencyEUR: "Euro",
	CurrencyCHF: "Swiss Franc",
	CurrencyGBP: "British Pound",
	CurrencyAED: "UAE Dirham",
}

// CurrencySymbols maps currency codes to their display symbols.
var CurrencySymbols = map[SupportedCurrency]string{
	CurrencyUSD: "$",
	CurrencyEUR: "€",
	CurrencyCHF: "CHF ",
	CurrencyGBP: "£",
	CurrencyAED: "AED ",
}

// IsValidCurrency returns true if the given currency is supported.
func IsValidCurrency(c string) bool {
	_, ok := ValidCurrencies[SupportedCurrency(c)]
	return ok
}

// WeiToFiat converts a wei amount to fiat given the token decimals and price.
func WeiToFiat(amountWei *big.Int, decimals int, priceFiat float64) (float64, error) {
	return WeiToUSD(amountWei, decimals, priceFiat)
}

// TransferType indicates the type of value transfer.
type TransferType string

const (
	TransferTypeETH   TransferType = "eth"
	TransferTypeERC20 TransferType = "erc20"
)

// UnknownPricePolicy indicates the policy when a token price is unknown.
type UnknownPricePolicy string

const (
	UnknownPriceAllowed   UnknownPricePolicy = "allowed"
	UnknownPriceForbidden UnknownPricePolicy = "forbidden"
)

// EnforcementMode selects how the compliance pipeline reacts to a violation.
//
//   - EnforcementEnforce (default): a violation BLOCKS the transaction
//     (fail-closed). This is the only safe default; new orgs and the
//     compliance_config column default both resolve to it.
//   - EnforcementMonitor: a would-block violation is ALLOWED to proceed but
//     is recorded in the compliance audit log with would_block=true plus the
//     real reason. Intended for phased rollout / observation periods, or
//     deployments that want compliance visibility without hard enforcement.
//
// IMPORTANT — sanctions are NOT monitor-eligible (RD-1044). A transfer that
// touches a sanctioned address stays hard-blocked even under monitor mode;
// only threshold-breach, travel-rule-record-required, and unknown-price
// violations are monitored. Relaxing the sanctions carve-out is a
// Compliance/Legal decision, not an engineering one.
type EnforcementMode string

const (
	EnforcementEnforce EnforcementMode = "enforce"
	EnforcementMonitor EnforcementMode = "monitor"
)

// IsValidEnforcementMode reports whether s is a recognised enforcement mode.
func IsValidEnforcementMode(s EnforcementMode) bool {
	return s == EnforcementEnforce || s == EnforcementMonitor
}

// ComplianceConfig stores per-org compliance settings.
type ComplianceConfig struct {
	ID                 string             `json:"id"`
	OrgID              string             `json:"org_id"`
	Enabled            bool               `json:"enabled"`
	ThresholdFiat      float64            `json:"threshold_fiat"`
	// Currency is the per-org fiat currency (usd/eur/chf/gbp/aed) that
	// threshold_fiat is denominated in and that transfers are valued against
	// (RD-1158). Per-org so one org's currency choice can never fail-close
	// another org. An empty value resolves to the global base_currency setting,
	// then to "usd" (see Server.orgCurrency).
	Currency           string             `json:"currency"`
	UnknownPricePolicy UnknownPricePolicy `json:"unknown_price_policy"`
	// EnforcementMode is enforce (block, default) or monitor (allow + record)
	// for monitor-eligible violations. An empty value resolves to the cluster
	// default (COMPLIANCE_DEFAULT_MODE), which itself defaults to enforce.
	EnforcementMode    EnforcementMode    `json:"enforcement_mode"`
	CreatedAt          time.Time          `json:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

// TokenPrice stores admin-configured fiat valuation for a token.
type TokenPrice struct {
	ID               string             `json:"id"`
	OrgID            string             `json:"org_id"`
	TokenAddress     string             `json:"token_address"` // "native" for ETH, or lowercase 0x-prefixed contract address
	Symbol           string             `json:"symbol"`
	Decimals         int                `json:"decimals"`
	PriceFiat        float64            `json:"price_fiat"`          // price in the active base currency
	PricesByCurrency map[string]float64 `json:"prices_by_currency"` // all manually-set currency prices
	CoingeckoID      *string            `json:"coingecko_id,omitempty"` // when set, price resolves from system_token_prices
	UpdatedByUserID  *string            `json:"updated_by_user_id,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// SystemTokenPrice is a global price cache entry populated by CoinGecko.
type SystemTokenPrice struct {
	ID                int                `json:"id"`
	CoingeckoID       *string            `json:"coingecko_id,omitempty"`
	Symbol            string             `json:"symbol"`
	Decimals          int                `json:"decimals"`
	PriceFiat         float64            `json:"price_fiat"`          // price in the active base currency
	Source            string             `json:"source"`
	TokenAddress      *string            `json:"token_address,omitempty"`
	PricesByCurrency  map[string]float64 `json:"prices_by_currency"` // all fetched currency prices
	UpdatedAt         time.Time          `json:"updated_at"`
}

// TravelRuleRecord stores IVMS101 compliance data submitted before a transfer.
type TravelRuleRecord struct {
	ID                   string                 `json:"id"`
	OrgID                string                 `json:"org_id"`
	OriginatorUserID     string                 `json:"originator_user_id"`
	OriginatorExternalID string                 `json:"originator_external_id,omitempty"`
	OriginatorData     map[string]any `json:"originator_data"`
	BeneficiaryData    map[string]any `json:"beneficiary_data"`
	TransferType       TransferType           `json:"transfer_type"`
	TokenAddress       *string                `json:"token_address,omitempty"`
	BeneficiaryAddress string                 `json:"beneficiary_address"`
	AmountWei          string                 `json:"amount_wei"`
	AmountFiat         float64                `json:"amount_fiat"`
	Currency           string                 `json:"currency"`
	ExpiresAt          time.Time              `json:"expires_at"`
	UsedAt             *time.Time             `json:"used_at,omitempty"`
	UsedTxHash         *string                `json:"used_tx_hash,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	Warning            string                 `json:"warning,omitempty"` // non-persisted, advisory only
}

// SanctionedAddress is a blocklisted address (global or per-org).
type SanctionedAddress struct {
	ID            string    `json:"id"`
	OrgID         *string   `json:"org_id,omitempty"` // nil = global
	Address       string    `json:"address"`
	Reason        string    `json:"reason"`
	Source        string    `json:"source,omitempty"`
	AddedByUserID *string   `json:"added_by_user_id,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ComplianceLog is an immutable record of a compliance decision.
type ComplianceLog struct {
	ID                 int64        `json:"id"`
	OrgID              string       `json:"org_id"`
	UserID             string       `json:"user_id"`
	UserExternalID     string       `json:"user_external_id,omitempty"`
	TransferType       TransferType `json:"transfer_type"`
	TokenAddress       *string      `json:"token_address,omitempty"`
	FromAddress        string       `json:"from_address"`
	ToAddress          string       `json:"to_address"`
	AmountWei          string       `json:"amount_wei"`
	AmountFiat         *float64     `json:"amount_fiat,omitempty"`
	ThresholdFiat      *float64     `json:"threshold_fiat,omitempty"`
	Currency           string       `json:"currency,omitempty"`
	Decision           string       `json:"decision"` // "allowed" or "denied"
	DenialReason       *string      `json:"denial_reason,omitempty"`
	// WouldBlock marks a monitor-mode violation: the transfer was allowed to
	// proceed (Decision="allowed") but WOULD have been blocked under enforce
	// mode. DenialReason carries the would-have-blocked reason. Lets auditors
	// distinguish a monitored violation from a genuinely-compliant allow.
	WouldBlock         bool         `json:"would_block"`
	TravelRuleRecordID *string      `json:"travel_rule_record_id,omitempty"`
	CorrelationID      string       `json:"correlation_id,omitempty"`
	CreatedAt          time.Time    `json:"created_at"`
}

// AddressThresholdOverride stores per-address threshold overrides for risk-based compliance.
// When set, the address-specific threshold takes precedence over the org-level threshold.
type AddressThresholdOverride struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	Address       string    `json:"address"` // lowercased 0x-prefixed
	ThresholdFiat float64   `json:"threshold_fiat"`
	Note          string    `json:"note,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ComplianceLogFilters for querying compliance logs.
type ComplianceLogFilters struct {
	UserSearch   *string
	Decision     *string
	TransferType *TransferType
	Limit        int
	Offset       int
}

