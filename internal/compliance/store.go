package compliance

import "context"

// Store defines database operations for travel rule compliance.
type Store interface {
	// Compliance config
	GetComplianceConfig(ctx context.Context, orgID string) (*ComplianceConfig, error)
	UpsertComplianceConfig(ctx context.Context, config *ComplianceConfig) error

	// Token pricing
	GetTokenPrice(ctx context.Context, orgID, tokenAddress string) (*TokenPrice, error)
	UpsertTokenPrice(ctx context.Context, price *TokenPrice, activeCurrency string) error
	DeleteTokenPrice(ctx context.Context, orgID, tokenAddress string) error
	ListTokenPrices(ctx context.Context, orgID string) ([]*TokenPrice, error)
	ListAllManualTokenPrices(ctx context.Context) ([]*TokenPrice, error)

	// System token prices (CoinGecko cache)
	GetSystemTokenPrice(ctx context.Context, coingeckoID string) (*SystemTokenPrice, error)
	UpsertSystemTokenPrice(ctx context.Context, price *SystemTokenPrice) error
	ListSystemTokenPrices(ctx context.Context) ([]*SystemTokenPrice, error)

	// Travel rule records
	CreateTravelRuleRecord(ctx context.Context, record *TravelRuleRecord) error
	GetTravelRuleRecord(ctx context.Context, id string) (*TravelRuleRecord, error)
	FindUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*TravelRuleRecord, error)
	// ClaimUnusedTravelRuleRecord atomically finds an unused record and marks it as used.
	// This prevents TOCTOU race conditions where two concurrent requests could claim the same record.
	// Only matches records where amount_fiat >= amountFiat (record must cover the transfer value).
	ClaimUnusedTravelRuleRecord(ctx context.Context, orgID, userID, beneficiaryAddr, tokenAddr string, amountFiat float64) (*TravelRuleRecord, error)
	MarkTravelRuleRecordUsed(ctx context.Context, id string, txHash *string) error
	DeleteTravelRuleRecord(ctx context.Context, orgID, id string) error
	ListTravelRuleRecords(ctx context.Context, orgID string, limit, offset int) ([]*TravelRuleRecord, int, error)
	CleanupExpiredRecords(ctx context.Context) (int64, error)

	// Address threshold overrides
	GetAddressThresholdOverride(ctx context.Context, orgID, address string) (*AddressThresholdOverride, error)
	ListAddressThresholdOverrides(ctx context.Context, orgID string, limit, offset int) ([]*AddressThresholdOverride, int, error)
	UpsertAddressThresholdOverride(ctx context.Context, override *AddressThresholdOverride) error
	DeleteAddressThresholdOverride(ctx context.Context, orgID, address string) error

	// Sanctioned addresses
	IsAddressSanctioned(ctx context.Context, orgID, address string) (bool, error)
	AddSanctionedAddress(ctx context.Context, sanction *SanctionedAddress) error
	RemoveSanctionedAddress(ctx context.Context, id string) error
	GetSanctionedAddress(ctx context.Context, id string) (*SanctionedAddress, error)
	ListSanctionedAddresses(ctx context.Context, orgID *string, limit, offset int) ([]*SanctionedAddress, int, error)

	// Compliance logs
	CreateComplianceLog(ctx context.Context, log *ComplianceLog) (int64, error)
	GetComplianceLog(ctx context.Context, id int64) (*ComplianceLog, error)
	ListComplianceLogs(ctx context.Context, orgID string, filters *ComplianceLogFilters) ([]*ComplianceLog, int, error)

	// System settings
	GetSystemSetting(ctx context.Context, key string) (string, error)
	SetSystemSetting(ctx context.Context, key, value string) error

}
