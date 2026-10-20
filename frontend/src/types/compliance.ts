export type TransferType = 'eth' | 'erc20';
export type Decision = 'allowed' | 'denied';
// EnforcementMode: 'enforce' blocks violations (default); 'monitor' allows them
// but records a would-have-blocked entry. Sanctions stay blocked in both. (RD-1044)
export type EnforcementMode = 'enforce' | 'monitor';

export interface ComplianceConfig {
  id: string;
  org_id: string;
  enabled: boolean;
  threshold_fiat: number;
  // Per-org fiat currency (RD-1158) that threshold_fiat is denominated in and
  // that transfers are valued against. usd/eur/chf/gbp/aed.
  currency: string;
  unknown_price_policy: 'allowed' | 'forbidden';
  enforcement_mode: EnforcementMode;
  created_at: string;
  updated_at: string;
}

export interface UpdateComplianceConfigInput {
  enabled?: boolean;
  threshold_fiat?: number;
  currency?: string;
  unknown_price_policy?: 'allowed' | 'forbidden';
  enforcement_mode?: EnforcementMode;
}

export interface TokenPrice {
  id: string;
  org_id: string;
  token_address: string;
  symbol: string;
  decimals: number;
  price_fiat: number;
  prices_by_currency?: Record<string, number>;
  coingecko_id?: string;
  updated_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface UpsertTokenPriceInput {
  symbol: string;
  decimals: number;
  prices?: Record<string, number>;  // e.g. {"usd": 42.50, "eur": 39.00}
  coingecko_id?: string | null;
}

export interface CurrencySwitchConflict {
  error: string;
  affected_tokens: Array<{
    org_id: string;
    token_address: string;
    symbol: string;
  }>;
  currency: string;
}

export interface SystemTokenPrice {
  id: number;
  coingecko_id?: string;
  source: string;
  token_address?: string;
  symbol: string;
  decimals: number;
  price_fiat: number;
  updated_at: string;
  is_stale: boolean;
}

export interface TravelRuleRecord {
  id: string;
  org_id: string;
  originator_user_id: string;
  originator_external_id?: string;
  originator_data: Record<string, unknown>;
  beneficiary_data: Record<string, unknown>;
  transfer_type: TransferType;
  token_address?: string;
  beneficiary_address: string;
  amount_wei: string;
  amount_fiat: number;
  currency: string;
  expires_at: string;
  used_at?: string;
  used_tx_hash?: string;
  created_at: string;
}

export interface CreateTravelRuleRecordInput {
  originator_user_id: string;
  originator_data: Record<string, unknown>;
  beneficiary_data: Record<string, unknown>;
  transfer_type: TransferType;
  token_address?: string;
  beneficiary_address: string;
  amount_wei: string;
}

export interface SanctionedAddress {
  id: string;
  org_id?: string;
  address: string;
  reason: string;
  source?: string;
  added_by_user_id?: string;
  created_at: string;
  updated_at: string;
}

export interface AddSanctionedAddressInput {
  org_id?: string;
  address: string;
  reason: string;
  source?: string;
}

export interface ComplianceLog {
  id: number;
  org_id: string;
  user_id: string;
  user_external_id?: string;
  transfer_type: TransferType;
  token_address?: string;
  from_address: string;
  to_address: string;
  amount_wei: string;
  amount_fiat?: number;
  threshold_fiat?: number;
  currency?: string;
  decision: Decision;
  denial_reason?: string;
  // would_block marks a monitor-mode violation: decision='allowed' but it would
  // have been blocked under enforce mode; denial_reason carries the reason. (RD-1044)
  would_block?: boolean;
  travel_rule_record_id?: string;
  created_at: string;
}

export interface AddressThresholdOverride {
  id: string;
  org_id: string;
  address: string;
  threshold_fiat: number;
  note?: string;
  created_at: string;
  updated_at: string;
}

export interface UpsertAddressThresholdInput {
  threshold_fiat: number;
  note?: string;
}

export interface ComplianceLogFilters {
  user_search?: string;
  decision?: Decision;
  transfer_type?: TransferType;
  limit?: number;
  offset?: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  limit: number;
  offset: number;
}

export type SupportedCurrency = 'usd' | 'eur' | 'chf' | 'gbp' | 'aed';

export interface CurrencyInfo {
  code: string;
  name: string;
  symbol: string;
}

export interface CurrencyConfig {
  currency: string;
  all_currencies: CurrencyInfo[];
  coingecko_enabled: boolean;
}

