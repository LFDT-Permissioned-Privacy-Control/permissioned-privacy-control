import api from './client';
import type {
  ComplianceConfig,
  UpdateComplianceConfigInput,
  TokenPrice,
  UpsertTokenPriceInput,
  SystemTokenPrice,
  TravelRuleRecord,
  CreateTravelRuleRecordInput,
  SanctionedAddress,
  AddSanctionedAddressInput,
  AddressThresholdOverride,
  UpsertAddressThresholdInput,
  ComplianceLog,
  ComplianceLogFilters,
  PaginatedResponse,
  CurrencyConfig,
} from '../types/compliance';

export const complianceApi = {
  config: {
    get: (orgId: string) =>
      api.get<ComplianceConfig>(`/orgs/${orgId}/compliance/config`),
    update: (orgId: string, input: UpdateComplianceConfigInput) =>
      api.put<ComplianceConfig>(`/orgs/${orgId}/compliance/config`, input),
  },

  tokens: {
    list: (orgId: string) =>
      api.get<{ data: TokenPrice[] }>(`/orgs/${orgId}/compliance/tokens`),
    upsert: (orgId: string, tokenAddress: string, input: UpsertTokenPriceInput) =>
      api.put<TokenPrice>(`/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`, input),
    delete: (orgId: string, tokenAddress: string) =>
      api.delete(`/orgs/${orgId}/compliance/tokens/${encodeURIComponent(tokenAddress)}`),
  },

  systemPrices: {
    list: () =>
      api.get<{ data: SystemTokenPrice[] }>('/compliance/system-token-prices'),
  },

  travelRules: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<TravelRuleRecord>>(`/orgs/${orgId}/compliance/travel-rule-records`, { params }),
    create: (orgId: string, input: CreateTravelRuleRecordInput) =>
      api.post<TravelRuleRecord & { warning?: string }>(`/orgs/${orgId}/compliance/travel-rule-records`, input),
    delete: (orgId: string, recordId: string) =>
      api.delete(`/orgs/${orgId}/compliance/travel-rule-records/${recordId}`),
  },

  addressThresholds: {
    list: (orgId: string, params?: { limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<AddressThresholdOverride>>(`/orgs/${orgId}/compliance/address-thresholds`, { params }),
    upsert: (orgId: string, address: string, input: UpsertAddressThresholdInput) =>
      api.put<AddressThresholdOverride>(`/orgs/${orgId}/compliance/address-thresholds/${encodeURIComponent(address)}`, input),
    delete: (orgId: string, address: string) =>
      api.delete(`/orgs/${orgId}/compliance/address-thresholds/${encodeURIComponent(address)}`),
  },

  sanctions: {
    list: (params?: { org_id?: string; limit?: number; offset?: number }) =>
      api.get<PaginatedResponse<SanctionedAddress>>('/compliance/sanctions', { params }),
    add: (input: AddSanctionedAddressInput) =>
      api.post<SanctionedAddress>('/compliance/sanctions', input),
    remove: (id: string) =>
      api.delete(`/compliance/sanctions/${id}`),
  },

  logs: {
    list: (orgId: string, params?: ComplianceLogFilters) =>
      api.get<PaginatedResponse<ComplianceLog>>(`/orgs/${orgId}/compliance/logs`, { params }),
  },

  currency: {
    get: () =>
      api.get<CurrencyConfig>('/compliance/currency'),
    set: (currency: string, force?: boolean) =>
      api.put<{ currency: string; message: string; warning?: string; affected_tokens?: Array<{ org_id: string; token_address: string; symbol: string }> }>('/compliance/currency', { currency, force }),
  },

};
