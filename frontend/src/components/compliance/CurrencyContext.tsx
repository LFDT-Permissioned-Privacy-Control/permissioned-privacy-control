import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { complianceApi } from '@/api/compliance';
import type { CurrencyInfo } from '@/types/compliance';

interface CurrencyContextType {
  currency: string;
  currencyInfo: CurrencyInfo | null;
  allCurrencies: CurrencyInfo[];
  setCurrency: (code: string) => Promise<void>;
  formatAmount: (amount: number) => string;
  currencyLabel: string; // e.g. "USD", "EUR"
  loading: boolean;
  coingeckoEnabled: boolean;
  // canEdit is true when a specific org is in scope. Currency is a per-org
  // setting (RD-1158) that a tier-2 org admin owns, so it is editable per org
  // and read-only when no org is selected (e.g. the system Token Prices view).
  canEdit: boolean;
}

const CurrencyContext = createContext<CurrencyContextType | null>(null);

const DEFAULT_CURRENCY_INFO: CurrencyInfo = { code: 'usd', name: 'US Dollar', symbol: '$' };

export function CurrencyProvider({ orgId, children }: { orgId?: string; children: React.ReactNode }) {
  const [currency, setCurrencyState] = useState('usd');
  const [allCurrencies, setAllCurrencies] = useState<CurrencyInfo[]>([DEFAULT_CURRENCY_INFO]);
  const [loading, setLoading] = useState(true);
  const [coingeckoEnabled, setCoingeckoEnabled] = useState(true);

  // The set of supported currencies + the coingecko flag are cluster-wide
  // metadata (fetched from the global endpoint). The *selected* currency is
  // per-org (RD-1158) and read from the org's compliance config. When no org
  // is in scope we display the global default for context only (read-only).
  const loadMetadata = useCallback(async () => {
    try {
      const { data } = await complianceApi.currency.get();
      if (data.all_currencies?.length) setAllCurrencies(data.all_currencies);
      setCoingeckoEnabled(data.coingecko_enabled ?? true);
      if (!orgId) setCurrencyState(data.currency || 'usd');
    } catch {
      // Fall back to USD metadata.
    }
  }, [orgId]);

  const loadOrgCurrency = useCallback(async () => {
    if (!orgId) return;
    try {
      const { data } = await complianceApi.config.get(orgId);
      setCurrencyState(data.currency || 'usd');
    } catch {
      setCurrencyState('usd');
    }
  }, [orgId]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([loadMetadata(), loadOrgCurrency()]).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [loadMetadata, loadOrgCurrency]);

  const setCurrency = useCallback(async (code: string) => {
    if (!orgId) {
      // No org in scope: currency is per-org and cannot be set globally from
      // the dashboard (the global default is an operator/API action).
      throw new Error('Select an organization to change its currency');
    }
    // Per-org currency is a field on the org's compliance config; partial
    // update — only the currency changes.
    await complianceApi.config.update(orgId, { currency: code });
    setCurrencyState(code);
  }, [orgId]);

  const currencyInfo = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;

  const formatAmount = useCallback((amount: number) => {
    const info = allCurrencies.find(c => c.code === currency) || DEFAULT_CURRENCY_INFO;
    return `${info.symbol}${amount.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
  }, [currency, allCurrencies]);

  const currencyLabel = currency.toUpperCase();

  return (
    <CurrencyContext.Provider value={{ currency, currencyInfo, allCurrencies, setCurrency, formatAmount, currencyLabel, loading, coingeckoEnabled, canEdit: !!orgId }}>
      {children}
    </CurrencyContext.Provider>
  );
}

// reason: useCurrency is the consumer hook for CurrencyProvider, intentionally
// co-located with it. Cost of co-location is full reload (not HMR) when editing
// this file; acceptable for this admin/compliance widget.
// eslint-disable-next-line react-refresh/only-export-components
export function useCurrency() {
  const context = useContext(CurrencyContext);
  if (!context) {
    throw new Error('useCurrency must be used within CurrencyProvider');
  }
  return context;
}
