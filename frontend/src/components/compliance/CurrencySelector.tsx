import { useState } from 'react';
import { Loader2, AlertCircle } from 'lucide-react';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useCurrency } from './CurrencyContext';

export default function CurrencySelector() {
  const { currency, allCurrencies, setCurrency, currencyInfo, loading, canEdit } = useCurrency();
  const [switching, setSwitching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleChange = async (code: string) => {
    if (code === currency) return;
    setSwitching(true);
    setError(null);
    try {
      await setCurrency(code);
    } catch (err) {
      // Surface the failure instead of silently reverting (the old behaviour
      // swallowed the error, so the control just "blinked" back to the prior
      // currency with no explanation).
      const axiosErr = err as { response?: { data?: { error?: string } } };
      setError(axiosErr?.response?.data?.error || 'Failed to change currency');
    } finally {
      setSwitching(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-[#94A3B8]">
        <Loader2 className="w-4 h-4 animate-spin" />
        <span className="text-sm">Currency...</span>
      </div>
    );
  }

  // Currency is a per-org setting (RD-1158): editable when an org is in scope,
  // read-only otherwise (e.g. the system Token Prices view with no org).
  if (!canEdit) {
    return (
      <div className="flex items-center gap-2" data-testid="currency-selector">
        <span className="text-sm text-[#6B7280]">Currency:</span>
        <span className="text-sm font-medium">
          {currencyInfo?.symbol} {currency.toUpperCase()}
        </span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-[#6B7280]">Currency:</span>
      <Select value={currency} onValueChange={handleChange} disabled={switching}>
        <SelectTrigger className="w-[140px] h-8 text-sm" data-testid="currency-selector">
          <SelectValue>
            {switching ? (
              <span className="flex items-center gap-1.5">
                <Loader2 className="w-3 h-3 animate-spin" />
                <span>Switching...</span>
              </span>
            ) : (
              <span>{currencyInfo?.symbol} {currency.toUpperCase()}</span>
            )}
          </SelectValue>
        </SelectTrigger>
        <SelectContent>
          {allCurrencies.map((c) => (
            <SelectItem key={c.code} value={c.code}>
              <span className="flex items-center gap-2">
                <span className="w-6 text-center font-medium">{c.symbol}</span>
                <span>{c.code.toUpperCase()}</span>
                <span className="text-[#94A3B8] text-xs">({c.name})</span>
              </span>
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {error && (
        <span className="flex items-center gap-1 text-xs text-error" title={error} role="alert">
          <AlertCircle className="w-3 h-3 shrink-0" />
          <span className="max-w-[220px] truncate">{error}</span>
        </span>
      )}
    </div>
  );
}
