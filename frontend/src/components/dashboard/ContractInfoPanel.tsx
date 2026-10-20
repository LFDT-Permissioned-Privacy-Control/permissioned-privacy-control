import { useState, useEffect, useRef } from 'react';
import { Badge } from '@/components/ui/badge';
import { testApi } from '@/api/client';
import { getClosestPresetLabel } from '@/types/rbac';
import { Loader2, FileText, AlertTriangle } from 'lucide-react';

const ADDRESS_REGEX = /^0x[0-9a-fA-F]{40}$/;

interface ContractLookupResult {
  contract: { id: string; name: string; address: string; org_id: string };
  organization: { id: string; name: string; slug: string };
  grants: Array<{
    grant: { id: string; contract_id: string; group_id: string; functions: Array<{ selector: string }> | null };
    group: { id: string; name: string; path: string };
    access: { claims: string[]; allowed_methods: string[] } | null;
  }>;
}

interface ContractInfoPanelProps {
  contractAddress: string;
}

export function ContractInfoPanel({ contractAddress }: ContractInfoPanelProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<ContractLookupResult | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastAddress = useRef<string>('');

  // reason: debounced lookup keyed on contractAddress only. `data` is read at
  // line 42 purely as a guard to skip a redundant refetch for the same address;
  // it is set inside this effect, so listing it as a dep would cause a loop. It
  // is intentionally not a trigger.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    const addr = contractAddress.trim().toLowerCase();

    if (!ADDRESS_REGEX.test(addr)) {
      setData(null);
      setError(null);
      lastAddress.current = '';
      return;
    }

    if (addr === lastAddress.current && data) return;

    debounceRef.current = setTimeout(async () => {
      lastAddress.current = addr;
      setLoading(true);
      setError(null);
      try {
        const result = await testApi.lookupContract(addr);
        setData(result);
      } catch (err: unknown) {
        const axiosError = err as { response?: { status?: number } };
        if (axiosError?.response?.status === 404) {
          setError('Contract not registered');
        } else {
          setError('Failed to look up contract');
        }
        setData(null);
      } finally {
        setLoading(false);
      }
    }, 500);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [contractAddress]);

  if (!ADDRESS_REGEX.test(contractAddress.trim().toLowerCase())) return null;

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-sky-50 border border-sky-200 text-sm text-neutral-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        Looking up contract...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-warning-light border border-warning/40 text-sm text-warning-dark" data-testid="contract-info-panel">
        <AlertTriangle className="w-4 h-4" />
        {error}
      </div>
    );
  }

  if (!data) return null;

  const { contract, organization, grants } = data;

  return (
    <div className="p-3 rounded-lg bg-sky-50 border border-sky-200 space-y-3 animate-fade-in" data-testid="contract-info-panel">
      {/* Header */}
      <div className="flex items-center gap-2">
        <FileText className="w-4 h-4 text-blue-600" />
        <span className="text-sm font-medium text-neutral-700">
          {contract.name || 'Unnamed Contract'}
        </span>
        <span className="text-xs text-neutral-400">&middot;</span>
        <span className="text-xs text-neutral-500">{organization.name}</span>
      </div>

      {/* Groups with access */}
      {grants.length > 0 ? (
        <div>
          <div className="text-xs font-medium text-neutral-500 mb-1.5">Groups with access</div>
          <div className="space-y-1">
            {grants.map((g) => {
              const methods = g.access?.allowed_methods || [];
              const filteredMethods = methods.filter(m => m !== '*');
              const hasFunctionRestrictions = g.grant.functions !== null && g.grant.functions !== undefined;

              return (
                <div key={g.grant.id} className="flex items-center gap-2 text-sm">
                  <span className="text-neutral-700">{g.group.name}</span>
                  <span className="text-neutral-400">&mdash;</span>
                  {filteredMethods.length > 0 ? (
                    <Badge
                      variant="outline"
                      className="text-xs py-0 bg-primary-50 text-primary border-primary-200"
                    >
                      {getClosestPresetLabel(filteredMethods)}
                    </Badge>
                  ) : (
                    <span className="text-xs text-neutral-400">No permissions</span>
                  )}
                  {hasFunctionRestrictions && (
                    <span className="text-xs text-neutral-400">
                      ({g.grant.functions!.length} function{g.grant.functions!.length !== 1 ? 's' : ''})
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="text-xs text-neutral-400">No groups have been granted access</div>
      )}
    </div>
  );
}
