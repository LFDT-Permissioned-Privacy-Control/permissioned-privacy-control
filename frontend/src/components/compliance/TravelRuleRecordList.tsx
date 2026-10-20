import { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog';
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select';
import Pagination from '@/components/ui/Pagination';
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import { Loader2, Plus, AlertCircle, AlertTriangle, FileText, Copy, Check, Trash2 } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useCurrency } from './CurrencyContext';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { UserSearchInput } from './UserSearchInput';
import type { TravelRuleRecord, TransferType, TokenPrice } from '@/types/compliance';

const PAGE_SIZE = 25;

function getRecordStatus(record: TravelRuleRecord): 'unused' | 'used' | 'expired' {
  if (record.used_at) return 'used';
  if (new Date(record.expires_at) < new Date()) return 'expired';
  return 'unused';
}

const statusBadgeVariant: Record<string, 'success' | 'secondary' | 'destructive'> = {
  unused: 'success',
  used: 'secondary',
  expired: 'destructive',
};

function isValidAddress(address: string): boolean {
  return /^0x[0-9a-fA-F]{40}$/.test(address);
}

function humanToWei(amount: string, decimals: number): string {
  if (!amount || isNaN(parseFloat(amount))) return '';
  const parts = amount.split('.');
  const whole = parts[0] || '0';
  const fraction = (parts[1] || '').padEnd(decimals, '0').slice(0, decimals);
  const combined = whole + fraction;
  // Remove leading zeros
  return combined.replace(/^0+/, '') || '0';
}

export default function TravelRuleRecordList() {
  const { selectedOrg } = useComplianceOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const { formatAmount, currencyLabel } = useCurrency();
  const orgId = selectedOrg?.id;

  const [records, setRecords] = useState<TravelRuleRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [selectedRecord, setSelectedRecord] = useState<TravelRuleRecord | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<TravelRuleRecord | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Form state
  const [formOriginatorUserId, setFormOriginatorUserId] = useState('');
  const [formOriginatorName, setFormOriginatorName] = useState('');
  const [formOriginatorAccountRef, setFormOriginatorAccountRef] = useState('');
  const [formBeneficiaryName, setFormBeneficiaryName] = useState('');
  const [formBeneficiaryInstitution, setFormBeneficiaryInstitution] = useState('');
  const [formTransferType, setFormTransferType] = useState<TransferType>('eth');
  const [formTokenAddress, setFormTokenAddress] = useState('');
  const [formBeneficiaryAddress, setFormBeneficiaryAddress] = useState('');
  const [formHumanAmount, setFormHumanAmount] = useState('');
  const [formEstimatedUsd, setFormEstimatedUsd] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);
  const [addressError, setAddressError] = useState('');
  const [createWarning, setCreateWarning] = useState<string | null>(null);
  const [availableTokens, setAvailableTokens] = useState<TokenPrice[]>([]);

  const selectedTokenInfo = formTransferType === 'eth'
    ? availableTokens.find(t => t.token_address === 'native')
    : availableTokens.find(t => t.token_address === formTokenAddress);

  const erc20Tokens = availableTokens.filter(t => t.token_address !== 'native');

  useEffect(() => {
    if (selectedTokenInfo && formHumanAmount && !isNaN(parseFloat(formHumanAmount))) {
      const usd = parseFloat(formHumanAmount) * selectedTokenInfo.price_fiat;
      setFormEstimatedUsd(usd.toFixed(2));
    } else {
      setFormEstimatedUsd('');
    }
  }, [formHumanAmount, selectedTokenInfo]);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  const loadRecords = async (newOffset: number = offset) => {
    if (!orgId) return;
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.travelRules.list(orgId, { limit: PAGE_SIZE, offset: newOffset });
      const page = response.data;
      setRecords(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setRecords([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load travel rule records');
      }
    } finally {
      setLoading(false);
    }
  };

  // reason: intentional reload-on-orgId. loadRecords is a non-memoised helper
  // that reads current state via closure; adding it to deps would require
  // useCallback and risk a refetch loop.
  useEffect(() => {
    setOffset(0);
    loadRecords(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const handleDelete = async () => {
    if (!deleteTarget || !orgId) return;
    try {
      await complianceApi.travelRules.delete(orgId, deleteTarget.id);
      setDeleteTarget(null);
      loadRecords(offset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to delete travel rule record');
    }
  };

  const openCreateForm = async () => {
    setFormOriginatorUserId('');
    setFormOriginatorName('');
    setFormOriginatorAccountRef('');
    setFormBeneficiaryName('');
    setFormBeneficiaryInstitution('');
    setFormTransferType('eth');
    setFormTokenAddress('');
    setFormBeneficiaryAddress('');
    setFormHumanAmount('');
    setFormEstimatedUsd('');
    setAddressError('');
    setFormError(null);
    setShowForm(true);
    // Fetch available tokens for the org
    try {
      const response = await complianceApi.tokens.list(orgId!);
      setAvailableTokens(response.data.data || []);
    } catch {
      setAvailableTokens([]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!orgId) return;

    if (formBeneficiaryAddress && !isValidAddress(formBeneficiaryAddress)) {
      setAddressError('Invalid address format. Must be 0x followed by 40 hex characters.');
      return;
    }

    const originatorData = {
      name: formOriginatorName.trim(),
      ...(formOriginatorAccountRef.trim() && { account_ref: formOriginatorAccountRef.trim() }),
    };
    const beneficiaryData = {
      name: formBeneficiaryName.trim(),
      ...(formBeneficiaryInstitution.trim() && { institution: formBeneficiaryInstitution.trim() }),
    };

    // C3: amount_fiat is computed server-side from amount_wei and token price.
    // We only send amount_wei; the server looks up the token price and calculates USD.
    const amountWei = selectedTokenInfo
      ? humanToWei(formHumanAmount, selectedTokenInfo.decimals)
      : formHumanAmount; // fallback: user enters wei directly if no token config

    try {
      setFormSaving(true);
      setFormError(null);
      const response = await complianceApi.travelRules.create(orgId, {
        originator_user_id: formOriginatorUserId.trim(),
        originator_data: originatorData,
        beneficiary_data: beneficiaryData,
        transfer_type: formTransferType,
        token_address: formTransferType === 'erc20' ? formTokenAddress.trim().toLowerCase() : undefined,
        beneficiary_address: formBeneficiaryAddress.trim().toLowerCase(),
        amount_wei: amountWei,
      });
      setShowForm(false);
      if (response.data?.warning) {
        setCreateWarning(response.data.warning);
      }
      loadRecords(0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to create travel rule record');
    } finally {
      setFormSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-base font-medium text-neutral-700">Travel Rule Records</h3>
        {!isReadonlyAdmin && (
          <Button size="sm" onClick={openCreateForm}>
            <Plus className="w-4 h-4 mr-1" />
            Create Record
          </Button>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {createWarning && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-amber-100 border border-amber-200 text-amber-800 text-sm">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="flex-1">
            <span>{createWarning}</span>
            <button onClick={() => setCreateWarning(null)} className="ml-2 underline text-xs hover:no-underline">dismiss</button>
          </div>
        </div>
      )}

      {records.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <FileText className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-2">No travel rule records</p>
          <p className="text-neutral-400 text-sm">
            Create a travel rule record to authorize high-value transfers
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Originator</TableHead>
                <TableHead>Beneficiary</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Amount ({currencyLabel})</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                {!isReadonlyAdmin && <TableHead className="w-[50px]"></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {records.map(record => {
                const status = getRecordStatus(record);
                const originatorName = record.originator_data?.name as string | undefined;
                return (
                  <TableRow
                    key={record.id}
                    className="cursor-pointer hover:bg-neutral-100"
                    onClick={() => setSelectedRecord(record)}
                  >
                    <TableCell className="text-sm text-neutral-500">
                      {record.originator_external_id ? (
                        <span className="font-mono text-xs">
                          {record.originator_external_id.length > 20
                            ? record.originator_external_id.slice(0, 15) + '...'
                            : record.originator_external_id}
                        </span>
                      ) : originatorName || (
                        <span className="font-mono text-xs">{record.originator_user_id.slice(0, 8)}...</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <span className="font-mono text-xs text-neutral-500">
                          {record.beneficiary_address.slice(0, 10)}...{record.beneficiary_address.slice(-6)}
                        </span>
                        <button
                          onClick={(e) => { e.stopPropagation(); copyToClipboard(record.beneficiary_address, `${record.id}-addr`); }}
                          className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors"
                          title="Copy address"
                        >
                          {copiedKey === `${record.id}-addr` ? (
                            <Check className="w-3.5 h-3.5 text-success" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{record.transfer_type.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>{formatAmount(record.amount_fiat)}</TableCell>
                    <TableCell>
                      <Badge variant={statusBadgeVariant[status]}>{status}</Badge>
                    </TableCell>
                    <TableCell className="text-neutral-500 text-sm">
                      {new Date(record.created_at).toLocaleDateString()}
                    </TableCell>
                    {!isReadonlyAdmin && (
                      <TableCell>
                        {status !== 'used' && (
                          <Button
                            variant="ghost"
                            size="icon"
                            onClick={(e) => { e.stopPropagation(); setDeleteTarget(record); }}
                          >
                            <Trash2 className="w-4 h-4 text-error-dark" />
                          </Button>
                        )}
                      </TableCell>
                    )}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadRecords(newOffset)}
          />
        </>
      )}

      {/* Detail Dialog */}
      <Dialog open={!!selectedRecord} onOpenChange={open => { if (!open) setSelectedRecord(null); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Travel Rule Record</DialogTitle>
          </DialogHeader>
          {selectedRecord && (() => {
            const status = getRecordStatus(selectedRecord);
            return (
              <div className="space-y-4">
                <div className="grid grid-cols-[120px_1fr] gap-y-3 gap-x-4 text-sm">
                  <span className="text-neutral-500 font-medium">Originator</span>
                  <div>
                    {selectedRecord.originator_external_id && (
                      <div className="font-mono text-xs break-all">{selectedRecord.originator_external_id}</div>
                    )}
                    {selectedRecord.originator_data?.name ? (
                      <div className="text-neutral-700 mt-1">
                        {String(selectedRecord.originator_data.name)}
                      </div>
                    ) : null}
                    {selectedRecord.originator_data?.account_ref ? (
                      <div className="text-neutral-500 text-xs mt-0.5">
                        Ref: {String(selectedRecord.originator_data.account_ref)}
                      </div>
                    ) : null}
                    <div className="font-mono text-xs text-neutral-400 mt-0.5 break-all">{selectedRecord.originator_user_id}</div>
                  </div>

                  <span className="text-neutral-500 font-medium">Beneficiary</span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm break-all">{selectedRecord.beneficiary_address}</span>
                      <button
                        onClick={() => copyToClipboard(selectedRecord.beneficiary_address, 'detail-beneficiary')}
                        className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                        title="Copy address"
                      >
                        {copiedKey === 'detail-beneficiary' ? (
                          <Check className="w-3.5 h-3.5 text-success" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                    </div>
                    {selectedRecord.beneficiary_data?.name ? (
                      <div className="text-neutral-700 mt-1">
                        {String(selectedRecord.beneficiary_data.name)}
                      </div>
                    ) : null}
                    {selectedRecord.beneficiary_data?.institution ? (
                      <div className="text-neutral-500 text-xs mt-0.5">
                        Institution: {String(selectedRecord.beneficiary_data.institution)}
                      </div>
                    ) : null}
                  </div>

                  <span className="text-neutral-500 font-medium">Transfer Type</span>
                  <div>
                    <Badge variant="outline">{selectedRecord.transfer_type.toUpperCase()}</Badge>
                  </div>

                  {selectedRecord.transfer_type === 'erc20' && selectedRecord.token_address && (
                    <>
                      <span className="text-neutral-500 font-medium">Token Address</span>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm break-all">{selectedRecord.token_address}</span>
                        <button
                          onClick={() => copyToClipboard(selectedRecord.token_address!, 'detail-token')}
                          className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                          title="Copy address"
                        >
                          {copiedKey === 'detail-token' ? (
                            <Check className="w-3.5 h-3.5 text-success" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </>
                  )}

                  <span className="text-neutral-500 font-medium">Amount (wei)</span>
                  <span className="font-mono text-sm break-all">{selectedRecord.amount_wei}</span>

                  <span className="text-neutral-500 font-medium">Amount ({currencyLabel})</span>
                  <span>{formatAmount(selectedRecord.amount_fiat)}</span>

                  <span className="text-neutral-500 font-medium">Status</span>
                  <div>
                    <Badge variant={statusBadgeVariant[status]}>{status}</Badge>
                  </div>

                  <span className="text-neutral-500 font-medium">Expires at</span>
                  <span>{new Date(selectedRecord.expires_at).toLocaleString()}</span>

                  <span className="text-neutral-500 font-medium">Created at</span>
                  <span>{new Date(selectedRecord.created_at).toLocaleString()}</span>

                  {selectedRecord.used_at && (
                    <>
                      <span className="text-neutral-500 font-medium">Used at</span>
                      <span>{new Date(selectedRecord.used_at).toLocaleString()}</span>
                    </>
                  )}

                  {selectedRecord.used_tx_hash && (
                    <>
                      <span className="text-neutral-500 font-medium">Used tx hash</span>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm break-all">{selectedRecord.used_tx_hash}</span>
                        <button
                          onClick={() => copyToClipboard(selectedRecord.used_tx_hash!, 'detail-txhash')}
                          className="p-1 rounded hover:bg-neutral-100 text-neutral-400 hover:text-neutral-500 transition-colors shrink-0"
                          title="Copy tx hash"
                        >
                          {copiedKey === 'detail-txhash' ? (
                            <Check className="w-3.5 h-3.5 text-success" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </>
                  )}
                </div>
              </div>
            );
          })()}
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => { if (!open) setDeleteTarget(null); }}
        title="Delete Travel Rule Record"
        description={`Are you sure you want to delete this travel rule record? This action cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={handleDelete}
        variant="destructive"
      />

      {/* Create Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Create Travel Rule Record</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                Originator
              </label>
              <UserSearchInput orgId={orgId!} value={formOriginatorUserId} onChange={setFormOriginatorUserId} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Originator Name <span className="text-error-dark">*</span>
                </label>
                <Input
                  value={formOriginatorName}
                  onChange={e => setFormOriginatorName(e.target.value)}
                  placeholder="Full legal name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Account Reference
                </label>
                <Input
                  value={formOriginatorAccountRef}
                  onChange={e => setFormOriginatorAccountRef(e.target.value)}
                  placeholder="Optional account ref"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Beneficiary Name <span className="text-error-dark">*</span>
                </label>
                <Input
                  value={formBeneficiaryName}
                  onChange={e => setFormBeneficiaryName(e.target.value)}
                  placeholder="Full legal name"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Institution
                </label>
                <Input
                  value={formBeneficiaryInstitution}
                  onChange={e => setFormBeneficiaryInstitution(e.target.value)}
                  placeholder="Optional institution"
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                  Transfer Type
                </label>
                <Select value={formTransferType} onValueChange={v => { setFormTransferType(v as TransferType); setFormTokenAddress(''); }}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="eth">ETH (Native)</SelectItem>
                    <SelectItem value="erc20">ERC-20 Token</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {formTransferType === 'erc20' && (
                <div>
                  <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                    Token
                  </label>
                  {erc20Tokens.length > 0 ? (
                    <Select value={formTokenAddress} onValueChange={setFormTokenAddress}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select token" />
                      </SelectTrigger>
                      <SelectContent>
                        {erc20Tokens.map(token => (
                          <SelectItem key={token.token_address} value={token.token_address}>
                            {token.symbol} ({token.token_address.slice(0, 6)}...{token.token_address.slice(-4)})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <p className="text-xs text-neutral-500 mt-2">
                      No ERC-20 tokens configured. Add them in Token Prices tab.
                    </p>
                  )}
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                Beneficiary Address
              </label>
              <Input
                value={formBeneficiaryAddress}
                onChange={e => { setFormBeneficiaryAddress(e.target.value); setAddressError(''); }}
                onBlur={() => {
                  if (formBeneficiaryAddress && !isValidAddress(formBeneficiaryAddress)) {
                    setAddressError('Invalid address format. Must be 0x followed by 40 hex characters.');
                  } else {
                    setAddressError('');
                  }
                }}
                placeholder="0x..."
                required
              />
              {addressError && <p className="text-xs text-error-dark mt-1">{addressError}</p>}
            </div>

            <div>
              {selectedTokenInfo ? (
                <>
                  <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                    Amount ({selectedTokenInfo.symbol})
                  </label>
                  <Input
                    value={formHumanAmount}
                    onChange={e => setFormHumanAmount(e.target.value)}
                    placeholder="1.5"
                    required
                  />
                  {formHumanAmount && !isNaN(parseFloat(formHumanAmount)) && (
                    <p className="text-xs text-neutral-500 mt-1">
                      ≈ {humanToWei(formHumanAmount, selectedTokenInfo.decimals)} wei{formEstimatedUsd && ` | ≈ $${formEstimatedUsd} USD (server will compute exact value)`}
                    </p>
                  )}
                </>
              ) : (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-100 border border-amber-200 text-amber-800 text-sm">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  Configure token prices in the Token Prices tab first to enable amount entry.
                </div>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving || !selectedTokenInfo}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Create Record
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
