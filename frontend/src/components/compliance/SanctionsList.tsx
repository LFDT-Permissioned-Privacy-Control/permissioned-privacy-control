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
import { ConfirmDialog } from '@/components/ui/ConfirmDialog';
import Pagination from '@/components/ui/Pagination';
import { Loader2, Plus, AlertCircle, ShieldBan, Trash2 } from 'lucide-react';
import { complianceApi } from '@/api/compliance';
import { useComplianceOrgContext } from './ComplianceManager';
import { useAdmin } from '@/components/auth/RequireAdmin';
import type { SanctionedAddress } from '@/types/compliance';

const PAGE_SIZE = 25;

export default function SanctionsList() {
  const { selectedOrg, organizations } = useComplianceOrgContext();
  const { isReadonlyAdmin } = useAdmin();
  const orgId = selectedOrg?.id;

  const [addresses, setAddresses] = useState<SanctionedAddress[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<SanctionedAddress | null>(null);

  // Form state
  const [formAddress, setFormAddress] = useState('');
  const [formReason, setFormReason] = useState('');
  const [formSource, setFormSource] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [formSaving, setFormSaving] = useState(false);

  const loadAddresses = async (newOffset: number = offset) => {
    // Backend (admin_compliance.go: listSanctionedAddresses) requires an
    // explicit `org_id` for JWT-admin callers and rejects empty values with
    // 400 "org_id query parameter is required". Skip the call when no org is
    // selected — ComplianceManager already shows a "Select an organization"
    // empty state in that case.
    if (!orgId) {
      setAddresses([]);
      setTotal(0);
      setLoading(false);
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const response = await complianceApi.sanctions.list({
        org_id: orgId,
        limit: PAGE_SIZE,
        offset: newOffset,
      });
      const page = response.data;
      setAddresses(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { status?: number; data?: { error?: string } } };
      if (axiosError.response?.status === 404) {
        setAddresses([]);
        setTotal(0);
      } else {
        setError(axiosError.response?.data?.error || 'Failed to load sanctioned addresses');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setOffset(0);
    loadAddresses(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  const openCreateForm = () => {
    setFormAddress('');
    setFormReason('');
    setFormSource('');
    setFormError(null);
    setShowForm(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!orgId) {
      setFormError('Select an organization before adding sanctions');
      return;
    }
    if (!formAddress.trim()) {
      setFormError('Address is required');
      return;
    }
    if (!formReason.trim()) {
      setFormError('Reason is required');
      return;
    }

    try {
      setFormSaving(true);
      setFormError(null);
      // Sanctions are always added to the currently selected org. Adding a
      // global (org_id == nil) sanction is super-admin only on the backend
      // (admin_compliance.go: addSanctionedAddress), so the dashboard never
      // offers a "Global" option here.
      await complianceApi.sanctions.add({
        address: formAddress.trim().toLowerCase(),
        reason: formReason.trim(),
        source: formSource.trim() || undefined,
        org_id: orgId,
      });
      setShowForm(false);
      loadAddresses(0);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setFormError(axiosError.response?.data?.error || 'Failed to add sanctioned address');
    } finally {
      setFormSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await complianceApi.sanctions.remove(deleteTarget.id);
      setDeleteTarget(null);
      loadAddresses(offset);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { error?: string } } };
      setError(axiosError.response?.data?.error || 'Failed to remove sanctioned address');
    }
  };

  const getOrgName = (orgId?: string) => {
    if (!orgId) return null;
    const org = organizations.find(o => o.id === orgId);
    return org?.name || orgId.slice(0, 8);
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
        <h3 className="text-base font-medium text-neutral-700">Sanctioned Addresses</h3>
        {!isReadonlyAdmin && (
          <Button size="sm" onClick={openCreateForm}>
            <Plus className="w-4 h-4 mr-1" />
            Add Address
          </Button>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {addresses.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <ShieldBan className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500 mb-2">No sanctioned addresses</p>
          <p className="text-neutral-400 text-sm">
            Add addresses to the sanctions list to block transfers involving them
          </p>
        </div>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Address</TableHead>
                <TableHead>Reason</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Scope</TableHead>
                <TableHead>Added</TableHead>
                {!isReadonlyAdmin && <TableHead className="w-[50px]"></TableHead>}
              </TableRow>
            </TableHeader>
            <TableBody>
              {addresses.map(addr => (
                <TableRow key={addr.id}>
                  <TableCell className="font-mono text-xs text-neutral-500">
                    {addr.address.slice(0, 10)}...{addr.address.slice(-6)}
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate">{addr.reason}</TableCell>
                  <TableCell className="text-neutral-500 text-sm">{addr.source || '—'}</TableCell>
                  <TableCell>
                    {addr.org_id ? (
                      <Badge variant="outline">{getOrgName(addr.org_id)}</Badge>
                    ) : (
                      <Badge variant="warning">Global</Badge>
                    )}
                  </TableCell>
                  <TableCell className="text-neutral-500 text-sm">
                    {new Date(addr.created_at).toLocaleDateString()}
                  </TableCell>
                  {!isReadonlyAdmin && (
                    <TableCell>
                      <Button variant="ghost" size="icon" onClick={() => setDeleteTarget(addr)}>
                        <Trash2 className="w-4 h-4 text-error-dark" />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pagination
            total={total}
            limit={PAGE_SIZE}
            offset={offset}
            onPageChange={newOffset => loadAddresses(newOffset)}
          />
        </>
      )}

      {/* Add Dialog */}
      <Dialog open={showForm} onOpenChange={open => { if (!open) setShowForm(false); }}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>Add Sanctioned Address</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            {formError && (
              <div className="flex items-center gap-2 p-3 rounded-lg bg-error-light border border-error/30 text-error-dark text-sm">
                <AlertCircle className="w-4 h-4 shrink-0" />
                {formError}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">Address</label>
              <Input
                value={formAddress}
                onChange={e => setFormAddress(e.target.value)}
                placeholder="0x..."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">Reason</label>
              <Input
                value={formReason}
                onChange={e => setFormReason(e.target.value)}
                placeholder="OFAC SDN list, etc."
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                Source <span className="text-neutral-400 font-normal">(optional)</span>
              </label>
              <Input
                value={formSource}
                onChange={e => setFormSource(e.target.value)}
                placeholder="OFAC, Chainalysis, manual"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-neutral-700 mb-1.5">
                Scope
              </label>
              <div className="flex items-center gap-2 px-3 py-2 rounded-md bg-neutral-100 text-sm text-neutral-700">
                <Badge variant="outline">{selectedOrg?.name ?? '—'}</Badge>
                <span className="text-neutral-500 text-xs">
                  Sanctions are scoped to the currently selected organization.
                </span>
              </div>
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={formSaving}>
                {formSaving && <Loader2 className="w-4 h-4 mr-2 animate-spin" />}
                Add to Sanctions
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={open => { if (!open) setDeleteTarget(null); }}
        title="Remove Sanctioned Address"
        description={`Are you sure you want to remove ${deleteTarget?.address || 'this address'} from the sanctions list? Transfers involving this address will no longer be blocked by sanctions screening.`}
        confirmLabel="Remove"
        onConfirm={handleDelete}
        variant="destructive"
      />
    </div>
  );
}
