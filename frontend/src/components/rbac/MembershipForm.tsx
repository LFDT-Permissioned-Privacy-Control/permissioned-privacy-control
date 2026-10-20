import { useState, useEffect, useMemo } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Organization, Group, MembershipWithDetails } from '@/types/rbac';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { AlertCircle, Save, X, Loader2, Building2, FolderTree } from 'lucide-react';
import AccessWindowField from './AccessWindowField';
import { resolveExpiry } from './accessWindow';

// Stable default value to prevent infinite render loops
const EMPTY_MEMBERSHIPS: MembershipWithDetails[] = [];

interface MembershipFormProps {
  userId: string;
  organizations: Organization[];
  existingMemberships?: MembershipWithDetails[];
  onClose: () => void;
  onSave: () => void;
}

export default function MembershipForm({
  userId,
  organizations,
  existingMemberships = EMPTY_MEMBERSHIPS,
  onClose,
  onSave,
}: MembershipFormProps) {
  const [selectedOrgId, setSelectedOrgId] = useState<string>('');
  const [allGroups, setAllGroups] = useState<Group[]>([]);
  const [availableGroups, setAvailableGroups] = useState<Group[]>([]);
  const [selectedGroupId, setSelectedGroupId] = useState<string>('');
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Time-boxed access window (RD-1145). 'none' = permanent.
  const [expiryPreset, setExpiryPreset] = useState<string>('none');
  const [customExpiry, setCustomExpiry] = useState<string>('');

  // Memoize the set of existing group IDs to prevent recreation on every render
  const existingGroupIds = useMemo(
    () => new Set(existingMemberships.map(m => m.membership.group_id)),
    [existingMemberships]
  );

  // reason: intentional reload-on-selectedOrgId. loadGroups is a non-memoised
  // helper that reads current state via closure; adding it to deps would require
  // useCallback and risk a refetch loop.
  useEffect(() => {
    if (selectedOrgId) {
      loadGroups();
    } else {
      setAllGroups([]);
      setAvailableGroups([]);
      setSelectedGroupId('');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedOrgId]);

  // Filter out groups user is already in whenever allGroups or existingGroupIds change
  // reason: this effect recomputes availableGroups from allGroups/existingGroupIds.
  // selectedGroupId is read only to clear a now-invalid selection; it is reset by
  // this effect, so listing it as a dep would refire on that reset. Intentionally
  // omitted.
  useEffect(() => {
    // Exclude groups the user is already in, and (RD-1099) org-admin groups:
    // assigning org-admin membership is super-admin-only, so the backend
    // rejects it from the dashboard's tier-2 (JWT) caller. Hiding them keeps
    // the UI honest; the backend gate is the real boundary. Read-only-admin
    // groups remain assignable (delegation, not escalation).
    const filtered = allGroups.filter(g => !existingGroupIds.has(g.id) && !g.is_org_admin);
    setAvailableGroups(filtered);
    // Reset selection if current selection is no longer available
    if (selectedGroupId && !filtered.some(g => g.id === selectedGroupId)) {
      setSelectedGroupId('');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allGroups, existingGroupIds]);

  const loadGroups = async () => {
    if (!selectedOrgId) return;

    setLoadingGroups(true);

    try {
      const groupsRes = await rbacApi.groups.list(selectedOrgId);
      setAllGroups((groupsRes.data?.data || []).map(gwa => gwa.group));
    } catch (error) {
      console.error('Failed to load groups:', error);
      setAllGroups([]);
    } finally {
      setLoadingGroups(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedGroupId) {
      setError('Please select a group');
      return;
    }

    setSaving(true);
    setError(null);

    const expires_at = resolveExpiry(expiryPreset, customExpiry);
    if (expiryPreset === 'custom' && !expires_at) {
      setError('Please pick a valid expiry date, or choose “No expiry”.');
      setSaving(false);
      return;
    }

    try {
      await rbacApi.users.createMembership(userId, {
        group_id: selectedGroupId,
        ...(expires_at ? { expires_at } : {}),
      });
      onSave();
    } catch (err: unknown) {
      console.error('Failed to create membership:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to create membership. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Organization</label>
        <Select value={selectedOrgId} onValueChange={setSelectedOrgId}>
          <SelectTrigger>
            <SelectValue placeholder="Select organization" />
          </SelectTrigger>
          <SelectContent>
            {organizations.map(org => (
              <SelectItem key={org.id} value={org.id}>
                <div className="flex items-center gap-2">
                  <Building2 className="w-4 h-4 text-neutral-400" />
                  <span>{org.name}</span>
                  <span className="text-neutral-400 text-xs">({org.slug})</span>
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Group</label>
        {loadingGroups ? (
          <div className="flex items-center gap-2 text-neutral-400 py-2">
            <Loader2 className="w-4 h-4 animate-spin" />
            <span className="text-sm">Loading groups...</span>
          </div>
        ) : !selectedOrgId ? (
          <p className="text-neutral-400 text-sm py-2">Select an organization first</p>
        ) : allGroups.length === 0 ? (
          <p className="text-neutral-400 text-sm py-2">No groups in this organization</p>
        ) : availableGroups.length === 0 ? (
          <p className="text-neutral-400 text-sm py-2">User is already a member of all groups in this organization</p>
        ) : (
          <Select
            value={selectedGroupId}
            onValueChange={setSelectedGroupId}
            disabled={!selectedOrgId}
          >
            <SelectTrigger>
              <SelectValue placeholder="Select group" />
            </SelectTrigger>
            <SelectContent>
              {availableGroups.map(group => (
                <SelectItem key={group.id} value={group.id}>
                  <div className="flex items-center gap-2">
                    <FolderTree className="w-4 h-4 text-neutral-400" />
                    <span>{group.name}</span>
                    <span className="text-neutral-400 text-xs font-mono">({group.path})</span>
                  </div>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Time-boxed access window (RD-1145). Picking a window makes the
          membership auto-expire — e.g. a regulator/auditor profile for 24h / 7d. */}
      {selectedGroupId && (
        <AccessWindowField
          preset={expiryPreset}
          onPresetChange={setExpiryPreset}
          custom={customExpiry}
          onCustomChange={setCustomExpiry}
          disabled={saving}
        />
      )}

      {/* Info about permissions */}
      {selectedGroupId && (
        <div className="p-3 rounded-lg bg-primary-50 border border-primary-200">
          <p className="text-sm text-primary-600">
            The user will inherit permissions from this group's access settings
            (allowed methods, claims, rate limits).
          </p>
        </div>
      )}

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={saving}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={saving || !selectedGroupId}
          className="gap-2"
        >
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Adding...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              Add Membership
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
