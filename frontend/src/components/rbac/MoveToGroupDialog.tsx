import { useState, useEffect, useCallback } from 'react';
import { rbacApi } from '@/api/rbac';
import type { GroupWithAccess } from '@/types/rbac';
import GroupForm from './GroupForm';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Loader2, ArrowRight, Plus } from 'lucide-react';

type Mode = 'existing' | 'new';

interface MoveToGroupDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  orgId: string;
  selectedContractIds: string[];
  onSuccess: () => void;
}

export default function MoveToGroupDialog({
  open,
  onOpenChange,
  orgId,
  selectedContractIds,
  onSuccess,
}: MoveToGroupDialogProps) {
  const [mode, setMode] = useState<Mode>('existing');
  const [groups, setGroups] = useState<GroupWithAccess[]>([]);
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [selectedGroupId, setSelectedGroupId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchGroups = useCallback(() => {
    setLoadingGroups(true);

    return rbacApi.groups
      .list(orgId, { limit: 200 })
      .then((res) => {
        const fetched = res.data.data || [];
        setGroups(fetched);
        return fetched;
      })
      .catch((err) => {
        console.error('Failed to load groups:', err);
        setError('Failed to load groups');
        return [] as GroupWithAccess[];
      })
      .finally(() => setLoadingGroups(false));
  }, [orgId]);

  // Load groups when dialog opens
  useEffect(() => {
    if (!open) return;
    fetchGroups();
  }, [open, fetchGroups]);

  // Reset form state when dialog opens
  useEffect(() => {
    if (open) {
      setMode('existing');
      setSelectedGroupId('');
      setSubmitting(false);
      setError(null);
    }
  }, [open]);

  // After GroupForm creates the group, re-fetch groups, auto-select the newest, switch to existing mode
  async function handleGroupCreated() {
    const fetched = await fetchGroups();
    if (fetched.length > 0) {
      // The most recently created group will be the one just made.
      // Sort by created_at descending and pick the first.
      const sorted = [...fetched].sort(
        (a, b) => new Date(b.group.created_at).getTime() - new Date(a.group.created_at).getTime()
      );
      setSelectedGroupId(sorted[0].group.id);
    }
    setMode('existing');
  }

  const canSubmit =
    !submitting &&
    selectedContractIds.length > 0 &&
    selectedGroupId !== '';

  async function handleSubmit() {
    setError(null);
    setSubmitting(true);

    try {
      await rbacApi.contracts.batchMove(orgId, {
        contract_ids: selectedContractIds,
        target_group_id: selectedGroupId,
      });
      onSuccess();
      onOpenChange(false);
    } catch (err: unknown) {
      // Extract error message from Axios response if available
      const axiosErr = err as { response?: { data?: { error?: string } } };
      const message =
        axiosErr?.response?.data?.error ||
        (err instanceof Error ? err.message : 'Failed to move contracts');
      setError(message);
    } finally {
      setSubmitting(false);
    }
  }

  const selectedGroup = selectedGroupId
    ? groups.find((g) => g.group.id === selectedGroupId)
    : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent data-testid="move-dialog" className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowRight className="h-5 w-5" />
            {mode === 'new' ? 'Create Group & Move Contracts' : 'Move Contracts to Group'}
          </DialogTitle>
        </DialogHeader>

        {mode === 'new' ? (
          /* ── Create new group mode ── */
          <div className="space-y-4">
            <p className="text-sm text-neutral-500">
              Create a new group, then move {selectedContractIds.length} contract
              {selectedContractIds.length !== 1 ? 's' : ''} into it.
            </p>
            <GroupForm
              orgId={orgId}
              groups={groups.map((g) => g.group)}
              onSave={handleGroupCreated}
              onClose={() => setMode('existing')}
            />
          </div>
        ) : (
          /* ── Select existing group mode ── */
          <>
            <div className="space-y-4">
              <p className="text-sm text-neutral-500">
                Moving {selectedContractIds.length} contract
                {selectedContractIds.length !== 1 ? 's' : ''} to a group.
              </p>

              {error && (
                <div className="rounded-md bg-red-50 border border-red-200 px-3 py-2 text-sm text-red-700">
                  {error}
                </div>
              )}

              {/* Group selector */}
              <div className="space-y-2">
                <label className="text-sm font-medium">Target group</label>
                {loadingGroups ? (
                  <div className="flex items-center gap-2 text-sm text-neutral-500 py-2">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading groups...
                  </div>
                ) : (
                  <Select value={selectedGroupId} onValueChange={setSelectedGroupId}>
                    <SelectTrigger data-testid="move-group-select">
                      <SelectValue placeholder="Select a group" />
                    </SelectTrigger>
                    <SelectContent>
                      {groups.map((g) => (
                        <SelectItem key={g.group.id} value={g.group.id}>
                          {g.group.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )}

                {selectedGroup && (
                  <p className="text-xs text-neutral-400">
                    Path: <code className="font-mono">{selectedGroup.group.path}</code>
                  </p>
                )}
              </div>

              {/* Create new group link */}
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="gap-1.5 text-primary"
                onClick={() => {
                  setError(null);
                  setMode('new');
                }}
              >
                <Plus className="h-4 w-4" />
                Create new group
              </Button>
            </div>

            <DialogFooter className="gap-2 sm:gap-0">
              <Button data-testid="move-cancel-btn" variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
                Cancel
              </Button>
              <Button data-testid="move-confirm-btn" onClick={handleSubmit} disabled={!canSubmit}>
                {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Move {selectedContractIds.length} Contract
                {selectedContractIds.length !== 1 ? 's' : ''}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
