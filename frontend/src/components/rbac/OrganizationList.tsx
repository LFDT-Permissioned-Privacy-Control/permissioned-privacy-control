import { useEffect, useState } from 'react';
import type { Organization } from '@/types/rbac';
import { useOrgContext } from './RBACManager';
import OrganizationForm from './OrganizationForm';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { rbacApi } from '@/api/rbac';
import Pagination from '@/components/ui/Pagination';
import {
  Building2,
  Pencil,
  Loader2,
} from 'lucide-react';
import { useAdmin } from '@/components/auth/RequireAdmin';

const PAGE_SIZE = 25;

export default function OrganizationList() {
  const { refreshOrgs, setSelectedOrg } = useOrgContext();
  // Tier-1 (super-admin) is the only role that should create / delete orgs,
  // and tier-1 has no UI session — `adminAuthMiddleware` only sets
  // auth_method=admin_token via the X-Admin-Token header (RD-917 §1).
  // So in the dashboard we never show "Add" or "Delete" — those are
  // operator-side actions. Edit (metadata change on an own org) is allowed
  // for tier-2 admins on rows where they are is_org_admin (full, not
  // readonly). We use the per-org adminOrgIds set populated by
  // /me/admin-status to decide per-row.
  const { adminOrgIds } = useAdmin();
  const [organizations, setOrganizations] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [editing, setEditing] = useState<Organization | null>(null);

  // reason: mount-only initial page load. loadPage is a non-memoised helper;
  // this must run exactly once on mount, so the empty dep array is intentional.
  useEffect(() => {
    loadPage(0);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadPage = async (newOffset: number = offset) => {
    try {
      setLoading(true);
      const response = await rbacApi.orgs.list({ limit: PAGE_SIZE, offset: newOffset });
      const page = response.data;
      setOrganizations(page.data || []);
      setTotal(page.total);
      setOffset(newOffset);
    } catch (error) {
      console.error('Failed to load organizations:', error);
      setOrganizations([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setEditing(null);
    await loadPage();
    await refreshOrgs(); // Update the dropdown
  };

  const formatDate = (dateStr: string) => {
    return new Date(dateStr).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-medium text-neutral-700">Organizations</h3>
          <p className="text-xs text-neutral-500 mt-0.5">
            Top-level tenants that contain groups and contracts
          </p>
        </div>
        {/* No "Add Organization" button: tenant creation is super-admin only
            and super-admin has no UI session (X-Admin-Token via API). */}
      </div>

      {loading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 text-neutral-400 animate-spin" />
        </div>
      ) : organizations.length === 0 ? (
        <div className="text-center py-12">
          <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-neutral-100 flex items-center justify-center">
            <Building2 className="w-8 h-8 text-neutral-400" />
          </div>
          <p className="text-neutral-500">No organizations found</p>
        </div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Slug</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {organizations.map((org, index) => (
              <TableRow
                key={org.id}
                className="animate-fade-in cursor-pointer"
                style={{ animationDelay: `${index * 30}ms` }}
                onClick={() => setSelectedOrg(org)}
              >
                <TableCell>
                  <div className="flex items-center gap-2">
                    <Building2 className="w-4 h-4 text-primary" />
                    <span className="font-medium">{org.name}</span>
                  </div>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="font-mono text-xs">
                    {org.slug}
                  </Badge>
                </TableCell>
                <TableCell className="text-neutral-500 text-sm">
                  {formatDate(org.created_at)}
                </TableCell>
                <TableCell>
                  <div className="flex items-center justify-end gap-2">
                    {/* Edit visible only on rows where the caller is a full
                        is_org_admin of THIS org. Read-only-admin rows and any
                        other-org leakage rows (shouldn't appear after the
                        listOrganizations membership filter) get no edit
                        button. Delete is super-admin-only — no UI button. */}
                    {adminOrgIds.includes(org.id) && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={e => {
                          e.stopPropagation();
                          setEditing(org);
                        }}
                        title="Edit organization"
                      >
                        <Pencil className="w-4 h-4" />
                      </Button>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      <Pagination total={total} limit={PAGE_SIZE} offset={offset} onPageChange={(newOffset) => loadPage(newOffset)} />

      {/* Edit Organization Dialog (metadata only — slug, name, settings).
          Tenant creation and deletion are platform-level operations not
          surfaced in the dashboard. */}
      <Dialog open={!!editing} onOpenChange={open => !open && setEditing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Organization</DialogTitle>
          </DialogHeader>
          {editing && (
            <OrganizationForm
              key={editing.id}
              organization={editing}
              onClose={() => setEditing(null)}
              onSave={handleSave}
            />
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
