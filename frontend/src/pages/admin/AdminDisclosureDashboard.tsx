import { useState, useEffect, useMemo, useCallback } from 'react';
import {
  Shield,
  CheckCircle2,
  Clock,
  XCircle,
  RefreshCw,
  AlertTriangle,
  Trash2,
  ShieldOff,
  Users,
  Plus,
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { DisclosureFilters } from '@/components/disclosure/DisclosureFilters';
import { CreateDisclosureRequestForm } from '@/components/disclosure/CreateDisclosureRequestForm';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { useAuth } from '@/contexts/AuthContext';
import { disclosureApi } from '@/api/disclosure';
import { userApiMethods, type UserOrg } from '@/api/auth';
import type {
  DisclosureFilter,
  DisclosureListResult,
  GrantListResult,
  DisclosureRequest,
  DisclosureGrant,
  CreateDisclosureRequestInput,
} from '@/types/disclosure';
import {
  DISCLOSURE_LEVEL_LABELS,
  SCOPE_LABELS,
} from '@/types/disclosure';

type TabValue = 'active' | 'pending' | 'inactive';

interface AdminDisclosureDashboardProps {
  onError?: (error: string) => void;
}

export function AdminDisclosureDashboard({ onError }: AdminDisclosureDashboardProps) {
  const { isReadonlyAdmin, adminOrgIds, readonlyAdminOrgIds } = useAdmin();
  const { accessToken } = useAuth();
  const [activeTab, setActiveTab] = useState<TabValue>('pending');
  const [requestsResult, setRequestsResult] = useState<DisclosureListResult | null>(null);
  const [grantsResult, setGrantsResult] = useState<GrantListResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // RD-944. The set of orgs the caller can scope disclosure listings to.
  // De-dupe (a group can flag both is_org_admin and is_org_readonly_admin,
  // though atypical) while preserving the full-admin-first order so
  // adminOrgs[0] picks a writable org when possible.
  const scopedOrgIds = useMemo(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const id of [...adminOrgIds, ...readonlyAdminOrgIds]) {
      if (!seen.has(id)) {
        seen.add(id);
        out.push(id);
      }
    }
    return out;
  }, [adminOrgIds, readonlyAdminOrgIds]);

  // Initial filter pre-populated with the caller's first scoped org.
  // For single-org admins this is the only org they could query anyway;
  // for multi-org admins the org-switcher in DisclosureFilters lets
  // them flip to another via the same API contract (backend still
  // re-verifies via requireTargetInScope — see RD-944 PR).
  const [filter, setFilter] = useState<DisclosureFilter>(() => ({
    org_id: scopedOrgIds[0],
  }));

  // Look up org names for the switcher. Calls /me/orgs which returns
  // ALL of the caller's org memberships including non-admin ones;
  // we filter down to scopedOrgIds before rendering.
  const [myOrgs, setMyOrgs] = useState<UserOrg[]>([]);
  useEffect(() => {
    if (!accessToken || scopedOrgIds.length === 0) {
      return;
    }
    let cancelled = false;
    userApiMethods
      .getMyOrganizations(accessToken)
      .then((resp) => {
        if (!cancelled) {
          setMyOrgs(resp.organizations);
        }
      })
      .catch(() => {
        // Non-fatal — the switcher just shows IDs instead of names.
      });
    return () => {
      cancelled = true;
    };
  }, [accessToken, scopedOrgIds.length]);

  // Build the org options the switcher renders. Lookup by id falls
  // back to the raw id when the user has admin scope on an org the
  // /me/orgs response doesn't list (shouldn't happen in practice but
  // keeps the UI honest if it does).
  const orgOptions = useMemo(
    () =>
      scopedOrgIds.map((id) => {
        const found = myOrgs.find((o) => o.id === id);
        return { id, label: found ? `${found.name} (${found.slug})` : id };
      }),
    [scopedOrgIds, myOrgs]
  );

  // Action state
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [revokeDialogOpen, setRevokeDialogOpen] = useState(false);
  const [detailDialogOpen, setDetailDialogOpen] = useState(false);
  const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);
  const [selectedGrantId, setSelectedGrantId] = useState<string | null>(null);
  const [selectedRequest, setSelectedRequest] = useState<DisclosureRequest | null>(null);
  const [selectedGrant, setSelectedGrant] = useState<DisclosureGrant | null>(null);
  const [revokeReason, setRevokeReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  // Create request state
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);

  const fetchData = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [requestsRes, grantsRes] = await Promise.all([
        disclosureApi.admin.listRequestsWithFilter(filter),
        disclosureApi.admin.listGrantsWithFilter(filter),
      ]);
      setRequestsResult(requestsRes.data);
      setGrantsResult(grantsRes.data);
    } catch (err) {
      console.error('Failed to fetch disclosure data:', err);
      const errorMsg = 'Failed to load disclosure data. Please try again.';
      setError(errorMsg);
      onError?.(errorMsg);
    } finally {
      setIsLoading(false);
    }
  }, [filter, onError]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Categorize data
  const { pendingRequests, activeGrants, inactiveGrants, stats } = useMemo(() => {
    const now = new Date();
    const requests = requestsResult?.requests || [];
    const grants = grantsResult?.grants || [];

    // Pending requests
    const pending = requests.filter((r) => r.status === 'pending');

    // Active grants
    const active = grants.filter((g) => {
      const isRevoked = !!g.revoked_at;
      const isExpired = new Date(g.valid_until || '') < now;
      return !isRevoked && !isExpired;
    });

    // Inactive grants (revoked or expired)
    const inactive = grants.filter((g) => {
      const isRevoked = !!g.revoked_at;
      const isExpired = new Date(g.valid_until || '') < now;
      return isRevoked || isExpired;
    });

    return {
      pendingRequests: pending,
      activeGrants: active,
      inactiveGrants: inactive,
      stats: {
        totalRequests: requestsResult?.total || 0,
        totalGrants: grantsResult?.total || 0,
        pendingCount: pending.length,
        activeCount: active.length,
        inactiveCount: inactive.length,
      },
    };
  }, [requestsResult, grantsResult]);

  const handleDeleteRequest = async () => {
    if (!selectedRequestId) return;
    setActionLoading(true);
    try {
      await disclosureApi.admin.deleteRequest(selectedRequestId);
      setDeleteDialogOpen(false);
      setSelectedRequestId(null);
      await fetchData();
    } catch (err) {
      console.error('Failed to delete request:', err);
      onError?.('Failed to delete request');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRevokeGrant = async () => {
    if (!selectedGrantId) return;
    setActionLoading(true);
    try {
      await disclosureApi.admin.revokeGrant(selectedGrantId, revokeReason || undefined);
      setRevokeDialogOpen(false);
      setSelectedGrantId(null);
      setRevokeReason('');
      await fetchData();
    } catch (err) {
      console.error('Failed to revoke grant:', err);
      onError?.('Failed to revoke grant');
    } finally {
      setActionLoading(false);
    }
  };

  const handleCreateRequest = async (input: CreateDisclosureRequestInput) => {
    setIsCreating(true);
    try {
      // Bind the request to whichever org the dashboard is currently filtered
      // to. Without this, the backend defaults to the system default org and
      // a JWT admin scoped to any other org gets 403 from requireFullAdminInScope.
      await disclosureApi.admin.createRequest({ ...input, org_id: filter.org_id });
      setCreateDialogOpen(false);
      await fetchData();
    } catch (err) {
      console.error('Failed to create disclosure request:', err);
      onError?.('Failed to create disclosure request');
    } finally {
      setIsCreating(false);
    }
  };

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const renderTabCount = (count: number, variant: 'warning' | 'success' | 'secondary') => {
    if (count === 0) return null;
    return (
      <Badge variant={variant} className="ml-2 text-xs px-1.5 py-0.5">
        {count}
      </Badge>
    );
  };

  if (error) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <AlertTriangle className="w-12 h-12 text-warning-dark mx-auto mb-4" />
          <h3 className="text-lg font-medium text-neutral-900 mb-2">Error Loading Data</h3>
          <p className="text-neutral-500 mb-4">{error}</p>
          <Button onClick={fetchData}>
            <RefreshCw className="w-4 h-4 mr-2" />
            Try Again
          </Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
            <Shield className="w-5 h-5 text-primary" />
          </div>
          <div>
            <h1 className="text-xl font-semibold text-neutral-900">Disclosure Management</h1>
            <p className="text-sm text-neutral-500">
              Admin view of all disclosure requests and grants
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {!isReadonlyAdmin && (
            <Button variant="default" size="sm" onClick={() => setCreateDialogOpen(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Create Request
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={fetchData} disabled={isLoading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-3">
              <Users className="w-8 h-8 text-primary" />
              <div>
                <p className="text-2xl font-semibold text-neutral-900">{stats.totalRequests}</p>
                <p className="text-xs text-neutral-500">Total Requests</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-3">
              <Clock className="w-8 h-8 text-warning-dark" />
              <div>
                <p className="text-2xl font-semibold text-neutral-900">{stats.pendingCount}</p>
                <p className="text-xs text-neutral-500">Pending</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-8 h-8 text-success-dark" />
              <div>
                <p className="text-2xl font-semibold text-neutral-900">{stats.activeCount}</p>
                <p className="text-xs text-neutral-500">Active Grants</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4">
            <div className="flex items-center gap-3">
              <XCircle className="w-8 h-8 text-neutral-400" />
              <div>
                <p className="text-2xl font-semibold text-neutral-900">{stats.inactiveCount}</p>
                <p className="text-xs text-neutral-500">Inactive</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <DisclosureFilters
        filter={filter}
        onFilterChange={setFilter}
        showStatusFilter={false}
        orgOptions={orgOptions}
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabValue)}>
        <TabsList className="grid w-full grid-cols-3 max-w-md">
          <TabsTrigger value="pending" className="flex items-center">
            <Clock className="w-4 h-4 mr-2" />
            Pending
            {renderTabCount(pendingRequests.length, 'warning')}
          </TabsTrigger>
          <TabsTrigger value="active" className="flex items-center">
            <CheckCircle2 className="w-4 h-4 mr-2" />
            Active
            {renderTabCount(activeGrants.length, 'success')}
          </TabsTrigger>
          <TabsTrigger value="inactive" className="flex items-center">
            <XCircle className="w-4 h-4 mr-2" />
            Inactive
            {renderTabCount(inactiveGrants.length, 'secondary')}
          </TabsTrigger>
        </TabsList>

        {/* Pending Requests Tab */}
        <TabsContent value="pending">
          {isLoading ? (
            <Card className="animate-pulse">
              <CardContent className="py-8">
                <div className="h-32 bg-neutral-200 rounded" />
              </CardContent>
            </Card>
          ) : pendingRequests.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Clock className="w-12 h-12 text-warning-dark mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Pending Requests</h3>
                <p className="text-neutral-500">
                  All disclosure requests have been processed.
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">Target User</TableHead>
                    <TableHead className="w-[200px]">Requester DID</TableHead>
                    <TableHead>Level</TableHead>
                    <TableHead>Created</TableHead>
                    <TableHead>Expires</TableHead>
                    {!isReadonlyAdmin && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {pendingRequests.map((request) => (
                    <TableRow
                      key={request.id}
                      className="cursor-pointer hover:bg-neutral-100"
                      onClick={() => {
                        setSelectedRequest(request);
                        setSelectedGrant(null);
                        setDetailDialogOpen(true);
                      }}
                    >
                      <TableCell className="font-mono text-xs max-w-[200px] truncate" title={request.user_id}>
                        {request.user_id}
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[200px] truncate" title={request.requester_did}>
                        {request.requester_did || '-'}
                      </TableCell>
                      <TableCell>
                        <div className="space-y-1">
                          {request.disclosure_level && (
                            <Badge
                              variant={
                                request.disclosure_level === 'full'
                                  ? 'destructive'
                                  : request.disclosure_level === 'redacted'
                                  ? 'success'
                                  : 'warning'
                              }
                            >
                              {DISCLOSURE_LEVEL_LABELS[request.disclosure_level]}
                            </Badge>
                          )}
                          {request.scope && request.scope.length > 0 && (
                            <div className="flex flex-wrap gap-0.5">
                              {request.scope.map((s) => (
                                <span key={s} className="text-[10px] text-neutral-400">{SCOPE_LABELS[s] || s}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-neutral-500">
                        {formatDate(request.created_at)}
                      </TableCell>
                      <TableCell className="text-sm text-neutral-500">
                        {formatDate(request.valid_until)}
                      </TableCell>
                      {!isReadonlyAdmin && (
                        <TableCell className="text-right">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedRequestId(request.id);
                              setDeleteDialogOpen(true);
                            }}
                          >
                            <Trash2 className="w-4 h-4 mr-1" />
                            Remove
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </TabsContent>

        {/* Active Grants Tab */}
        <TabsContent value="active">
          {isLoading ? (
            <Card className="animate-pulse">
              <CardContent className="py-8">
                <div className="h-32 bg-neutral-200 rounded" />
              </CardContent>
            </Card>
          ) : activeGrants.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <CheckCircle2 className="w-12 h-12 text-success-dark mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Active Grants</h3>
                <p className="text-neutral-500">
                  There are no active disclosure grants.
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[200px]">Target User</TableHead>
                    <TableHead className="w-[200px]">Requester DID</TableHead>
                    <TableHead>Level</TableHead>
                    <TableHead>Granted</TableHead>
                    <TableHead>Expires</TableHead>
                    {!isReadonlyAdmin && <TableHead className="text-right">Actions</TableHead>}
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {activeGrants.map((grant) => (
                    <TableRow
                      key={grant.id}
                      className="cursor-pointer hover:bg-neutral-100"
                      onClick={() => {
                        setSelectedGrant(grant);
                        setSelectedRequest(null);
                        setDetailDialogOpen(true);
                      }}
                    >
                      <TableCell className="font-mono text-xs max-w-[200px] truncate" title={grant.user_id}>
                        {grant.user_id}
                      </TableCell>
                      <TableCell className="font-mono text-xs max-w-[200px] truncate" title={grant.requester_did}>
                        {grant.requester_did || '-'}
                      </TableCell>
                      <TableCell>
                        {grant.disclosure_level && (
                          <Badge
                            variant={
                              grant.disclosure_level === 'full'
                                ? 'destructive'
                                : grant.disclosure_level === 'redacted'
                                ? 'success'
                                : 'warning'
                            }
                          >
                            {DISCLOSURE_LEVEL_LABELS[grant.disclosure_level]}
                          </Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-sm text-neutral-500">
                        {formatDate(grant.created_at)}
                      </TableCell>
                      <TableCell className="text-sm text-neutral-500">
                        {formatDate(grant.valid_until)}
                      </TableCell>
                      {!isReadonlyAdmin && (
                        <TableCell className="text-right">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedGrantId(grant.id);
                              setRevokeDialogOpen(true);
                            }}
                          >
                            <ShieldOff className="w-4 h-4 mr-1" />
                            Revoke
                          </Button>
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </TabsContent>

        {/* Inactive Tab */}
        <TabsContent value="inactive">
          {isLoading ? (
            <Card className="animate-pulse">
              <CardContent className="py-8">
                <div className="h-32 bg-neutral-200 rounded" />
              </CardContent>
            </Card>
          ) : inactiveGrants.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <XCircle className="w-12 h-12 text-neutral-400 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Inactive Grants</h3>
                <p className="text-neutral-500">
                  There are no revoked or expired grants.
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Status</TableHead>
                    <TableHead className="w-[200px]">Target User</TableHead>
                    <TableHead className="w-[200px]">Requester DID</TableHead>
                    <TableHead>Granted</TableHead>
                    <TableHead>Ended</TableHead>
                    <TableHead>Reason</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {inactiveGrants.map((grant) => {
                    const isRevoked = !!grant.revoked_at;
                    const status = isRevoked ? 'Revoked' : 'Expired';
                    const endDate = isRevoked ? grant.revoked_at : grant.valid_until;

                    return (
                      <TableRow
                        key={grant.id}
                        className="opacity-75 cursor-pointer hover:bg-neutral-100"
                        onClick={() => {
                          setSelectedGrant(grant);
                          setSelectedRequest(null);
                          setDetailDialogOpen(true);
                        }}
                      >
                        <TableCell>
                          <Badge variant={isRevoked ? 'destructive' : 'secondary'}>
                            {status}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[200px] truncate" title={grant.user_id}>
                          {grant.user_id}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[200px] truncate" title={grant.requester_did}>
                          {grant.requester_did || '-'}
                        </TableCell>
                        <TableCell className="text-sm text-neutral-500">
                          {formatDate(grant.created_at)}
                        </TableCell>
                        <TableCell className="text-sm text-neutral-500">
                          {formatDate(endDate)}
                        </TableCell>
                        <TableCell className="text-sm text-neutral-500 max-w-[200px] truncate">
                          {grant.revoke_reason || '-'}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </Card>
          )}
        </TabsContent>
      </Tabs>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-warning-dark" />
              Remove Pending Request
            </DialogTitle>
            <DialogDescription>
              Are you sure you want to remove this pending disclosure request?
              This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setDeleteDialogOpen(false);
                setSelectedRequestId(null);
              }}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleDeleteRequest}
              disabled={actionLoading}
            >
              {actionLoading ? 'Removing...' : 'Remove Request'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Revoke Confirmation Dialog */}
      <Dialog open={revokeDialogOpen} onOpenChange={setRevokeDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldOff className="w-5 h-5 text-error-dark" />
              Revoke Grant
            </DialogTitle>
            <DialogDescription>
              This will immediately revoke the disclosure grant. The requester will
              lose access to the user's data.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <label className="text-sm text-neutral-500 block mb-2">
              Reason (optional)
            </label>
            <Textarea
              value={revokeReason}
              onChange={(e) => setRevokeReason(e.target.value)}
              placeholder="Enter a reason for revocation..."
              rows={3}
            />
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setRevokeDialogOpen(false);
                setSelectedGrantId(null);
                setRevokeReason('');
              }}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRevokeGrant}
              disabled={actionLoading}
            >
              {actionLoading ? 'Revoking...' : 'Revoke Grant'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Detail Dialog */}
      <Dialog open={detailDialogOpen} onOpenChange={setDetailDialogOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>
              {selectedRequest ? 'Request Details' : 'Grant Details'}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {selectedRequest && (
              <>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Request ID</label>
                  <p className="font-mono text-sm break-all">{selectedRequest.id}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Target User ID</label>
                  <p className="font-mono text-sm break-all">{selectedRequest.user_id}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Requester DID</label>
                  <p className="font-mono text-sm break-all">{selectedRequest.requester_did || '-'}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Data Access Scope</label>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedRequest.scope && selectedRequest.scope.length > 0
                      ? selectedRequest.scope.map((s) => (
                          <span key={s} className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-primary-50 text-primary-700">
                            {SCOPE_LABELS[s] || s}
                          </span>
                        ))
                      : <span className="text-neutral-400 text-sm">-</span>}
                  </div>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Disclosure Level</label>
                  <p>{selectedRequest.disclosure_level ? DISCLOSURE_LEVEL_LABELS[selectedRequest.disclosure_level] : '-'}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Purpose</label>
                  <p className="text-sm">{selectedRequest.purpose || '-'}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Legal Basis</label>
                  <p className="text-sm">{selectedRequest.legal_basis || '-'}</p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-neutral-500 uppercase tracking-wide">Created</label>
                    <p className="text-sm">{formatDate(selectedRequest.created_at)}</p>
                  </div>
                  <div>
                    <label className="text-xs text-neutral-500 uppercase tracking-wide">Expires</label>
                    <p className="text-sm">{formatDate(selectedRequest.valid_until)}</p>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Status</label>
                  <p className="capitalize">{selectedRequest.status}</p>
                </div>
              </>
            )}
            {selectedGrant && (
              <>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Grant ID</label>
                  <p className="font-mono text-sm break-all">{selectedGrant.id}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Request ID</label>
                  <p className="font-mono text-sm break-all">{selectedGrant.request_id}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Target User ID</label>
                  <p className="font-mono text-sm break-all">{selectedGrant.user_id}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Requester DID</label>
                  <p className="font-mono text-sm break-all">{selectedGrant.requester_did || '-'}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Disclosure Level</label>
                  <p>{selectedGrant.disclosure_level ? DISCLOSURE_LEVEL_LABELS[selectedGrant.disclosure_level] : '-'}</p>
                </div>
                <div>
                  <label className="text-xs text-neutral-500 uppercase tracking-wide">Reason</label>
                  <p className="text-sm">{selectedGrant.reason || '-'}</p>
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-neutral-500 uppercase tracking-wide">Granted At</label>
                    <p className="text-sm">{formatDate(selectedGrant.created_at)}</p>
                  </div>
                  <div>
                    <label className="text-xs text-neutral-500 uppercase tracking-wide">Expires At</label>
                    <p className="text-sm">{formatDate(selectedGrant.valid_until)}</p>
                  </div>
                </div>
                {selectedGrant.revoked_at && (
                  <div>
                    <label className="text-xs text-neutral-500 uppercase tracking-wide">Revoked At</label>
                    <p className="text-sm">{formatDate(selectedGrant.revoked_at)}</p>
                  </div>
                )}
              </>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetailDialogOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Request Dialog */}
      <Dialog open={createDialogOpen} onOpenChange={setCreateDialogOpen}>
        <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Create Disclosure Request</DialogTitle>
            <DialogDescription>
              Create a new disclosure request for a user's data
            </DialogDescription>
          </DialogHeader>
          <CreateDisclosureRequestForm
            onSubmit={handleCreateRequest}
            onCancel={() => setCreateDialogOpen(false)}
            isLoading={isCreating}
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default AdminDisclosureDashboard;
