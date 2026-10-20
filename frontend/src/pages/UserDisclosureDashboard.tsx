import { useState, useEffect, useMemo } from 'react';
import { Shield, CheckCircle2, Clock, XCircle, RefreshCw, AlertTriangle } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { DisclosureRequestCard } from '@/components/disclosure/DisclosureRequestCard';
import { DisclosureGrantCard } from '@/components/disclosure/DisclosureGrantCard';
import { DisclosureFilters } from '@/components/disclosure/DisclosureFilters';
import { disclosureApi } from '@/api/disclosure';
import type { DisclosureRequest, DisclosureGrant, DisclosureFilter } from '@/types/disclosure';

interface UserDisclosureDashboardProps {
  accessToken: string;
}

type TabValue = 'active' | 'pending' | 'inactive';

export function UserDisclosureDashboard({ accessToken }: UserDisclosureDashboardProps) {
  const [activeTab, setActiveTab] = useState<TabValue>('active');
  const [requests, setRequests] = useState<DisclosureRequest[]>([]);
  const [grants, setGrants] = useState<DisclosureGrant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<DisclosureFilter>({});

  const fetchData = async () => {
    setIsLoading(true);
    setError(null);

    try {
      const [requestsRes, grantsRes] = await Promise.all([
        disclosureApi.user.getAllMyRequests(accessToken),
        disclosureApi.user.getAllMyGrants(accessToken),
      ]);
      setRequests(requestsRes.data || []);
      setGrants(grantsRes.data || []);
    } catch (err) {
      console.error('Failed to fetch disclosure data:', err);
      setError('Failed to load disclosure data. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  // reason: intentional reload-on-accessToken. fetchData is a non-memoised
  // helper that reads current state via closure; adding it to deps would require
  // useCallback and risk a refetch loop.
  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [accessToken]);

  // Filter and categorize data
  const { pendingRequests, activeGrants, inactiveItems } = useMemo(() => {
    const now = new Date();

    // Apply filters to requests
    const filteredRequests = requests.filter((req) => {
      if (filter.requester_did && !req.requester_did?.toLowerCase().includes(filter.requester_did.toLowerCase())) {
        return false;
      }
      if (filter.disclosure_level && req.disclosure_level !== filter.disclosure_level) {
        return false;
      }
      if (filter.date_from && new Date(req.created_at) < new Date(filter.date_from)) {
        return false;
      }
      if (filter.date_to && new Date(req.created_at) > new Date(filter.date_to)) {
        return false;
      }
      return true;
    });

    // Apply filters to grants
    const filteredGrants = grants.filter((grant) => {
      if (filter.requester_did && !grant.requester_did?.toLowerCase().includes(filter.requester_did.toLowerCase())) {
        return false;
      }
      if (filter.disclosure_level && grant.disclosure_level !== filter.disclosure_level) {
        return false;
      }
      if (filter.date_from && new Date(grant.created_at) < new Date(filter.date_from)) {
        return false;
      }
      if (filter.date_to && new Date(grant.created_at) > new Date(filter.date_to)) {
        return false;
      }
      return true;
    });

    // Pending requests
    const pending = filteredRequests.filter((req) => req.status === 'pending');

    // Active grants (not revoked, not expired)
    const active = filteredGrants.filter((grant) => {
      const isRevoked = !!grant.revoked_at;
      const isExpired = new Date(grant.valid_until) < now;
      return !isRevoked && !isExpired;
    });

    // Inactive: rejected requests, revoked grants, expired grants
    const inactive: Array<{ type: 'request' | 'grant'; item: DisclosureRequest | DisclosureGrant }> = [];

    // Add rejected/revoked/expired requests
    filteredRequests
      .filter((req) => ['rejected', 'revoked', 'expired'].includes(req.status))
      .forEach((req) => {
        inactive.push({ type: 'request', item: req });
      });

    // Add revoked or expired grants
    filteredGrants
      .filter((grant) => {
        const isRevoked = !!grant.revoked_at;
        const isExpired = new Date(grant.valid_until) < now;
        return isRevoked || isExpired;
      })
      .forEach((grant) => {
        inactive.push({ type: 'grant', item: grant });
      });

    // Sort inactive by date (most recent first)
    inactive.sort((a, b) => {
      const dateA = new Date(a.item.updated_at || a.item.created_at);
      const dateB = new Date(b.item.updated_at || b.item.created_at);
      return dateB.getTime() - dateA.getTime();
    });

    return {
      pendingRequests: pending,
      activeGrants: active,
      inactiveItems: inactive,
    };
  }, [requests, grants, filter]);

  const handleApprove = async (requestId: string) => {
    await disclosureApi.user.approveRequest(accessToken, requestId);
    await fetchData();
  };

  const handleReject = async (requestId: string, reason?: string) => {
    await disclosureApi.user.rejectRequest(accessToken, requestId, reason ? { reason } : undefined);
    await fetchData();
  };

  const handleRevoke = async (requestId: string, reason?: string) => {
    await disclosureApi.user.revokeRequest(accessToken, requestId, reason ? { reason } : undefined);
    await fetchData();
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
            <h1 className="text-xl font-semibold text-neutral-900">Data Disclosures</h1>
            <p className="text-sm text-neutral-500">
              Manage who can access your activity data
            </p>
          </div>
        </div>
        <Button variant="outline" size="sm" onClick={fetchData} disabled={isLoading}>
          <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {/* Filters */}
      <DisclosureFilters
        filter={filter}
        onFilterChange={setFilter}
        showStatusFilter={false}
      />

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabValue)}>
        <TabsList className="grid w-full grid-cols-3 max-w-md">
          <TabsTrigger value="active" className="flex items-center">
            <CheckCircle2 className="w-4 h-4 mr-2" />
            Active
            {renderTabCount(activeGrants.length, 'success')}
          </TabsTrigger>
          <TabsTrigger value="pending" className="flex items-center">
            <Clock className="w-4 h-4 mr-2" />
            Pending
            {renderTabCount(pendingRequests.length, 'warning')}
          </TabsTrigger>
          <TabsTrigger value="inactive" className="flex items-center">
            <XCircle className="w-4 h-4 mr-2" />
            Inactive
            {renderTabCount(inactiveItems.length, 'secondary')}
          </TabsTrigger>
        </TabsList>

        {/* Active Tab */}
        <TabsContent value="active">
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[1, 2].map((i) => (
                <Card key={i} className="animate-pulse">
                  <CardHeader className="pb-3">
                    <div className="h-10 bg-neutral-200 rounded w-3/4" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="h-4 bg-neutral-200 rounded w-full" />
                      <div className="h-4 bg-neutral-200 rounded w-2/3" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : activeGrants.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <CheckCircle2 className="w-12 h-12 text-success-dark mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Active Grants</h3>
                <p className="text-neutral-500">
                  You have not approved any disclosure requests yet.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {activeGrants.map((grant) => (
                <DisclosureGrantCard
                  key={grant.id}
                  grant={grant}
                  onRevoke={handleRevoke}
                  showActions={true}
                />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Pending Tab */}
        <TabsContent value="pending">
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[1, 2].map((i) => (
                <Card key={i} className="animate-pulse">
                  <CardHeader className="pb-3">
                    <div className="h-10 bg-neutral-200 rounded w-3/4" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="h-4 bg-neutral-200 rounded w-full" />
                      <div className="h-4 bg-neutral-200 rounded w-2/3" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : pendingRequests.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Clock className="w-12 h-12 text-warning-dark mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Pending Requests</h3>
                <p className="text-neutral-500">
                  There are no disclosure requests awaiting your approval.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {pendingRequests.map((request) => (
                <DisclosureRequestCard
                  key={request.id}
                  request={request}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  showActions={true}
                />
              ))}
            </div>
          )}
        </TabsContent>

        {/* Inactive Tab */}
        <TabsContent value="inactive">
          {isLoading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {[1, 2].map((i) => (
                <Card key={i} className="animate-pulse">
                  <CardHeader className="pb-3">
                    <div className="h-10 bg-neutral-200 rounded w-3/4" />
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      <div className="h-4 bg-neutral-200 rounded w-full" />
                      <div className="h-4 bg-neutral-200 rounded w-2/3" />
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : inactiveItems.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <XCircle className="w-12 h-12 text-neutral-400 mx-auto mb-4 opacity-50" />
                <h3 className="text-lg font-medium text-neutral-900 mb-2">No Inactive Items</h3>
                <p className="text-neutral-500">
                  You have no rejected, revoked, or expired disclosures.
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {inactiveItems.map(({ type, item }) =>
                type === 'request' ? (
                  <DisclosureRequestCard
                    key={`req-${item.id}`}
                    request={item as DisclosureRequest}
                    showActions={false}
                  />
                ) : (
                  <DisclosureGrantCard
                    key={`grant-${item.id}`}
                    grant={item as DisclosureGrant}
                    showActions={false}
                  />
                )
              )}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default UserDisclosureDashboard;
