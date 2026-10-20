import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, FileText, Key, RefreshCw, Check, AlertCircle, ArrowLeft } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { useAuth } from '@/contexts/AuthContext';
import { disclosureApi } from '@/api/disclosure';
import { DisclosureRequestCard, DisclosureGrantCard } from '@/components/disclosure';
import type { DisclosureRequest, DisclosureGrant } from '@/types/disclosure';

export function DisclosurePage() {
  const navigate = useNavigate();
  const { isAuthenticated, accessToken, isLoading: isAuthLoading } = useAuth();

  const [pendingRequests, setPendingRequests] = useState<DisclosureRequest[]>([]);
  const [activeGrants, setActiveGrants] = useState<DisclosureGrant[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Success dialog state
  const [showSuccessDialog, setShowSuccessDialog] = useState(false);

  // Redirect if not authenticated (wait for auth to load first)
  useEffect(() => {
    if (!isAuthLoading && !isAuthenticated) {
      navigate('/login');
    }
  }, [isAuthenticated, isAuthLoading, navigate, accessToken]);

  const loadData = useCallback(async () => {
    if (!accessToken) return;

    setIsLoading(true);
    setError(null);

    try {
      const [requestsResponse, grantsResponse] = await Promise.all([
        disclosureApi.user.getMyRequests(accessToken),
        disclosureApi.user.getMyGrants(accessToken),
      ]);

      // Filter to only show pending requests
      setPendingRequests(
        requestsResponse.data.filter((r) => r.status === 'pending')
      );
      setActiveGrants(grantsResponse.data);
    } catch (err) {
      console.error('Failed to load disclosure data:', err);
      setError('Failed to load disclosure data. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }, [accessToken]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleApprove = async (requestId: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.approveRequest(accessToken, requestId);
      setShowSuccessDialog(true);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to approve request:', err);
      setError('Failed to approve request. Please try again.');
    }
  };

  const handleReject = async (requestId: string, reason?: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.rejectRequest(accessToken, requestId, reason ? { reason } : undefined);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to reject request:', err);
      setError('Failed to reject request. Please try again.');
    }
  };

  const handleRevoke = async (requestId: string, reason?: string) => {
    if (!accessToken) return;

    try {
      await disclosureApi.user.revokeRequest(accessToken, requestId, reason ? { reason } : undefined);
      // Reload data to reflect changes
      await loadData();
    } catch (err) {
      console.error('Failed to revoke grant:', err);
      setError('Failed to revoke grant. Please try again.');
    }
  };


  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="min-h-screen bg-neutral-100 p-4">
      <div className="max-w-2xl mx-auto animate-fade-in">
        {/* Header */}
        <div className="mb-8">
          <Button
            onClick={() => navigate('/success')}
            variant="ghost"
            size="sm"
            className="mb-4"
          >
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Dashboard
          </Button>

          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary to-primary-300 flex items-center justify-center shadow-lg shadow-primary">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-neutral-900">Data Disclosure</h1>
              <p className="text-neutral-500">Manage access to your data</p>
            </div>
          </div>
        </div>

        {/* Error Alert */}
        {error && (
          <Card variant="default" className="mb-4 border-error-light">
            <CardContent className="py-4">
              <div className="flex items-center gap-3">
                <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0" />
                <p className="text-error-dark text-sm flex-1">{error}</p>
                <Button
                  onClick={() => setError(null)}
                  variant="ghost"
                  size="sm"
                >
                  Dismiss
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Info Card */}
        <Card variant="default" className="mb-6">
          <CardContent className="py-4">
            <div className="flex items-start gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center flex-shrink-0">
                <FileText className="w-5 h-5 text-primary" />
              </div>
              <div>
                <h3 className="text-neutral-900 font-medium">Selective Disclosure</h3>
                <p className="text-neutral-500 text-sm mt-1">
                  Review and manage requests from auditors, regulators, and other parties
                  who need access to your activity data. You control what data is shared
                  and can revoke access at any time.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Pending Requests Section */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-neutral-900">Pending Requests</h2>
              {pendingRequests.length > 0 && (
                <Badge variant="warning">{pendingRequests.length}</Badge>
              )}
            </div>
            <Button
              onClick={loadData}
              variant="ghost"
              size="sm"
              disabled={isLoading}
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>

          {isLoading ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-neutral-400 animate-spin mx-auto mb-3" />
                <p className="text-neutral-500">Loading requests...</p>
              </CardContent>
            </Card>
          ) : pendingRequests.length === 0 ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <Shield className="w-12 h-12 text-neutral-300 mx-auto mb-3" />
                <p className="text-neutral-500">No pending disclosure requests</p>
                <p className="text-neutral-400 text-sm mt-1">
                  You will be notified when someone requests access to your data
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {pendingRequests.map((request) => (
                <DisclosureRequestCard
                  key={request.id}
                  request={request}
                  onApprove={handleApprove}
                  onReject={handleReject}
                  isLoading={isLoading}
                />
              ))}
            </div>
          )}
        </div>

        {/* Active Grants Section */}
        <div>
          <div className="flex items-center gap-2 mb-4">
            <h2 className="text-lg font-semibold text-neutral-900">Active Data Access Grants</h2>
            {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length > 0 && (
              <Badge variant="success">
                {activeGrants.filter((g) => !g.revoked_at && new Date(g.valid_until) > new Date()).length}
              </Badge>
            )}
          </div>

          {isLoading ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <RefreshCw className="w-8 h-8 text-neutral-400 animate-spin mx-auto mb-3" />
                <p className="text-neutral-500">Loading grants...</p>
              </CardContent>
            </Card>
          ) : activeGrants.length === 0 ? (
            <Card variant="default">
              <CardContent className="py-12 text-center">
                <Key className="w-12 h-12 text-neutral-300 mx-auto mb-3" />
                <p className="text-neutral-500">No active data access grants</p>
                <p className="text-neutral-400 text-sm mt-1">
                  Grants you approve will appear here
                </p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-4">
              {activeGrants.map((grant) => (
                <DisclosureGrantCard
                  key={grant.id}
                  grant={grant}
                  onRevoke={handleRevoke}
                  isLoading={isLoading}
                />
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Success Dialog */}
      <Dialog open={showSuccessDialog} onOpenChange={setShowSuccessDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Check className="w-5 h-5 text-success-dark" />
              Access Granted Successfully
            </DialogTitle>
          </DialogHeader>

          <div className="py-4">
            <div className="p-4 bg-success-light border border-success/30 rounded-lg">
              <p className="text-sm text-success-dark">
                The disclosure request has been approved. The authorized auditor can now
                access your data through their authenticated session.
              </p>
            </div>
          </div>

          <div className="flex justify-end">
            <Button onClick={() => setShowSuccessDialog(false)}>
              Done
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default DisclosurePage;
