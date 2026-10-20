import { useState } from 'react';
import { Clock, Key, ShieldOff, AlertTriangle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import type { DisclosureGrant } from '@/types/disclosure';
import { SCOPE_LABELS } from '@/types/disclosure';

interface DisclosureGrantCardProps {
  grant: DisclosureGrant;
  onRevoke?: (requestId: string, reason?: string) => Promise<void>;
  showActions?: boolean;
  isLoading?: boolean;
}

export function DisclosureGrantCard({
  grant,
  onRevoke,
  showActions = true,
  isLoading = false,
}: DisclosureGrantCardProps) {
  const [showRevokeDialog, setShowRevokeDialog] = useState(false);
  const [revokeReason, setRevokeReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const isRevoked = !!grant.revoked_at;
  const isExpired = new Date(grant.valid_until) < new Date();
  const isActive = !isRevoked && !isExpired;

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleString();
  };

  const getStatusBadge = () => {
    if (isRevoked) {
      return <Badge variant="destructive">Revoked</Badge>;
    }
    if (isExpired) {
      return <Badge variant="secondary">Expired</Badge>;
    }
    return <Badge variant="success">Active</Badge>;
  };

  const getTimeRemaining = () => {
    if (isRevoked || isExpired) return null;

    const now = new Date();
    const validUntil = new Date(grant.valid_until);
    const diff = validUntil.getTime() - now.getTime();

    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

    if (days > 0) {
      return `${days} day${days !== 1 ? 's' : ''} remaining`;
    }
    if (hours > 0) {
      return `${hours} hour${hours !== 1 ? 's' : ''} remaining`;
    }
    return 'Less than an hour remaining';
  };

  const handleRevoke = async () => {
    if (!onRevoke) return;
    setActionLoading(true);
    try {
      await onRevoke(grant.request_id, revokeReason || undefined);
      setShowRevokeDialog(false);
      setRevokeReason('');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <Card variant="default" className={isActive ? '' : 'opacity-75'}>
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                isActive ? 'bg-success-light' : 'bg-neutral-100'
              }`}>
                <Key className={`w-5 h-5 ${isActive ? 'text-success-dark' : 'text-neutral-400'}`} />
              </div>
              <div>
                <CardTitle className="text-base">
                  Data Access Grant
                </CardTitle>
                <div className="text-neutral-500 text-sm mt-0.5">
                  ID: {grant.id.slice(0, 8)}...
                </div>
              </div>
            </div>
            {getStatusBadge()}
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Scope */}
          <div>
            <label className="text-xs text-neutral-400 uppercase tracking-wide mb-2 block">
              Granted Access
            </label>
            <div className="flex flex-wrap gap-2">
              {grant.scope.map((scope) => (
                <Badge key={scope} variant="outline" className="text-xs">
                  {SCOPE_LABELS[scope]}
                </Badge>
              ))}
            </div>
          </div>

          {/* Validity Period */}
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-neutral-500">
              <Clock className="w-4 h-4" />
              <span>Valid: {formatDate(grant.valid_from)} - {formatDate(grant.valid_until)}</span>
            </div>
            {getTimeRemaining() && (
              <p className="text-sm text-success-dark ml-6">{getTimeRemaining()}</p>
            )}
          </div>

          {/* Revocation Info */}
          {isRevoked && grant.revoked_at && (
            <div className="p-3 bg-error-light border border-error/30 rounded-lg">
              <p className="text-sm text-error-dark">
                Revoked on {formatDate(grant.revoked_at)}
              </p>
              {grant.revoke_reason && (
                <p className="text-sm text-neutral-700 mt-1">
                  Reason: {grant.revoke_reason}
                </p>
              )}
            </div>
          )}

          {/* Timestamps */}
          <div className="text-xs text-neutral-400 pt-2 border-t border-neutral-200">
            Granted on {formatDate(grant.created_at)}
          </div>

          {/* Revoke Action */}
          {isActive && showActions && onRevoke && (
            <div className="pt-2">
              <Button
                onClick={() => setShowRevokeDialog(true)}
                variant="destructive"
                size="sm"
                disabled={isLoading}
                className="w-full"
              >
                <ShieldOff className="w-4 h-4 mr-2" />
                Revoke Access
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Revoke Confirmation Dialog */}
      <Dialog open={showRevokeDialog} onOpenChange={setShowRevokeDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-error-dark" />
              Revoke Data Access
            </DialogTitle>
            <DialogDescription>
              You are about to revoke this data access grant. The requester will immediately
              lose access to your data. This action cannot be undone.
            </DialogDescription>
          </DialogHeader>

          <div className="py-4">
            <div className="mb-4 space-y-2">
              <p className="text-sm text-neutral-500">Access being revoked:</p>
              <div className="flex flex-wrap gap-2">
                {grant.scope.map((scope) => (
                  <Badge key={scope} variant="outline" className="text-xs">
                    {SCOPE_LABELS[scope]}
                  </Badge>
                ))}
              </div>
            </div>

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
                setShowRevokeDialog(false);
                setRevokeReason('');
              }}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleRevoke}
              disabled={actionLoading}
            >
              {actionLoading ? 'Revoking...' : 'Revoke Access'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default DisclosureGrantCard;
