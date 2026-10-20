import { useState } from 'react';
import { Clock, Building2, FileText, Shield, Check, X, AlertTriangle } from 'lucide-react';
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
import type { DisclosureRequest } from '@/types/disclosure';
import {
  SCOPE_LABELS,
  SCOPE_DESCRIPTIONS,
  STATUS_LABELS,
  STATUS_VARIANTS,
  DISCLOSURE_LEVEL_LABELS,
  DISCLOSURE_LEVEL_DESCRIPTIONS,
} from '@/types/disclosure';

interface DisclosureRequestCardProps {
  request: DisclosureRequest;
  onApprove?: (requestId: string) => Promise<void>;
  onReject?: (requestId: string, reason?: string) => Promise<void>;
  showActions?: boolean;
  isLoading?: boolean;
}

export function DisclosureRequestCard({
  request,
  onApprove,
  onReject,
  showActions = true,
  isLoading = false,
}: DisclosureRequestCardProps) {
  const [showApproveDialog, setShowApproveDialog] = useState(false);
  const [showRejectDialog, setShowRejectDialog] = useState(false);
  const [rejectReason, setRejectReason] = useState('');
  const [actionLoading, setActionLoading] = useState(false);

  const isPending = request.status === 'pending';
  const canTakeAction = isPending && showActions && (onApprove || onReject);

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A';
    return new Date(dateString).toLocaleString();
  };

  const handleApprove = async () => {
    if (!onApprove) return;
    setActionLoading(true);
    try {
      await onApprove(request.id);
      setShowApproveDialog(false);
    } finally {
      setActionLoading(false);
    }
  };

  const handleReject = async () => {
    if (!onReject) return;
    setActionLoading(true);
    try {
      await onReject(request.id, rejectReason || undefined);
      setShowRejectDialog(false);
      setRejectReason('');
    } finally {
      setActionLoading(false);
    }
  };

  return (
    <>
      <Card variant="default" className="overflow-hidden">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-primary-50 flex items-center justify-center">
                <Shield className="w-5 h-5 text-primary" />
              </div>
              <div>
                <CardTitle className="text-base">{request.requester_name}</CardTitle>
                {request.requester_org && (
                  <div className="flex items-center gap-1 text-neutral-500 text-sm mt-0.5">
                    <Building2 className="w-3 h-3" />
                    <span>{request.requester_org}</span>
                  </div>
                )}
              </div>
            </div>
            <Badge variant={STATUS_VARIANTS[request.status]}>
              {STATUS_LABELS[request.status]}
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {/* Purpose */}
          <div>
            <label className="text-xs text-neutral-400 uppercase tracking-wide">Purpose</label>
            <p className="text-neutral-900 text-sm mt-1">{request.purpose}</p>
          </div>

          {/* Legal Basis */}
          {request.legal_basis && (
            <div>
              <label className="text-xs text-neutral-400 uppercase tracking-wide">Legal Basis</label>
              <p className="text-neutral-700 text-sm mt-1">{request.legal_basis}</p>
            </div>
          )}

          {/* Reference */}
          {request.request_reference && (
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-neutral-400" />
              <span className="text-neutral-500 text-sm">Ref: {request.request_reference}</span>
            </div>
          )}

          {/* Scope */}
          <div>
            <label className="text-xs text-neutral-400 uppercase tracking-wide mb-2 block">
              Requested Data Access
            </label>
            <div className="flex flex-wrap gap-2">
              {request.scope.map((scope) => (
                <div
                  key={scope}
                  className="group relative"
                  title={SCOPE_DESCRIPTIONS[scope]}
                >
                  <Badge variant="outline" className="text-xs">
                    {SCOPE_LABELS[scope]}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* Disclosure Level */}
          {request.disclosure_level && (
            <div>
              <label className="text-xs text-neutral-400 uppercase tracking-wide mb-2 block">
                Address Visibility
              </label>
              <div
                className="group relative inline-block"
                title={DISCLOSURE_LEVEL_DESCRIPTIONS[request.disclosure_level]}
              >
                <Badge
                  variant={
                    request.disclosure_level === 'full'
                      ? 'destructive'
                      : request.disclosure_level === 'redacted'
                      ? 'success'
                      : 'warning'
                  }
                  className="text-xs"
                >
                  {DISCLOSURE_LEVEL_LABELS[request.disclosure_level]}
                </Badge>
              </div>
              <p className="text-xs text-neutral-400 mt-1">
                {DISCLOSURE_LEVEL_DESCRIPTIONS[request.disclosure_level]}
              </p>
            </div>
          )}

          {/* Validity Period */}
          <div className="flex items-center gap-4 text-sm">
            <div className="flex items-center gap-2 text-neutral-500">
              <Clock className="w-4 h-4" />
              <span>
                {request.valid_from && request.valid_until
                  ? `${formatDate(request.valid_from)} - ${formatDate(request.valid_until)}`
                  : request.valid_until
                  ? `Until ${formatDate(request.valid_until)}`
                  : 'No expiration set'}
              </span>
            </div>
          </div>

          {/* Request ID and Timestamps */}
          <div className="text-xs text-neutral-400 pt-2 border-t border-neutral-200 space-y-1">
            <div className="flex items-center justify-between">
              <span>Requested on {formatDate(request.created_at)}</span>
            </div>
            <div className="flex items-center gap-2 font-mono">
              <span className="text-neutral-300">ID:</span>
              <span className="text-neutral-400">{request.id}</span>
            </div>
            {(request.target_did || request.user_id) && (
              <div className="flex items-center gap-2 font-mono">
                <span className="text-neutral-300">Target User:</span>
                <span className="text-neutral-400">{request.target_did || request.user_id}</span>
              </div>
            )}
            {request.target_did && request.user_id && (
              <div className="flex items-center gap-2 font-mono">
                <span className="text-neutral-300">User ID:</span>
                <span className="text-neutral-400">{request.user_id}</span>
              </div>
            )}
          </div>

          {/* Actions */}
          {canTakeAction && (
            <div className="flex items-center gap-3 pt-2">
              {onApprove && (
                <Button
                  onClick={() => setShowApproveDialog(true)}
                  variant="success"
                  size="sm"
                  disabled={isLoading}
                  className="flex-1"
                >
                  <Check className="w-4 h-4 mr-2" />
                  Approve
                </Button>
              )}
              {onReject && (
                <Button
                  onClick={() => setShowRejectDialog(true)}
                  variant="destructive"
                  size="sm"
                  disabled={isLoading}
                  className="flex-1"
                >
                  <X className="w-4 h-4 mr-2" />
                  Reject
                </Button>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Approve Confirmation Dialog */}
      <Dialog open={showApproveDialog} onOpenChange={setShowApproveDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-warning-dark" />
              Approve Disclosure Request
            </DialogTitle>
            <DialogDescription>
              You are about to grant {request.requester_name} access to your data.
              The authorized party will be able to view data through their authenticated session.
            </DialogDescription>
          </DialogHeader>

          <div className="py-4 space-y-3">
            <div>
              <p className="text-sm text-neutral-500">Data that will be accessible:</p>
              <div className="flex flex-wrap gap-2 mt-1">
                {request.scope.map((scope) => (
                  <Badge key={scope} variant="outline" className="text-xs">
                    {SCOPE_LABELS[scope]}
                  </Badge>
                ))}
              </div>
            </div>
            {request.disclosure_level && (
              <div>
                <p className="text-sm text-neutral-500">Address visibility:</p>
                <div className="mt-1">
                  <Badge
                    variant={
                      request.disclosure_level === 'full'
                        ? 'destructive'
                        : request.disclosure_level === 'redacted'
                        ? 'success'
                        : 'warning'
                    }
                    className="text-xs"
                  >
                    {DISCLOSURE_LEVEL_LABELS[request.disclosure_level]}
                  </Badge>
                  <p className="text-xs text-neutral-400 mt-1">
                    {DISCLOSURE_LEVEL_DESCRIPTIONS[request.disclosure_level]}
                  </p>
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowApproveDialog(false)}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="success"
              onClick={handleApprove}
              disabled={actionLoading}
            >
              {actionLoading ? 'Approving...' : 'Approve Access'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Reject Confirmation Dialog */}
      <Dialog open={showRejectDialog} onOpenChange={setShowRejectDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reject Disclosure Request</DialogTitle>
            <DialogDescription>
              You are about to reject the disclosure request from {request.requester_name}.
              You can optionally provide a reason.
            </DialogDescription>
          </DialogHeader>

          <div className="py-4">
            <label className="text-sm text-neutral-500 block mb-2">
              Reason (optional)
            </label>
            <Textarea
              value={rejectReason}
              onChange={(e) => setRejectReason(e.target.value)}
              placeholder="Enter a reason for rejection..."
              rows={3}
            />
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setShowRejectDialog(false);
                setRejectReason('');
              }}
              disabled={actionLoading}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={handleReject}
              disabled={actionLoading}
            >
              {actionLoading ? 'Rejecting...' : 'Reject Request'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default DisclosureRequestCard;
