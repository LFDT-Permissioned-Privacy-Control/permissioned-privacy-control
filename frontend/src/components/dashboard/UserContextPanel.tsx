import { useState, useEffect, useRef } from 'react';
import { Badge } from '@/components/ui/badge';
import { testApi } from '@/api/client';
import { getClosestPresetLabel } from '@/types/rbac';
import { Loader2, User, AlertTriangle } from 'lucide-react';

function parseJWT(token: string): { sub?: string; exp?: number } | null {
  try {
    const base64Url = token.split('.')[1];
    if (!base64Url) return null;
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

export interface UserLookupResult {
  user: { id: string; external_id: string; kyc: boolean; banned: boolean };
  memberships: Array<{
    membership: { id: string; group_id: string; source: string };
    group: { id: string; org_id: string; name: string; path: string };
  }>;
  linkedAddresses: Array<{ address: string; verified_at: string }>;
  orgGroupsMap: Record<string, Array<{
    group: { id: string; name: string; path: string };
    access: { claims: string[] } | null;
  }>>;
  orgNames: Record<string, string>;
}

interface UserContextPanelProps {
  jwtToken: string;
  onUserLoaded?: (data: UserLookupResult | null) => void;
}

export function UserContextPanel({ jwtToken, onUserLoaded }: UserContextPanelProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<UserLookupResult | null>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const lastDid = useRef<string>('');

  // reason: debounced lookup keyed on jwtToken only. `data` is read at line 64
  // purely as a guard to skip a redundant refetch for the same DID (it is set
  // inside this effect, so listing it would loop). `onUserLoaded` is a parent
  // callback invoked as a side effect, not a trigger — adding it would refire
  // the effect whenever the parent re-renders without memoising it. Both are
  // intentionally omitted.
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);

    const claims = parseJWT(jwtToken);
    const did = claims?.sub || '';

    if (!did || !jwtToken.includes('.')) {
      setData(null);
      onUserLoaded?.(null);
      setError(null);
      lastDid.current = '';
      return;
    }

    if (did === lastDid.current && data) return;

    debounceRef.current = setTimeout(async () => {
      lastDid.current = did;
      setLoading(true);
      setError(null);
      try {
        const result = await testApi.lookupUser(did);
        if (!result) {
          setError('User not found for this DID');
          setData(null);
          onUserLoaded?.(null);
        } else {
          setData(result);
          onUserLoaded?.(result);
        }
      } catch {
        setError('Failed to look up user');
        setData(null);
        onUserLoaded?.(null);
      } finally {
        setLoading(false);
      }
    }, 500);

    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jwtToken]);

  if (!jwtToken || !jwtToken.includes('.')) return null;

  if (loading) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-primary-50 border border-primary-50 text-sm text-neutral-500">
        <Loader2 className="w-4 h-4 animate-spin" />
        Looking up user...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 p-3 rounded-lg bg-warning-light border border-warning/40 text-sm text-warning-dark">
        <AlertTriangle className="w-4 h-4" />
        {error}
      </div>
    );
  }

  if (!data) return null;

  const { user, memberships, linkedAddresses, orgGroupsMap, orgNames } = data;

  // Group memberships by org
  const membershipsByOrg: Record<string, typeof memberships> = {};
  for (const m of memberships) {
    const orgId = m.group.org_id;
    if (!membershipsByOrg[orgId]) membershipsByOrg[orgId] = [];
    membershipsByOrg[orgId].push(m);
  }

  return (
    <div className="p-3 rounded-lg bg-primary-50 border border-primary-50 space-y-3 animate-fade-in" data-testid="user-context-panel">
      {/* Header */}
      <div className="flex items-center gap-2">
        <User className="w-4 h-4 text-purple-600" />
        <span className="text-sm font-mono text-neutral-700 truncate" title={user.external_id}>
          {user.external_id.length > 40
            ? user.external_id.slice(0, 20) + '...' + user.external_id.slice(-12)
            : user.external_id}
        </span>
      </div>

      {/* Status badges */}
      <div className="flex items-center gap-2">
        <Badge variant="outline" className={user.kyc
          ? 'text-green-700 border-green-300 bg-green-50'
          : 'text-yellow-700 border-yellow-300 bg-yellow-50'
        }>
          KYC {user.kyc ? 'Verified' : 'Unverified'}
        </Badge>
        {user.banned && (
          <Badge variant="destructive">Banned</Badge>
        )}
        {!user.banned && (
          <Badge variant="outline" className="text-green-700 border-green-300 bg-green-50">Active</Badge>
        )}
      </div>

      {/* Groups by org */}
      {Object.keys(membershipsByOrg).length > 0 && (
        <div>
          <div className="text-xs font-medium text-neutral-500 mb-1.5">Groups</div>
          {Object.entries(membershipsByOrg).map(([orgId, orgMemberships]) => (
            <div key={orgId} className="mb-2">
              <div className="text-xs text-neutral-400 mb-1">{orgNames[orgId] || 'Unknown Org'}</div>
              <div className="space-y-1">
                {orgMemberships.map((m) => {
                  // Find group access for this group
                  const orgGroups = orgGroupsMap[orgId] || [];
                  const groupWithAccess = orgGroups.find(g => g.group.id === m.group.id);
                  const claims = groupWithAccess?.access?.claims || [];

                  // Build method list from the access object
                  const methods = groupWithAccess?.access ? (
                    (groupWithAccess.access as { allowed_methods?: string[] }).allowed_methods || []
                  ) : [];
                  const filteredMethods = methods.filter((m: string) => m !== '*');

                  return (
                    <div key={m.membership.id} className="flex items-center gap-2 text-sm">
                      <span className="text-neutral-700">{m.group.name}</span>
                      <span className="text-neutral-400">&mdash;</span>
                      {filteredMethods.length > 0 ? (
                        <Badge
                          variant="outline"
                          className="text-xs py-0 bg-primary-50 text-primary border-primary-200"
                        >
                          {getClosestPresetLabel(filteredMethods)}
                        </Badge>
                      ) : claims.length > 0 ? (
                        <Badge
                          variant="outline"
                          className="text-xs py-0 bg-primary-50 text-primary border-primary-200"
                        >
                          {getClosestPresetLabel([])}
                        </Badge>
                      ) : (
                        <span className="text-xs text-neutral-400">No permissions</span>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* ETH Addresses */}
      {linkedAddresses.length > 0 && (
        <div>
          <div className="text-xs font-medium text-neutral-500 mb-1">ETH Addresses</div>
          <div className="flex flex-wrap gap-1.5">
            {linkedAddresses.map((addr) => (
              <span key={addr.address} className="text-xs font-mono text-neutral-700 bg-white/60 px-1.5 py-0.5 rounded border border-primary-50">
                {addr.address.slice(0, 6)}...{addr.address.slice(-4)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
