import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Copy, Check, Wallet, Building2, LogOut,
  Clock, ShieldCheck, ShieldX, KeyRound,
} from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { ethLinkApiMethods, EthAddressResponse, userApiMethods, UserOrg } from '@/api/auth';

export function AccountPage() {
  const navigate = useNavigate();
  const {
    userDID, accessToken, authProvider, kyc,
    zkRoles, expiresAt, issuedAt, logout,
  } = useAuth();

  const [linkedAddresses, setLinkedAddresses] = useState<EthAddressResponse[]>([]);
  const [userOrgs, setUserOrgs] = useState<UserOrg[]>([]);
  const [adminOrgIds, setAdminOrgIds] = useState<string[]>([]);
  const [readonlyAdminOrgIds, setReadonlyAdminOrgIds] = useState<string[]>([]);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    if (!accessToken) return;

    ethLinkApiMethods.getAddresses(accessToken)
      .then((res) => setLinkedAddresses(res.addresses))
      .catch(() => {});

    userApiMethods.getMyOrganizations(accessToken)
      .then((res) => setUserOrgs(res.organizations))
      .catch(() => {});

    fetch('/api/v1/me/admin-status', {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
      .then((r) => r.json())
      .then((data) => {
        setAdminOrgIds(data.admin_org_ids || []);
        setReadonlyAdminOrgIds(data.readonly_admin_org_ids || []);
      })
      .catch(() => {});
  }, [accessToken]);

  const copyToClipboard = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-999999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleSignOut = async () => {
    await logout();
    navigate('/login');
  };

  const formatTime = (ts: number | null) => {
    if (!ts) return 'Unknown';
    return new Date(ts).toLocaleString();
  };

  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  const timeUntilExpiry = expiresAt ? expiresAt - now : 0;
  const minutesLeft = Math.max(0, Math.round(timeUntilExpiry / 60000));

  return (
    <div className="space-y-6" data-testid="account-page">
      {/* Page header */}
      <div>
        <h2 className="text-2xl font-semibold text-neutral-900">Account</h2>
        <p className="mt-1 text-sm text-neutral-500">Your identity, session, and linked resources</p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Identity */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-primary" />
              Identity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Auth Provider</p>
              <p className="text-sm font-medium text-neutral-900">
                {authProvider === 'azure_ad' ? 'Microsoft Entra ID' : 'Privado ID'}
              </p>
            </div>
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">DID</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 truncate rounded-lg bg-neutral-100 px-3 py-2 font-mono text-xs text-neutral-700" title={userDID || undefined}>
                  {userDID || 'Unknown'}
                </code>
                {userDID && (
                  <Button
                    onClick={() => copyToClipboard(userDID, 'did')}
                    variant="ghost"
                    size="icon"
                    className="h-8 w-8 flex-shrink-0"
                  >
                    {copied === 'did' ? (
                      <Check className="h-4 w-4 text-success-dark" />
                    ) : (
                      <Copy className="h-4 w-4 text-neutral-400" />
                    )}
                  </Button>
                )}
              </div>
            </div>
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">KYC Status</p>
              <Badge variant={kyc ? 'success' : 'warning'} className="gap-1">
                {kyc ? <ShieldCheck className="h-3 w-3" /> : <ShieldX className="h-3 w-3" />}
                {kyc ? 'Verified' : 'Not Verified'}
              </Badge>
            </div>
            {zkRoles?.claims && zkRoles.claims.length > 0 && (
              <div>
                <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Claims</p>
                <div className="flex flex-wrap gap-1.5">
                  {zkRoles.claims.map((claim) => (
                    <Badge key={claim} variant="info">
                      {claim}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Session */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Clock className="h-4 w-4 text-primary" />
              Session
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Token Issued</p>
              <p className="text-sm text-neutral-700">{formatTime(issuedAt)}</p>
            </div>
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Expires</p>
              <p className="text-sm text-neutral-700">{formatTime(expiresAt)}</p>
            </div>
            <div>
              <p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Time Remaining</p>
              <Badge variant={minutesLeft <= 5 ? 'destructive' : minutesLeft <= 10 ? 'warning' : 'success'}>
                {minutesLeft > 0 ? `${minutesLeft} min` : 'Expired'}
              </Badge>
              <p className="mt-1 text-xs text-neutral-400">Token auto-refreshes before expiry</p>
            </div>
            <div className="pt-2">
              <Button variant="outline" size="sm" onClick={handleSignOut} className="gap-2">
                <LogOut className="h-4 w-4" />
                Sign Out
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Organizations */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Building2 className="h-4 w-4 text-primary" />
              Organizations
            </CardTitle>
          </CardHeader>
          <CardContent>
            {userOrgs.length === 0 ? (
              <p className="text-sm text-neutral-400">No organizations</p>
            ) : (
              <div className="space-y-3">
                {userOrgs.map((org) => (
                  <div key={org.id} className="flex items-start gap-3 rounded-lg bg-neutral-50 p-3">
                    <div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-primary-50">
                      <Building2 className="h-4 w-4 text-primary" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <p className="text-sm font-medium text-neutral-900">{org.name}</p>
                        {adminOrgIds.includes(org.id) && (
                          <Badge variant="info" className="text-[10px] px-1.5 py-0">admin</Badge>
                        )}
                        {readonlyAdminOrgIds.includes(org.id) && !adminOrgIds.includes(org.id) && (
                          <Badge variant="secondary" className="text-[10px] px-1.5 py-0">read-only admin</Badge>
                        )}
                      </div>
                      <p className="text-xs text-neutral-400">{org.slug}</p>
                      <div className="mt-1 flex items-center gap-1">
                        <code className="truncate text-[10px] font-mono text-neutral-400" title={org.id}>
                          {org.id}
                        </code>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(org.id, `org-${org.id}`)}
                          className="flex-shrink-0 rounded p-0.5 text-neutral-300 transition-colors hover:text-neutral-500"
                          title="Copy org ID"
                        >
                          {copied === `org-${org.id}` ? (
                            <Check className="h-3 w-3 text-success-dark" />
                          ) : (
                            <Copy className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Linked Addresses */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <KeyRound className="h-4 w-4 text-primary" />
              Linked Addresses
            </CardTitle>
          </CardHeader>
          <CardContent>
            {linkedAddresses.length === 0 ? (
              <div>
                <p className="text-sm text-neutral-400">No linked Ethereum addresses</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-3 gap-2"
                  onClick={() => navigate('/link-wallet')}
                >
                  <Wallet className="h-4 w-4" />
                  Link Wallet
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                {linkedAddresses.map((addr) => (
                  <div key={addr.address} className="flex items-center gap-2 rounded-lg bg-neutral-50 p-3">
                    <Wallet className="h-4 w-4 flex-shrink-0 text-primary" />
                    <div className="min-w-0 flex-1">
                      <p className="truncate font-mono text-xs text-neutral-700" title={addr.address}>
                        {addr.address}
                      </p>
                      {addr.ens_name && (
                        <p className="text-xs text-primary">{addr.ens_name}</p>
                      )}
                    </div>
                    <button
                      type="button"
                      onClick={() => copyToClipboard(addr.address, addr.address)}
                      className="flex-shrink-0 rounded p-1 text-neutral-300 transition-colors hover:text-neutral-500"
                      title="Copy address"
                    >
                      {copied === addr.address ? (
                        <Check className="h-3.5 w-3.5 text-success-dark" />
                      ) : (
                        <Copy className="h-3.5 w-3.5" />
                      )}
                    </button>
                  </div>
                ))}
                <Button
                  variant="outline"
                  size="sm"
                  className="mt-2 gap-2"
                  onClick={() => navigate('/link-wallet')}
                >
                  <Wallet className="h-4 w-4" />
                  Manage Wallets
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
