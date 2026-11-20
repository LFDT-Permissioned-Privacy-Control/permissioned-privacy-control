import { useEffect, useState, type ReactNode } from 'react';
import { Shield, Wallet, Building2, Clock, ShieldCheck, ShieldX, KeyRound } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../ui/card';
import { Badge } from '../ui/badge';
import { CopyValue } from '../ui/CopyValue';
export { CopyValue } from '../ui/CopyValue';

// The original AccountPage cards take verified display data and action slots.
// They neither choose a session nor fetch identity/membership information.
export function AccountPresentation({ children }: { children: ReactNode }) {
  return <div className="space-y-6" data-testid="account-page">
    <div><h2 className="text-2xl font-semibold text-neutral-900">Account</h2><p className="mt-1 text-sm text-neutral-500">Your identity, session, and linked resources</p></div>
    <div className="grid grid-cols-1 gap-6 md:grid-cols-2">{children}</div>
  </div>;
}
export function IdentityCard({ provider, identity, identityLabel = 'DID', kyc, claims }: { provider: string; identity: string | null; identityLabel?: string; kyc?: boolean; claims?: readonly string[] }) {
  return <Card data-testid="account-identity"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Shield className="h-4 w-4 text-primary" />Identity</CardTitle></CardHeader>
    <CardContent className="space-y-4"><div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Auth Provider</p><p className="text-sm font-medium text-neutral-900">{provider}</p></div>
      <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">{identityLabel}</p><div className="flex items-center gap-2"><code data-field="actorId" className="flex-1 truncate rounded-lg bg-neutral-100 px-3 py-2 font-mono text-xs text-neutral-700" title={identity || undefined}>{identity || 'Unknown'}</code>{identity && <CopyValue value={identity} label="Copy identity" />}</div></div>
      {kyc !== undefined && <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">KYC Status</p><Badge variant={kyc ? 'success' : 'warning'} className="gap-1">{kyc ? <ShieldCheck className="h-3 w-3" /> : <ShieldX className="h-3 w-3" />}{kyc ? 'Verified' : 'Not Verified'}</Badge></div>}
      {!!claims?.length && <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Claims</p><div className="flex flex-wrap gap-1.5">{claims.map(claim => <Badge key={claim} variant="info">{claim}</Badge>)}</div></div>}
    </CardContent></Card>;
}
export function SessionCard({ expiresAt, issuedAt, note, actions }: { expiresAt: number | null; issuedAt?: number | null; note: ReactNode; actions: ReactNode }) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  const seconds = expiresAt ? Math.max(0, Math.ceil((expiresAt - now) / 1000)) : null;
  const minutes = seconds === null ? null : Math.ceil(seconds / 60);
  const format = (ts: number | null) => ts ? new Date(ts).toLocaleString() : 'Unknown';
  return <Card data-testid="account-session"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Clock className="h-4 w-4 text-primary" />Session</CardTitle></CardHeader><CardContent className="space-y-4">
    {issuedAt !== undefined && <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Token Issued</p><p className="text-sm text-neutral-700">{format(issuedAt)}</p></div>}
    <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Expires</p><p className="text-sm text-neutral-700">{expiresAt ? <time data-field="sessionExpiresAt" dateTime={new Date(expiresAt).toISOString()}>{format(expiresAt)}</time> : 'Unknown'}</p></div>
    <div><p className="text-xs text-neutral-400 uppercase tracking-wide mb-1">Time Remaining</p><Badge variant={minutes === null ? 'secondary' : minutes <= 5 ? 'destructive' : minutes <= 10 ? 'warning' : 'success'}>{minutes === null ? 'Unknown' : seconds === 0 ? 'Expired' : seconds! < 60 ? `${seconds} sec` : `${minutes} min`}</Badge><div className="mt-1 text-xs text-neutral-400">{note}</div></div>
    <div className="pt-2 flex flex-wrap gap-2">{actions}</div>
  </CardContent></Card>;
}
export interface AccountOrganization { id: string; name: string; slug: string; isOrgAdmin: boolean; isOrgReadonlyAdmin: boolean }
export function OrganizationsCard({ organizations }: { organizations: readonly AccountOrganization[] }) {
  return <Card data-testid="account-organizations"><CardHeader><CardTitle className="flex items-center gap-2 text-base"><Building2 className="h-4 w-4 text-primary" />Organizations</CardTitle></CardHeader><CardContent>
    {!organizations.length ? <p className="text-sm text-neutral-400">No organizations</p> : <div className="space-y-3">{organizations.map(org => <div key={org.id} className="flex items-start gap-3 rounded-lg bg-neutral-50 p-3"><div className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg bg-primary-50"><Building2 className="h-4 w-4 text-primary" /></div><div className="min-w-0 flex-1"><div className="flex items-center gap-2"><p className="text-sm font-medium text-neutral-900">{org.name}</p>{org.isOrgAdmin ? <Badge variant="info" className="text-[10px] px-1.5 py-0">admin</Badge> : org.isOrgReadonlyAdmin && <Badge variant="secondary" className="text-[10px] px-1.5 py-0">read-only admin</Badge>}</div><p className="text-xs text-neutral-400">{org.slug}</p><div className="mt-1 flex items-center gap-1"><code className="truncate text-[10px] font-mono text-neutral-400" title={org.id}>{org.id}</code><CopyValue value={org.id} label="Copy org ID" /></div></div></div>)}</div>}
  </CardContent></Card>;
}
export function LinkedAddressesCard({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return <Card data-testid="account-wallets"><CardHeader><div className="flex items-center justify-between gap-2"><CardTitle className="flex items-center gap-2 text-base"><KeyRound className="h-4 w-4 text-primary" />Linked Addresses</CardTitle>{actions}</div></CardHeader><CardContent>{children}</CardContent></Card>;
}
export function LinkedAddressRows({ addresses, actions }: { addresses: readonly { address: string; secondary?: string }[]; actions?: (address: string) => ReactNode }) {
  return <div className="space-y-2">{addresses.map(address => <div key={address.address} className="flex items-center gap-2 rounded-lg bg-neutral-50 p-3" data-testid="linked-address"><Wallet className="h-4 w-4 flex-shrink-0 text-primary" /><div className="min-w-0 flex-1"><p className="truncate font-mono text-xs text-neutral-700" title={address.address}>{address.address}</p>{address.secondary && <p className="text-xs text-primary">{address.secondary}</p>}</div><CopyValue value={address.address} label="Copy address" />{actions?.(address.address)}</div>)}</div>;
}
