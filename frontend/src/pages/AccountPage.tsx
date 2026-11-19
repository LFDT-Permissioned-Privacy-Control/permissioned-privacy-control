import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogOut, Wallet } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { ethLinkApiMethods, EthAddressResponse, userApiMethods, UserOrg } from '@/api/auth';
import { AccountPresentation, IdentityCard, SessionCard, OrganizationsCard, LinkedAddressesCard, LinkedAddressRows } from '@/components/auth/AccountPresentation';

export function AccountPage() {
  const navigate = useNavigate();
  const { userDID, accessToken, authProvider, kyc, zkRoles, expiresAt, issuedAt, logout } = useAuth();
  const [linkedAddresses, setLinkedAddresses] = useState<EthAddressResponse[]>([]);
  const [userOrgs, setUserOrgs] = useState<UserOrg[]>([]);
  const [adminOrgIds, setAdminOrgIds] = useState<string[]>([]);
  const [readonlyAdminOrgIds, setReadonlyAdminOrgIds] = useState<string[]>([]);
  useEffect(() => {
    if (!accessToken) return;
    ethLinkApiMethods.getAddresses(accessToken).then(res => setLinkedAddresses(res.addresses)).catch(() => {});
    userApiMethods.getMyOrganizations(accessToken).then(res => setUserOrgs(res.organizations)).catch(() => {});
    fetch('/api/v1/me/admin-status', { headers: { Authorization: `Bearer ${accessToken}` } })
      .then(r => r.json()).then(data => { setAdminOrgIds(data.admin_org_ids || []); setReadonlyAdminOrgIds(data.readonly_admin_org_ids || []); }).catch(() => {});
  }, [accessToken]);
  return <AccountPresentation>
    <IdentityCard provider={authProvider === 'azure_ad' ? 'Microsoft Entra ID' : 'Privado ID'} identity={userDID} kyc={kyc} claims={zkRoles?.claims} />
    <SessionCard expiresAt={expiresAt} issuedAt={issuedAt} note="Token auto-refreshes before expiry" actions={<Button variant="outline" size="sm" className="gap-2" onClick={async () => { await logout(); navigate('/login'); }}><LogOut className="h-4 w-4" />Sign Out</Button>} />
    <OrganizationsCard organizations={userOrgs.map(org => ({ ...org, isOrgAdmin: adminOrgIds.includes(org.id), isOrgReadonlyAdmin: readonlyAdminOrgIds.includes(org.id) }))} />
    <LinkedAddressesCard>
      {linkedAddresses.length ? <LinkedAddressRows addresses={linkedAddresses.map(address => ({ address: address.address, secondary: address.ens_name }))} /> : <p className="text-sm text-neutral-400">No linked Ethereum addresses</p>}
      <Button variant="outline" size="sm" className="mt-3 gap-2" onClick={() => navigate('/link-wallet')}><Wallet className="h-4 w-4" />{linkedAddresses.length ? 'Manage Wallets' : 'Link Wallet'}</Button>
    </LinkedAddressesCard>
  </AccountPresentation>;
}
