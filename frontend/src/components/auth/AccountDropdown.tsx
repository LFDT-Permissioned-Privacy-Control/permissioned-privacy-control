import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { AccountMenu } from './AccountMenu';

export function AccountDropdown() {
  const { userDID, authProvider, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  return <AccountMenu userDID={userDID} providerLabel={authProvider === 'azure_ad' ? 'Microsoft Entra ID' : 'Privado ID'}
    isAccountPage={location.pathname === '/admin/account'} onAccount={() => navigate('/admin/account')}
    onDashboard={() => navigate('/success')} onSignOut={async () => { await logout(); navigate('/login'); }} />;
}
