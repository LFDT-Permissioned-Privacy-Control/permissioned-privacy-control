import { Outlet } from 'react-router-dom';
import { AdminLayout } from './components/AdminLayout';
import { AccountDropdown } from './components/auth/AccountDropdown';

export default function App() {
  return <AdminLayout accountMenu={<AccountDropdown />}><Outlet /></AdminLayout>;
}
