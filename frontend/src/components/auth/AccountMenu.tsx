import { useState, useRef, useEffect } from 'react';
import { User, LogOut, ChevronDown, ArrowLeftRight } from 'lucide-react';

function truncateDID(did: string): string {
  if (did.startsWith('azuread:')) {
    // Azure AD: show email-like portion after prefix
    const id = did.slice('azuread:'.length);
    if (id.length > 20) return id.slice(0, 17) + '...';
    return id;
  }
  // Privado DID: show first and last parts
  if (did.length > 24) {
    return did.slice(0, 14) + '...' + did.slice(-6);
  }
  return did;
}

interface AccountMenuProps {
  userDID: string | null;
  providerLabel: string;
  isAccountPage: boolean;
  onAccount(): void;
  onDashboard?(): void;
  onSignOut(): Promise<void>;
  dashboardLabel?: string;
  busy?: boolean;
}

export function AccountMenu({ userDID, providerLabel, isAccountPage, onAccount, onDashboard, onSignOut, dashboardLabel = 'User dashboard', busy = false }: AccountMenuProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  }, [open]);

  // Close on Escape
  useEffect(() => {
    function handleEscape(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    if (open) {
      document.addEventListener('keydown', handleEscape);
      return () => document.removeEventListener('keydown', handleEscape);
    }
  }, [open]);

  const handleSignOut = async () => {
    setOpen(false);
    await onSignOut();
  };


  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-neutral-700 transition-colors hover:bg-neutral-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
        aria-expanded={open}
        aria-haspopup="true"
        data-testid="account-dropdown-trigger"
      >
        <div className="flex h-7 w-7 items-center justify-center rounded-full bg-primary-50">
          <User className="h-4 w-4 text-primary" />
        </div>
        <span className="hidden md:inline max-w-[140px] truncate font-medium">
          {userDID ? truncateDID(userDID) : 'Account'}
        </span>
        <ChevronDown className={`h-3.5 w-3.5 text-neutral-400 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-1 w-64 rounded-xl border border-neutral-200 bg-white shadow-elevated z-50 animate-fade-in"
          role="menu"
          data-testid="account-dropdown-menu"
        >
          {/* User identity */}
          <div className="border-b border-neutral-100 px-4 py-3">
            <p className="text-xs text-neutral-400">
              {providerLabel}
            </p>
            <p className="mt-0.5 truncate text-sm font-medium text-neutral-900" title={userDID || undefined}>
              {userDID || 'Unknown'}
            </p>
          </div>

          {/* Menu items */}
          <div className="py-1">
            <button
              type="button"
              onClick={() => { setOpen(false); onAccount(); }}
              className={`flex w-full items-center gap-2.5 px-4 py-2 text-sm transition-colors ${
                isAccountPage
                  ? 'bg-primary-50 text-primary font-medium'
                  : 'text-neutral-700 hover:bg-neutral-50'
              }`}
              role="menuitem"
              data-testid="account-link"
            >
              <User className="h-4 w-4" />
              Account
            </button>
            {/* The counterpart to the "Admin dashboard" button on the user
                page — an admin who switched over should not have to edit the
                URL to get back. */}
            {onDashboard && <button
              type="button"
              onClick={() => { setOpen(false); onDashboard(); }}
              className="flex w-full items-center gap-2.5 px-4 py-2 text-sm text-neutral-700 transition-colors hover:bg-neutral-50"
              role="menuitem"
              data-testid="back-to-app-link"
            >
              <ArrowLeftRight className="h-4 w-4" />
              {dashboardLabel}
            </button>}
            <button
              type="button"
              disabled={busy}
              onClick={handleSignOut}
              className="flex w-full items-center gap-2.5 px-4 py-2 text-sm text-neutral-700 transition-colors hover:bg-neutral-50"
              role="menuitem"
              data-testid="sign-out-btn"
            >
              <LogOut className="h-4 w-4" />
              Sign Out
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
