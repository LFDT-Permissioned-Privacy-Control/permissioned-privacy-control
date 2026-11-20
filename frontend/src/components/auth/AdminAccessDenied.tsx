import { ShieldAlert } from 'lucide-react'
import { Button } from '../ui/button'

// Shared presentation only; each runtime supplies its own verified role check.
export function AdminAccessDenied({ onAccount, accountLabel = 'Go to your dashboard' }: { onAccount?: () => void; accountLabel?: string }) {
  return <div className="flex min-h-[60vh] items-center justify-center">
    <div className="mx-auto max-w-md rounded-lg border border-red-200 bg-red-50 p-8 text-center">
      <ShieldAlert className="mx-auto mb-4 h-12 w-12 text-red-500" />
      <h2 className="mb-2 text-xl font-semibold text-red-900">Access Denied</h2>
      <p className="text-sm text-red-700">You don't have admin privileges. Contact your organization administrator.</p>
      {onAccount && <Button onClick={onAccount} variant="outline" className="mt-6" data-testid="admin-denied-back-btn">{accountLabel}</Button>}
    </div>
  </div>
}
