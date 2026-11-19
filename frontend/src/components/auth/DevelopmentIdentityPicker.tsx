import type { ReactNode } from 'react'
import { FlaskConical } from 'lucide-react'

export interface DevelopmentIdentity {
  id: string; name: string; detail?: string; organization?: string; testId?: string
}
// Shared V1 development badge/grid presentation. Authentication is supplied by
// the caller; no mock token, directory or backend dependency lives here.
export function DevelopmentIdentityPicker({ identities, disabled = false, separated = true, onSelect, children }: {
  identities: DevelopmentIdentity[]; disabled?: boolean; separated?: boolean; onSelect(id: string): void; children?: ReactNode
}) {
  return <div className={separated ? 'mt-6 border-t border-neutral-200 pt-6' : ''} data-testid="dev-tools">
    <div className="text-center mb-3"><span className="inline-flex items-center gap-1.5 rounded-full bg-warning-light px-2 py-1 text-xs font-medium text-warning-dark"><FlaskConical className="w-3 h-3" />Development Only</span></div>
    {identities.length > 0 && <div className="mb-4 space-y-2" data-testid="identity-picker">
      <p className="text-xs text-neutral-500 text-center mb-2">Quick login as test identity:</p>
      <div className="grid grid-cols-2 gap-2">{identities.map(identity => <button type="button" key={identity.id} onClick={() => onSelect(identity.id)} disabled={disabled}
        className="flex flex-col items-start p-2 rounded-lg border border-neutral-200 hover:border-warning hover:bg-warning-light/50 transition-colors text-left text-xs disabled:opacity-50 disabled:cursor-not-allowed"
        data-testid={identity.testId ?? `identity-btn-${identity.id}`}>
        <span className="font-medium text-neutral-900">{identity.name}</span>
        {identity.detail && <span className="text-neutral-400 font-mono">{identity.detail}</span>}
        {identity.organization && <span className="text-neutral-500">{identity.organization}</span>}
      </button>)}</div>
    </div>}
    {children}
  </div>
}
