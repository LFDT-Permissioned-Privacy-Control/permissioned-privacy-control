import { Check } from 'lucide-react'
import { cn } from '../../lib/utils'

// Pure selection visuals extracted from GroupAccessForm. Controllers retain
// their own source/authority semantics; these helpers perform no state changes.
export function permissionClaimClasses(selected: boolean, interactive = true, implied = false) {
  return cn(
    'flex items-start gap-3 p-3 rounded-lg border transition-colors',
    selected ? 'border-primary bg-white shadow-sm' : 'border-neutral-200 bg-white',
    interactive && !selected && 'hover:border-primary-200',
    interactive && 'focus-within:outline-none focus-within:ring-2 focus-within:ring-primary/40 focus-within:ring-offset-2 cursor-pointer',
    implied && 'opacity-60 cursor-not-allowed',
  )
}
export function permissionPresetClasses(selected: boolean, interactive = true) {
  return cn(
    'flex flex-col items-start gap-1 p-3 rounded-lg border-2 text-left transition-all',
    selected ? 'border-primary bg-primary-50' : 'border-neutral-200',
    interactive && !selected && 'hover:border-primary-200',
    interactive && 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40 focus-visible:ring-offset-2',
  )
}
export function permissionMethodClasses(interactive = true, locked = false) {
  return cn(
    'flex items-center gap-2 p-1.5 rounded border border-transparent transition-colors',
    interactive && 'hover:bg-primary-50 hover:border-neutral-100 focus-within:outline-none focus-within:ring-2 focus-within:ring-primary/40 cursor-pointer',
    locked && 'opacity-60 cursor-not-allowed',
  )
}
export function PermissionCheck({ checked, size = 'method' }: { checked: boolean; size?: 'claim' | 'method' }) {
  return <span aria-hidden="true" data-state={checked ? 'checked' : 'unchecked'} className={cn(
    'rounded border flex items-center justify-center flex-shrink-0 transition-colors',
    size === 'claim' ? 'w-4 h-4 mt-0.5' : 'w-3.5 h-3.5',
    checked ? 'bg-primary border-primary' : 'border-neutral-300 bg-white',
  )}>{checked && <Check className={cn('text-white stroke-[3]', size === 'claim' ? 'w-3 h-3' : 'w-2.5 h-2.5')} />}</span>
}
export function PermissionCount({ selected, total, label }: { selected: number; total: number; label?: string }) {
  return <span aria-label={label} className="text-xs px-2 py-0.5 rounded-full bg-primary-50 text-primary">{selected} / {total}</span>
}
