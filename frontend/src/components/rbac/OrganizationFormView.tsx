import type { FormEvent } from 'react'
import { Button } from '../ui/button'
import { Input } from '../ui/input'
import { AlertCircle, Save, X, Loader2 } from 'lucide-react'

export interface OrganizationFormViewProps {
  name: string; slug: string; editing: boolean; busy: boolean; error: string | null
  onNameChange(value: string): void; onSlugChange(value: string): void
  onClose(): void; onSubmit(event: FormEvent): void
  submitLabel?: string
}

// Shared V1 presentation. Authentication, persistence and draft ownership are
// supplied by its caller; importing this component never imports a data API.
export function OrganizationFormView({ name, slug, editing, busy, error, onNameChange, onSlugChange, onClose, onSubmit, submitLabel }: OrganizationFormViewProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label htmlFor="org-name" className="block text-sm font-medium text-neutral-700">Name</label>
        <Input
          id="org-name"
          type="text"
          value={name}
          onChange={e => onNameChange(e.target.value)}
          placeholder="e.g., Acme Corporation"
          required
        />
        <p className="text-xs text-neutral-400">Display name for the organization</p>
      </div>

      <div className="space-y-2">
        <label htmlFor="org-slug" className="block text-sm font-medium text-neutral-700">Slug</label>
        <Input
          id="org-slug"
          type="text"
          value={slug}
          onChange={e => onSlugChange(e.target.value)}
          placeholder="e.g., acme-corp"
          required
          pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
          title="Lowercase letters, numbers, and hyphens only"
        />
        <p className="text-xs text-neutral-400">
          URL-friendly identifier (lowercase, hyphens allowed)
        </p>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={busy}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button type="submit" disabled={busy} className="gap-2">
          {busy ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {submitLabel ?? (editing ? 'Update Organization' : 'Create Organization')}
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
