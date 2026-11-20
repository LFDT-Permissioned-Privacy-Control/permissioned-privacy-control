import type { FormEvent, ReactNode } from 'react'
import { Button } from '../ui/button'
import { Input } from '../ui/input'
import { Textarea } from '../ui/textarea'
import { AlertCircle, Save, X, Loader2, Shield, Check } from 'lucide-react'

export interface GroupFormViewProps {
  name: string; slug: string; description: string; saving: boolean; error: string | null
  isEditing: boolean; isOrgAdminGroup: boolean; isOrgReadonlyAdmin: boolean
  nameConflict: boolean; slugConflict: boolean; trimmedName: string
  onNameChange(value: string): void; onSlugChange(value: string): void; onDescriptionChange(value: string): void
  onReadonlyChange(value: boolean): void; onClose(): void; onSubmit(event: FormEvent): void
  roleControl?: ReactNode; submitLabel?: string; slugPattern?: string; slugHelp?: string
}
// Pure V1 presentation; each runtime supplies its own data and save behavior.
export function GroupFormView({ name, slug, description, saving, error, isEditing, isOrgAdminGroup, isOrgReadonlyAdmin,
  nameConflict, slugConflict, trimmedName, onNameChange, onSlugChange, onDescriptionChange, onReadonlyChange, onClose, onSubmit,
  roleControl, submitLabel, slugPattern = '^[a-z0-9]+(_[a-z0-9]+)*$', slugHelp = 'Lowercase letters, numbers and underscores only',
}: GroupFormViewProps) {
  return (
    <form onSubmit={onSubmit} className="space-y-5">
      {error && (
        <div className="p-4 rounded-lg bg-error-light border border-error/30 flex items-start gap-3">
          <AlertCircle className="w-5 h-5 text-error-dark flex-shrink-0 mt-0.5" />
          <span className="text-error-dark text-sm">{error}</span>
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">Name</label>
        <Input
          aria-label="Name"
          type="text"
          value={name}
          onChange={e => onNameChange(e.target.value)}
          placeholder="e.g., Engineering, DevOps, Auditors"
          required
          aria-invalid={nameConflict}
          className={nameConflict ? 'border-error ring-1 ring-error/20' : ''}
        />
        {nameConflict && (
          <p className="text-xs text-error-dark">
            A group named &quot;{trimmedName}&quot; already exists in this organization (names are case-insensitive). Pick a different name.
          </p>
        )}
      </div>

      {!isEditing && (
        <div className="space-y-2">
          <label className="block text-sm font-medium text-neutral-700">Slug</label>
          <Input
            aria-label="Slug"
            type="text"
            value={slug}
            onChange={e => onSlugChange(e.target.value)}
            placeholder="e.g., engineering"
            required
            pattern={slugPattern}
            title={slugHelp}
            aria-invalid={slugConflict}
            className={slugConflict ? 'border-error ring-1 ring-error/20' : ''}
          />
          {slugConflict ? (
            <p className="text-xs text-error-dark">
              A group with slug &quot;{slug}&quot; already exists in this organization.
            </p>
          ) : (
            <p className="text-xs text-neutral-400">
              {slugHelp}
            </p>
          )}
        </div>
      )}

      <div className="space-y-2">
        <label className="block text-sm font-medium text-neutral-700">
          Description (optional)
        </label>
        <Textarea
          aria-label="Description"
          value={description}
          onChange={e => onDescriptionChange(e.target.value)}
          placeholder="Describe the purpose of this group..."
          className="h-20"
        />
      </div>

      {/* Admin role. A full org-admin group cannot also be a read-only org
          admin (RD-968 Gap 2) — when editing one, show a banner instead of the
          toggle. Otherwise show the read-only admin toggle. */}
      {roleControl ?? (isOrgAdminGroup ? (
        <div className="flex items-start gap-3 p-3 rounded-lg bg-primary-50 border border-primary-200">
          <Shield className="w-4 h-4 text-primary-700 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <span className="text-sm font-medium text-primary-700">Full Org Admin</span>
            <p className="text-xs text-neutral-500 mt-1">
              Members have full admin access to this organization — all claims on every
              contract, automatically. The read-only admin role does not apply and cannot
              be combined with it.
            </p>
          </div>
        </div>
      ) : (
        <div className="space-y-2">
          <label
            className="flex items-start gap-3 p-3 rounded-lg bg-primary-50 border border-primary-200 cursor-pointer hover:bg-primary-100 transition-colors"
            onClick={() => {
              onReadonlyChange(!isOrgReadonlyAdmin);
            }}
          >
            <div className={`w-5 h-5 rounded border flex items-center justify-center flex-shrink-0 mt-0.5 transition-colors ${
              isOrgReadonlyAdmin
                ? 'bg-primary border-primary'
                : 'border-neutral-300 bg-white'
            }`}>
              {isOrgReadonlyAdmin && <Check className="w-3 h-3 text-white" />}
            </div>
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-primary-700" />
                <span className="text-sm font-medium text-primary-700">Read-only Org Admin</span>
              </div>
              <p className="text-xs text-neutral-500 mt-1">
                Members get read-only access to the admin dashboard (auditor role). They cannot modify settings or resources.
              </p>
            </div>
          </label>
        </div>
      ))}

      <div className="p-3 rounded-lg bg-neutral-50 border border-neutral-200">
        <p className="text-sm text-neutral-600">
          <strong>Tip:</strong> After creating the group, use the settings icon to configure
          allowed RPC methods, execution claims and connection settings.
        </p>
      </div>

      <div className="flex justify-end gap-3 pt-2">
        <Button
          type="button"
          variant="ghost"
          onClick={onClose}
          disabled={saving}
          className="gap-2"
        >
          <X className="w-4 h-4" />
          Cancel
        </Button>
        <Button type="submit" disabled={saving || nameConflict || slugConflict} className="gap-2">
          {saving ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Saving...
            </>
          ) : (
            <>
              <Save className="w-4 h-4" />
              {submitLabel ?? ((isEditing ? 'Update' : 'Create') + ' Group')}
            </>
          )}
        </Button>
      </div>
    </form>
  );
}
