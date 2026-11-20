import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Group } from '@/types/rbac';
import { GroupFormView } from './GroupFormView';

interface GroupFormProps {
  orgId: string;
  groups?: Group[]; // sibling groups in this org; used for client-side
                    // name-uniqueness pre-validation. Server is source of truth.
  group?: Group;
  onClose: () => void;
  onSave: () => void;
}

export default function GroupForm({
  orgId,
  groups = [],
  group,
  onClose,
  onSave,
}: GroupFormProps) {
  const [name, setName] = useState(group?.name || '');
  const [slug, setSlug] = useState(group?.slug || '');
  const [description, setDescription] = useState(group?.description || '');
  // is_org_admin is intentionally not user-editable here: tier-1 (super-admin)
  // never has a UI session — the dashboard is always tier-2 or RO-admin —
  // and tier-2 cannot promote to is_org_admin (server returns 403). Existing
  // is_org_admin is preserved on edit by passing the original value through.
  const [isOrgReadonlyAdmin, setIsOrgReadonlyAdmin] = useState(group?.is_org_readonly_admin || false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isEditing = !!group;
  // A full org-admin group already grants every admin permission, so the
  // read-only admin role is mutually exclusive with it (RD-968 Gap 2; enforced
  // server-side with a 400 + DB CHECK constraint). When editing such a group we
  // hide the toggle and never send is_org_readonly_admin=true.
  const isOrgAdminGroup = !!group?.is_org_admin;

  // Names are unique within an org (case-insensitive). Match the server-side
  // constraint exactly; this is a UX shortcut that surfaces the conflict
  // before the user clicks Save. The backend is still authoritative — it's
  // what catches concurrent creates between two browser tabs.
  const trimmedName = name.trim();
  const nameConflict = trimmedName !== '' && groups.some(
    g => g.id !== group?.id && g.name.toLowerCase() === trimmedName.toLowerCase()
  );
  const slugConflict = !isEditing && slug !== '' && groups.some(
    g => g.slug.toLowerCase() === slug.toLowerCase()
  );

  // Auto-generate slug from name (only for new groups)
  const handleNameChange = (value: string) => {
    setName(value);
    if (!isEditing) {
      const generatedSlug = value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '_')
        .replace(/^_|_$/g, '');
      setSlug(generatedSlug);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (isEditing) {
        await rbacApi.groups.update(orgId, group.id, {
          name,
          description,
          is_org_readonly_admin: isOrgAdminGroup ? false : isOrgReadonlyAdmin,
        });
      } else {
        await rbacApi.groups.create(orgId, {
          slug,
          name,
          description,
          parent_id: null,
          is_org_readonly_admin: isOrgReadonlyAdmin,
        });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save group:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save group. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return <GroupFormView name={name} slug={slug} description={description} saving={saving} error={error}
    isEditing={isEditing} isOrgAdminGroup={isOrgAdminGroup} isOrgReadonlyAdmin={isOrgReadonlyAdmin}
    nameConflict={nameConflict} slugConflict={slugConflict} trimmedName={trimmedName}
    onNameChange={handleNameChange} onSlugChange={setSlug} onDescriptionChange={setDescription} onReadonlyChange={setIsOrgReadonlyAdmin}
    onClose={onClose} onSubmit={handleSubmit} />;
}
