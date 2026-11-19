import { useState } from 'react';
import { rbacApi } from '@/api/rbac';
import type { Organization } from '@/types/rbac';
import { OrganizationFormView } from './OrganizationFormView';

interface OrganizationFormProps {
  organization?: Organization;
  onClose: () => void;
  onSave: () => void;
}

export default function OrganizationForm({
  organization,
  onClose,
  onSave,
}: OrganizationFormProps) {
  const [name, setName] = useState(organization?.name || '');
  const [slug, setSlug] = useState(organization?.slug || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auto-generate slug from name (only for new orgs)
  const handleNameChange = (value: string) => {
    setName(value);
    if (!organization) {
      const generatedSlug = value
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-|-$/g, '');
      setSlug(generatedSlug);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);

    try {
      if (organization) {
        await rbacApi.orgs.update(organization.id, { name, slug });
      } else {
        await rbacApi.orgs.create({ name, slug });
      }
      onSave();
    } catch (err: unknown) {
      console.error('Failed to save organization:', err);
      const axiosError = err as {
        response?: { data?: { error?: string }; status?: number };
      };
      if (axiosError.response?.data?.error) {
        setError(axiosError.response.data.error);
      } else {
        setError('Failed to save organization. Please try again.');
      }
    } finally {
      setSaving(false);
    }
  };

  return <OrganizationFormView name={name} slug={slug} editing={!!organization} busy={saving} error={error}
    onNameChange={handleNameChange} onSlugChange={setSlug} onClose={onClose} onSubmit={handleSubmit} />;
}
