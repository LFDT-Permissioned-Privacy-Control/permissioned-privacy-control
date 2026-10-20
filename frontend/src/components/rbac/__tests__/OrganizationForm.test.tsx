import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import OrganizationForm from '../OrganizationForm';
import { mockOrganizations } from '@/test/mocks/rbac-fixtures';
import type { Organization } from '@/types/rbac';

// Create a fresh QueryClient for each test
function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
        gcTime: 0,
        staleTime: 0,
      },
      mutations: {
        retry: false,
      },
    },
  });
}

interface RenderOptions {
  organization?: Organization;
  onClose?: () => void;
  onSave?: () => void;
}

function renderOrganizationForm(options: RenderOptions = {}) {
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();
  const onClose = options.onClose || vi.fn();
  const onSave = options.onSave || vi.fn();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <OrganizationForm
            organization={options.organization}
            onClose={onClose}
            onSave={onSave}
          />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user, onClose, onSave };
}

describe('OrganizationForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe('Create Mode', () => {
    it('shows empty slug and name fields', () => {
      renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');

      expect(nameInput).toHaveValue('');
      expect(slugInput).toHaveValue('');
    });

    it('validates slug is required', async () => {
      const { user, onSave } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'Test Org');

      // Clear the auto-generated slug
      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      // Form should not submit due to HTML5 required validation
      expect(onSave).not.toHaveBeenCalled();
    });

    it('validates name is required', async () => {
      const { user, onSave } = renderOrganizationForm();

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.type(slugInput, 'test-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      // Form should not submit due to HTML5 required validation
      expect(onSave).not.toHaveBeenCalled();
    });

    it('slug field accepts alphanumeric and hyphens', async () => {
      const { user } = renderOrganizationForm();

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.type(slugInput, 'test-org-123');

      expect(slugInput).toHaveValue('test-org-123');
    });

    it('auto-generates slug from name for new organizations', async () => {
      const { user } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'Acme Corporation');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      expect(slugInput).toHaveValue('acme-corporation');
    });

    it('submits POST to /orgs with form data', async () => {
      let capturedRequest: { name: string; slug: string } | null = null;

      server.use(
        http.post('/api/v1/admin/orgs', async ({ request }) => {
          capturedRequest = (await request.json()) as { name: string; slug: string };
          return HttpResponse.json({
            id: 'org-new',
            slug: capturedRequest.slug,
            name: capturedRequest.name,
            settings: {},
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const { user, onSave } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'new-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(capturedRequest).toEqual({
          name: 'New Organization',
          slug: 'new-org',
        });
      });

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('closes dialog on successful create', async () => {
      server.use(
        http.post('/api/v1/admin/orgs', () => {
          return HttpResponse.json({
            id: 'org-new',
            slug: 'new-org',
            name: 'New Organization',
            settings: {},
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const onSave = vi.fn();
      const { user } = renderOrganizationForm({ onSave });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'new-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('shows error on API failure', async () => {
      server.use(
        http.post('/api/v1/admin/orgs', () => {
          return HttpResponse.json(
            { error: 'Slug already exists' },
            { status: 400 }
          );
        })
      );

      const { user, onSave } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'existing-slug');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Slug already exists')).toBeInTheDocument();
      });

      expect(onSave).not.toHaveBeenCalled();
    });

    it('shows generic error message when API returns no error details', async () => {
      server.use(
        http.post('/api/v1/admin/orgs', () => {
          return HttpResponse.json({}, { status: 500 });
        })
      );

      const { user } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'new-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(
          screen.getByText('Failed to save organization. Please try again.')
        ).toBeInTheDocument();
      });
    });
  });

  describe('Edit Mode', () => {
    const existingOrg = mockOrganizations[0]; // Acme Corporation

    it('populates form with existing org data', () => {
      renderOrganizationForm({ organization: existingOrg });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');

      expect(nameInput).toHaveValue('Acme Corporation');
      expect(slugInput).toHaveValue('acme-corp');
    });

    it('does not auto-generate slug when editing', async () => {
      const { user } = renderOrganizationForm({ organization: existingOrg });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.clear(nameInput);
      await user.type(nameInput, 'New Name');

      // Slug should remain unchanged (not auto-generated)
      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      expect(slugInput).toHaveValue('acme-corp');
    });

    it('shows Update button instead of Create', () => {
      renderOrganizationForm({ organization: existingOrg });

      expect(screen.getByText('Update Organization')).toBeInTheDocument();
      expect(screen.queryByText('Create Organization')).not.toBeInTheDocument();
    });

    it('submits PUT to /orgs/:id', async () => {
      let capturedRequest: { name: string; slug: string } | null = null;
      let capturedOrgId: string | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId', async ({ request, params }) => {
          capturedOrgId = params.orgId as string;
          capturedRequest = (await request.json()) as { name: string; slug: string };
          return HttpResponse.json({
            ...existingOrg,
            name: capturedRequest.name,
            slug: capturedRequest.slug,
            updated_at: new Date().toISOString(),
          });
        })
      );

      const { user, onSave } = renderOrganizationForm({ organization: existingOrg });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      const submitButton = screen.getByText('Update Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(capturedOrgId).toBe('org-1');
        expect(capturedRequest).toEqual({
          name: 'Updated Name',
          slug: 'acme-corp',
        });
      });

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('closes dialog on successful update', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId', () => {
          return HttpResponse.json({
            ...existingOrg,
            name: 'Updated Name',
            updated_at: new Date().toISOString(),
          });
        })
      );

      const onSave = vi.fn();
      const { user } = renderOrganizationForm({ organization: existingOrg, onSave });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      const submitButton = screen.getByText('Update Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('shows error on API failure during update', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId', () => {
          return HttpResponse.json(
            { error: 'Organization not found' },
            { status: 404 }
          );
        })
      );

      const { user, onSave } = renderOrganizationForm({ organization: existingOrg });

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      const submitButton = screen.getByText('Update Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Organization not found')).toBeInTheDocument();
      });

      expect(onSave).not.toHaveBeenCalled();
    });
  });

  describe('Cancel Button', () => {
    it('calls onClose when Cancel button is clicked', async () => {
      const onClose = vi.fn();
      const { user } = renderOrganizationForm({ onClose });

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });

    it('Cancel button is disabled while saving', async () => {
      // Make the API call take a long time
      server.use(
        http.post('/api/v1/admin/orgs', async () => {
          await new Promise(resolve => setTimeout(resolve, 5000));
          return HttpResponse.json({
            id: 'org-new',
            slug: 'new-org',
            name: 'New Organization',
            settings: {},
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const { user } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'new-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      // Cancel should be disabled while saving
      await waitFor(() => {
        const cancelButton = screen.getByText('Cancel');
        expect(cancelButton).toBeDisabled();
      });
    });
  });

  describe('Loading State', () => {
    it('shows saving indicator while submitting', async () => {
      server.use(
        http.post('/api/v1/admin/orgs', async () => {
          await new Promise(resolve => setTimeout(resolve, 5000));
          return HttpResponse.json({
            id: 'org-new',
            slug: 'new-org',
            name: 'New Organization',
            settings: {},
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const { user } = renderOrganizationForm();

      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      await user.type(nameInput, 'New Organization');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      await user.clear(slugInput);
      await user.type(slugInput, 'new-org');

      const submitButton = screen.getByText('Create Organization');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument();
      });
    });
  });
});
