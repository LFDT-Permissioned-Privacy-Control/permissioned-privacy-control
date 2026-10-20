import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import type { AllowedAzureTenant } from '@/types/rbac';

function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

// We need to import the component after we set up the mock
// (AzureTenantList does not use useOrgContext, so no mock needed for that)
import AzureTenantList from '../AzureTenantList';

const mockTenants: AllowedAzureTenant[] = [
  {
    id: 'tenant-1',
    tenant_id: 'aaaabbbb-cccc-dddd-eeee-ffffffffffff',
    label: 'Contoso Corp',
    default_org_id: null,
    default_group_id: null,
    auto_provision: true,
    created_at: '2024-06-01T00:00:00Z',
    updated_at: '2024-06-01T00:00:00Z',
  },
  {
    id: 'tenant-2',
    tenant_id: '11111111-2222-3333-4444-555555555555',
    label: 'Fabrikam Inc',
    default_org_id: 'org-1',
    default_group_id: 'group-1',
    auto_provision: false,
    created_at: '2024-07-15T00:00:00Z',
    updated_at: '2024-07-15T00:00:00Z',
  },
];

function renderAzureTenantList() {
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <AzureTenantList />
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user };
}

describe('AzureTenantList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows heading and description', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();

      expect(screen.getByText('Azure AD Tenants')).toBeInTheDocument();
      expect(
        screen.getByText('Control which Azure AD tenants can authenticate')
      ).toBeInTheDocument();
    });

    it('shows empty state when no tenants', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: [] });
        })
      );

      renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('No Azure AD tenants allowed')).toBeInTheDocument();
      });
      expect(screen.getByText('Allow your first tenant')).toBeInTheDocument();
    });

    it('displays table with correct headers', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Label')).toBeInTheDocument();
      });

      expect(screen.getByText('Tenant ID')).toBeInTheDocument();
      expect(screen.getByText('Auto-provision')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  describe('Data Display', () => {
    it('shows tenant labels in table rows', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });
      expect(screen.getByText('Fabrikam Inc')).toBeInTheDocument();
    });

    it('shows tenant IDs in table rows', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('aaaabbbb-cccc-dddd-eeee-ffffffffffff')).toBeInTheDocument();
      });
    });

    it('shows correct number of rows', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      renderAzureTenantList();

      await waitFor(() => {
        const table = screen.getByRole('table');
        const rows = within(table).getAllByRole('row');
        // 1 header + 2 data rows
        expect(rows).toHaveLength(3);
      });
    });
  });

  describe('Actions', () => {
    it('Add button opens form dialog', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        }),
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 1000, offset: 0 });
        })
      );

      const { user } = renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });

      const addButton = screen.getByRole('button', { name: /add tenant/i });
      await user.click(addButton);

      await waitFor(() => {
        expect(screen.getByRole('dialog')).toBeInTheDocument();
      });

      expect(screen.getByText('Add Azure AD Tenant')).toBeInTheDocument();
    });

    it('Edit button opens form with tenant data', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        }),
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 1000, offset: 0 });
        })
      );

      const { user } = renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });

      const editButtons = screen.getAllByTitle('Edit tenant');
      await user.click(editButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Edit Azure AD Tenant')).toBeInTheDocument();
      });

      // Form should be populated with tenant data
      const tenantIdInput = screen.getByPlaceholderText(/aaaabbbb/i);
      expect(tenantIdInput).toHaveValue('aaaabbbb-cccc-dddd-eeee-ffffffffffff');
    });

    it('Delete button shows confirmation dialog', async () => {
      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          return HttpResponse.json({ data: mockTenants });
        })
      );

      const { user } = renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete tenant');
      await user.click(deleteButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Remove Azure AD Tenant')).toBeInTheDocument();
      });
      expect(screen.getByText(/Are you sure you want to remove "Contoso Corp"/)).toBeInTheDocument();
    });

    it('Delete success removes tenant from list', async () => {
      let deleteCalled = false;

      server.use(
        http.get('/api/v1/admin/azure-tenants', () => {
          if (deleteCalled) {
            return HttpResponse.json({ data: [mockTenants[1]] });
          }
          return HttpResponse.json({ data: mockTenants });
        }),
        http.delete('/api/v1/admin/azure-tenants/:id', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'azure tenant deleted' });
        })
      );

      const { user } = renderAzureTenantList();

      await waitFor(() => {
        expect(screen.getByText('Contoso Corp')).toBeInTheDocument();
      });

      const deleteButtons = screen.getAllByTitle('Delete tenant');
      await user.click(deleteButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Remove Azure AD Tenant')).toBeInTheDocument();
      });
      const removeButton = screen.getByRole('button', { name: /^remove$/i });
      await user.click(removeButton);

      await waitFor(() => {
        expect(screen.queryByText('Contoso Corp')).not.toBeInTheDocument();
      });
    });
  });
});
