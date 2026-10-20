import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider } from '@/contexts/AuthContext';
import { mockOrganizations } from '@/test/mocks/rbac-fixtures';
import type { Organization } from '@/types/rbac';
import React, { useState } from 'react';

// Mock the useOrgContext hook from RBACManager
// Use the shared TestOrgContext from test-utils so MockOrgProvider works
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

// Override the global useAdmin mock to grant full-admin status on every
// fixture org. The real component shows the Edit button only when
// adminOrgIds includes the row's org id (RD-917 §1 — tier-2 admin can edit
// only their own orgs); for tests we treat all fixture orgs as own.
vi.mock('@/components/auth/RequireAdmin', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/components/auth/RequireAdmin')>();
  return {
    ...actual,
    useAdmin: vi.fn().mockReturnValue({
      isAdmin: true,
      isReadonlyAdmin: false,
      adminOrgIds: ['org-1', 'org-2', 'org-3'],
      readonlyAdminOrgIds: [],
    }),
  };
});

// Import after mock is set up
import OrganizationList from '../OrganizationList';
import { TestOrgContext } from './test-utils';

// Note: We no longer mock window.confirm and window.alert since we use styled dialogs

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

interface MockOrgProviderProps {
  children: React.ReactNode;
  organizations?: Organization[];
  onOrgChange?: (org: Organization | null) => void;
}

function MockOrgProvider({
  children,
  organizations: initialOrganizations = [],
  onOrgChange,
}: MockOrgProviderProps) {
  const [selectedOrg, setSelectedOrg] = useState<Organization | null>(null);
  const [organizations, setOrganizations] = useState<Organization[]>(initialOrganizations);

  const handleSetSelectedOrg = (org: Organization | null) => {
    setSelectedOrg(org);
    onOrgChange?.(org);
  };

  const refreshOrgs = async () => {
    // Fetch from mock API
    const response = await fetch('/api/v1/admin/orgs');
    const json = await response.json();
    // Handle both paginated and plain array formats
    const data = json.data || json;
    setOrganizations(data);
  };

  return (
    <TestOrgContext.Provider
      value={{
        selectedOrg,
        setSelectedOrg: handleSetSelectedOrg,
        organizations,
        refreshOrgs,
      }}
    >
      {children}
    </TestOrgContext.Provider>
  );
}

function renderOrganizationList(options: { organizations?: Organization[] } = {}) {
  const queryClient = createTestQueryClient();
  const user = userEvent.setup();

  render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <MockOrgProvider organizations={options.organizations}>
            <OrganizationList />
          </MockOrgProvider>
        </MemoryRouter>
      </AuthProvider>
    </QueryClientProvider>
  );

  return { user };
}

describe('OrganizationList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.resetHandlers();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', () => {
      // Return organizations after a delay to see loading state
      server.use(
        http.get('/api/v1/admin/orgs', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      // Should show loading spinner (via animate-spin class on Loader2)
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
    });

    it('shows "Organizations" heading and description text', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      expect(screen.getByText('Organizations')).toBeInTheDocument();
      expect(
        screen.getByText('Top-level tenants that contain groups and contracts')
      ).toBeInTheDocument();
    });

    it('shows empty state message when no organizations', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('No organizations found')).toBeInTheDocument();
      });

      // RD-917 §1: no "Create your first organization" CTA — tenant creation
      // is super-admin only, super-admin has no UI session.
      expect(screen.queryByText('Create your first organization')).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /add organization/i })).not.toBeInTheDocument();
    });

    it('displays table with correct headers (Name, Slug, Created, Actions)', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Name')).toBeInTheDocument();
      });

      expect(screen.getByText('Slug')).toBeInTheDocument();
      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Actions')).toBeInTheDocument();
    });
  });

  describe('Data Display', () => {
    it('shows organization name in table row', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });
    });

    it('shows organization slug in table row', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('acme-corp')).toBeInTheDocument();
      });
    });

    it('formats created date correctly', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      // mockOrganizations[0].created_at is '2024-01-01T00:00:00Z'
      // Should format as "Jan 1, 2024"
      await waitFor(() => {
        expect(screen.getByText('Jan 1, 2024')).toBeInTheDocument();
      });
    });

    it('shows correct number of rows matching API response', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        // mockOrganizations has 3 organizations
        const table = screen.getByRole('table');
        const rows = within(table).getAllByRole('row');
        // 1 header row + 3 data rows = 4 total
        expect(rows).toHaveLength(4);
      });
    });
  });

  describe('Actions', () => {
    // RD-917 §1: "Add Organization" button removed entirely. Tenant creation
    // is super-admin-only and super-admin has no UI session, so there is no
    // path through the dashboard to call POST /admin/orgs.
    it('does NOT render an Add Organization button (super-admin has no UI)', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      expect(screen.queryByRole('button', { name: /add organization/i })).not.toBeInTheDocument();
    });

    // RD-917 §1: per-row Delete button removed entirely. Same rationale as
    // Add — DELETE /admin/orgs/:id is super-admin-only.
    it('does NOT render per-row Delete buttons', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      expect(screen.queryAllByTitle('Delete organization')).toHaveLength(0);
    });

    it('Edit button opens form populated with org data', async () => {
      server.use(
        http.get('/api/v1/admin/orgs', () => {
          return HttpResponse.json({ data: mockOrganizations, total: mockOrganizations.length, limit: 25, offset: 0 });
        })
      );

      const { user } = renderOrganizationList();

      await waitFor(() => {
        expect(screen.getByText('Acme Corporation')).toBeInTheDocument();
      });

      // Find the edit button for the first org (by title attribute)
      const editButtons = screen.getAllByTitle('Edit organization');
      await user.click(editButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Edit Organization')).toBeInTheDocument();
      });

      // Form should be populated with org data
      const nameInput = screen.getByPlaceholderText('e.g., Acme Corporation');
      expect(nameInput).toHaveValue('Acme Corporation');

      const slugInput = screen.getByPlaceholderText('e.g., acme-corp');
      expect(slugInput).toHaveValue('acme-corp');
    });

    // RD-917 §1: Delete tests removed. The Delete button is no longer
    // surfaced (DELETE /admin/orgs/:id is super-admin-only and super-admin
    // has no UI session). Backend rejection is covered by the Go integration
    // tests in admin_org_isolation_test.go.
  });
});
