import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithRBACContext } from './test-utils';
import { useAdmin } from '@/components/auth/RequireAdmin';
import { mockContracts, mockOrganizations } from '@/test/mocks/rbac-fixtures';

// RBACManager → orgcontext mock pattern matches the other RBAC tests.
vi.mock('../RBACManager', async () => {
  const { TestOrgContext, useOrgContext, useOrgContextOptional } = await import('./test-utils');
  return {
    OrgContext: TestOrgContext,
    useOrgContext,
    useOrgContextOptional,
  };
});

// Imports after mocks
import OrganizationList from '../OrganizationList';
import GroupList from '../GroupList';
import ContractList from '../ContractList';

/**
 * RD-866: read-only admins must not see mutating UI controls (Add / Edit /
 * Delete / batch-delete). API enforcement is covered by the Go integration
 * tests + the demo-verify-readonly-admin.sh script in the e2e demo repo;
 * these tests pin the React-state half so a future refactor can't
 * accidentally re-render the buttons for a viewer who shouldn't see them.
 */
describe('Read-only admin: mutating buttons hidden (RD-866)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(useAdmin).mockReturnValue({
      isAdmin: true,
      isReadonlyAdmin: true,
      adminOrgIds: [],
      readonlyAdminOrgIds: ['org-1'],
    });
  });

  afterEach(() => {
    cleanup();
    // Restore the default (non-readonly) so other tests aren't affected.
    vi.mocked(useAdmin).mockReturnValue({
      isAdmin: true,
      isReadonlyAdmin: false,
      adminOrgIds: [],
      readonlyAdminOrgIds: [],
    });
  });

  describe('OrganizationList', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs', () =>
          HttpResponse.json({
            data: mockOrganizations,
            total: mockOrganizations.length,
            limit: 50,
            offset: 0,
          })
        )
      );
    });

    it('hides Add Organization button', async () => {
      renderWithRBACContext(<OrganizationList />);
      // Wait for the heading so the list is fully rendered.
      await waitFor(() => {
        expect(screen.getByText('Organizations')).toBeInTheDocument();
      });
      expect(screen.queryByRole('button', { name: /add organization/i })).not.toBeInTheDocument();
    });

    it('hides per-row Edit / Delete actions', async () => {
      renderWithRBACContext(<OrganizationList />);
      await waitFor(() => {
        expect(screen.getByText('Organizations')).toBeInTheDocument();
      });
      // Pre-readonly UI exposes these via title attributes — assert none are present.
      expect(document.querySelector('[title="Edit Organization"]')).toBeNull();
      expect(document.querySelector('[title="Delete Organization"]')).toBeNull();
    });
  });

  describe('GroupList', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () =>
          HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 })
        )
      );
    });

    it('hides Add Group button (empty-state variant included)', async () => {
      renderWithRBACContext(<GroupList />);
      await waitFor(() => {
        expect(screen.getByText('No groups found')).toBeInTheDocument();
      });
      // Both the toolbar Add button and the empty-state "Create your first group"
      // CTA must be hidden — they share the !isReadonlyAdmin guard.
      expect(screen.queryByRole('button', { name: /add group/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /create your first group/i })).not.toBeInTheDocument();
    });
  });

  describe('ContractList', () => {
    beforeEach(() => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/contracts', () =>
          HttpResponse.json({
            data: mockContracts,
            total: mockContracts.length,
            limit: 25,
            offset: 0,
          })
        ),
        http.get('/api/v1/admin/orgs/:orgId/contracts/grant-summary', () =>
          HttpResponse.json({})
        )
      );
    });

    it('hides Add Contract / batch action buttons', async () => {
      renderWithRBACContext(<ContractList />);
      await waitFor(() => {
        expect(screen.getByText('Contracts')).toBeInTheDocument();
      });
      // Add button should be gone.
      expect(screen.queryByRole('button', { name: /add contract/i })).not.toBeInTheDocument();
      // Sync / batch-action buttons that mutate state should be gone too.
      expect(screen.queryByRole('button', { name: /move to group/i })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: /sync.*chain/i })).not.toBeInTheDocument();
    });
  });
});

// Note: a "Read-only admin: mutating buttons present for full admin"
// describe used to live here as the inverse of the readonly assertions
// above, with one test case for OrganizationList's Add Organization
// button. PR #207 (RD-917 §1) removed that button from
// OrganizationList.tsx entirely — tenant lifecycle is X-Admin-Token only
// and that auth method never has a UI session — so the regression case
// no longer applies. The readonly-vs-full-admin distinction is still
// exercised by the GroupList and ContractList specs in the earlier
// describe block; if a future PR re-introduces a tenant-create UI for
// full admins, add a fresh describe here to pin its full-admin path.
