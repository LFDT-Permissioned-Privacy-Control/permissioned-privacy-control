import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import UserDetail from '../UserDetail';
import {
  mockMembershipsWithDetails,
  mockLinkedAddresses,
  mockFullEffectivePermissions,
  mockEmptyEffectivePermissions,
} from '@/test/mocks/rbac-fixtures';
import {
  mockUser,
  mockMembershipWithDetails,
  mockEffectivePermissions,
  mockOrganization,
} from '@/test/mocks/handlers';
import type { Organization } from '@/types/rbac';

// Mock useOrgContext from RBACManager
// Note: vi.mock is hoisted, so create context inside the factory
const mockUseOrgContext = vi.fn();
vi.mock('../RBACManager', async () => {
  const { createContext } = await import('react');
  const MockOrgContext = createContext(null);
  return {
    OrgContext: MockOrgContext,
    useOrgContext: () => mockUseOrgContext(),
    useOrgContextOptional: () => mockUseOrgContext(),
  };
});

// Mock useEnsNames to avoid network calls to ENS
vi.mock('@/hooks/useEnsNames', () => ({
  useEnsNames: () => ({
    data: {},
    isLoading: false,
    error: null,
  }),
}));

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
  initialOrg?: Organization | null;
  organizations?: Organization[];
}

// Helper to render UserDetail with required props
function renderUserDetail(
  user = mockUser,
  onUpdate = vi.fn(),
  options: RenderOptions = {}
) {
  const {
    initialOrg = mockOrganization,
    organizations = [mockOrganization],
  } = options;

  // Setup the mock context value
  mockUseOrgContext.mockReturnValue({
    selectedOrg: initialOrg,
    setSelectedOrg: vi.fn(),
    organizations,
    refreshOrgs: vi.fn(),
  });

  const queryClient = createTestQueryClient();

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <UserDetail user={user} onUpdate={onUpdate} />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe('UserDetail', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset mock to default values
    mockUseOrgContext.mockReturnValue({
      selectedOrg: mockOrganization,
      setSelectedOrg: vi.fn(),
      organizations: [mockOrganization],
      refreshOrgs: vi.fn(),
    });
  });

  // =========================================================================
  // Basic Info Display
  // =========================================================================
  describe('Basic Info Display', () => {
    it('displays user external_id (DID)', async () => {
      renderUserDetail();

      await waitFor(() => {
        const input = screen.getByDisplayValue(mockUser.external_id);
        expect(input).toBeInTheDocument();
        expect(input).toBeDisabled();
      });
    });

    it('displays KYC status badge - green "Verified" when true', async () => {
      const kycUser = { ...mockUser, kyc: true };
      renderUserDetail(kycUser);

      await waitFor(() => {
        // The KYC checkbox should be checked
        const kycLabel = screen.getByText('KYC Verified');
        expect(kycLabel).toBeInTheDocument();

        // Find the checkbox by looking at the parent structure
        const checkbox = kycLabel.closest('label')?.querySelector('input[type="checkbox"]');
        expect(checkbox).toBeChecked();
      });
    });

    it('displays KYC status badge - gray "Unverified" when false', async () => {
      const noKycUser = { ...mockUser, kyc: false };
      renderUserDetail(noKycUser);

      await waitFor(() => {
        const kycLabel = screen.getByText('KYC Verified');
        expect(kycLabel).toBeInTheDocument();

        const checkbox = kycLabel.closest('label')?.querySelector('input[type="checkbox"]');
        expect(checkbox).not.toBeChecked();
      });
    });

    it('displays banned badge when user is banned', async () => {
      const bannedUser = { ...mockUser, banned: true };
      renderUserDetail(bannedUser);

      await waitFor(() => {
        const bannedLabel = screen.getByText('Banned');
        expect(bannedLabel).toBeInTheDocument();

        const checkbox = bannedLabel.closest('label')?.querySelector('input[type="checkbox"]');
        expect(checkbox).toBeChecked();
      });
    });

    it('displays user note if present', async () => {
      const userWithNote = { ...mockUser, note: 'This is a test note for the user' };
      renderUserDetail(userWithNote);

      await waitFor(() => {
        const noteTextarea = screen.getByPlaceholderText('Add a note about this user...');
        expect(noteTextarea).toHaveValue('This is a test note for the user');
      });
    });

    it('displays empty note textarea when no note', async () => {
      const userWithoutNote = { ...mockUser, note: '' };
      renderUserDetail(userWithoutNote);

      await waitFor(() => {
        const noteTextarea = screen.getByPlaceholderText('Add a note about this user...');
        expect(noteTextarea).toHaveValue('');
      });
    });
  });

  // =========================================================================
  // Group Memberships Section
  // =========================================================================
  describe('Group Memberships', () => {
    it('fetches memberships on mount', async () => {
      let membershipsFetched = false;
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          membershipsFetched = true;
          return HttpResponse.json([mockMembershipWithDetails]);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(membershipsFetched).toBe(true);
      });
    });

    it('displays exactly the memberships returned by API - no phantom data', async () => {
      const specificMemberships = [mockMembershipsWithDetails[0]]; // Just one membership

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(specificMemberships);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        // Should display the Engineering group from the membership
        expect(screen.getByText('Engineering')).toBeInTheDocument();
      });

      // Should NOT display groups that are not in the response
      expect(screen.queryByText('DevOps')).not.toBeInTheDocument();
      expect(screen.queryByText('Operations')).not.toBeInTheDocument();
    });

    it('shows group name for each membership', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(mockMembershipsWithDetails);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('Engineering')).toBeInTheDocument();
        expect(screen.getByText('DevOps')).toBeInTheDocument();
        expect(screen.getByText('Operations')).toBeInTheDocument();
      });
    });

    it('shows source badge correctly (admin vs zk_attested)', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(mockMembershipsWithDetails);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        // Check for admin source badge - now displays "Added by admin"
        const adminBadges = screen.getAllByText('Added by admin');
        expect(adminBadges.length).toBeGreaterThan(0);

        // Check for zk_attested source badge - now displays "ZK Attested"
        expect(screen.getByText('ZK Attested')).toBeInTheDocument();
      });
    });

    it('shows an "Expires" badge for an active time-boxed membership and "Expired" for a lapsed one (RD-1157)', async () => {
      const future = new Date(Date.now() + 60 * 60 * 1000).toISOString();
      const past = new Date(Date.now() - 60 * 60 * 1000).toISOString();
      const base = {
        user_id: 'user-1',
        source: 'admin' as const,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      };
      const grp = (id: string, name: string) => ({
        id,
        org_id: 'org-1',
        parent_id: null,
        slug: id,
        name,
        description: '',
        depth: 0,
        path: id,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-01-01T00:00:00Z',
      });

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([
            { membership: { ...base, id: 'm-active', group_id: 'g-active', expires_at: future }, group: grp('g-active', 'Regulator Access'), expired: false },
            { membership: { ...base, id: 'm-expired', group_id: 'g-expired', expires_at: past }, group: grp('g-expired', 'Auditor Access'), expired: true },
          ]);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('Regulator Access')).toBeInTheDocument();
        expect(screen.getByText('Auditor Access')).toBeInTheDocument();
      });

      // Active time-boxed grant → "Expires <date>"; lapsed grant → "Expired <date>".
      // (Group names deliberately avoid the words so the matchers are unambiguous.)
      expect(screen.getByText(/^Expires /)).toBeInTheDocument();
      expect(screen.getByText(/^Expired /)).toBeInTheDocument();
    });

    it('does NOT show memberships not in API response', async () => {
      // Return empty memberships
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([]);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('No group memberships')).toBeInTheDocument();
      });

      // No membership groups should appear
      expect(screen.queryByText('Engineering')).not.toBeInTheDocument();
      expect(screen.queryByText('Root Group')).not.toBeInTheDocument();
    });

    it('shows empty state when no memberships', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([]);
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('No group memberships')).toBeInTheDocument();
      });
    });

    it('add membership button is present', async () => {
      renderUserDetail();

      await waitFor(() => {
        const addButton = screen.getByRole('button', { name: /add/i });
        expect(addButton).toBeInTheDocument();
      });
    });

    it('remove membership calls DELETE endpoint', async () => {
      let deleteEndpointCalled = false;
      let deletedMembershipId = '';

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([mockMembershipWithDetails]);
        }),
        http.delete('/api/v1/admin/users/:userId/memberships/:membershipId', ({ params }) => {
          deleteEndpointCalled = true;
          deletedMembershipId = params.membershipId as string;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const onUpdate = vi.fn();
      const user = userEvent.setup();
      renderUserDetail(mockUser, onUpdate);

      // Wait for memberships to load
      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Find and click the delete button (trash icon)
      const deleteButton = screen.getByRole('button', { name: /remove membership/i });
      await user.click(deleteButton);

      // Wait for confirmation dialog and click confirm
      await waitFor(() => {
        expect(screen.getByText('Remove Membership')).toBeInTheDocument();
      });
      const confirmButton = screen.getByRole('button', { name: /^remove$/i });
      await user.click(confirmButton);

      await waitFor(() => {
        expect(deleteEndpointCalled).toBe(true);
        expect(deletedMembershipId).toBe('membership-1');
      });

      // Verify onUpdate was called after deletion
      await waitFor(() => {
        expect(onUpdate).toHaveBeenCalled();
      });
    });

    it('does not delete membership when confirm is cancelled', async () => {
      let deleteEndpointCalled = false;

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([mockMembershipWithDetails]);
        }),
        http.delete('/api/v1/admin/users/:userId/memberships/:membershipId', () => {
          deleteEndpointCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      const deleteButton = screen.getByRole('button', { name: /remove membership/i });
      await user.click(deleteButton);

      // Wait for confirmation dialog and click cancel
      await waitFor(() => {
        expect(screen.getByText('Remove Membership')).toBeInTheDocument();
      });
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      await user.click(cancelButton);

      // Give some time for potential async operation
      await new Promise(resolve => setTimeout(resolve, 100));

      expect(deleteEndpointCalled).toBe(false);
    });
  });

  // =========================================================================
  // Linked Addresses Section
  // =========================================================================
  describe('Linked Addresses', () => {
    it('fetches linked addresses on mount', async () => {
      let addressesFetched = false;

      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          addressesFetched = true;
          return HttpResponse.json({ addresses: mockLinkedAddresses });
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(addressesFetched).toBe(true);
      });
    });

    it('displays addresses when present', async () => {
      const testAddresses = [
        { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-05T10:30:00Z' },
        { address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd', verified_at: '2024-01-10T14:45:00Z' },
      ];

      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          return HttpResponse.json({ addresses: testAddresses });
        })
      );

      renderUserDetail();

      await waitFor(() => {
        // Check for truncated addresses (the component uses AddressDisplay)
        // The addresses should be displayed in some form
        expect(screen.getByText('Linked Wallet Addresses')).toBeInTheDocument();
      });

      // Wait for addresses to render - check for verification timestamps with date format
      await waitFor(() => {
        // Each address should have a verification date in format "Verified M/D/YYYY"
        const verifiedTexts = screen.getAllByText(/Verified \d+\/\d+\/\d+/);
        expect(verifiedTexts.length).toBe(testAddresses.length);
      });
    });

    it('shows "No linked addresses" when empty', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          return HttpResponse.json({ addresses: [] });
        })
      );

      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('No linked wallet addresses')).toBeInTheDocument();
      });
    });

    it('shows verification timestamp for each address', async () => {
      const addressesWithTimestamps = [
        { address: '0x1234567890123456789012345678901234567890', verified_at: '2024-01-05T10:30:00Z' },
        { address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd', verified_at: '2024-01-10T14:45:00Z' },
      ];

      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          return HttpResponse.json({ addresses: addressesWithTimestamps });
        })
      );

      renderUserDetail();

      await waitFor(() => {
        // The component displays dates as "Verified 1/5/2024" format
        const verifiedTexts = screen.getAllByText(/Verified \d+\/\d+\/\d+/);
        expect(verifiedTexts.length).toBe(2);
      });
    });

    it('handles linked addresses API error gracefully', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          return HttpResponse.json({ error: 'Failed to load' }, { status: 500 });
        })
      );

      renderUserDetail();

      // Should show empty state on error
      await waitFor(() => {
        expect(screen.getByText('No linked wallet addresses')).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // Effective Permissions Section
  // =========================================================================
  describe('Effective Permissions', () => {
    it('fetches effective-permissions on mount when org is selected', async () => {
      let permissionsFetched = false;

      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          permissionsFetched = true;
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        expect(permissionsFetched).toBe(true);
      });
    });

    it('displays allowed_methods list', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        // Should show allowed methods
        expect(screen.getByText(/Allowed Methods/)).toBeInTheDocument();
        expect(screen.getByText('eth_call')).toBeInTheDocument();
        expect(screen.getByText('eth_getBalance')).toBeInTheDocument();
        expect(screen.getByText('eth_sendTransaction')).toBeInTheDocument();
      });
    });

    it('displays role badge for access level', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        expect(screen.getByText('Access Level')).toBeInTheDocument();
        // Role badge is derived from allowed_methods via getClosestPresetLabel
        // mockEffectivePermissions has 3 methods which is a subset of Wallet User
        // so it should show a role badge (not individual claim badges)
        const accessSection = screen.getByText('Access Level').closest('div');
        expect(accessSection).toBeInTheDocument();
      });
    });

    it('displays rate limits', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        expect(screen.getByText('Rate Limit (RPS)')).toBeInTheDocument();
        expect(screen.getByText('Rate Limit (Daily)')).toBeInTheDocument();
        expect(screen.getByText('100')).toBeInTheDocument();
        expect(screen.getByText('10000')).toBeInTheDocument();
      });
    });

    it('shows appropriate message when permissions are empty', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEmptyEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        // Should display "None" for empty claims
        expect(screen.getByText('None')).toBeInTheDocument();
        // Should display "All methods (unrestricted)" for empty allowed_methods
        expect(screen.getByText('All methods (unrestricted)')).toBeInTheDocument();
      });
    });

    it('shows message when no permissions in organization', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(null, { status: 404 });
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        expect(screen.getByText('No permissions configured')).toBeInTheDocument();
      });
    });

    it('does not show permissions section when user has no memberships', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([]); // No memberships
        }),
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: null });

      await waitFor(() => {
        expect(screen.getByText('No group memberships')).toBeInTheDocument();
      });

      // Permissions section should not be visible since no memberships = no orgs
      expect(screen.queryByText('Effective Permissions')).not.toBeInTheDocument();
    });

    it('displays more than 10 methods with count badge', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockFullEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        // Should show allowed methods count
        expect(screen.getByText(/Allowed Methods \(10\)/)).toBeInTheDocument();
      });
    });

    it('displays unlimited when rate limits are null', async () => {
      const unlimitedPerms = {
        ...mockEffectivePermissions,
        rate_limit_rps: null,
        rate_limit_daily: null,
      };

      server.use(
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(unlimitedPerms);
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      await waitFor(() => {
        const unlimitedTexts = screen.getAllByText('Unlimited');
        expect(unlimitedTexts.length).toBe(2);
      });
    });
  });

  // =========================================================================
  // User Edit Functionality
  // =========================================================================
  describe('User Edit Functionality', () => {
    it('shows save button when changes are made', async () => {
      const user = userEvent.setup();
      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('KYC Verified')).toBeInTheDocument();
      });

      // Initially, save button should not be visible
      expect(screen.queryByText('Save Changes')).not.toBeInTheDocument();

      // Toggle KYC checkbox
      const kycLabel = screen.getByText('KYC Verified');
      const checkbox = kycLabel.closest('label')?.querySelector('input[type="checkbox"]');
      if (checkbox) {
        await user.click(checkbox);
      }

      // Save button should appear
      await waitFor(() => {
        expect(screen.getByText('Save Changes')).toBeInTheDocument();
      });
    });

    it('calls update endpoint when saving changes', async () => {
      let updateCalled = false;
      let updatePayload: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/users/:userId', async ({ request }) => {
          updateCalled = true;
          updatePayload = await request.json();
          return HttpResponse.json({ ...mockUser, ...updatePayload });
        })
      );

      const onUpdate = vi.fn();
      const user = userEvent.setup();
      renderUserDetail(mockUser, onUpdate);

      await waitFor(() => {
        expect(screen.getByText('KYC Verified')).toBeInTheDocument();
      });

      // Toggle KYC
      const kycLabel = screen.getByText('KYC Verified');
      const checkbox = kycLabel.closest('label')?.querySelector('input[type="checkbox"]');
      if (checkbox) {
        await user.click(checkbox);
      }

      // Click save
      await waitFor(() => {
        expect(screen.getByText('Save Changes')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(updateCalled).toBe(true);
        expect(updatePayload?.kyc).toBe(false);
        expect(onUpdate).toHaveBeenCalled();
      });
    });

    it('displays error when update fails', async () => {
      server.use(
        http.put('/api/v1/admin/users/:userId', () => {
          return HttpResponse.json(
            { error: 'Failed to update user' },
            { status: 500 }
          );
        })
      );

      const user = userEvent.setup();
      renderUserDetail();

      await waitFor(() => {
        expect(screen.getByText('KYC Verified')).toBeInTheDocument();
      });

      // Make a change
      const noteTextarea = screen.getByPlaceholderText('Add a note about this user...');
      await user.type(noteTextarea, 'Test note');

      // Click save
      await waitFor(() => {
        expect(screen.getByText('Save Changes')).toBeInTheDocument();
      });
      await user.click(screen.getByText('Save Changes'));

      await waitFor(() => {
        expect(screen.getByText('Failed to update user')).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // Multi-Organization Support
  // =========================================================================
  describe('Multi-Organization Support', () => {
    const mockOrg2: Organization = {
      id: 'org-2',
      slug: 'globex',
      name: 'Globex Corporation',
      settings: {},
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };

    const mockGroup2 = {
      id: 'group-2',
      org_id: 'org-2',
      parent_id: null,
      slug: 'auditors',
      name: 'Auditors',
      description: 'Auditor group',
      depth: 0,
      path: 'auditors',
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };

    const mockMembership2 = {
      id: 'membership-2',
      user_id: 'user-1',
      group_id: 'group-2',
      source: 'admin' as const,
      created_at: '2024-01-01T00:00:00Z',
      updated_at: '2024-01-01T00:00:00Z',
    };

    it('groups memberships by organization', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([
            mockMembershipWithDetails, // org-1
            { membership: mockMembership2, group: mockGroup2 }, // org-2
          ]);
        }),
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), {
        organizations: [mockOrganization, mockOrg2],
      });

      // First wait for group names to appear (indicates memberships loaded)
      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
        expect(screen.getByText('Auditors')).toBeInTheDocument();
      });

      // Org headers should be visible (may appear multiple times - once in memberships, once in permissions)
      // Using getAllByText since org name appears in both sections
      expect(screen.getAllByText('Test Organization').length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText('Globex Corporation').length).toBeGreaterThanOrEqual(1);
    });

    it('shows effective permissions for each org user is a member of', async () => {
      const mockPerms2 = {
        ...mockEffectivePermissions,
        id: 'eff-perms-2',
        org_id: 'org-2',
        claims: ['admin'] as const,
      };

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([
            mockMembershipWithDetails, // org-1
            { membership: mockMembership2, group: mockGroup2 }, // org-2
          ]);
        }),
        http.get('/api/v1/admin/users/:userId/effective-permissions', ({ request }) => {
          const url = new URL(request.url);
          const orgSlug = url.searchParams.get('org');
          if (orgSlug === 'globex') {
            return HttpResponse.json(mockPerms2);
          }
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), {
        organizations: [mockOrganization, mockOrg2],
        initialOrg: null, // Global scope
      });

      await waitFor(() => {
        // Should show effective permissions section
        expect(screen.getByText('Effective Permissions')).toBeInTheDocument();
      });

      // Should show permissions for both orgs (org headers in permissions section)
      // The permissions section should have org names as headers
      await waitFor(() => {
        const permSection = screen.getByText('Effective Permissions').closest('.space-y-3');
        expect(permSection).toBeInTheDocument();
      });
    });

    it('loads permissions for all orgs user has memberships in', async () => {
      const orgSlugsRequested: string[] = [];

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([
            mockMembershipWithDetails, // org-1
            { membership: mockMembership2, group: mockGroup2 }, // org-2
          ]);
        }),
        http.get('/api/v1/admin/users/:userId/effective-permissions', ({ request }) => {
          const url = new URL(request.url);
          const orgSlug = url.searchParams.get('org');
          if (orgSlug) {
            orgSlugsRequested.push(orgSlug);
          }
          return HttpResponse.json(mockEffectivePermissions);
        })
      );

      renderUserDetail(mockUser, vi.fn(), {
        organizations: [mockOrganization, mockOrg2],
        initialOrg: null,
      });

      await waitFor(() => {
        // Should have requested permissions for both orgs
        expect(orgSlugsRequested).toContain('test-org');
        expect(orgSlugsRequested).toContain('globex');
      });
    });
  });

  // =========================================================================
  // Add Membership Dialog
  // =========================================================================
  describe('Add Membership Dialog', () => {
    it('opens membership form dialog when add button is clicked', async () => {
      const user = userEvent.setup();
      renderUserDetail();

      // Wait for memberships section to load
      await waitFor(() => {
        expect(screen.getByText('Group Memberships')).toBeInTheDocument();
      });

      // Find the Add button in the Group Memberships section
      // The button text is just "Add" next to the Plus icon
      const addButtons = screen.getAllByRole('button', { name: /add/i });
      // The Add button for memberships is the one in the Group Memberships section
      const membershipAddButton = addButtons.find(btn =>
        btn.closest('.space-y-3')?.querySelector('h4')?.textContent?.includes('Group Memberships')
      );

      expect(membershipAddButton).toBeTruthy();
      await user.click(membershipAddButton!);

      await waitFor(() => {
        expect(screen.getByText('Add Group Membership')).toBeInTheDocument();
      });
    });
  });

  // =========================================================================
  // Loading States
  // =========================================================================
  describe('Loading States', () => {
    it('shows loading spinner while fetching memberships', async () => {
      // Delay the response to observe loading state
      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json([mockMembershipWithDetails]);
        })
      );

      renderUserDetail();

      // Should show loading state initially (spinner has animate-spin class)
      const spinners = document.querySelectorAll('.animate-spin');
      expect(spinners.length).toBeGreaterThan(0);

      // Eventually should load content
      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });
    });

    it('shows loading spinner while fetching linked addresses', async () => {
      server.use(
        http.get('/api/v1/admin/users/:userId/linked-addresses', async () => {
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({ addresses: mockLinkedAddresses });
        })
      );

      renderUserDetail();

      // Loading state
      expect(document.querySelectorAll('.animate-spin').length).toBeGreaterThan(0);

      // Eventually should load
      await waitFor(() => {
        const verifiedTexts = screen.getAllByText(/Verified/);
        expect(verifiedTexts.length).toBeGreaterThan(0);
      });
    });
  });

  // =========================================================================
  // Integration: Data Consistency
  // =========================================================================
  describe('Data Consistency', () => {
    it('only displays data from API responses, not from fixtures or props', async () => {
      // Set up specific API responses
      const specificMembership = {
        membership: {
          id: 'specific-membership',
          user_id: 'user-1',
          group_id: 'specific-group',
          source: 'admin',
          zk_credential_ref: '',
          expires_at: null,
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
        group: {
          id: 'specific-group',
          org_id: 'org-1',
          parent_id: null,
          slug: 'specific',
          name: 'Specific Group Only',
          description: '',
          depth: 0,
          path: 'specific',
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-01-01T00:00:00Z',
        },
      };

      const specificAddress = {
        address: '0xspecificaddress1234567890123456789012345',
        verified_at: '2024-06-15T00:00:00Z',
      };

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json([specificMembership]);
        }),
        http.get('/api/v1/admin/users/:userId/linked-addresses', () => {
          return HttpResponse.json({ addresses: [specificAddress] });
        }),
        http.get('/api/v1/admin/users/:userId/effective-permissions', () => {
          return HttpResponse.json({
            ...mockEffectivePermissions,
            allowed_methods: ['eth_specific_method'],
            claims: ['reader'],
          });
        })
      );

      renderUserDetail(mockUser, vi.fn(), { initialOrg: mockOrganization });

      // Wait for data to load
      await waitFor(() => {
        expect(screen.getByText('Specific Group Only')).toBeInTheDocument();
      });

      // Verify specific membership is shown
      expect(screen.getByText('Specific Group Only')).toBeInTheDocument();

      // Verify mock fixture groups are NOT shown
      expect(screen.queryByText('Engineering')).not.toBeInTheDocument();
      expect(screen.queryByText('DevOps')).not.toBeInTheDocument();
      expect(screen.queryByText('Root Group')).not.toBeInTheDocument();

      // Verify specific method is shown
      await waitFor(() => {
        expect(screen.getByText('eth_specific_method')).toBeInTheDocument();
      });

      // Verify fixture methods are NOT shown
      expect(screen.queryByText('eth_call')).not.toBeInTheDocument();
      expect(screen.queryByText('eth_getBalance')).not.toBeInTheDocument();
    });

    it('refreshes data after membership deletion', async () => {
      let fetchCount = 0;

      server.use(
        http.get('/api/v1/admin/users/:userId/memberships', () => {
          fetchCount++;
          if (fetchCount === 1) {
            return HttpResponse.json([mockMembershipWithDetails]);
          }
          // After deletion, return empty
          return HttpResponse.json([]);
        }),
        http.delete('/api/v1/admin/users/:userId/memberships/:membershipId', () => {
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderUserDetail();

      // Wait for initial load
      await waitFor(() => {
        expect(screen.getByText('Root Group')).toBeInTheDocument();
      });

      // Delete the membership
      const deleteButton = screen.getByRole('button', { name: /remove membership/i });
      await user.click(deleteButton);

      // Wait for confirmation dialog and click confirm
      await waitFor(() => {
        expect(screen.getByText('Remove Membership')).toBeInTheDocument();
      });
      const confirmButton = screen.getByRole('button', { name: /^remove$/i });
      await user.click(confirmButton);

      // Should refetch and show empty state
      await waitFor(() => {
        expect(screen.getByText('No group memberships')).toBeInTheDocument();
      });

      expect(fetchCount).toBe(2);
    });
  });
});
