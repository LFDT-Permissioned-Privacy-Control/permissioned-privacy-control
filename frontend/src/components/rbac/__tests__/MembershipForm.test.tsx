import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import MembershipForm from '../MembershipForm';
import {
  mockOrganizations,
  createMockGroup,
} from '@/test/mocks/rbac-fixtures';
import { mockOrganization, mockGroup, mockChildGroup } from '@/test/mocks/handlers';

// Helper function to interact with Radix UI Select components
async function selectOption(user: ReturnType<typeof userEvent.setup>, triggerText: string, optionText: string) {
  // Find trigger by its accessible role (combobox)
  const triggers = screen.getAllByRole('combobox');
  // Find the trigger that contains or is preceded by the expected text/label
  let targetTrigger = triggers.find(trigger =>
    trigger.textContent?.includes(triggerText) ||
    trigger.textContent?.includes('Select')
  );

  // Fallback: find by placeholder text
  if (!targetTrigger) {
    targetTrigger = triggers[0];
  }

  await user.click(targetTrigger!);

  // Wait for the dropdown to open and find the option
  await waitFor(() => {
    const option = screen.getByRole('option', { name: new RegExp(optionText, 'i') });
    expect(option).toBeInTheDocument();
  });

  const option = screen.getByRole('option', { name: new RegExp(optionText, 'i') });
  await user.click(option);
}

// Wrapper component for MembershipForm tests
function renderMembershipForm(
  props: Partial<React.ComponentProps<typeof MembershipForm>> = {}
) {
  const defaultProps = {
    userId: 'user-1',
    organizations: [mockOrganization],
    onClose: vi.fn(),
    onSave: vi.fn(),
  };

  return render(<MembershipForm {...defaultProps} {...props} />);
}

describe('MembershipForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Form Display', () => {
    it('shows organization selection dropdown', () => {
      renderMembershipForm();

      expect(screen.getByText('Organization')).toBeInTheDocument();
      // The combobox (select trigger) should exist
      expect(screen.getAllByRole('combobox')).toHaveLength(1); // Only org select shown initially
    });

    it('shows group selection section', () => {
      renderMembershipForm();

      expect(screen.getByText('Group')).toBeInTheDocument();
      expect(screen.getByText('Select an organization first')).toBeInTheDocument();
    });

    it('dropdown lists available organizations from props', async () => {
      const user = userEvent.setup();

      renderMembershipForm({
        organizations: mockOrganizations,
      });

      // Click on the organization dropdown (combobox)
      const combobox = screen.getByRole('combobox');
      await user.click(combobox);

      await waitFor(() => {
        mockOrganizations.forEach(org => {
          expect(screen.getByRole('option', { name: new RegExp(org.name, 'i') })).toBeInTheDocument();
        });
      });
    });

    it('groups are fetched on organization selection', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', ({ params }) => {
          if (params.orgId === 'org-1') {
            return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
          }
          return HttpResponse.json({ data: [], total: 0, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Select an organization using combobox
      await selectOption(user, 'Select organization', 'Test Organization');

      // Wait for groups to be loaded
      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Now click on group dropdown - should now have 2 comboboxes
      const comboboxes = screen.getAllByRole('combobox');
      expect(comboboxes).toHaveLength(2);

      await user.click(comboboxes[1]); // Group dropdown

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });
    });
  });

  describe('Validation', () => {
    it('requires group selection before submit', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm({ onSave });

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Submit button should be disabled without group selection
      const submitButton = screen.getByRole('button', { name: /Add Membership/i });
      expect(submitButton).toBeDisabled();

      // onSave should not have been called
      expect(onSave).not.toHaveBeenCalled();
    });

    it('submit button disabled until group selected', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Initially disabled
      const submitButton = screen.getByRole('button', { name: /Add Membership/i });
      expect(submitButton).toBeDisabled();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Still disabled without group
      expect(submitButton).toBeDisabled();

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Now enabled
      await waitFor(() => {
        expect(submitButton).not.toBeDisabled();
      });
    });

    it('shows error if user already in selected group', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(
            { error: 'User is already a member of this group' },
            { status: 409 }
          );
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(screen.getByText('User is already a member of this group')).toBeInTheDocument();
      });
    });
  });

  describe('Submission', () => {
    it('submits POST to /users/:id/memberships', async () => {
      const user = userEvent.setup();
      let capturedRequest: { group_id: string } | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', async ({ request, params }) => {
          capturedRequest = (await request.json()) as { group_id: string };
          expect(params.userId).toBe('user-1');
          return HttpResponse.json({
            id: 'membership-new',
            user_id: 'user-1',
            group_id: capturedRequest.group_id,
            source: 'admin',
            zk_credential_ref: '',
            expires_at: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(capturedRequest).not.toBeNull();
        expect(capturedRequest?.group_id).toBe('group-1');
      });
    });

    it('includes selected group_id in request', async () => {
      const user = userEvent.setup();
      let capturedGroupId: string | null = null;

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', async ({ request }) => {
          const body = (await request.json()) as { group_id: string };
          capturedGroupId = body.group_id;
          return HttpResponse.json({
            id: 'membership-new',
            user_id: 'user-1',
            group_id: body.group_id,
            source: 'admin',
            zk_credential_ref: '',
            expires_at: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select the child group (Engineering)
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Engineering/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(capturedGroupId).toBe('group-2'); // mockChildGroup.id
      });
    });

    it('calls onSave callback after successful create', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json({
            id: 'membership-new',
            user_id: 'user-1',
            group_id: 'group-1',
            source: 'admin',
            zk_credential_ref: '',
            expires_at: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      renderMembershipForm({ onSave });

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(onSave).toHaveBeenCalledTimes(1);
      });
    });

    it('shows error message on API failure', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.json(
            { error: 'Internal server error' },
            { status: 500 }
          );
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(screen.getByText('Internal server error')).toBeInTheDocument();
      });
    });

    it('shows generic error message when no specific error returned', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', () => {
          return HttpResponse.error();
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      await waitFor(() => {
        expect(screen.getByText('Failed to create membership. Please try again.')).toBeInTheDocument();
      });
    });
  });

  describe('Group Display', () => {
    it('groups shown with name', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Open group dropdown
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });
    });

    it('shows group path if available', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Open group dropdown
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        // mockGroup path is 'root', mockChildGroup path is 'root.engineering'
        // The path is shown in parentheses
        const rootOption = screen.getByRole('option', { name: /Root Group/i });
        const engOption = screen.getByRole('option', { name: /Engineering/i });

        expect(rootOption).toHaveTextContent('(root)');
        expect(engOption).toHaveTextContent('(root.engineering)');
      });
    });

    it('shows message when no groups in organization', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.getByText('No groups in this organization')).toBeInTheDocument();
      });
    });
  });

  describe('Cancel Button', () => {
    it('calls onClose when cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderMembershipForm({ onClose });

      await user.click(screen.getByRole('button', { name: /Cancel/i }));

      expect(onClose).toHaveBeenCalledTimes(1);
    });

    it('cancel button is disabled during submission', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', async () => {
          // Delay to see the loading state
          await new Promise(resolve => setTimeout(resolve, 100));
          return HttpResponse.json({
            id: 'membership-new',
            user_id: 'user-1',
            group_id: 'group-1',
            source: 'admin',
            zk_credential_ref: '',
            expires_at: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit - this will start the save process
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      // Cancel should be disabled during save
      await waitFor(() => {
        expect(screen.getByText('Adding...')).toBeInTheDocument();
      });
    });
  });

  describe('Loading States', () => {
    it('shows loading indicator while fetching groups', async () => {
      const user = userEvent.setup();

      // Use a deferred promise we control so the groups endpoint never responds
      // until we explicitly release it. A fixed setTimeout delay is flaky because
      // the waitFor polling inside selectOption can accumulate enough wall-clock
      // time to let the fetch complete before we check for the loading indicator.
      let resolveGroups!: () => void;
      const groupsPending = new Promise<void>(resolve => { resolveGroups = resolve; });

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', async () => {
          await groupsPending;
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      // Loading indicator must be visible — groups endpoint is still pending.
      // Use findByText (not getByText) because the useEffect that triggers
      // the fetch runs asynchronously after React commits the org selection.
      expect(await screen.findByText('Loading groups...')).toBeInTheDocument();

      // Release the endpoint and wait for loading to finish
      resolveGroups();
      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });
    });

    it('shows "Adding..." during form submission', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        }),
        http.post('/api/v1/admin/users/:userId/memberships', async () => {
          await new Promise(resolve => setTimeout(resolve, 200));
          return HttpResponse.json({
            id: 'membership-new',
            user_id: 'user-1',
            group_id: 'group-1',
            source: 'admin',
            zk_credential_ref: '',
            expires_at: null,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Submit
      await user.click(screen.getByRole('button', { name: /Add Membership/i }));

      // Should show loading state
      expect(screen.getByText('Adding...')).toBeInTheDocument();
    });
  });

  describe('Permissions Info', () => {
    it('shows permissions info when group is selected', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm();

      // Initially no info shown
      expect(
        screen.queryByText(/will inherit permissions/)
      ).not.toBeInTheDocument();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Root Group/i }));

      // Info should appear
      await waitFor(() => {
        expect(
          screen.getByText(/will inherit permissions from this group/)
        ).toBeInTheDocument();
      });
    });
  });

  describe('Existing Memberships Filtering', () => {
    it('filters out groups user is already a member of', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
        })
      );

      // User is already in mockGroup (group-1)
      const existingMemberships = [
        {
          membership: {
            id: 'membership-1',
            user_id: 'user-1',
            group_id: 'group-1', // mockGroup.id
            source: 'admin' as const,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          group: mockGroup,
        },
      ];

      renderMembershipForm({ existingMemberships });

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Open group dropdown
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        // Should only show Engineering (group-2), not Root Group (group-1)
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });

      // Root Group should NOT be in the options
      expect(screen.queryByRole('option', { name: /Root Group/i })).not.toBeInTheDocument();
    });

    it('excludes org-admin groups but keeps normal and read-only-admin groups (RD-1099)', async () => {
      const user = userEvent.setup();

      const normalGroup = createMockGroup({ id: 'group-normal', org_id: 'org-1', name: 'Members', path: 'members' });
      const orgAdminGroup = createMockGroup({ id: 'group-admin', org_id: 'org-1', name: 'Org Admins', path: 'admins', is_org_admin: true });
      const readonlyAdminGroup = createMockGroup({ id: 'group-ro', org_id: 'org-1', name: 'Read Only Admins', path: 'ro-admins', is_org_readonly_admin: true });

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({
            data: [
              { group: normalGroup, access: null },
              { group: orgAdminGroup, access: null },
              { group: readonlyAdminGroup, access: null },
            ],
            total: 3,
            limit: 50,
            offset: 0,
          });
        })
      );

      renderMembershipForm();

      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Members/i })).toBeInTheDocument();
      });
      // Read-only-admin assignment is delegation, not escalation — stays visible.
      expect(screen.getByRole('option', { name: /Read Only Admins/i })).toBeInTheDocument();
      // Full org-admin assignment is super-admin-only — hidden from the tier-2 dropdown.
      expect(screen.queryByRole('option', { name: /Org Admins/i })).not.toBeInTheDocument();
    });

    it('shows message when user is in all groups', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }], total: 1, limit: 50, offset: 0 });
        })
      );

      // User is already in the only group
      const existingMemberships = [
        {
          membership: {
            id: 'membership-1',
            user_id: 'user-1',
            group_id: 'group-1',
            source: 'admin' as const,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          },
          group: mockGroup,
        },
      ];

      renderMembershipForm({ existingMemberships });

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Should show message that user is in all groups
      expect(
        screen.getByText('User is already a member of all groups in this organization')
      ).toBeInTheDocument();
    });

    it('shows all groups when no existing memberships provided', async () => {
      const user = userEvent.setup();

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json({ data: [{ group: mockGroup, access: null }, { group: mockChildGroup, access: null }], total: 2, limit: 50, offset: 0 });
        })
      );

      // No existingMemberships prop
      renderMembershipForm();

      // Select organization
      await selectOption(user, 'Select organization', 'Test Organization');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Open group dropdown
      const comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        // Both groups should be available
        expect(screen.getByRole('option', { name: /Root Group/i })).toBeInTheDocument();
        expect(screen.getByRole('option', { name: /Engineering/i })).toBeInTheDocument();
      });
    });
  });

  describe('Multiple Organizations', () => {
    it('clears groups when organization changes', async () => {
      const user = userEvent.setup();

      const org1Groups = [
        createMockGroup({ id: 'group-a', org_id: 'org-1', name: 'Group A', path: 'group-a' }),
      ];
      const org2Groups = [
        createMockGroup({ id: 'group-b', org_id: 'org-2', name: 'Group B', path: 'group-b' }),
      ];

      server.use(
        http.get('/api/v1/admin/orgs/:orgId/groups', ({ params }) => {
          if (params.orgId === 'org-1') {
            const data = org1Groups.map(g => ({ group: g, access: null }));
            return HttpResponse.json({ data, total: data.length, limit: 50, offset: 0 });
          }
          const data = org2Groups.map(g => ({ group: g, access: null }));
          return HttpResponse.json({ data, total: data.length, limit: 50, offset: 0 });
        })
      );

      renderMembershipForm({
        organizations: mockOrganizations.slice(0, 2),
      });

      // Select first organization
      await selectOption(user, 'Select organization', 'Acme Corporation');

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Select group from first org
      let comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Group A/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Group A/i }));

      // Change organization - click on the org combobox (first one)
      comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[0]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Globex/i })).toBeInTheDocument();
      });

      await user.click(screen.getByRole('option', { name: /Globex/i }));

      await waitFor(() => {
        expect(screen.queryByText('Loading groups...')).not.toBeInTheDocument();
      });

      // Group dropdown should now show Group B
      comboboxes = screen.getAllByRole('combobox');
      await user.click(comboboxes[1]);

      await waitFor(() => {
        expect(screen.getByRole('option', { name: /Group B/i })).toBeInTheDocument();
      });

      // Group A should not be in the options anymore
      expect(screen.queryByRole('option', { name: /Group A/i })).not.toBeInTheDocument();
    });
  });
});
