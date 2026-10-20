import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import GroupForm from '../GroupForm';
import { mockGroup } from '@/test/mocks/handlers';

// Minimal wrapper since GroupForm doesn't need org context directly
function renderGroupForm(props: {
  orgId?: string;
  groups?: typeof mockGroup[];
  group?: typeof mockGroup;
  onClose?: () => void;
  onSave?: () => void;
}) {
  const defaultProps = {
    orgId: 'org-1',
    groups: [],
    onClose: vi.fn(),
    onSave: vi.fn(),
  };

  return render(<GroupForm {...defaultProps} {...props} />);
}

describe('GroupForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Create Mode', () => {
    it('shows empty form fields', () => {
      renderGroupForm({});

      // Name field should be empty
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      expect(nameInput).toHaveValue('');

      // Slug field should be empty
      const slugInput = screen.getByPlaceholderText(/engineering/);
      expect(slugInput).toHaveValue('');
    });

    it('does not show parent group dropdown', () => {
      renderGroupForm({});

      // No combobox/select for parent should exist
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
      expect(screen.queryByText('Parent Group')).not.toBeInTheDocument();
    });

    it('validates name is required', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      renderGroupForm({ onSave });

      // Fill in slug but not name
      const slugInput = screen.getByPlaceholderText(/engineering/);
      await user.type(slugInput, 'test_slug');

      // Try to submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      // onSave should not have been called (form validation failed)
      expect(onSave).not.toHaveBeenCalled();
    });

    it('validates slug is required', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();

      renderGroupForm({ onSave });

      // Fill in name but clear auto-generated slug
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Test Group');

      // Clear the auto-generated slug
      const slugInput = screen.getByPlaceholderText(/engineering/);
      await user.clear(slugInput);

      // Try to submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      // onSave should not have been called (form validation failed)
      expect(onSave).not.toHaveBeenCalled();
    });

    it('submits POST with null parent_id', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroup,
            id: 'group-new',
          });
        })
      );

      renderGroupForm({ onSave });

      // Fill in name
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'New Team');

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        parent_id: null,
      });
    });

    it('auto-generates slug from name', async () => {
      const user = userEvent.setup();

      renderGroupForm({});

      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'My Test Group');

      const slugInput = screen.getByPlaceholderText(/engineering/);
      expect(slugInput).toHaveValue('my_test_group');
    });
  });

  describe('Edit Mode', () => {
    it('populates with existing group data', () => {
      renderGroupForm({
        group: mockGroup,
        groups: [],
      });

      // Name should be populated
      expect(screen.getByDisplayValue('Root Group')).toBeInTheDocument();

      // Slug field should not be shown in edit mode
      expect(screen.queryByPlaceholderText(/engineering/)).not.toBeInTheDocument();
    });

    it('shows Update button in edit mode', () => {
      renderGroupForm({
        group: mockGroup,
        groups: [],
      });

      expect(screen.getByText('Update Group')).toBeInTheDocument();
    });

    it('submits PUT request in edit mode', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json({
            ...mockGroup,
            name: capturedBody.name,
          });
        })
      );

      renderGroupForm({
        group: mockGroup,
        groups: [],
        onSave,
      });

      // Change the name
      const nameInput = screen.getByDisplayValue('Root Group');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Root');

      // Submit
      const submitButton = screen.getByText('Update Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        name: 'Updated Root',
      });
    });
  });

  describe('Read-only Org Admin Toggle', () => {
    it('shows the read-only admin toggle and not the org admin toggle', () => {
      // Tier-1 super-admin never has a UI session, and tier-2 cannot promote
      // to is_org_admin (server returns 403). The Organization Admin checkbox
      // is removed in the UI; only Read-only Org Admin remains.
      renderGroupForm({});

      expect(screen.getByText('Read-only Org Admin')).toBeInTheDocument();
      expect(screen.queryByText('Organization Admin')).not.toBeInTheDocument();
    });

    it('can toggle read-only org admin status', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockGroup);
        })
      );

      renderGroupForm({ onSave });

      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Auditors');

      const roLabel = screen.getByText('Read-only Org Admin').closest('label');
      if (roLabel) {
        await user.click(roLabel);
      }

      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({
        is_org_readonly_admin: true,
      });
      // is_org_admin is no longer sent at all
      expect(capturedBody).not.toHaveProperty('is_org_admin');
    });
  });

  describe('Org-admin group (RD-968)', () => {
    it('hides the read-only toggle and shows a Full Org Admin banner when editing an org-admin group', () => {
      renderGroupForm({ group: { ...mockGroup, is_org_admin: true } });

      expect(screen.getByText('Full Org Admin')).toBeInTheDocument();
      // The read-only toggle is mutually exclusive with full org admin, so it's gone.
      expect(screen.queryByText('Read-only Org Admin')).not.toBeInTheDocument();
    });

    it('does not send is_org_readonly_admin=true when editing an org-admin group', async () => {
      const user = userEvent.setup();
      const onSave = vi.fn();
      let capturedBody: Record<string, unknown> | null = null;

      server.use(
        http.put('/api/v1/admin/orgs/:orgId/groups/:groupId', async ({ request }) => {
          capturedBody = (await request.json()) as Record<string, unknown>;
          return HttpResponse.json(mockGroup);
        })
      );

      renderGroupForm({ group: { ...mockGroup, is_org_admin: true }, onSave });

      await user.click(screen.getByText('Update Group'));

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(capturedBody).toMatchObject({ is_org_readonly_admin: false });
    });
  });

  describe('Error Handling', () => {
    it('shows error message on save failure', async () => {
      const user = userEvent.setup();

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/groups', () => {
          return HttpResponse.json(
            { error: 'Slug already exists' },
            { status: 400 }
          );
        })
      );

      renderGroupForm({});

      // Fill in form
      const nameInput = screen.getByPlaceholderText(/Engineering, DevOps/);
      await user.type(nameInput, 'Test Group');

      // Submit
      const submitButton = screen.getByText('Create Group');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Slug already exists')).toBeInTheDocument();
      });
    });
  });

  describe('Cancel Button', () => {
    it('calls onClose when Cancel is clicked', async () => {
      const user = userEvent.setup();
      const onClose = vi.fn();

      renderGroupForm({ onClose });

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });
  });
});
