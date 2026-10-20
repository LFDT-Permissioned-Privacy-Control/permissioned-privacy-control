import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import ContractForm from '../ContractForm';
import { mockContract } from '@/test/mocks/handlers';
import { createMockContract } from '@/test/mocks/rbac-fixtures';

// Simple wrapper for ContractForm tests (no org context needed, orgId is a prop)
function renderContractForm(props: {
  orgId?: string;
  contract?: typeof mockContract;
  onClose?: () => void;
  onSave?: () => void;
}) {
  const defaultProps = {
    orgId: 'org-1',
    onClose: vi.fn(),
    onSave: vi.fn(),
    ...props,
  };

  return {
    ...render(<ContractForm {...defaultProps} />),
    onClose: defaultProps.onClose,
    onSave: defaultProps.onSave,
  };
}

describe('ContractForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Create Mode', () => {
    it('shows empty address and name fields', () => {
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      expect(addressInput).toHaveValue('');

      const nameInput = screen.getByPlaceholderText(
        'e.g., MyToken, Governance Contract'
      );
      expect(nameInput).toHaveValue('');
    });

    it('validates address is required', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({});

      // Try to submit without address
      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      // The form should not submit - HTML5 validation
      expect(onSave).not.toHaveBeenCalled();
    });

    it('validates address format (starts with 0x)', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');

      // Enter invalid address without 0x prefix
      await user.type(addressInput, '1234567890123456789012345678901234567890');

      // The input has pattern validation - check that value doesn't match pattern
      expect(addressInput).toHaveAttribute('pattern', '^0x[a-fA-F0-9]{40}$');
      expect(addressInput).toBeInvalid();
    });

    it('validates address length (42 characters)', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');

      // Enter address that's too short (0x + only 38 chars)
      await user.type(addressInput, '0x12345678901234567890123456789012345678');

      expect(addressInput).toBeInvalid();
    });

    it('name field is optional', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({});

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', async ({ request }) => {
          const body = (await request.json()) as { address: string; name?: string };
          return HttpResponse.json({
            ...mockContract,
            address: body.address,
            name: body.name || null,
          });
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');

      // Enter valid address, leave name empty
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('submits POST to /orgs/:id/contracts', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({});

      let receivedRequest: { address: string; name?: string } | null = null;
      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', async ({ request, params }) => {
          receivedRequest = (await request.json()) as { address: string; name?: string };
          expect(params.orgId).toBe('org-1');
          return HttpResponse.json({
            ...mockContract,
            address: receivedRequest.address,
            name: receivedRequest.name,
          });
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      const nameInput = screen.getByPlaceholderText(
        'e.g., MyToken, Governance Contract'
      );

      await user.type(
        addressInput,
        '0xABCDEF1234567890ABCDEF1234567890ABCDEF12'
      );
      await user.type(nameInput, 'My New Contract');

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      // Address should be lowercased
      expect(receivedRequest?.address).toBe(
        '0xabcdef1234567890abcdef1234567890abcdef12'
      );
      expect(receivedRequest?.name).toBe('My New Contract');
    });

    it('closes dialog on success', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({});

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json(mockContract);
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });
    });

    it('shows error message on failure', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json(
            { error: 'Contract already exists' },
            { status: 409 }
          );
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Contract already exists')).toBeInTheDocument();
      });
    });
  });

  describe('Edit Mode', () => {
    it('address field is read-only (cannot change contract address)', () => {
      renderContractForm({ contract: mockContract });

      const addressInput = screen.getByDisplayValue(mockContract.address!);
      expect(addressInput).toBeDisabled();
    });

    it('name field is editable', async () => {
      const user = userEvent.setup();
      renderContractForm({ contract: mockContract });

      const nameInput = screen.getByDisplayValue('Test Contract');
      expect(nameInput).not.toBeDisabled();

      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Contract Name');

      expect(nameInput).toHaveValue('Updated Contract Name');
    });

    it('can update metadata', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({ contract: mockContract });

      let receivedRequest: { name?: string } | null = null;
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/contracts/:address', async ({ request }) => {
          receivedRequest = (await request.json()) as { name?: string };
          return HttpResponse.json({
            ...mockContract,
            name: receivedRequest.name,
          });
        })
      );

      const nameInput = screen.getByDisplayValue('Test Contract');
      await user.clear(nameInput);
      await user.type(nameInput, 'Updated Name');

      const submitButton = screen.getByText('Update Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(receivedRequest?.name).toBe('Updated Name');
    });

    it('submits PUT to /orgs/:id/contracts/:address', async () => {
      const user = userEvent.setup();
      const { onSave } = renderContractForm({ contract: mockContract });

      let requestParams: { orgId?: string; address?: string } = {};
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/contracts/:address', async ({ params }) => {
          requestParams = params as { orgId?: string; address?: string };
          return HttpResponse.json(mockContract);
        })
      );

      const nameInput = screen.getByDisplayValue('Test Contract');
      await user.clear(nameInput);
      await user.type(nameInput, 'New Name');

      const submitButton = screen.getByText('Update Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(onSave).toHaveBeenCalled();
      });

      expect(requestParams.orgId).toBe('org-1');
      expect(requestParams.address).toBe(mockContract.address);
    });

    it('shows Update button in edit mode', () => {
      renderContractForm({ contract: mockContract });

      expect(screen.getByText('Update Contract')).toBeInTheDocument();
    });

    it('pre-fills form with contract data', () => {
      const contract = createMockContract({
        id: 'contract-prefill',
        address: '0xDEADBEEF1234567890DEADBEEF1234567890DEAD',
        name: 'Prefilled Contract',
      });

      renderContractForm({ contract });

      expect(
        screen.getByDisplayValue('0xDEADBEEF1234567890DEADBEEF1234567890DEAD')
      ).toBeInTheDocument();
      expect(screen.getByDisplayValue('Prefilled Contract')).toBeInTheDocument();
    });
  });

  describe('Address Validation', () => {
    it('rejects address without 0x prefix', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(addressInput, '1234567890123456789012345678901234567890');

      // Check HTML5 validity
      expect(addressInput).toBeInvalid();
    });

    it('rejects address shorter than 42 chars', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      // Only 30 hex chars (32 total with 0x)
      await user.type(addressInput, '0x123456789012345678901234567890');

      expect(addressInput).toBeInvalid();
    });

    it('rejects address longer than 42 chars', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      // 42 hex chars (44 total with 0x) - too long
      await user.type(
        addressInput,
        '0x123456789012345678901234567890123456789012'
      );

      expect(addressInput).toBeInvalid();
    });

    it('accepts valid checksum address', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      // Valid checksum address
      await user.type(
        addressInput,
        '0xABCDEF1234567890ABCDEF1234567890ABCDEF12'
      );

      expect(addressInput).toBeValid();
    });

    it('accepts valid lowercase address', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      const addressInput = screen.getByPlaceholderText('0x...');
      // Valid lowercase address
      await user.type(
        addressInput,
        '0xabcdef1234567890abcdef1234567890abcdef12'
      );

      expect(addressInput).toBeValid();
    });
  });

  describe('Form Controls', () => {
    it('Cancel button calls onClose', async () => {
      const user = userEvent.setup();
      const { onClose } = renderContractForm({});

      const cancelButton = screen.getByText('Cancel');
      await user.click(cancelButton);

      expect(onClose).toHaveBeenCalled();
    });

    it('shows loading state while saving', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      // Make the request hang
      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument();
      });
    });

    it('disables buttons while saving', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      // Make the request hang
      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', async () => {
          await new Promise(() => {}); // Never resolves
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      const cancelButton = screen.getByText('Cancel');

      await user.click(submitButton);

      await waitFor(() => {
        expect(screen.getByText('Saving...')).toBeInTheDocument();
      });

      // Buttons should be disabled
      expect(cancelButton).toBeDisabled();
    });

    it('shows tip about adding grants after registration', () => {
      renderContractForm({});

      expect(
        screen.getByText(/After registering the contract, add grants/)
      ).toBeInTheDocument();
    });
  });


  describe('Error Handling', () => {
    it('shows generic error when no specific error message', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json({}, { status: 500 });
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(
          screen.getByText('Failed to save contract. Please try again.')
        ).toBeInTheDocument();
      });
    });

    it('shows specific error message from server', async () => {
      const user = userEvent.setup();
      renderContractForm({});

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/contracts', () => {
          return HttpResponse.json(
            { error: 'Invalid contract address: not a contract' },
            { status: 400 }
          );
        })
      );

      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(
        addressInput,
        '0x1234567890123456789012345678901234567890'
      );

      const submitButton = screen.getByText('Register Contract');
      await user.click(submitButton);

      await waitFor(() => {
        expect(
          screen.getByText('Invalid contract address: not a contract')
        ).toBeInTheDocument();
      });
    });
  });
});
