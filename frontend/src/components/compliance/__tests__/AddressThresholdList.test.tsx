import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import AddressThresholdList from '../AddressThresholdList';

const mockOverrides = [
  {
    id: 'ato-1',
    org_id: 'org-1',
    address: '0xabcdef1234567890abcdef1234567890abcdef12',
    threshold_fiat: 100,
    note: 'High-risk counterparty',
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'ato-2',
    org_id: 'org-1',
    address: '0x1111111111111111111111111111111111111111',
    threshold_fiat: 0,
    note: null,
    created_at: '2024-01-10T00:00:00Z',
    updated_at: '2024-01-10T00:00:00Z',
  },
];

const listUrl = '/api/v1/admin/orgs/:orgId/compliance/address-thresholds';

describe('AddressThresholdList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    server.use(
      http.get(listUrl, () => {
        return HttpResponse.json({ data: mockOverrides, total: 2, limit: 25, offset: 0 });
      })
    );
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get(listUrl, async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<AddressThresholdList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no overrides', async () => {
      server.use(
        http.get(listUrl, () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('No address threshold overrides')).toBeInTheDocument();
      });
      expect(screen.getByText('All addresses use the org-level threshold')).toBeInTheDocument();
    });

    it('displays overrides in a table', async () => {
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Address')).toBeInTheDocument();
      expect(screen.getByText('Threshold (USD)')).toBeInTheDocument();
      expect(screen.getByText('Note')).toBeInTheDocument();
      expect(screen.getByText('Updated')).toBeInTheDocument();

      // Check data rendered
      expect(screen.getByText('High-risk counterparty')).toBeInTheDocument();
      expect(screen.getByText('0x1111111111111111111111111111111111111111')).toBeInTheDocument();
    });

    it('shows $0 as red "all transfers" text', async () => {
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('$0.00 (all transfers)')).toBeInTheDocument();
      });

      const zeroSpan = screen.getByText('$0.00 (all transfers)');
      expect(zeroSpan).toHaveClass('text-red-600', 'font-medium');
    });

    it('shows formatted USD threshold', async () => {
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText(/\$100/)).toBeInTheDocument();
      });
    });

    it('shows dash for empty notes', async () => {
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('0x1111111111111111111111111111111111111111')).toBeInTheDocument();
      });

      // The second override has note: null, should show '-'
      const dashCells = screen.getAllByText('-');
      expect(dashCells.length).toBeGreaterThanOrEqual(1);
    });

    it('treats 404 as empty state', async () => {
      server.use(
        http.get(listUrl, () => {
          return HttpResponse.json({ error: 'Not found' }, { status: 404 });
        })
      );

      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('No address threshold overrides')).toBeInTheDocument();
      });
    });
  });

  describe('CRUD Operations', () => {
    it('opens create dialog with Add Override button', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('Add Override')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Override'));

      await waitFor(() => {
        expect(screen.getByText('Add Address Threshold Override')).toBeInTheDocument();
      });

      // Address input should be enabled
      const addressInput = screen.getByPlaceholderText('0x...');
      expect(addressInput).toBeInTheDocument();
      expect(addressInput).not.toBeDisabled();

      // Threshold and note inputs
      expect(screen.getByPlaceholderText('0')).toBeInTheDocument();
      expect(screen.getByPlaceholderText('e.g., High-risk counterparty')).toBeInTheDocument();
    });

    it('submits new override', async () => {
      let putCalled = false;
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/address-thresholds/:address', async () => {
          putCalled = true;
          return HttpResponse.json({
            id: 'ato-new',
            org_id: 'org-1',
            address: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
            threshold_fiat: 500,
            note: 'Test note',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('Add Override')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Override'));

      await waitFor(() => {
        expect(screen.getByText('Add Address Threshold Override')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('0x...'), '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef');

      // Clear default threshold value and type new one
      const thresholdInput = screen.getByPlaceholderText('0');
      await user.clear(thresholdInput);
      await user.type(thresholdInput, '500');

      await user.type(screen.getByPlaceholderText('e.g., High-risk counterparty'), 'Test note');

      await user.click(screen.getByRole('button', { name: 'Add Override' }));

      await waitFor(() => {
        expect(putCalled).toBe(true);
      });
    });

    it('validates address format', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('Add Override')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Override'));

      await waitFor(() => {
        expect(screen.getByText('Add Address Threshold Override')).toBeInTheDocument();
      });

      await user.type(screen.getByPlaceholderText('0x...'), '0xinvalid');

      await user.click(screen.getByRole('button', { name: 'Add Override' }));

      await waitFor(() => {
        expect(screen.getByText('Invalid address format (must be 0x + 40 hex chars)')).toBeInTheDocument();
      });
    });

    it('validates threshold >= 0', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('Add Override')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Override'));

      await waitFor(() => {
        expect(screen.getByText('Add Address Threshold Override')).toBeInTheDocument();
      });

      // Enter a valid address first so address validation passes
      await user.type(screen.getByPlaceholderText('0x...'), '0xabcdef1234567890abcdef1234567890abcdef12');

      const thresholdInput = screen.getByPlaceholderText('0');
      await user.clear(thresholdInput);

      await user.click(screen.getByRole('button', { name: 'Add Override' }));

      await waitFor(() => {
        expect(screen.getByText('Threshold must be >= 0')).toBeInTheDocument();
      });
    });

    it('opens edit dialog with pre-filled values', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12')).toBeInTheDocument();
      });

      // Find the first row and click the edit button (index 1; index 0 is the copy button)
      const firstRow = screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12').closest('tr')!;
      const editButton = firstRow.querySelectorAll('button')[1];
      expect(editButton).toBeTruthy();
      await user.click(editButton);

      await waitFor(() => {
        expect(screen.getByText('Edit Address Threshold Override')).toBeInTheDocument();
      });

      // Address should be disabled in edit mode
      const addressInput = screen.getByDisplayValue('0xabcdef1234567890abcdef1234567890abcdef12');
      expect(addressInput).toBeDisabled();

      // Threshold should be pre-filled
      expect(screen.getByDisplayValue('100')).toBeInTheDocument();
    });

    it('shows delete confirmation dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('High-risk counterparty')).toBeInTheDocument();
      });

      // Find the first row and click the delete button (index 2; 0=copy, 1=edit, 2=delete)
      const firstRow = screen.getByText('High-risk counterparty').closest('tr')!;
      const rowButtons = firstRow.querySelectorAll('button');
      const deleteButton = rowButtons[2];
      expect(deleteButton).toBeTruthy();
      await user.click(deleteButton);

      await waitFor(() => {
        expect(screen.getByText('Delete Threshold Override')).toBeInTheDocument();
      });
    });

    it('deletes override after confirmation', async () => {
      let deleteCalled = false;
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/compliance/address-thresholds/:address', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12')).toBeInTheDocument();
      });

      const firstRow = screen.getByText('0xabcdef1234567890abcdef1234567890abcdef12').closest('tr')!;
      const deleteButton = firstRow.querySelectorAll('button')[2];
      expect(deleteButton).toBeTruthy();
      await user.click(deleteButton);

      await waitFor(() => {
        expect(screen.getByText('Delete Threshold Override')).toBeInTheDocument();
      });

      await user.click(screen.getByRole('button', { name: 'Delete' }));

      await waitFor(() => {
        expect(deleteCalled).toBe(true);
      });
    });
  });

  describe('Error Handling', () => {
    it('shows error when list fails to load', async () => {
      server.use(
        http.get(listUrl, () => {
          return HttpResponse.json({ error: 'Service unavailable' }, { status: 503 });
        })
      );

      renderWithComplianceContext(<AddressThresholdList />);

      await waitFor(() => {
        expect(screen.getByText('Service unavailable')).toBeInTheDocument();
      });
    });
  });
});
