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

import TravelRuleRecordList from '../TravelRuleRecordList';

describe('TravelRuleRecordList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      const { unmount } = renderWithComplianceContext(<TravelRuleRecordList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no records', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('No travel rule records')).toBeInTheDocument();
      });
    });

    it('displays records in a table', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        // Should show originator DIDs (short enough to display fully)
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
        expect(screen.getByText('did:test:charlie')).toBeInTheDocument();
      });

      // Check table headers
      expect(screen.getByText('Originator')).toBeInTheDocument();
      expect(screen.getByText('Beneficiary')).toBeInTheDocument();
      expect(screen.getByText('Status')).toBeInTheDocument();
    });

    it('shows correct status badges', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        // First record: unused (expires_at is in the future)
        expect(screen.getByText('unused')).toBeInTheDocument();
        // Second record: used (has used_at)
        expect(screen.getByText('used')).toBeInTheDocument();
      });
    });

    it('shows transfer type badges', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('ETH')).toBeInTheDocument();
        expect(screen.getByText('ERC20')).toBeInTheDocument();
      });
    });

    it('shows Create Record button', async () => {
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });
    });
  });

  describe('Create Record', () => {
    it('opens create dialog with new form fields', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Verify form fields are present
      // "Originator" appears in both the table header and form label
      expect(screen.getAllByText('Originator').length).toBeGreaterThanOrEqual(2);
      expect(screen.getByText(/Originator Name/)).toBeInTheDocument();
      expect(screen.getByText('Account Reference')).toBeInTheDocument();
      expect(screen.getByText(/Beneficiary Name/)).toBeInTheDocument();
      expect(screen.getByText('Institution')).toBeInTheDocument();
      expect(screen.getByText('Transfer Type')).toBeInTheDocument();
      expect(screen.getByText('Beneficiary Address')).toBeInTheDocument();

      // Amount label may show "Amount (ETH)" once tokens are loaded
      // "Amount" appears in both the table header ("Amount (USD)") and form label
      await waitFor(() => {
        expect(screen.getAllByText(/Amount/).length).toBeGreaterThanOrEqual(1);
      });

      // Search input with placeholder for DID search
      expect(screen.getByPlaceholderText('Search users by DID...')).toBeInTheDocument();
    });

    it('submits record with structured fields', async () => {
      interface TravelRuleCreateBody {
        originator_data?: { name?: string };
        beneficiary_data?: { name?: string };
        beneficiary_address?: string;
        amount_wei?: string;
      }
      let createCalled = false;
      let createBody: TravelRuleCreateBody = {};

      server.use(
        http.post('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', async ({ request }) => {
          createBody = (await request.json()) as TravelRuleCreateBody;
          createCalled = true;
          // C3: amount_fiat is computed server-side, not provided by the client
          return HttpResponse.json({
            id: 'tr-new',
            org_id: 'org-1',
            originator_user_id: '',
            originator_data: createBody.originator_data,
            beneficiary_data: createBody.beneficiary_data,
            transfer_type: 'eth',
            beneficiary_address: createBody.beneficiary_address,
            amount_wei: createBody.amount_wei,
            amount_fiat: 3750, // server-computed from amount_wei * token price
            expires_at: new Date(Date.now() + 86400000).toISOString(),
            created_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Wait for tokens to load so amount label updates
      await waitFor(() => {
        expect(screen.getByText('Amount (ETH)')).toBeInTheDocument();
      });

      // Fill in Originator Name (first "Full legal name" placeholder)
      const nameInputs = screen.getAllByPlaceholderText('Full legal name');
      await user.type(nameInputs[0], 'Alice Smith');

      // Fill in Beneficiary Name (second "Full legal name" placeholder)
      await user.type(nameInputs[1], 'Bob Jones');

      // Fill in Beneficiary Address
      await user.type(screen.getByPlaceholderText('0x...'), '0x1234567890123456789012345678901234567890');

      // Fill in Amount (placeholder is '1.5' when native token is loaded)
      await user.type(screen.getByPlaceholderText('1.5'), '1.5');

      // Click submit button
      await user.click(screen.getByRole('button', { name: 'Create Record' }));

      await waitFor(() => {
        expect(createCalled).toBe(true);
      });

      // Verify structured data was sent
      expect(createBody.originator_data?.name).toBe('Alice Smith');
      expect(createBody.beneficiary_data?.name).toBe('Bob Jones');
      // 1.5 ETH with 18 decimals = 1500000000000000000 wei
      expect(createBody.amount_wei).toBe('1500000000000000000');
    });

    it('validates beneficiary address format', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Type an invalid address
      const addressInput = screen.getByPlaceholderText('0x...');
      await user.type(addressInput, '0xinvalid');

      // Trigger blur by tabbing away
      await user.tab();

      await waitFor(() => {
        expect(screen.getByText('Invalid address format. Must be 0x followed by 40 hex characters.')).toBeInTheDocument();
      });
    });

    it('shows ERC-20 token selector when transfer type is erc20', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Create Record')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Create Record'));

      await waitFor(() => {
        expect(screen.getByText('Create Travel Rule Record')).toBeInTheDocument();
      });

      // Wait for tokens to load
      await waitFor(() => {
        expect(screen.getByText('Amount (ETH)')).toBeInTheDocument();
      });

      // Change transfer type to ERC-20
      // Find the select trigger showing "ETH (Native)" default
      const triggers = screen.getAllByRole('combobox');
      await user.click(triggers[0]);
      // Multiple elements may match "ERC-20 Token" (trigger + option), pick the option role
      const erc20Options = screen.getAllByText('ERC-20 Token');
      await user.click(erc20Options[erc20Options.length - 1]);

      // Should now show the Token label and USDT option
      await waitFor(() => {
        expect(screen.getByText('Token')).toBeInTheDocument();
      });

      // Open the token dropdown to see USDT
      const tokenTriggers = screen.getAllByRole('combobox');
      // The token select should be the second combobox now
      const tokenTrigger = tokenTriggers[1];
      await user.click(tokenTrigger);

      await waitFor(() => {
        expect(screen.getAllByText(/USDT/).length).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('Delete Record', () => {
    it('shows delete button for non-used records and handles deletion', async () => {
      let deleteCalled = false;
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records/:id', () => {
          deleteCalled = true;
          return new HttpResponse(null, { status: 204 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('did:test:alice')).toBeInTheDocument();
      });

      // Find the trash icon button in the table
      // lucide-react renders SVG elements inside buttons
      const tableBody = document.querySelector('tbody');
      const svgs = tableBody!.querySelectorAll('svg');
      // Log SVG class names for debugging
      const trashSvg = Array.from(svgs).find(svg => {
        // Trash2 icon has a specific path - look for the polyline/path combo
        return svg.classList.contains('lucide-trash-2') ||
          svg.querySelector('path[d*="M3 6"]') !== null;
      });

      // Alternative: find buttons in table cells that are NOT copy buttons
      const tableCells = tableBody!.querySelectorAll('td');
      const lastCellButtons: Element[] = [];
      tableCells.forEach(cell => {
        const btn = cell.querySelector('button');
        if (btn && !btn.getAttribute('title')?.includes('Copy')) {
          lastCellButtons.push(btn);
        }
      });

      const trashButton = trashSvg?.closest('button') || lastCellButtons[0];
      expect(trashButton).toBeTruthy();

      // Click the delete button
      await user.click(trashButton! as HTMLElement);

      // Confirmation dialog should appear
      await waitFor(() => {
        expect(screen.getByText('Delete Travel Rule Record')).toBeInTheDocument();
      });

      // Click confirm
      await user.click(screen.getByRole('button', { name: 'Delete' }));

      await waitFor(() => {
        expect(deleteCalled).toBe(true);
      });
    });
  });

  describe('Error Handling', () => {
    it('shows error when list fails to load', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/travel-rule-records', () => {
          return HttpResponse.json({ error: 'Database error' }, { status: 500 });
        })
      );

      renderWithComplianceContext(<TravelRuleRecordList />);

      await waitFor(() => {
        expect(screen.getByText('Database error')).toBeInTheDocument();
      });
    });
  });
});
