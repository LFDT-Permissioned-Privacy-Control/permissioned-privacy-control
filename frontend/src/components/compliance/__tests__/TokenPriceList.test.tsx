import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';
import { useCurrency } from '../CurrencyContext';

vi.mock('../ComplianceManager', async () => {
  const { TestComplianceOrgContext, useComplianceOrgContext } = await import('./test-utils');
  return {
    ComplianceOrgContext: TestComplianceOrgContext,
    useComplianceOrgContext,
  };
});

import TokenPriceList from '../TokenPriceList';

describe('TokenPriceList', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading spinner initially', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', async () => {
          await delay('infinite');
          return HttpResponse.json({ data: [] });
        })
      );

      const { unmount } = renderWithComplianceContext(<TokenPriceList />);
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();
      unmount();
    });

    it('shows empty state when no tokens', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json({ data: [] });
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('No per-org token prices configured')).toBeInTheDocument();
      });
    });

    it('displays token table with data', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        // ETH/USDT appear in both system prices and per-org sections
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
        expect(screen.getAllByText('USDT').length).toBeGreaterThanOrEqual(1);
      });

      // Check table headers
      expect(screen.getByText('Token Address')).toBeInTheDocument();
      expect(screen.getByText('Symbol')).toBeInTheDocument();
      expect(screen.getByText('Source')).toBeInTheDocument();
    });

    it('shows native badge for native token', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('native (ETH)')).toBeInTheDocument();
      });
    });

    it('shows Add Token button', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });
    });
  });

  describe('CRUD Operations', () => {
    it('opens add dialog and pre-fills native values', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      // Should pre-fill with "native" and "ETH"
      expect(screen.getByDisplayValue('native')).toBeInTheDocument();
      expect(screen.getByDisplayValue('ETH')).toBeInTheDocument();
    });

    it('submits new token price', async () => {
      let upsertCalled = false;
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', async () => {
          upsertCalled = true;
          return HttpResponse.json({
            id: 'token-new',
            org_id: 'org-1',
            token_address: 'native',
            symbol: 'ETH',
            decimals: 18,
            price_fiat: 3000,
            created_at: '2024-01-01T00:00:00Z',
            updated_at: new Date().toISOString(),
          });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      // Fill price
      const priceInput = screen.getByPlaceholderText('2500.00');
      await user.type(priceInput, '3000');

      // Submit
      await user.click(screen.getByRole('button', { name: 'Add' }));

      await waitFor(() => {
        expect(upsertCalled).toBe(true);
      });
    });

    it('opens edit dialog with existing values', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
      });

      // Click edit on first row (pencil icon)
      // Use the pencil button - get all ghost buttons
      const allButtons = screen.getAllByRole('button');
      // Find the first edit button (in the table rows)
      const editButton = allButtons.find(btn => btn.querySelector('.lucide-pencil'));
      if (editButton) {
        await user.click(editButton);

        await waitFor(() => {
          expect(screen.getByText('Edit Token Price')).toBeInTheDocument();
        });

        // Token address should be disabled in edit mode
        const addressInput = screen.getByDisplayValue('native');
        expect(addressInput).toBeDisabled();
      }
    });

    it('shows delete confirmation dialog', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
      });

      // Click delete button (trash icon)
      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Delete Token Price')).toBeInTheDocument();
          expect(screen.getByText(/Are you sure/)).toBeInTheDocument();
        });
      }
    });

    it('deletes token after confirmation', async () => {
      let deleteCalled = false;
      server.use(
        http.delete('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', () => {
          deleteCalled = true;
          return HttpResponse.json({ message: 'Deleted' });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
      });

      const allButtons = screen.getAllByRole('button');
      const deleteButton = allButtons.find(btn => btn.querySelector('.lucide-trash-2'));
      if (deleteButton) {
        await user.click(deleteButton);

        await waitFor(() => {
          expect(screen.getByText('Delete Token Price')).toBeInTheDocument();
        });

        await user.click(screen.getByRole('button', { name: 'Delete' }));

        await waitFor(() => {
          expect(deleteCalled).toBe(true);
        });
      }
    });
  });

  describe('Currency Change', () => {
    it('reloads system prices when currency changes', async () => {
      let systemPriceCallCount = 0;
      let currentCurrency = 'usd';

      server.use(
        http.get('/api/v1/admin/compliance/currency', () => {
          return HttpResponse.json({
            currency: currentCurrency,
            all_currencies: [
              { code: 'usd', name: 'US Dollar', symbol: '$' },
              { code: 'eur', name: 'Euro', symbol: '€' },
            ],
            coingecko_enabled: true,
          });
        }),
        // RD-1158: currency is set per-org via the compliance config, not the
        // global base-currency endpoint.
        http.put('/api/v1/admin/orgs/:orgId/compliance/config', async ({ request }) => {
          const body = await request.json() as { currency?: string };
          if (body.currency) currentCurrency = body.currency;
          return HttpResponse.json({ currency: currentCurrency });
        }),
        http.get('/api/v1/admin/compliance/system-token-prices', () => {
          systemPriceCallCount++;
          const ethPrice = currentCurrency === 'eur' ? 2300 : 2500;
          return HttpResponse.json({ data: [
            { id: 1, coingecko_id: 'ethereum', source: 'coingecko', symbol: 'ETH', decimals: 18, price_fiat: ethPrice, updated_at: new Date().toISOString(), is_stale: false },
          ] });
        }),
      );

      // Render TokenPriceList with a button that triggers currency change
      // This simulates what CurrencySelector does
      function TestWrapper() {
        const { setCurrency } = useCurrency();
        return (
          <>
            <button data-testid="switch-eur" onClick={() => setCurrency('eur')}>Switch EUR</button>
            <TokenPriceList />
          </>
        );
      }

      renderWithComplianceContext(<TestWrapper />);

      // Wait for initial load with USD prices
      await waitFor(() => {
        expect(screen.getByText('Auto-Fetched Prices (CoinGecko)')).toBeInTheDocument();
      });

      const initialCallCount = systemPriceCallCount;

      // Switch currency to EUR
      const user = userEvent.setup();
      await user.click(screen.getByTestId('switch-eur'));

      // System prices should be re-fetched
      await waitFor(() => {
        expect(systemPriceCallCount).toBeGreaterThan(initialCallCount);
      });

      // New EUR price should be displayed with € symbol
      await waitFor(() => {
        expect(screen.getByText('€2,300.00')).toBeInTheDocument();
      });
    });
  });

  describe('Blocked Tokens Warning', () => {
    it('shows warning banner when manual tokens have zero price', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json({ data: [
            {
              id: 'token-ok',
              org_id: 'org-1',
              token_address: 'native',
              symbol: 'ETH',
              decimals: 18,
              price_fiat: 2500,
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
            {
              id: 'token-blocked',
              org_id: 'org-1',
              token_address: '0xabc',
              symbol: 'BLOCKED',
              decimals: 18,
              price_fiat: 0, // no price for active currency
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ] });
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText(/1 token blocking transactions/)).toBeInTheDocument();
      });
      expect(screen.getAllByText(/BLOCKED/).length).toBeGreaterThanOrEqual(1);
      expect(screen.getByText(/block all transactions/)).toBeInTheDocument();
    });

    it('does not show warning when all tokens have prices', async () => {
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
      });

      expect(screen.queryByText(/blocking transactions/)).not.toBeInTheDocument();
    });

    it('does not warn about CoinGecko-linked tokens with zero price_fiat', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json({ data: [
            {
              id: 'token-cg',
              org_id: 'org-1',
              token_address: 'native',
              symbol: 'ETH',
              decimals: 18,
              price_fiat: 0, // zero but CoinGecko-linked — resolves from system
              coingecko_id: 'ethereum',
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            },
          ] });
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getAllByText('ETH').length).toBeGreaterThanOrEqual(1);
      });

      expect(screen.queryByText(/blocking transactions/)).not.toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('shows error when token list fails to load', async () => {
      server.use(
        http.get('/api/v1/admin/orgs/:orgId/compliance/tokens', () => {
          return HttpResponse.json({ error: 'Internal server error' }, { status: 500 });
        })
      );

      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Internal server error')).toBeInTheDocument();
      });
    });

    it('shows form error when submission fails', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/tokens/:tokenAddress', () => {
          return HttpResponse.json({ error: 'Price must be positive' }, { status: 400 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<TokenPriceList />);

      await waitFor(() => {
        expect(screen.getByText('Add Token')).toBeInTheDocument();
      });

      await user.click(screen.getByText('Add Token'));

      await waitFor(() => {
        expect(screen.getByText('Add Token Price')).toBeInTheDocument();
      });

      const priceInput = screen.getByPlaceholderText('2500.00');
      await user.type(priceInput, '3000');

      await user.click(screen.getByRole('button', { name: 'Add' }));

      await waitFor(() => {
        expect(screen.getByText('Price must be positive')).toBeInTheDocument();
      });
    });
  });
});
