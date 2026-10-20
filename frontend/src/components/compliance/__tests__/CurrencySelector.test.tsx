import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { screen, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { http, HttpResponse, delay } from 'msw';
import { server } from '@/test/mocks/server';
import { renderWithComplianceContext } from './test-utils';

vi.mock('../CurrencyContext', async () => {
  const actual = await vi.importActual('../CurrencyContext');
  return actual;
});

import CurrencySelector from '../CurrencySelector';

describe('CurrencySelector', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('shows loading state while currency loads', async () => {
      server.use(
        http.get('/api/v1/admin/compliance/currency', async () => {
          await delay('infinite');
          return HttpResponse.json({
            currency: 'usd',
            all_currencies: [{ code: 'usd', name: 'US Dollar', symbol: '$' }],
          });
        })
      );

      const { unmount } = renderWithComplianceContext(<CurrencySelector />);

      expect(screen.getByText('Currency...')).toBeInTheDocument();
      const spinner = document.querySelector('.animate-spin');
      expect(spinner).toBeInTheDocument();

      unmount();
    });

    it('shows current currency after loading', async () => {
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });

      expect(screen.getByText('Currency:')).toBeInTheDocument();
    });

    it('displays selector with correct test id', async () => {
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByTestId('currency-selector')).toBeInTheDocument();
      });
    });
  });

  describe('Interactions', () => {
    it('persists the org currency via the per-org compliance config (RD-1158)', async () => {
      let putCalled = false;
      let putBody: { currency?: string } | null = null;

      // Per-org: the switch writes the org's compliance config, NOT the global
      // super-admin base-currency endpoint.
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/config', async ({ request }) => {
          putCalled = true;
          putBody = await request.json() as { currency?: string };
          return HttpResponse.json({ currency: putBody.currency });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<CurrencySelector />);

      // Wait for selector to load the org's current currency
      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });

      // Open the dropdown and select EUR
      await user.click(screen.getByTestId('currency-selector'));
      await waitFor(() => {
        expect(screen.getByText('EUR')).toBeInTheDocument();
      });
      await user.click(screen.getByText('EUR'));

      await waitFor(() => {
        expect(putCalled).toBe(true);
      });
      expect(putBody?.currency).toBe('eur');
    });

    it('surfaces an error when the currency update fails (no silent revert)', async () => {
      server.use(
        http.put('/api/v1/admin/orgs/:orgId/compliance/config', async () => {
          return HttpResponse.json({ error: 'unsupported currency' }, { status: 400 });
        })
      );

      const user = userEvent.setup();
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });

      await user.click(screen.getByTestId('currency-selector'));
      await waitFor(() => {
        expect(screen.getByText('EUR')).toBeInTheDocument();
      });
      await user.click(screen.getByText('EUR'));

      // The error is shown to the user instead of the old silent "blink".
      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
      expect(screen.getByText('unsupported currency')).toBeInTheDocument();
    });

    it('shows all available currencies in dropdown', async () => {
      const user = userEvent.setup();
      renderWithComplianceContext(<CurrencySelector />);

      await waitFor(() => {
        expect(screen.getByTestId('currency-selector')).toBeInTheDocument();
      });

      // Open dropdown
      await user.click(screen.getByTestId('currency-selector'));

      await waitFor(() => {
        expect(screen.getByText('(US Dollar)')).toBeInTheDocument();
        expect(screen.getByText('(Euro)')).toBeInTheDocument();
        expect(screen.getByText('(Swiss Franc)')).toBeInTheDocument();
        expect(screen.getByText('(British Pound)')).toBeInTheDocument();
        expect(screen.getByText('(UAE Dirham)')).toBeInTheDocument();
      });
    });
  });

  describe('Per-org scope (RD-1158)', () => {
    it('is read-only when no organization is in scope', async () => {
      renderWithComplianceContext(<CurrencySelector />, { initialOrg: null });

      await waitFor(() => {
        expect(screen.getByText('$ USD')).toBeInTheDocument();
      });
      // No interactive dropdown when there is no org to scope the currency to.
      expect(screen.queryByRole('combobox')).not.toBeInTheDocument();
    });
  });
});
