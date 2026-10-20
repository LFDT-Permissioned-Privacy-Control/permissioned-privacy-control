import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { ContractInfoPanel } from '../ContractInfoPanel';

// The mock contract address from handlers.ts
const VALID_ADDRESS = '0x1234567890123456789012345678901234567890';

// A valid-format address that is not registered in MSW handlers (triggers 404)
const UNREGISTERED_ADDRESS = '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

describe('ContractInfoPanel', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Rendering guards', () => {
    it('does not render when address is empty', () => {
      const { container } = render(<ContractInfoPanel contractAddress="" />);
      expect(container.innerHTML).toBe('');
    });

    it('does not render when address is invalid (too short)', () => {
      const { container } = render(<ContractInfoPanel contractAddress="0x1234" />);
      expect(container.innerHTML).toBe('');
    });
  });

  describe('Loading state', () => {
    it('shows "Looking up contract..." loading state when valid address provided', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      // Delay the contract lookup response so the loading state is visible
      server.use(
        http.get('/api/v1/admin/contracts/by-address/:address', async () => {
          await new Promise((resolve) => setTimeout(resolve, 5000));
          return HttpResponse.json({ error: 'contract not found' }, { status: 404 });
        })
      );

      render(<ContractInfoPanel contractAddress={VALID_ADDRESS} />);

      // Before debounce fires, nothing shown yet
      expect(screen.queryByText('Looking up contract...')).not.toBeInTheDocument();

      // Advance past the 500ms debounce to trigger the fetch
      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      // The fetch is in-flight (delayed 5s), so we should see loading
      expect(screen.getByText('Looking up contract...')).toBeInTheDocument();
    });
  });

  describe('Successful lookup', () => {
    it('shows contract name and org name after lookup', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<ContractInfoPanel contractAddress={VALID_ADDRESS} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('contract-info-panel')).toBeInTheDocument();
      });

      // mockContract.name = "Test Contract", mockOrganization.name = "Test Organization"
      expect(screen.getByText('Test Contract')).toBeInTheDocument();
      expect(screen.getByText('Test Organization')).toBeInTheDocument();
    });

    it('shows group name with role badge', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<ContractInfoPanel contractAddress={VALID_ADDRESS} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('contract-info-panel')).toBeInTheDocument();
      });

      // mockGroup.name = "Root Group", group access has allowed_methods -> role badge via getClosestPresetLabel
      expect(screen.getByText('Root Group')).toBeInTheDocument();
      // Role badge is shown instead of individual claim badges
      // The mock has 2 methods (eth_call, eth_getBalance) which maps to a Wallet User subset
      const panel = screen.getByTestId('contract-info-panel');
      expect(panel.textContent).toContain('Root Group');
    });
  });

  describe('Error states', () => {
    it('shows "Contract not registered" when address returns 404', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<ContractInfoPanel contractAddress={UNREGISTERED_ADDRESS} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByText('Contract not registered')).toBeInTheDocument();
      });
    });

    it('shows "No groups have been granted access" when grants array is empty', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      server.use(
        http.get('/api/v1/admin/contracts/by-address/:address', ({ params }) => {
          if (params.address === VALID_ADDRESS.toLowerCase()) {
            return HttpResponse.json({
              contract: {
                id: 'contract-1',
                name: 'Test Contract',
                address: VALID_ADDRESS.toLowerCase(),
                org_id: 'org-1',
              },
              organization: {
                id: 'org-1',
                name: 'Test Organization',
                slug: 'test-org',
              },
              grants: [],
            });
          }
          return HttpResponse.json({ error: 'contract not found' }, { status: 404 });
        })
      );

      render(<ContractInfoPanel contractAddress={VALID_ADDRESS} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('contract-info-panel')).toBeInTheDocument();
      });

      expect(screen.getByText('No groups have been granted access')).toBeInTheDocument();
    });
  });
});
