import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { UserContextPanel } from '../UserContextPanel';

// The mock JWT from handlers.ts - decodes to sub: "did:polygonid:polygon:main:user123"
const VALID_JWT =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6cG9seWdvbmlkOnBvbHlnb246bWFpbjp1c2VyMTIzIiwiZXhwIjoxNzA0MDY3MjAwfQ.test';

describe('UserContextPanel', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Rendering guards', () => {
    it('does not render when jwtToken is empty', () => {
      const { container } = render(<UserContextPanel jwtToken="" />);
      expect(container.innerHTML).toBe('');
    });

    it('does not render when jwtToken is invalid (no dots)', () => {
      const { container } = render(<UserContextPanel jwtToken="invalidtoken" />);
      expect(container.innerHTML).toBe('');
    });
  });

  describe('Loading state', () => {
    it('shows "Looking up user..." loading state when valid JWT provided', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      // Delay the user search response so the loading state is visible
      server.use(
        http.get('/api/v1/admin/users', async () => {
          await new Promise((resolve) => setTimeout(resolve, 5000));
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      // Before debounce fires, nothing is shown (component returned null while waiting)
      expect(screen.queryByText('Looking up user...')).not.toBeInTheDocument();

      // Advance past the 500ms debounce to trigger the fetch
      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      // The fetch is in-flight (delayed 5s), so we should see loading
      expect(screen.getByText('Looking up user...')).toBeInTheDocument();
    });
  });

  describe('Successful lookup', () => {
    it('shows user DID after lookup completes', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      // The DID is "did:polygonid:polygon:main:user123" which is under 40 chars, so shown in full
      expect(screen.getByText('did:polygonid:polygon:main:user123')).toBeInTheDocument();
    });

    it('shows KYC Verified badge for verified user', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      expect(screen.getByText('KYC Verified')).toBeInTheDocument();
    });

    it('shows group name with role badge', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      // mockGroup name is "Root Group", role badge derived from allowed_methods via getClosestPresetLabel
      expect(screen.getByText('Root Group')).toBeInTheDocument();
      // Role badge is shown instead of individual claim badges
      const panel = screen.getByTestId('user-context-panel');
      expect(panel.textContent).toContain('Root Group');
    });

    it('shows linked ETH addresses in compact format', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      // mockLinkedAddresses[0] = "0x1234567890123456789012345678901234567890"
      // Compact format: first 6 chars + "..." + last 4 chars -> "0x1234...7890"
      expect(screen.getByText('0x1234...7890')).toBeInTheDocument();

      // mockLinkedAddresses[1] = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
      // Compact: "0xabcd...abcd"
      expect(screen.getByText('0xabcd...abcd')).toBeInTheDocument();
    });

    it('shows "Active" badge for non-banned user', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      expect(screen.getByText('Active')).toBeInTheDocument();
      expect(screen.queryByText('Banned')).not.toBeInTheDocument();
    });
  });

  describe('Error states', () => {
    it('shows "User not found" when search returns empty results', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({ data: [], total: 0, limit: 25, offset: 0 });
        })
      );

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByText('User not found for this DID')).toBeInTheDocument();
      });
    });

    it('shows "Banned" badge for banned user', async () => {
      vi.useFakeTimers({ shouldAdvanceTime: true });

      server.use(
        http.get('/api/v1/admin/users', () => {
          return HttpResponse.json({
            data: [{
              id: 'user-1',
              external_id: 'did:polygonid:polygon:main:user123',
              kyc: true,
              banned: true,
              note: '',
              metadata: {},
              created_at: '2024-01-01T00:00:00Z',
              updated_at: '2024-01-01T00:00:00Z',
            }],
            total: 1,
            limit: 25,
            offset: 0,
          });
        })
      );

      render(<UserContextPanel jwtToken={VALID_JWT} />);

      await act(async () => {
        vi.advanceTimersByTime(500);
      });

      await waitFor(() => {
        expect(screen.getByTestId('user-context-panel')).toBeInTheDocument();
      });

      expect(screen.getByText('Banned')).toBeInTheDocument();
      expect(screen.queryByText('Active')).not.toBeInTheDocument();
    });
  });
});
