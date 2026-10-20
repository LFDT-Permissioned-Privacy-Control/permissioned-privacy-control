import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

// Mock authApiMethods before importing the component
const mockCompleteAzureLogin = vi.fn();
vi.mock('@/api/auth', () => ({
  authApiMethods: {
    completeAzureLogin: (...args: unknown[]) => mockCompleteAzureLogin(...args),
  },
}));

// Mock useAuth to capture the login call
const mockLogin = vi.fn();
const mockNavigate = vi.fn();

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    login: mockLogin,
    isAuthenticated: false,
    isLoading: false,
    accessToken: null,
    refreshToken: null,
    userDID: null,
    expiresAt: null,
    logout: vi.fn(),
    refreshAccessToken: vi.fn(),
  }),
}));

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom');
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  };
});

import { AzureCallbackPage } from '../AzureCallbackPage';

function renderCallbackPage(initialRoute: string) {
  return render(
    <MemoryRouter
      future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
      initialEntries={[initialRoute]}
    >
      <AzureCallbackPage />
    </MemoryRouter>,
  );
}

describe('AzureCallbackPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Loading State', () => {
    it('should show loading spinner while exchanging code', () => {
      // completeAzureLogin never resolves so we stay in loading state
      mockCompleteAzureLogin.mockReturnValue(new Promise(() => {}));

      renderCallbackPage('/auth/azure/callback?code=abc123&state=xyz789');

      expect(screen.getByText('Completing Microsoft sign-in...')).toBeInTheDocument();
    });
  });

  describe('Success Flow', () => {
    it('should exchange code for tokens, call login, and navigate to /link-wallet', async () => {
      const mockTokens = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
      };

      mockCompleteAzureLogin.mockResolvedValue(mockTokens);

      renderCallbackPage('/auth/azure/callback?code=abc123&state=xyz789');

      await waitFor(() => {
        expect(mockCompleteAzureLogin).toHaveBeenCalledWith(
          'abc123',
          'xyz789',
          expect.stringContaining('/auth/azure/callback'),
        );
      });

      await waitFor(() => {
        expect(mockLogin).toHaveBeenCalledWith(
          'test-access-token',
          'test-refresh-token',
          3600,
        );
      });

      await waitFor(() => {
        expect(mockNavigate).toHaveBeenCalledWith('/link-wallet', { replace: true });
      });
    });
  });

  describe('Microsoft Error', () => {
    it('should show error message when URL has error and error_description', () => {
      renderCallbackPage(
        '/auth/azure/callback?error=access_denied&error_description=User+cancelled+the+request',
      );

      expect(screen.getByText('Authentication Failed')).toBeInTheDocument();
      expect(
        screen.getByText('Microsoft login failed: User cancelled the request'),
      ).toBeInTheDocument();
    });

    it('should fall back to error param when error_description is missing', () => {
      renderCallbackPage('/auth/azure/callback?error=server_error');

      expect(
        screen.getByText('Microsoft login failed: server_error'),
      ).toBeInTheDocument();
    });
  });

  describe('Missing Params', () => {
    it('should show error when code is missing', () => {
      renderCallbackPage('/auth/azure/callback?state=xyz789');

      expect(
        screen.getByText('Missing code or state from Microsoft redirect'),
      ).toBeInTheDocument();
    });

    it('should show error when state is missing', () => {
      renderCallbackPage('/auth/azure/callback?code=abc123');

      expect(
        screen.getByText('Missing code or state from Microsoft redirect'),
      ).toBeInTheDocument();
    });

    it('should show error when both code and state are missing', () => {
      renderCallbackPage('/auth/azure/callback');

      expect(
        screen.getByText('Missing code or state from Microsoft redirect'),
      ).toBeInTheDocument();
    });
  });

  describe('Backend Error', () => {
    it('should show error from response data when completeAzureLogin rejects', async () => {
      mockCompleteAzureLogin.mockRejectedValue({
        response: { data: { error: 'invalid_grant' } },
      });

      renderCallbackPage('/auth/azure/callback?code=abc123&state=xyz789');

      await waitFor(() => {
        expect(screen.getByText('invalid_grant')).toBeInTheDocument();
      });

      expect(screen.getByText('Authentication Failed')).toBeInTheDocument();
    });

    it('should show error message from Error instance when no response data', async () => {
      mockCompleteAzureLogin.mockRejectedValue(new Error('Network Error'));

      renderCallbackPage('/auth/azure/callback?code=abc123&state=xyz789');

      await waitFor(() => {
        expect(screen.getByText('Network Error')).toBeInTheDocument();
      });
    });

    it('should show generic message when error has no response or message', async () => {
      mockCompleteAzureLogin.mockRejectedValue({});

      renderCallbackPage('/auth/azure/callback?code=abc123&state=xyz789');

      await waitFor(() => {
        expect(screen.getByText('Authentication failed')).toBeInTheDocument();
      });
    });
  });

  describe('Back to Login Button', () => {
    it('should navigate to /login when clicking Back to Login', async () => {
      const user = userEvent.setup();

      renderCallbackPage('/auth/azure/callback');

      // Error state shows due to missing params
      expect(screen.getByText('Authentication Failed')).toBeInTheDocument();

      await user.click(screen.getByRole('button', { name: 'Back to Login' }));

      expect(mockNavigate).toHaveBeenCalledWith('/login');
    });
  });
});
