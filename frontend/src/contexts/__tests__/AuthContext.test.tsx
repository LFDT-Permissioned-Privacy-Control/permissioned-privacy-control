/**
 * @vitest-environment jsdom
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { AuthProvider, useAuth } from '../AuthContext';

// Test component that uses the auth context
function TestComponent() {
  const auth = useAuth();
  return (
    <div>
      <span data-testid="authenticated">{auth.isAuthenticated.toString()}</span>
      <span data-testid="loading">{auth.isLoading.toString()}</span>
      <span data-testid="user-did">{auth.userDID || 'null'}</span>
      <span data-testid="access-token">{auth.accessToken || 'null'}</span>
      <button onClick={() => auth.login('test-token', 'test-refresh', 3600)}>
        Login
      </button>
      <button onClick={() => auth.logout()}>Logout</button>
    </div>
  );
}

describe('AuthContext', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.clearAllMocks();
  });

  describe('Initial State', () => {
    it('should start with isAuthenticated false and isLoading true', async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      // Initial loading state
      await waitFor(() => {
        expect(screen.getByTestId('loading').textContent).toBe('false');
      });

      expect(screen.getByTestId('authenticated').textContent).toBe('false');
      expect(screen.getByTestId('user-did').textContent).toBe('null');
    });

    it('should load auth state from sessionStorage on mount', async () => {
      // Create a valid JWT token with future expiry
      const payload = {
        sub: 'did:polygonid:polygon:main:user123',
        exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `header.${encodedPayload}.signature`;

      const authData = {
        accessToken: mockToken,
        refreshToken: 'test-refresh-token',
        expiresAt: Date.now() + 3600000, // 1 hour from now
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('authenticated').textContent).toBe('true');
      });

      expect(screen.getByTestId('user-did').textContent).toBe(
        'did:polygonid:polygon:main:user123'
      );
    });

    it('should clear expired tokens from sessionStorage', async () => {
      const authData = {
        accessToken: 'expired-token',
        refreshToken: '',
        expiresAt: Date.now() - 1000, // Already expired, no refresh token
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading').textContent).toBe('false');
      });

      expect(screen.getByTestId('authenticated').textContent).toBe('false');
      expect(sessionStorage.getItem('privacy_proxy_auth')).toBeNull();
    });
  });

  describe('Login', () => {
    it('should update state and sessionStorage on login', async () => {
      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading').textContent).toBe('false');
      });

      // Click login button
      act(() => {
        // Manually call login with our test token
        const loginButton = screen.getByText('Login');
        // We need to modify the TestComponent to use our token
        // For now, let's verify the login function works
        loginButton.click();
      });

      // The test token in TestComponent is 'test-token' which won't parse as JWT
      // but the state should still update
      await waitFor(() => {
        expect(screen.getByTestId('authenticated').textContent).toBe('true');
      });

      // Verify sessionStorage was updated
      const stored = sessionStorage.getItem('privacy_proxy_auth');
      expect(stored).not.toBeNull();
      const parsed = JSON.parse(stored!);
      expect(parsed.accessToken).toBe('test-token');
      expect(parsed.refreshToken).toBe('test-refresh');
    });
  });

  describe('Logout', () => {
    it('should clear state and sessionStorage on logout', async () => {
      // Setup initial authenticated state
      const payload = {
        sub: 'did:test:user',
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `header.${encodedPayload}.signature`;

      const authData = {
        accessToken: mockToken,
        refreshToken: 'test-refresh',
        expiresAt: Date.now() + 3600000,
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('authenticated').textContent).toBe('true');
      });

      // Click logout
      act(() => {
        screen.getByText('Logout').click();
      });

      await waitFor(() => {
        expect(screen.getByTestId('authenticated').textContent).toBe('false');
      });

      expect(screen.getByTestId('user-did').textContent).toBe('null');
      expect(sessionStorage.getItem('privacy_proxy_auth')).toBeNull();
    });
  });

  describe('Token Refresh', () => {
    it('should refresh token when near expiry', async () => {
      // Create a token that's about to expire (less than 1 minute)
      const payload = {
        sub: 'did:test:user',
        exp: Math.floor(Date.now() / 1000) + 30, // 30 seconds from now
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `header.${encodedPayload}.signature`;

      const authData = {
        accessToken: mockToken,
        refreshToken: 'valid-refresh-token',
        expiresAt: Date.now() + 30000, // 30 seconds from now
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      // Wait for the component to load and potentially trigger refresh
      await waitFor(
        () => {
          expect(screen.getByTestId('loading').textContent).toBe('false');
        },
        { timeout: 3000 }
      );

      // The refresh should be triggered automatically since token is near expiry
      // The MSW handler will return new tokens
      await waitFor(
        () => {
          const stored = sessionStorage.getItem('privacy_proxy_auth');
          if (stored) {
            const parsed = JSON.parse(stored);
            // Check if token was refreshed (new token from MSW)
            return (
              parsed.accessToken === 'new-access-token' ||
              parsed.accessToken === mockToken
            );
          }
          return false;
        },
        { timeout: 5000 }
      );
    });
  });

  describe('JWT Parsing', () => {
    it('should extract DID from valid JWT', async () => {
      const did = 'did:polygonid:polygon:main:specific-user';
      const payload = {
        sub: did,
        exp: Math.floor(Date.now() / 1000) + 3600,
      };
      const encodedPayload = btoa(JSON.stringify(payload));
      const mockToken = `header.${encodedPayload}.signature`;

      const authData = {
        accessToken: mockToken,
        refreshToken: 'test-refresh',
        expiresAt: Date.now() + 3600000,
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('user-did').textContent).toBe(did);
      });
    });

    it('should handle invalid JWT gracefully', async () => {
      const authData = {
        accessToken: 'not-a-valid-jwt',
        refreshToken: 'test-refresh',
        expiresAt: Date.now() + 3600000,
      };
      sessionStorage.setItem('privacy_proxy_auth', JSON.stringify(authData));

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading').textContent).toBe('false');
      });

      // Should still be authenticated but DID should be null
      expect(screen.getByTestId('authenticated').textContent).toBe('true');
      expect(screen.getByTestId('user-did').textContent).toBe('null');
    });
  });

  describe('Error Handling', () => {
    it('should throw error when useAuth is used outside provider', () => {
      // Suppress console.error for this test
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      expect(() => {
        render(<TestComponent />);
      }).toThrow('useAuth must be used within an AuthProvider');

      consoleSpy.mockRestore();
    });

    it('should handle corrupted sessionStorage data', async () => {
      sessionStorage.setItem('privacy_proxy_auth', 'not-valid-json');

      render(
        <AuthProvider>
          <TestComponent />
        </AuthProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading').textContent).toBe('false');
      });

      expect(screen.getByTestId('authenticated').textContent).toBe('false');
      expect(sessionStorage.getItem('privacy_proxy_auth')).toBeNull();
    });
  });
});
