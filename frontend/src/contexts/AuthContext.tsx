import { createContext, useContext, useState, useEffect, useMemo, ReactNode, useCallback } from 'react';

export interface ZKRoleClaims {
  groups?: string[];
  claims?: string[];
  credential_refs?: string[];
  proof_ts?: number;
}

export interface AuthState {
  isAuthenticated: boolean;
  accessToken: string | null;
  refreshToken: string | null;
  userDID: string | null;
  expiresAt: number | null;
  kyc: boolean;
  zkRoles: ZKRoleClaims | null;
  issuedAt: number | null;
  authProvider: 'azure_ad' | 'privado_id' | null;
}

interface AuthContextType extends AuthState {
  login: (accessToken: string, refreshToken: string, expiresIn: number) => void;
  logout: () => void;
  refreshAccessToken: () => Promise<boolean>;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const STORAGE_KEY = 'privacy_proxy_auth';

interface StoredAuth {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

interface JWTPayload {
  sub?: string;
  exp?: number;
  iat?: number;
  kyc?: boolean;
  zk_roles?: ZKRoleClaims;
}

function parseJWT(token: string): JWTPayload | null {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch {
    return null;
  }
}

function detectAuthProvider(did: string | undefined): 'azure_ad' | 'privado_id' | null {
  if (!did) return null;
  return did.startsWith('azuread:') ? 'azure_ad' : 'privado_id';
}

function buildAuthState(accessToken: string, refreshToken: string, expiresAt: number): AuthState {
  const claims = parseJWT(accessToken);
  return {
    isAuthenticated: true,
    accessToken,
    refreshToken,
    userDID: claims?.sub || null,
    expiresAt,
    kyc: claims?.kyc ?? false,
    zkRoles: claims?.zk_roles ?? null,
    issuedAt: claims?.iat ? claims.iat * 1000 : null,
    authProvider: detectAuthProvider(claims?.sub),
  };
}

// Module-scope constant: the logged-out auth state. Hoisted out of the
// component so it has a stable identity and can be safely referenced from
// useCallback/useEffect dependency arrays without re-creating each render.
const emptyState: AuthState = {
  isAuthenticated: false,
  accessToken: null,
  refreshToken: null,
  userDID: null,
  expiresAt: null,
  kyc: false,
  zkRoles: null,
  issuedAt: null,
  authProvider: null,
};

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(emptyState);
  const [isLoading, setIsLoading] = useState(true);

  // Stable: only touches setState / sessionStorage / fetch and module-scope
  // helpers, so it has no reactive dependencies. Memoised so it can be listed
  // as a dependency of the effects/callbacks below without retriggering them.
  const refreshWithToken = useCallback(async (refreshToken: string): Promise<boolean> => {
    try {
      const response = await fetch('/api/v1/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      if (!response.ok) {
        throw new Error('Refresh failed');
      }

      const data = await response.json();
      const expiresAt = Date.now() + data.expires_in * 1000;

      const newAuth: StoredAuth = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
      };
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify(newAuth));

      setState(buildAuthState(data.access_token, data.refresh_token, expiresAt));

      return true;
    } catch {
      sessionStorage.removeItem(STORAGE_KEY);
      setState(emptyState);
      return false;
    }
  }, []);

  // Load auth state from sessionStorage on mount (per-tab isolation).
  // refreshWithToken is memoised with an empty dep array so it is stable; the
  // effect still only runs once on mount.
  useEffect(() => {
    const loadAuth = async () => {
      const stored = sessionStorage.getItem(STORAGE_KEY);
      if (stored) {
        try {
          const auth: StoredAuth = JSON.parse(stored);
          const now = Date.now();

          // Check if token is still valid (with 1 minute buffer)
          if (auth.expiresAt > now + 60000) {
            setState(buildAuthState(auth.accessToken, auth.refreshToken, auth.expiresAt));
          } else if (auth.refreshToken) {
            // Token expired but we have refresh token - try to refresh
            await refreshWithToken(auth.refreshToken);
          } else {
            sessionStorage.removeItem(STORAGE_KEY);
          }
        } catch {
          sessionStorage.removeItem(STORAGE_KEY);
        }
      }
      setIsLoading(false);
    };

    loadAuth();
  }, [refreshWithToken]);

  const login = useCallback((accessToken: string, refreshToken: string, expiresIn: number) => {
    const expiresAt = Date.now() + expiresIn * 1000;

    const auth: StoredAuth = {
      accessToken,
      refreshToken,
      expiresAt,
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(auth));

    setState(buildAuthState(accessToken, refreshToken, expiresAt));
  }, []);

  const logout = useCallback(async () => {
    // Revoke both tokens on server for immediate invalidation
    // Access token revocation ensures immediate logout (vs 30 min expiry)
    if (state.refreshToken) {
      try {
        await fetch('/api/v1/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            refresh_token: state.refreshToken,
            access_token: state.accessToken, // Include for immediate invalidation
          }),
        });
      } catch {
        // Ignore errors, we're logging out anyway
      }
    }

    sessionStorage.removeItem(STORAGE_KEY);
    setState(emptyState);
  }, [state.refreshToken, state.accessToken]);

  const refreshAccessToken = useCallback(async (): Promise<boolean> => {
    if (!state.refreshToken) return false;
    return refreshWithToken(state.refreshToken);
  }, [state.refreshToken, refreshWithToken]);

  // Auto-refresh token before expiry
  useEffect(() => {
    if (!state.expiresAt || !state.refreshToken) return;

    const timeUntilExpiry = state.expiresAt - Date.now();
    const refreshTime = timeUntilExpiry - 60000; // Refresh 1 minute before expiry

    if (refreshTime <= 0) {
      refreshAccessToken();
      return;
    }

    const timer = setTimeout(() => {
      refreshAccessToken();
    }, refreshTime);

    return () => clearTimeout(timer);
  }, [state.expiresAt, state.refreshToken, refreshAccessToken]);

  const value = useMemo(() => ({
    ...state,
    login,
    logout,
    refreshAccessToken,
    isLoading,
  }), [state, login, logout, refreshAccessToken, isLoading]);

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}

// reason: useAuth is the consumer hook for AuthProvider and is intentionally
// co-located with it in this context file. Splitting it out would touch every
// auth consumer; the only cost of co-location is full reload (not HMR) when
// editing this file.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

// useAuthOptional returns the auth context when available, or null when the
// component is rendered outside an AuthProvider (e.g. in component-unit
// tests that mount RBAC widgets without wrapping in the full app context).
// Use this for purely-cosmetic affordances that depend on the current user
// — never for code paths that must enforce auth. Hook auth-required code to
// useAuth() so the throw still catches accidental misuse.
// reason: optional-auth consumer hook co-located with AuthProvider, same
// rationale as useAuth above.
// eslint-disable-next-line react-refresh/only-export-components
export function useAuthOptional(): AuthContextType | null {
  const context = useContext(AuthContext);
  return context ?? null;
}
