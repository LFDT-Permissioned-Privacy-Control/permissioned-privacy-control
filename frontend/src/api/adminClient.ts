import axios, { AxiosHeaders } from 'axios';
import type { InternalAxiosRequestConfig } from 'axios';

const ADMIN_TOKEN_STORAGE_KEYS = [
  'privacy_proxy_admin_api_token',
  'privacy_proxy_admin_token',
  'admin_api_token',
] as const;

/** Storage key used by AuthContext to persist the user's JWT session. */
const AUTH_STORAGE_KEY = 'privacy_proxy_auth';

function getStoredAdminToken(): string {
  for (const key of ADMIN_TOKEN_STORAGE_KEYS) {
    const localValue = window.localStorage.getItem(key)?.trim();
    if (localValue) {
      return localValue;
    }

    const sessionValue = window.sessionStorage.getItem(key)?.trim();
    if (sessionValue) {
      return sessionValue;
    }
  }

  return '';
}

export function getAdminToken(): string {
  // SECURITY: Admin tokens are read only from browser storage (localStorage /
  // sessionStorage), never from environment variables. Vite env vars are baked
  // into the JS bundle at build time and would be visible to every visitor.
  return getStoredAdminToken();
}

/** Read the user's JWT access token from AuthContext's sessionStorage entry. */
function getStoredAccessToken(): string {
  try {
    const raw = window.sessionStorage.getItem(AUTH_STORAGE_KEY);
    if (!raw) return '';
    const parsed = JSON.parse(raw) as { accessToken?: string; expiresAt?: number };
    // Only use the token if it has not expired (with 1 minute buffer).
    if (parsed.accessToken && parsed.expiresAt && parsed.expiresAt > Date.now() + 60_000) {
      return parsed.accessToken;
    }
  } catch {
    // Ignore parse errors.
  }
  return '';
}

function applyAdminHeaders(config: InternalAxiosRequestConfig): InternalAxiosRequestConfig {
  const headers = config.headers instanceof AxiosHeaders
    ? config.headers
    : new AxiosHeaders(config.headers);

  // Already has auth headers — don't override.
  if (headers.has('X-Admin-Token') || headers.has('Authorization')) {
    config.headers = headers;
    return config;
  }

  // Prefer X-Admin-Token (M2M / bootstrap).
  const adminToken = getAdminToken();
  if (adminToken) {
    headers.set('X-Admin-Token', adminToken);
    config.headers = headers;
    return config;
  }

  // Fall back to user's JWT (browser-based admin access).
  const accessToken = getStoredAccessToken();
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  config.headers = headers;
  return config;
}

export const adminApi = axios.create({
  baseURL: '/api/v1/admin',
  headers: {
    'Content-Type': 'application/json',
  },
});

adminApi.interceptors.request.use(applyAdminHeaders);

export function createAdminClient(extraHeaders?: Record<string, string>) {
  const client = axios.create({
    baseURL: '/api/v1/admin',
    headers: {
      'Content-Type': 'application/json',
      ...(extraHeaders ?? {}),
    },
  });

  client.interceptors.request.use(applyAdminHeaders);
  return client;
}
