import { APIRequestContext } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

interface AuthRequestResponse {
  session_id: string;
  auth_request: unknown;
}

interface AuthVerifyResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

/**
 * Get a JWT access token for the given user DID.
 * Uses the dev-only /auth/verify endpoint with mock JWZ tokens.
 */
export async function getJWTToken(request: APIRequestContext, userDID: string): Promise<string> {
  // Step 1: Create auth request to get session ID
  const authRequestResponse = await request.post(`${ADMIN_URL}/auth/request`, {
    headers: { 'Content-Type': 'application/json' },
  });

  if (!authRequestResponse.ok()) {
    const body = await authRequestResponse.text();
    throw new Error(`Failed to create auth request: ${authRequestResponse.status()} - ${body}`);
  }

  const { session_id } = (await authRequestResponse.json()) as AuthRequestResponse;

  // Step 2: Verify with mock JWZ token (dev mode only)
  // The mock verifier extracts the DID from the token format: mock.{userDID}
  const verifyResponse = await request.post(`${ADMIN_URL}/auth/verify`, {
    headers: { 'Content-Type': 'application/json' },
    data: {
      session_id,
      jwz_token: `mock.${userDID}`,
    },
  });

  if (!verifyResponse.ok()) {
    const body = await verifyResponse.text();
    throw new Error(`Failed to verify auth: ${verifyResponse.status()} - ${body}`);
  }

  const { access_token } = (await verifyResponse.json()) as AuthVerifyResponse;
  return access_token;
}

/**
 * Make an authenticated JSON-RPC request.
 *
 * Pass `orgId` to target `/rpc/:org_id` — required for non-metadata methods
 * when the caller has no default-org membership (RD-877 removed the implicit
 * default-org fallback on the org-free `/` and `/rpc` paths).
 */
export async function makeRPCRequest(
  request: APIRequestContext,
  token: string,
  method: string,
  params: unknown[] = [],
  orgId?: string
): Promise<{
  status: number;
  body: unknown;
}> {
  const path = orgId ? `/rpc/${orgId}` : '/';
  const response = await request.post(path, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    data: {
      jsonrpc: '2.0',
      method,
      params,
      id: 1,
    },
  });

  return {
    status: response.status(),
    body: await response.json(),
  };
}

/**
 * Make an unauthenticated JSON-RPC request
 */
export async function makeUnauthenticatedRPCRequest(
  request: APIRequestContext,
  method: string,
  params: unknown[] = []
): Promise<{
  status: number;
  body: unknown;
}> {
  const response = await request.post('/', {
    headers: {
      'Content-Type': 'application/json',
    },
    data: {
      jsonrpc: '2.0',
      method,
      params,
      id: 1,
    },
  });

  return {
    status: response.status(),
    body: await response.json(),
  };
}
