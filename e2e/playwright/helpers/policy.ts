import { APIRequestContext } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';

export interface PolicyOptions {
  kyc?: boolean;
  banned?: boolean;
  allowMethods?: string[];
  note?: string;
}

export interface Policy {
  external_id: string;
  kyc: boolean;
  banned: boolean;
  allow_methods: string[];
  note: string;
}

/**
 * Create or update a policy for a user via the admin API
 */
export async function createPolicy(
  request: APIRequestContext,
  externalId: string,
  opts: PolicyOptions = {}
): Promise<Policy> {
  const policy = {
    external_id: externalId,
    kyc: opts.kyc ?? true,
    banned: opts.banned ?? false,
    allow_methods: opts.allowMethods ?? ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
    note: opts.note ?? `E2E test policy for ${externalId}`,
  };

  const response = await request.post(`${ADMIN_URL}/api/policies`, {
    headers: { 'Content-Type': 'application/json' },
    data: policy,
  });

  if (!response.ok()) {
    const body = await response.text();
    throw new Error(`Failed to create policy: ${response.status()} - ${body}`);
  }

  return (await response.json()) as Policy;
}

/**
 * Get a policy by external ID
 */
export async function getPolicy(
  request: APIRequestContext,
  externalId: string
): Promise<Policy | null> {
  const response = await request.get(`${ADMIN_URL}/api/policies/${encodeURIComponent(externalId)}`);

  if (response.status() === 404) {
    return null;
  }

  if (!response.ok()) {
    const body = await response.text();
    throw new Error(`Failed to get policy: ${response.status()} - ${body}`);
  }

  return (await response.json()) as Policy;
}

/**
 * Update an existing policy
 */
export async function updatePolicy(
  request: APIRequestContext,
  externalId: string,
  updates: Partial<PolicyOptions>
): Promise<Policy> {
  const data: Record<string, unknown> = {};
  if (updates.kyc !== undefined) data.kyc = updates.kyc;
  if (updates.banned !== undefined) data.banned = updates.banned;
  if (updates.allowMethods !== undefined) data.allow_methods = updates.allowMethods;
  if (updates.note !== undefined) data.note = updates.note;

  const response = await request.put(`${ADMIN_URL}/api/policies/${encodeURIComponent(externalId)}`, {
    headers: { 'Content-Type': 'application/json' },
    data,
  });

  if (!response.ok()) {
    const body = await response.text();
    throw new Error(`Failed to update policy: ${response.status()} - ${body}`);
  }

  return (await response.json()) as Policy;
}

/**
 * Delete a policy by external ID
 */
export async function deletePolicy(
  request: APIRequestContext,
  externalId: string
): Promise<void> {
  const response = await request.delete(`${ADMIN_URL}/api/policies/${encodeURIComponent(externalId)}`);

  // Ignore 404 (policy doesn't exist) - it's fine for cleanup
  if (!response.ok() && response.status() !== 404) {
    const body = await response.text();
    throw new Error(`Failed to delete policy: ${response.status()} - ${body}`);
  }
}
