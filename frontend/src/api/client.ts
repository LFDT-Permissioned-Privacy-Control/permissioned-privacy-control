import axios from 'axios';
import { adminApi } from './adminClient';

const api = adminApi;

export interface AccessLog {
  id: number;
  external_id: string;
  method: string;
  status_code: number;
  response_status?: number | null;
  ip_address: string;
  correlation_id?: string | null;
  created_at: string;
  org_id?: string | null;
  // Curated denial-reason code for denied requests (RD-1137), e.g.
  // "sender_not_linked". Null for successful or unclassified requests.
  denial_reason?: string | null;
}

// Outcome buckets sent to the backend as the `outcome` query param. "all" =
// no constraint; the others map server-side to the matching HTTP status range
// (success → 2xx, denied → 4xx, error → 5xx) so RBAC denials at any 4xx code
// (401 anonymous, 403 authenticated, 429 rate-limited, etc.) all show up
// under "denied". Mirrors how the SIEM forwarder buckets each access event.
export type AccessLogOutcome = 'all' | 'success' | 'denied' | 'error';

export interface AccessLogFilters {
  externalId?: string;
  method?: string;
  outcome?: AccessLogOutcome;
  statusCode?: number;
  correlationId?: string;
  from?: string; // ISO/RFC3339
  to?: string; // ISO/RFC3339
  limit?: number;
  offset?: number;
}

export interface AccessLogListResponse {
  data: AccessLog[];
  total: number;
  limit: number;
  offset: number;
}

export const logsApi = {
  list: (filters: AccessLogFilters = {}) => {
    const params: Record<string, string | number> = {};
    if (filters.externalId) params.external_id = filters.externalId;
    if (filters.method) params.method = filters.method;
    if (filters.correlationId) params.correlation_id = filters.correlationId;
    // status_code (exact) and outcome (range bucket) are mutually exclusive on
    // the wire — the backend rejects both. Prefer status_code when an explicit
    // code is set; otherwise let the bucket flow through.
    if (typeof filters.statusCode === 'number' && filters.statusCode > 0) {
      params.status_code = filters.statusCode;
    } else if (filters.outcome && filters.outcome !== 'all') {
      params.outcome = filters.outcome;
    }
    if (filters.from) params.from = filters.from;
    if (filters.to) params.to = filters.to;
    if (typeof filters.limit === 'number' && filters.limit > 0) params.limit = filters.limit;
    if (typeof filters.offset === 'number' && filters.offset >= 0) params.offset = filters.offset;
    return api.get<AccessLogListResponse>('/logs', { params });
  },
};

export interface StatusResponse {
  proxy: {
    status: string;
    port: string;
  };
  node: {
    status: string;
    url: string;
    latency_ms: number;
    error?: string;
  };
}

export interface TestRequestResponse {
  result?: unknown;
  error?: string;
  latency_ms?: number;
  identity?: string;
}

export interface TestRequestResult {
  status: number;
  data: TestRequestResponse;
}

export const statusApi = {
  get: () => api.get<StatusResponse>('/status'),
};

// RD-1076: build identity of the running privacy-proxy binary. Admin-gated
// (GET /api/v1/admin/system/version). Surfaced in the Diagnostics tab.
export interface SystemVersion {
  version: string;
  commit: string;
  build_time: string;
}

export const systemApi = {
  getVersion: () => api.get<SystemVersion>('/system/version'),
};

export const testApi = {
  send: async (method: string, params: unknown[] = [], jwtToken?: string): Promise<TestRequestResult> => {
    try {
      const response = await api.post<TestRequestResponse>('/test-request', {
        method,
        params,
        ...(jwtToken && { jwt_token: jwtToken })
      });
      return { status: response.status, data: response.data };
    } catch (err) {
      if (axios.isAxiosError(err) && err.response) {
        // Return 4xx/5xx responses as results, not errors
        return { status: err.response.status, data: err.response.data as TestRequestResponse };
      }
      throw err;
    }
  },

  lookupUser: async (did: string) => {
    // Search for user by DID
    const usersResponse = await api.get('/users', { params: { search: did, limit: 1 } });
    const users = usersResponse.data as { data: Array<{ id: string; external_id: string; kyc: boolean; banned: boolean }> };
    if (!users.data || users.data.length === 0) return null;
    const user = users.data[0];

    // Fetch memberships and linked addresses in parallel
    const [membershipsRes, addressesRes] = await Promise.all([
      api.get(`/users/${user.id}/memberships`),
      api.get(`/users/${user.id}/linked-addresses`),
    ]);

    // Get unique org IDs and fetch groups per org for claims
    const memberships = (membershipsRes.data || []) as Array<{ membership: { id: string; group_id: string; source: string }; group: { id: string; org_id: string; name: string; path: string } }>;
    const orgIds = [...new Set(memberships.map(m => m.group.org_id))];

    // Fetch groups with access for each org
    const orgGroupsMap: Record<string, Array<{ group: { id: string; name: string; path: string }; access: { claims: string[] } | null }>> = {};
    await Promise.all(orgIds.map(async (orgId) => {
      const res = await api.get(`/orgs/${orgId}/groups`, { params: { limit: 100 } });
      const data = res.data as { data: Array<{ group: { id: string; name: string; path: string }; access: { claims: string[] } | null }> };
      orgGroupsMap[orgId] = data.data || [];
    }));

    // Build org names map
    const orgNames: Record<string, string> = {};
    await Promise.all(orgIds.map(async (orgId) => {
      const res = await api.get(`/orgs/${orgId}`);
      const org = res.data as { name: string };
      orgNames[orgId] = org.name;
    }));

    return {
      user,
      memberships,
      linkedAddresses: ((addressesRes.data as { addresses: Array<{ address: string; verified_at: string }> }).addresses || []),
      orgGroupsMap,
      orgNames,
    };
  },

  lookupContract: async (address: string) => {
    const response = await api.get(`/contracts/by-address/${address}`);
    return response.data as {
      contract: { id: string; name: string; address: string; org_id: string };
      organization: { id: string; name: string; slug: string };
      grants: Array<{
        grant: { id: string; contract_id: string; group_id: string; functions: Array<{ selector: string }> | null };
        group: { id: string; name: string; path: string };
        access: { claims: string[]; allowed_methods: string[] } | null;
      }>;
    };
  },
};

export interface DeployDemoERC20Response {
  address: string;
  tx_hash: string;
  registered: boolean;
  name: string;
}

export const devApi = {
  deployDemoERC20: (params?: { org_id?: string; name?: string }) =>
    api.post<DeployDemoERC20Response>('/dev/deploy-demo-erc20', params ?? {}),
};

export default api;
