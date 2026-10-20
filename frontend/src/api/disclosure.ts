import axios from 'axios';
import { adminApi, createAdminClient } from './adminClient';
import type {
  DisclosureRequest,
  DisclosureGrant,
  DisclosureAccessEvent,
  DisclosureActivityLog,
  DisclosureActivitySummary,
  DisclosureReport,
  CreateDisclosureRequestInput,
  ApproveDisclosureResponse,
  RejectDisclosureInput,
  RevokeDisclosureInput,
  DisclosureReportType,
  DisclosureFilter,
} from '../types/disclosure';

const api = adminApi;

// Create an authenticated API client
const createAuthenticatedClient = (accessToken: string) => {
  return axios.create({
    baseURL: '/api/v1',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${accessToken}`,
    },
  });
};

// Create a disclosure token authenticated client
const createTokenClient = (disclosureToken: string) => {
  return createAdminClient({ 'X-Disclosure-Token': disclosureToken });
};

export const disclosureApi = {
  // ============================================
  // Admin endpoints (localhost/private network + optional shared admin token)
  // ============================================
  admin: {
    // Create a new disclosure request
    createRequest: (input: CreateDisclosureRequestInput) => {
      // Transform frontend input to backend format
      const backendInput: Record<string, unknown> = {
        target_user_id: input.user_external_id, // user_external_id is actually the user UUID from dropdown
        requester_did: input.requester_did, // DID of auditor who will get access
        org_id: input.org_id, // Required for JWT org admins; backend defaults to system default org if omitted.
        reason: input.purpose,
        legal_basis: input.legal_basis,
        scope: {
          methods: input.scope || [],
          disclosure_level: input.disclosure_level || 'pseudonymous',
        },
      };

      // Calculate expires_in_hours from valid_until if provided
      if (input.valid_until) {
        const now = new Date();
        const until = new Date(input.valid_until);
        const hoursUntil = Math.max(1, Math.ceil((until.getTime() - now.getTime()) / (1000 * 60 * 60)));
        backendInput.expires_in_hours = hoursUntil;
      }

      return api.post<DisclosureRequest>('/disclosure/requests', backendInput);
    },

    // List all disclosure requests
    listRequests: async (limit?: number, offset?: number) => {
      // Backend returns { request: {...}, target_did: "" }[] wrapper
      interface BackendRequestWithDetails {
        request: {
          id: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
        };
        target_did: string;
      }

      const response = await api.get<BackendRequestWithDetails[]>('/disclosure/requests', {
        params: { limit, offset },
      });

      // Transform backend response to frontend format
      const transformedData: DisclosureRequest[] = (response.data || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        target_did: item.target_did,
        requester_name: 'System', // Backend doesn't track requester name
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.requested_at,
        valid_until: item.request.expires_at,
      }));

      return { ...response, data: transformedData };
    },

    // Get a specific disclosure request
    getRequest: (requestId: string) =>
      api.get<DisclosureRequest>(`/disclosure/requests/${requestId}`),

    // List disclosure requests with filtering
    listRequestsWithFilter: async (filter?: DisclosureFilter) => {
      const params = new URLSearchParams();
      if (filter) {
        // org_id MUST be passed first (RD-944) — for jwt-admin callers
        // the backend now defaults to the caller's first admin org when
        // omitted, but multi-org admins need to specify explicitly to
        // avoid silent scoping to the wrong org.
        if (filter.org_id) params.append('org_id', filter.org_id);
        if (filter.status) params.append('status', filter.status);
        if (filter.target_user_id) params.append('target_user_id', filter.target_user_id);
        if (filter.requester_did) params.append('requester_did', filter.requester_did);
        if (filter.disclosure_level) params.append('disclosure_level', filter.disclosure_level);
        if (filter.date_from) params.append('date_from', filter.date_from);
        if (filter.date_to) params.append('date_to', filter.date_to);
        if (filter.limit) params.append('limit', filter.limit.toString());
        if (filter.offset) params.append('offset', filter.offset.toString());
      }

      // Backend returns nested structure: { requests: [{ request: {...}, target_did }] }
      interface BackendRequestWithDetails {
        request: {
          id: string;
          requester_did?: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
        };
        target_did: string;
      }
      interface BackendListResult {
        requests: BackendRequestWithDetails[];
        total: number;
        limit: number;
        offset: number;
      }

      const response = await api.get<BackendListResult>(`/disclosure/requests?${params.toString()}`);

      // Transform to frontend format
      const transformedRequests: DisclosureRequest[] = (response.data.requests || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        target_did: item.target_did,
        requester_did: item.request.requester_did,
        requester_name: 'System',
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.requested_at,
        valid_until: item.request.expires_at,
        decided_at: item.request.decided_at,
        decision_reason: item.request.decision_reason,
      }));

      return {
        ...response,
        data: {
          requests: transformedRequests,
          total: response.data.total,
          limit: response.data.limit,
          offset: response.data.offset,
        },
      };
    },

    // List disclosure grants with filtering
    listGrantsWithFilter: async (filter?: DisclosureFilter) => {
      const params = new URLSearchParams();
      if (filter) {
        // org_id MUST be passed first (RD-944) — see listRequestsWithFilter
        // for the rationale and backend behaviour.
        if (filter.org_id) params.append('org_id', filter.org_id);
        if (filter.status) params.append('status', filter.status);
        if (filter.target_user_id) params.append('target_user_id', filter.target_user_id);
        if (filter.requester_did) params.append('requester_did', filter.requester_did);
        if (filter.disclosure_level) params.append('disclosure_level', filter.disclosure_level);
        if (filter.date_from) params.append('date_from', filter.date_from);
        if (filter.date_to) params.append('date_to', filter.date_to);
        if (filter.limit) params.append('limit', filter.limit.toString());
        if (filter.offset) params.append('offset', filter.offset.toString());
      }

      // Backend returns nested structure: { grants: [{ grant: {...}, request: {...} }] }
      interface BackendGrantWithRequest {
        grant: {
          id: string;
          request_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          granted_at: string;
          expires_at: string;
          revoked_at?: string;
        };
        request: {
          id: string;
          requester_did?: string;
          target_user_id: string;
          reason: string;
        };
      }
      interface BackendGrantListResult {
        grants: BackendGrantWithRequest[];
        total: number;
        limit: number;
        offset: number;
      }

      const response = await api.get<BackendGrantListResult>(`/disclosure/grants?${params.toString()}`);

      // Transform to frontend format
      const transformedGrants: DisclosureGrant[] = (response.data.grants || []).map((item) => ({
        id: item.grant.id,
        request_id: item.grant.request_id,
        user_id: item.request.target_user_id,
        token_hash: '', // Not exposed to frontend
        requester_did: item.request.requester_did,
        reason: item.request.reason,
        scope: (item.grant.scope?.methods || []) as DisclosureGrant['scope'],
        disclosure_level: (item.grant.scope?.disclosure_level || 'pseudonymous') as DisclosureGrant['disclosure_level'],
        valid_from: item.grant.granted_at,
        valid_until: item.grant.expires_at,
        revoked_at: item.grant.revoked_at,
        created_at: item.grant.granted_at,
        updated_at: item.grant.granted_at,
      }));

      return {
        ...response,
        data: {
          grants: transformedGrants,
          total: response.data.total,
          limit: response.data.limit,
          offset: response.data.offset,
        },
      };
    },

    // Delete a pending disclosure request
    deleteRequest: (requestId: string) =>
      api.delete(`/disclosure/requests/${requestId}`),

    // Revoke a disclosure grant (admin action)
    revokeGrant: (grantId: string, reason?: string) =>
      api.post(`/disclosure/grants/${grantId}/revoke`, { reason }),
  },

  // ============================================
  // Grant access endpoints (require disclosure token)
  // ============================================
  grant: {
    // View activity logs for a grant
    getLogs: (grantId: string, token: string, limit?: number, offset?: number) =>
      createTokenClient(token).get<DisclosureActivityLog[]>(
        `/disclosure/grants/${grantId}/logs`,
        { params: { limit, offset } }
      ),

    // View activity summary for a grant
    getSummary: (grantId: string, token: string) =>
      createTokenClient(token).get<DisclosureActivitySummary>(
        `/disclosure/grants/${grantId}/summary`
      ),

    // Generate a report for a grant
    getReport: (grantId: string, token: string, reportType: DisclosureReportType) =>
      createTokenClient(token).get<DisclosureReport>(
        `/disclosure/grants/${grantId}/report/${reportType}`
      ),

    // View access audit trail for a grant
    getEvents: (grantId: string, token: string, limit?: number, offset?: number) =>
      createTokenClient(token).get<DisclosureAccessEvent[]>(
        `/disclosure/grants/${grantId}/events`,
        { params: { limit, offset } }
      ),
  },

  // ============================================
  // User endpoints (require JWT auth)
  // ============================================
  user: {
    // View pending disclosure requests for the current user
    getMyRequests: async (accessToken: string) => {
      // Backend returns { request: {...}, target_did: "" }[] wrapper
      interface BackendRequestWithDetails {
        request: {
          id: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
        };
        target_did: string;
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendRequestWithDetails[]>(
        '/me/disclosure/requests'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureRequest[] = (response.data || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        target_did: item.target_did,
        requester_name: 'Compliance Request', // Backend doesn't track requester name
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.requested_at,
        valid_until: item.request.expires_at,
      }));

      return { ...response, data: transformedData };
    },

    // Approve a disclosure request
    approveRequest: (accessToken: string, requestId: string) =>
      createAuthenticatedClient(accessToken).post<ApproveDisclosureResponse>(
        `/me/disclosure/requests/${requestId}/approve`
      ),

    // Reject a disclosure request
    rejectRequest: (accessToken: string, requestId: string, input?: RejectDisclosureInput) =>
      createAuthenticatedClient(accessToken).post<DisclosureRequest>(
        `/me/disclosure/requests/${requestId}/reject`,
        input || {}
      ),

    // Revoke a previously approved grant
    revokeRequest: (accessToken: string, requestId: string, input?: RevokeDisclosureInput) =>
      createAuthenticatedClient(accessToken).post<DisclosureRequest>(
        `/me/disclosure/requests/${requestId}/revoke`,
        input || {}
      ),

    // View active grants on user's data
    getMyGrants: async (accessToken: string) => {
      // Backend returns GrantWithRequest[] wrapper
      interface BackendGrantWithRequest {
        grant: {
          id: string;
          request_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          granted_at: string;
          expires_at: string;
          revoked_at?: string;
          revoked_reason?: string;
        };
        request: {
          id: string;
          target_user_id: string;
          requester_did?: string;
          reason: string;
          legal_basis?: string;
          status: string;
        };
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendGrantWithRequest[]>(
        '/me/disclosure/grants'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureGrant[] = (response.data || []).map((item) => ({
        id: item.grant.id,
        request_id: item.grant.request_id,
        user_id: item.request.target_user_id,
        token_hash: '', // Not exposed to frontend
        scope: (item.grant.scope?.methods || []) as DisclosureGrant['scope'],
        disclosure_level: (item.grant.scope?.disclosure_level || 'pseudonymous') as DisclosureGrant['disclosure_level'],
        valid_from: item.grant.granted_at,
        valid_until: item.grant.expires_at,
        revoked_at: item.grant.revoked_at,
        revoke_reason: item.grant.revoked_reason,
        requester_did: item.request.requester_did,
        reason: item.request.reason,
        created_at: item.grant.granted_at,
        updated_at: item.grant.granted_at,
      }));

      return { ...response, data: transformedData };
    },

    // View all requests for the current user (not just pending)
    getAllMyRequests: async (accessToken: string) => {
      // Backend returns { request: {...}, target_did: "" }[] wrapper
      interface BackendRequestWithDetails {
        request: {
          id: string;
          target_user_id: string;
          org_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          reason: string;
          legal_basis?: string;
          status: string;
          requested_at: string;
          expires_at?: string;
          decided_at?: string;
          decided_by_user_id?: string;
          decision_reason?: string;
          requester_did?: string;
        };
        target_did: string;
        active_grant_id?: string;
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendRequestWithDetails[]>(
        '/me/disclosure/requests/all'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureRequest[] = (response.data || []).map((item) => ({
        id: item.request.id,
        user_id: item.request.target_user_id,
        target_did: item.target_did,
        requester_name: item.request.requester_did || 'Compliance Request',
        requester_did: item.request.requester_did,
        purpose: item.request.reason,
        scope: (item.request.scope?.methods || []) as DisclosureRequest['scope'],
        disclosure_level: (item.request.scope?.disclosure_level || 'pseudonymous') as DisclosureRequest['disclosure_level'],
        status: item.request.status as DisclosureRequest['status'],
        legal_basis: item.request.legal_basis,
        created_at: item.request.requested_at,
        updated_at: item.request.decided_at || item.request.requested_at,
        valid_until: item.request.expires_at,
        decided_at: item.request.decided_at,
        decision_reason: item.request.decision_reason,
        active_grant_id: item.active_grant_id,
      }));

      return { ...response, data: transformedData };
    },

    // View all grants on user's data (not just active)
    getAllMyGrants: async (accessToken: string) => {
      // Backend returns GrantWithRequest[] wrapper
      interface BackendGrantWithRequest {
        grant: {
          id: string;
          request_id: string;
          scope: { methods?: string[]; addresses?: string[]; disclosure_level?: string };
          granted_at: string;
          expires_at: string;
          revoked_at?: string;
          revoked_reason?: string;
        };
        request: {
          id: string;
          target_user_id: string;
          requester_did?: string;
          reason: string;
          legal_basis?: string;
          status: string;
        };
      }

      const response = await createAuthenticatedClient(accessToken).get<BackendGrantWithRequest[]>(
        '/me/disclosure/grants/all'
      );

      // Transform backend response to frontend format
      const transformedData: DisclosureGrant[] = (response.data || []).map((item) => ({
        id: item.grant.id,
        request_id: item.grant.request_id,
        user_id: item.request.target_user_id,
        token_hash: '', // Not exposed to frontend
        scope: (item.grant.scope?.methods || []) as DisclosureGrant['scope'],
        disclosure_level: (item.grant.scope?.disclosure_level || 'pseudonymous') as DisclosureGrant['disclosure_level'],
        valid_from: item.grant.granted_at,
        valid_until: item.grant.expires_at,
        revoked_at: item.grant.revoked_at,
        revoke_reason: item.grant.revoked_reason,
        requester_did: item.request.requester_did,
        reason: item.request.reason,
        created_at: item.grant.granted_at,
        updated_at: item.grant.granted_at,
      }));

      return { ...response, data: transformedData };
    },
  },
};

export default disclosureApi;
