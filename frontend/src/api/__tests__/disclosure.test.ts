/**
 * Frontend → backend contract tests for disclosureApi.
 *
 * These tests capture the exact JSON body produced by disclosureApi.admin.createRequest
 * and assert that it carries the fields the Go backend's createDisclosureRequest
 * handler requires under JWT-admin authorization — most importantly `org_id`.
 *
 * Why this matters: a frontend bug that silently dropped org_id from the body
 * shipped to production and broke disclosure-create for every tier-2 admin not
 * scoped to the system default org. The Go handler-level tests
 * (TestRD944_CreateRequest_JWTAdmin_*) prove the backend behaves correctly for
 * every payload shape; these tests prove the frontend ASSEMBLES the payload
 * shape the backend expects. The combination is what catches FE/BE drift.
 *
 * Scope: this file intentionally tests the API adapter directly (no React
 * component rendering, no playwright). End-to-end click flows live in
 * e2e/playwright; this is the cheaper layer that fails fast on contract drift.
 */

import { describe, it, expect } from 'vitest';
import { http, HttpResponse } from 'msw';
import { server } from '@/test/mocks/server';
import { disclosureApi } from '../disclosure';
import type { CreateDisclosureRequestInput } from '@/types/disclosure';

interface CapturedBody {
  target_user_id?: unknown;
  org_id?: unknown;
  reason?: unknown;
  legal_basis?: unknown;
  requester_did?: unknown;
  scope?: {
    methods?: unknown;
    disclosure_level?: unknown;
  };
  expires_in_hours?: unknown;
  [key: string]: unknown;
}

// captureCreateRequest installs an MSW handler that intercepts the
// disclosure-create POST, records the JSON body, and returns a minimal
// valid response so the FE Promise resolves cleanly.
function captureCreateRequest(): { read: () => CapturedBody | undefined } {
  let captured: CapturedBody | undefined;
  server.use(
    http.post('/api/v1/admin/disclosure/requests', async ({ request }) => {
      captured = (await request.json()) as CapturedBody;
      return HttpResponse.json(
        {
          id: 'req-test-1',
          target_user_id: (captured.target_user_id as string) ?? '',
          org_id: (captured.org_id as string) ?? '',
          scope: { methods: [], disclosure_level: 'pseudonymous' },
          reason: (captured.reason as string) ?? '',
          status: 'pending',
          requested_at: '2026-01-01T00:00:00Z',
        },
        { status: 201 }
      );
    })
  );
  return { read: () => captured };
}

const baseInput: CreateDisclosureRequestInput = {
  user_external_id: 'user-uuid-from-dropdown',
  requester_name: 'SEC',
  requester_did: 'did:test:eve',
  purpose: 'AUDIT',
  scope: ['eth_call'],
  disclosure_level: 'pseudonymous',
  legal_basis: 'Court #1213',
};

describe('disclosureApi.admin.createRequest — backend payload contract', () => {
  it('forwards org_id at the top level of the POST body', async () => {
    const capture = captureCreateRequest();

    await disclosureApi.admin.createRequest({
      ...baseInput,
      org_id: '2cfff951-e780-44c5-bf39-0d338df82267',
    });

    const body = capture.read();
    expect(body).toBeDefined();
    expect(body?.org_id).toBe('2cfff951-e780-44c5-bf39-0d338df82267');
  });

  it('omits org_id from the body when caller does not supply one (super-admin / dev-mode path)', async () => {
    // The backend defaults to the system default org in this case (see
    // disclosure.go ~line 192). The FE adapter must NOT inject a stub —
    // dropping org_id is how callers without an org filter (super-admin,
    // dev-mode) get the default-org fallback they expect.
    const capture = captureCreateRequest();

    await disclosureApi.admin.createRequest({ ...baseInput });

    const body = capture.read();
    expect(body).toBeDefined();
    expect(body?.org_id).toBeUndefined();
  });

  it('keeps the other backend-required fields (target_user_id, reason, scope)', async () => {
    const capture = captureCreateRequest();

    await disclosureApi.admin.createRequest({
      ...baseInput,
      org_id: 'org-A',
    });

    const body = capture.read();
    expect(body?.target_user_id).toBe('user-uuid-from-dropdown'); // FE.user_external_id → BE.target_user_id
    expect(body?.reason).toBe('AUDIT'); // FE.purpose → BE.reason
    expect(body?.legal_basis).toBe('Court #1213');
    expect(body?.requester_did).toBe('did:test:eve');
    expect(body?.scope).toEqual({
      methods: ['eth_call'],
      disclosure_level: 'pseudonymous',
    });
  });
});

/**
 * RD-1071: the backend RequestWithDetails wrapper returns `target_did`
 * alongside each request, but the FE transforms used to drop it and surface
 * only the opaque internal user UUID. These tests pin that the transforms now
 * carry `target_did` onto the DisclosureRequest while keeping `user_id` (the
 * internal UUID) for ops/support.
 */
describe('disclosureApi — target_did carried onto DisclosureRequest (RD-1071)', () => {
  const TARGET_UUID = 'a4c5e984-45d1-4188-8c90-71046d44a848';
  const wrapper = (targetDid: string) => ({
    request: {
      id: 'req-1',
      target_user_id: TARGET_UUID,
      org_id: 'org-1',
      scope: { methods: ['eth_call'], disclosure_level: 'pseudonymous' },
      reason: 'AUDIT',
      status: 'pending',
      requested_at: '2026-01-01T00:00:00Z',
    },
    target_did: targetDid,
  });

  it('admin.listRequests maps target_did and keeps user_id as the UUID', async () => {
    server.use(
      http.get('/api/v1/admin/disclosure/requests', () =>
        HttpResponse.json([wrapper('did:test:eve')])
      )
    );

    const res = await disclosureApi.admin.listRequests();
    expect(res.data[0].target_did).toBe('did:test:eve');
    expect(res.data[0].user_id).toBe(TARGET_UUID);
  });

  it('admin.listRequestsWithFilter maps target_did onto each request', async () => {
    server.use(
      http.get('/api/v1/admin/disclosure/requests', () =>
        HttpResponse.json({ requests: [wrapper('did:test:eve')], total: 1, limit: 50, offset: 0 })
      )
    );

    const res = await disclosureApi.admin.listRequestsWithFilter({ org_id: 'org-1' });
    expect(res.data.requests[0].target_did).toBe('did:test:eve');
    expect(res.data.requests[0].user_id).toBe(TARGET_UUID);
  });

  it('user.getAllMyRequests maps target_did', async () => {
    server.use(
      http.get('/api/v1/me/disclosure/requests/all', () =>
        HttpResponse.json([wrapper('did:test:dave')])
      )
    );

    const res = await disclosureApi.user.getAllMyRequests('test-token');
    expect(res.data[0].target_did).toBe('did:test:dave');
    expect(res.data[0].user_id).toBe(TARGET_UUID);
  });
});
