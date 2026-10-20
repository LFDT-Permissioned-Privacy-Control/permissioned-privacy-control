import { APIRequestContext } from '@playwright/test';

const ADMIN_URL = process.env.ADMIN_URL || process.env.PROXY_URL || 'http://localhost:8080';
const ADMIN_TOKEN = process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token';

// === Types ===

// Claims: read, write, admin, upgrade, deploy
export type Claim = 'read' | 'write' | 'admin' | 'upgrade' | 'deploy';

export type MembershipSource = 'admin' | 'zk_attested';

export interface Organization {
  id: string;
  slug: string;
  name: string;
  settings: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface Group {
  id: string;
  org_id: string;
  parent_id: string | null;
  slug: string;
  name: string;
  description: string;
  depth: number;
  path: string;
  auto_created?: boolean;
  created_at: string;
  updated_at: string;
}

// GroupAccess - RPC method permissions and rate limits for a group (replaces old GroupPermissions)
export interface GroupAccess {
  id: string;
  group_id: string;
  allowed_methods: string[];
  claims: Claim[];
  rate_limit_rps: number | null;
  rate_limit_daily: number | null;
  created_at: string;
  updated_at: string;
}

export interface User {
  id: string;
  external_id: string;
  kyc: boolean;
  banned: boolean;
  note: string;
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface LinkedAddress {
  address: string;
  verified_at: string;
  ens_name?: string;
  ens_resolved_at?: string;
}

export interface UserMembership {
  id: string;
  user_id: string;
  group_id: string;
  source: MembershipSource;
  zk_credential_ref: string;
  expires_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface MembershipWithDetails {
  membership: UserMembership;
  group: Group;
}

// Contract - first-class resource (replaces old ContractOwnership)
export interface Contract {
  id: string;
  org_id: string;
  address?: string; // new format
  contract_address?: string; // legacy format - deprecated
  name?: string;
  abi?: string; // Contract ABI JSON for function-level access control
  deployed_by_user_id?: string | null;
  deployed_at?: string | null;
  owner_group_id?: string; // legacy format - deprecated
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

// Helper to get contract address from either format
export function getContractAddress(contract: Contract): string {
  return contract.address || contract.contract_address || '';
}

// FunctionRule - structured function selector with optional parameter constraints
export interface FunctionRule {
  selector: string;
  param_rules?: ParamRule[];
}

// ParamRule - constrains a single ABI parameter of a function call
export interface ParamRule {
  index: number;
  must_be: string; // "self" for now
}

// EventRule - describes visibility of a single contract event with optional parameter constraints
export interface EventRule {
  topic0: string;    // keccak256(EventName(paramTypes)) — 32-byte hex with 0x prefix
  name: string;      // human-readable event name, from ABI
  param_rules?: ParamRule[] | null;
}

// EventSignature returned by GET /orgs/:org_id/contracts/:address/events
export interface EventSignature {
  name: string;        // e.g. "Transfer"
  signature: string;   // e.g. "Transfer(address,address,uint256)"
  topic0: string;      // keccak256 of signature, hex-encoded with 0x prefix
  inputs: EventInput[];
}

// EventInput describes one parameter of an event
export interface EventInput {
  name: string;
  type: string;    // ABI type string (e.g. "address", "uint256")
  indexed: boolean;
}

// ContractGrant - links groups to contracts (claims are inherited from GroupAccess)
export interface ContractGrant {
  id: string;
  contract_id: string;
  group_id: string;
  functions?: FunctionRule[] | null; // null = all functions, or structured rules
  event_rules?: EventRule[] | null;  // null = all events visible, or allowlist
  created_at: string;
  updated_at: string;
}

// ContractAccess - per-contract permissions in EffectivePermissions
export interface ContractAccess {
  claims: Claim[];
  functions?: FunctionRule[] | null;
}

// Helper to extract selector strings from FunctionRule arrays (for assertions)
export function selectorsOf(functions: FunctionRule[] | null | undefined): string[] | null {
  if (functions == null) return null;
  return functions.map((f) => f.selector);
}

export interface EffectivePermissions {
  id: string;
  user_id: string;
  org_id: string;
  allowed_methods: string[];
  contract_access: Record<string, ContractAccess>; // address -> access
  claims: Claim[];
  rate_limit_rps: number | null;
  rate_limit_daily: number | null;
  computed_at: string;
  expires_at: string;
}

export interface AccessCheckRequest {
  user_external_id: string;
  org_slug?: string;
  method: string;
  target_address?: string;
  function_selector?: string; // First 4 bytes of calldata (e.g., "0xa9059cbb")
  required_claims?: Claim[];
}

export interface AccessCheckResult {
  allowed: boolean;
  reason?: string;
  rate_limit_rps?: number;
  rate_limit_daily?: number;
  claims?: Claim[];
}

export interface CacheStats {
  entries: number;
  expired_pending: number;
  max_entries: number;
}

// === Input Types ===

export interface CreateOrgInput {
  slug: string;
  name: string;
  settings?: Record<string, unknown>;
}

export interface UpdateOrgInput {
  slug?: string;
  name?: string;
  settings?: Record<string, unknown>;
}

export interface CreateGroupInput {
  slug: string;
  name: string;
  description?: string;
  parent_id?: string;
  auto_created?: boolean;
  is_org_admin?: boolean;
  is_org_readonly_admin?: boolean;
}

export interface UpdateGroupInput {
  name?: string;
  description?: string;
  auto_created?: boolean;
  is_org_admin?: boolean;
  is_org_readonly_admin?: boolean;
}

export interface SetGroupAccessInput {
  allowed_methods?: string[];
  claims?: Claim[];
  rate_limit_rps?: number;
  rate_limit_daily?: number;
}

export interface UpdateUserInput {
  kyc?: boolean;
  banned?: boolean;
  note?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateMembershipInput {
  group_id: string;
}

export interface CreateContractInput {
  address: string;
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface UpdateContractInput {
  name?: string;
  metadata?: Record<string, unknown>;
}

export interface CreateContractGrantInput {
  group_id: string;
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | null;
}

export interface UpdateContractGrantInput {
  functions?: FunctionRule[] | null;
  event_rules?: EventRule[] | null;
}

// Shorthand: convert a selector string to a FunctionRule with no param constraints.
export function fn(selector: string): FunctionRule {
  return { selector };
}

// Shorthand: convert an array of selector strings to FunctionRule[].
export function fns(...selectors: string[]): FunctionRule[] {
  return selectors.map((s) => ({ selector: s }));
}

// === API Client ===

export class RBACApiClient {
  // RD-1107: when authToken is set, calls authenticate as that org-admin
  // (Authorization: Bearer) instead of the super-admin token — the super-admin
  // token can no longer perform per-org tenant management. Bootstrap/global
  // operations keep using a super-admin client (authToken undefined).
  constructor(
    private request: APIRequestContext,
    private authToken?: string,
  ) {}

  // Auth headers: org-admin JWT when set, else the super-admin token.
  private get adminHeaders(): Record<string, string> {
    return this.authToken
      ? { 'Content-Type': 'application/json', Authorization: `Bearer ${this.authToken}` }
      : { 'Content-Type': 'application/json', 'X-Admin-Token': ADMIN_TOKEN };
  }

  /** Returns a clone of this client that authenticates as the given org-admin JWT. */
  asOrgAdmin(token: string): RBACApiClient {
    return new RBACApiClient(this.request, token);
  }

  // Helper: GET with admin auth headers
  private get(url: string) {
    return this.request.get(url, { headers: this.adminHeaders });
  }

  // Helper: DELETE with admin auth headers
  private del(url: string) {
    return this.request.delete(url, { headers: this.adminHeaders });
  }

  // === Organizations ===

  async listOrganizations(limit = 1000, offset = 0): Promise<Organization[]> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/orgs?limit=${limit}&offset=${offset}`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list organizations: ${response.status()} - ${body}`);
    }
    const body = (await response.json()) as { data: Organization[] };
    return body.data ?? [];
  }

  async createOrganization(input: CreateOrgInput): Promise<Organization> {
    const response = await this.request.post(`${ADMIN_URL}/api/v1/admin/orgs`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  async getOrganization(orgId: string): Promise<Organization | null> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}`);
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  async updateOrganization(orgId: string, input: UpdateOrgInput): Promise<Organization> {
    const response = await this.request.put(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update organization: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Organization;
  }

  async deleteOrganization(orgId: string): Promise<void> {
    const response = await this.del(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}`);
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete organization: ${response.status()} - ${body}`);
    }
  }

  // === Groups ===

  async listGroups(orgId: string): Promise<Group[]> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list groups: ${response.status()} - ${body}`);
    }
    const body = (await response.json()) as { data: Array<{ group: Group; access: GroupAccess | null }> };
    return (body.data ?? []).map(item => item.group);
  }

  async createGroup(orgId: string, input: CreateGroupInput): Promise<Group> {
    const response = await this.request.post(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async getGroup(orgId: string, groupId: string): Promise<Group | null> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/${groupId}`);
    // 404 is the historical "not found" shape; 403 with the opaque
    // "access denied to target resource" body is the post-RD-916/917 shape —
    // both map to null here so callers can do "find or null" without caring
    // about the wire-level distinction. The opaque-deny design intentionally
    // collapses "exists in another org" and "does not exist" into one
    // indistinguishable response (see admin_scope.go:errTargetForeignOrg).
    if (response.status() === 404 || response.status() === 403) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async updateGroup(orgId: string, groupId: string, input: UpdateGroupInput): Promise<Group> {
    const response = await this.request.put(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/${groupId}`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update group: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Group;
  }

  async deleteGroup(orgId: string, groupId: string): Promise<void> {
    const response = await this.del(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/${groupId}`);
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete group: ${response.status()} - ${body}`);
    }
  }

  async getGroupAccess(orgId: string, groupId: string): Promise<GroupAccess | null> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/${groupId}/access`
    );
    // See getGroup() comment — 403 maps to null (opaque-deny shape).
    if (response.status() === 404 || response.status() === 403) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get group access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupAccess;
  }

  async setGroupAccess(
    orgId: string,
    groupId: string,
    input: SetGroupAccessInput
  ): Promise<GroupAccess> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/${groupId}/access`,
      {
        headers: this.adminHeaders,
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to set group access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as GroupAccess;
  }

  // === Users ===

  async listUsers(limit = 100, offset = 0): Promise<User[]> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/users?limit=${limit}&offset=${offset}`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list users: ${response.status()} - ${body}`);
    }
    const body = (await response.json()) as { data: User[] };
    return body.data ?? [];
  }

  async getUser(userId: string): Promise<User | null> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/users/${userId}`);
    // See getGroup() comment — 403 is the opaque-deny shape that collapses
    // "not found" and "cross-org" into a single response.
    if (response.status() === 404 || response.status() === 403) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get user: ${response.status()} - ${body}`);
    }
    return (await response.json()) as User;
  }

  async updateUser(userId: string, input: UpdateUserInput): Promise<User> {
    const response = await this.request.put(`${ADMIN_URL}/api/v1/admin/users/${userId}`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update user: ${response.status()} - ${body}`);
    }
    return (await response.json()) as User;
  }

  async findUserByExternalId(externalId: string): Promise<User | null> {
    const users = await this.listUsers(1000);
    return users.find((u) => u.external_id === externalId) ?? null;
  }

  // === Linked Addresses ===

  async getUserLinkedAddresses(userId: string): Promise<LinkedAddress[]> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/users/${userId}/linked-addresses`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get user linked addresses: ${response.status()} - ${body}`);
    }
    const data = (await response.json()) as { addresses: LinkedAddress[] };
    // Verify the response has the expected structure
    if (!data.addresses || !Array.isArray(data.addresses)) {
      throw new Error(`Invalid linked addresses response format: expected {addresses: [...]}, got ${JSON.stringify(data)}`);
    }
    return data.addresses;
  }

  // === Memberships ===

  async listUserMemberships(userId: string): Promise<MembershipWithDetails[]> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/users/${userId}/memberships`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list user memberships: ${response.status()} - ${body}`);
    }
    const memberships = (await response.json()) as MembershipWithDetails[] | null;
    return memberships ?? [];
  }

  async createMembership(userId: string, input: CreateMembershipInput): Promise<UserMembership> {
    const response = await this.request.post(`${ADMIN_URL}/api/v1/admin/users/${userId}/memberships`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create membership: ${response.status()} - ${body}`);
    }
    return (await response.json()) as UserMembership;
  }

  async deleteMembership(userId: string, membershipId: string): Promise<void> {
    const response = await this.del(
      `${ADMIN_URL}/api/v1/admin/users/${userId}/memberships/${membershipId}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete membership: ${response.status()} - ${body}`);
    }
  }

  // === Contracts ===

  async listContracts(orgId: string): Promise<Contract[]> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contracts: ${response.status()} - ${body}`);
    }
    const body = (await response.json()) as { data: Contract[] };
    return body.data ?? [];
  }

  async createContract(orgId: string, input: CreateContractInput): Promise<Contract> {
    const response = await this.request.post(`${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts`, {
      headers: this.adminHeaders,
      data: input,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async updateContract(
    orgId: string,
    address: string,
    input: UpdateContractInput
  ): Promise<Contract> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}`,
      {
        headers: this.adminHeaders,
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async deleteContract(orgId: string, address: string): Promise<void> {
    const response = await this.del(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete contract: ${response.status()} - ${body}`);
    }
  }

  async getContract(orgId: string, address: string): Promise<Contract | null> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}`
    );
    if (response.status() === 404) {
      return null;
    }
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get contract: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async updateContractABI(orgId: string, address: string, abi: string): Promise<Contract> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/abi`,
      {
        headers: this.adminHeaders,
        data: { abi },
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract ABI: ${response.status()} - ${body}`);
    }
    return (await response.json()) as Contract;
  }

  async listContractEvents(orgId: string, address: string): Promise<EventSignature[]> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/events`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contract events: ${response.status()} - ${body}`);
    }
    const body = (await response.json()) as { events: EventSignature[] };
    return body.events ?? [];
  }

  // === Contract Grants ===

  async listContractGrants(orgId: string, address: string): Promise<ContractGrant[]> {
    const response = await this.get(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/grants`
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to list contract grants: ${response.status()} - ${body}`);
    }
    const grants = (await response.json()) as ContractGrant[] | null;
    return grants ?? [];
  }

  async createContractGrant(
    orgId: string,
    address: string,
    input: CreateContractGrantInput
  ): Promise<ContractGrant> {
    const response = await this.request.post(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/grants`,
      {
        headers: this.adminHeaders,
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to create contract grant: ${response.status()} - ${body}`);
    }
    return (await response.json()) as ContractGrant;
  }

  async updateContractGrant(
    orgId: string,
    address: string,
    groupId: string,
    input: UpdateContractGrantInput
  ): Promise<ContractGrant> {
    const response = await this.request.put(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/grants/${groupId}`,
      {
        headers: this.adminHeaders,
        data: input,
      }
    );
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to update contract grant: ${response.status()} - ${body}`);
    }
    return (await response.json()) as ContractGrant;
  }

  async deleteContractGrant(orgId: string, address: string, groupId: string): Promise<void> {
    const response = await this.del(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/${address}/grants/${groupId}`
    );
    if (!response.ok() && response.status() !== 404) {
      const body = await response.text();
      throw new Error(`Failed to delete contract grant: ${response.status()} - ${body}`);
    }
  }

  // === Access Control ===

  async checkAccess(req: AccessCheckRequest): Promise<AccessCheckResult> {
    const response = await this.request.post(`${ADMIN_URL}/api/v1/admin/access/check`, {
      headers: this.adminHeaders,
      data: req,
    });
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to check access: ${response.status()} - ${body}`);
    }
    return (await response.json()) as AccessCheckResult;
  }

  async getEffectivePermissions(userId: string, orgSlug?: string): Promise<EffectivePermissions> {
    const url = orgSlug
      ? `${ADMIN_URL}/api/v1/admin/users/${userId}/effective-permissions?org=${orgSlug}`
      : `${ADMIN_URL}/api/v1/admin/users/${userId}/effective-permissions`;
    const response = await this.get(url);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get effective permissions: ${response.status()} - ${body}`);
    }
    return (await response.json()) as EffectivePermissions;
  }

  async getCacheStats(): Promise<CacheStats> {
    const response = await this.get(`${ADMIN_URL}/api/v1/admin/cache/stats`);
    if (!response.ok()) {
      const body = await response.text();
      throw new Error(`Failed to get cache stats: ${response.status()} - ${body}`);
    }
    return (await response.json()) as CacheStats;
  }

  // === Batch Operations ===

  async batchMoveContracts(orgId: string, body: {
    contract_ids: string[];
    target_group_id?: string;
    new_group?: { slug: string; name: string };
    delete_empty_auto_groups?: boolean;
  }): Promise<{ target_group_id: string; moved_count: number; deleted_group_ids?: string[] }> {
    const response = await this.request.post(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/contracts/batch-move`,
      { headers: this.adminHeaders, data: body }
    );
    if (!response.ok()) {
      const text = await response.text();
      throw new Error(`Failed to batch move contracts: ${response.status()} - ${text}`);
    }
    return (await response.json()) as any;
  }

  async batchDeleteGroups(orgId: string, groupIds: string[]): Promise<{ deleted_count: number }> {
    const response = await this.request.post(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/batch-delete`,
      { headers: this.adminHeaders, data: { group_ids: groupIds } }
    );
    if (!response.ok()) {
      const text = await response.text();
      throw new Error(`Failed to batch delete groups: ${response.status()} - ${text}`);
    }
    return (await response.json()) as any;
  }

  async batchDeletePreview(orgId: string, groupIds: string[]): Promise<{
    groups: Array<{
      id: string; name: string; slug: string; auto_created: boolean;
      contract_count: number; member_count: number; contracts: string[];
    }>;
  }> {
    const response = await this.request.post(
      `${ADMIN_URL}/api/v1/admin/orgs/${orgId}/groups/batch-delete-preview`,
      { headers: this.adminHeaders, data: { group_ids: groupIds } }
    );
    if (!response.ok()) {
      const text = await response.text();
      throw new Error(`Failed to batch delete preview: ${response.status()} - ${text}`);
    }
    return (await response.json()) as any;
  }
}
