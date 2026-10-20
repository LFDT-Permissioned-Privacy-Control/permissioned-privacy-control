import { randomUUID } from 'crypto';
import { APIRequestContext } from '@playwright/test';
import {
  RBACApiClient,
  Organization,
  Group,
  User,
  UserMembership,
  Contract,
  Claim,
} from './rbac-api.js';
import { getJWTToken } from './auth.js';

// Lazy lookup so API-only specs that don't go through ui/auth-helpers still
// load this fixture cleanly. Returns null when no UI mock-login has run.
async function tryGetMockAdminDID(): Promise<string | null> {
  try {
    const m = await import('./ui/auth-helpers.js');
    return m.getCurrentMockAdminDID?.() ?? null;
  } catch {
    return null;
  }
}

// RD-1107 companion to tryGetMockAdminDID: the mock admin's access token, so
// the fixture can perform per-org mutations as that org-admin (the super-admin
// token can no longer manage per-org tenant data).
async function tryGetMockAdminToken(): Promise<string | null> {
  try {
    const m = await import('./ui/auth-helpers.js');
    return m.getCurrentMockAdminToken?.() ?? null;
  } catch {
    return null;
  }
}

/**
 * Hierarchy definition for creating nested group structures.
 */
export interface HierarchyNode {
  slug: string;
  name: string;
  access?: {
    allowed_methods?: string[];
    claims?: Claim[];
    rate_limit_rps?: number;
    rate_limit_daily?: number;
  };
  children?: HierarchyNode[];
}

/**
 * Options for creating a user with membership.
 */
export interface CreateUserOptions {
  kyc?: boolean;
  banned?: boolean;
  /**
   * If true, keep the user's default membership to the default group.
   * By default, the default membership is removed so that only the custom membership applies.
   * Set to true when testing multiple memberships behavior.
   */
  keepDefaultMembership?: boolean;
}

const DEFAULT_GROUP_ID = '00000000-0000-0000-0000-000000000001';

/**
 * RBACTestFixture provides test data factories with automatic cleanup.
 * Each test should create its own fixture instance to ensure isolation.
 *
 * RD-1107: the super-admin token (X-Admin-Token) may only perform platform /
 * bootstrap operations — create orgs, mint is_org_admin groups, and manage the
 * system default org/group. Per-org tenant management (regular groups, group
 * access, contracts, grants, regular memberships) is the org admin's job and
 * must go through an org-admin JWT. This fixture therefore keeps two clients:
 *   - `sa`   — super-admin (X-Admin-Token), for bootstrap/global ops.
 *   - `rbac` — org-admin (Bearer JWT) once an org exists, for per-org ops.
 * The JWT is the mock admin set up by mockLoginViaAPI; createOrg makes that
 * user is_org_admin in every org it creates, so one JWT works across them.
 */
export class RBACTestFixture {
  readonly testId: string;
  /** Per-org client used by specs for per-org mutations (JWT once an org exists). */
  rbac: RBACApiClient;
  /** Super-admin client for bootstrap/global ops (org + is_org_admin group + default org). */
  private sa: RBACApiClient;
  private request: APIRequestContext;
  private orgAdminToken: string | null = null;

  // Tracked resources for cleanup. viaSuper marks resources whose deletion
  // must use the super-admin client (is_org_admin groups / their memberships /
  // orgs); the rest are deleted as the org admin (JWT).
  private orgs: Organization[] = [];
  private groups: { orgId: string; group: Group; viaSuper: boolean }[] = [];
  private users: User[] = [];
  private memberships: { userId: string; membership: UserMembership; viaSuper: boolean }[] = [];
  private contracts: { orgId: string; address: string }[] = [];

  constructor(request: APIRequestContext) {
    this.testId = randomUUID().slice(0, 8);
    this.request = request;
    this.sa = new RBACApiClient(request);
    // Starts as super-admin; swapped to the org-admin JWT on first createOrg.
    this.rbac = this.sa;
  }

  // Resolve the mock-admin JWT (once) and switch `rbac` to an org-admin client.
  // No-op when there is no mock admin (e.g. pure-API specs) — `rbac` then stays
  // super-admin and per-org mutations would be rejected, which no spec does.
  private async ensureOrgAdminClient(): Promise<void> {
    if (this.orgAdminToken) return;
    const token = await tryGetMockAdminToken();
    if (token) {
      this.orgAdminToken = token;
      this.rbac = this.sa.asOrgAdmin(token);
    }
  }

  /**
   * Generate a unique slug for test isolation.
   * Uses only lowercase + digits + hyphens so the slug also passes the
   * frontend OrganizationForm pattern `^[a-z0-9]+(-[a-z0-9]+)*$`.
   */
  slug(base: string): string {
    return `${base}-${this.testId}`;
  }

  /**
   * Generate a unique DID for test isolation.
   */
  did(): string {
    const uniquePart = randomUUID().slice(0, 8);
    return `did:privado:test_${this.testId}_${uniquePart}`;
  }

  /**
   * Generate a unique Ethereum address for test isolation.
   * Ethereum addresses are 40 hex characters (20 bytes) after the 0x prefix.
   */
  contractAddress(): string {
    // UUID is only 32 hex chars, so combine two UUIDs and take 40 chars
    const hex1 = randomUUID().replace(/-/g, '');
    const hex2 = randomUUID().replace(/-/g, '');
    const bytes = (hex1 + hex2).slice(0, 40);
    return `0x${bytes}`;
  }

  // === Organization Methods ===

  /**
   * Create an organization and track for cleanup.
   */
  async createOrg(slugBase: string, name?: string): Promise<Organization> {
    const orgSlug = this.slug(slugBase);
    // Org lifecycle is a super-admin (platform) operation.
    const org = await this.sa.createOrganization({
      slug: orgSlug,
      name: name ?? `Test Org ${orgSlug}`,
    });
    this.orgs.push(org);

    // If a UI test has logged in via mockLoginViaAPI, grant that user tier-2
    // admin in this newly-created org. The admin-auth middleware gates
    // /api/v1/admin/orgs/:org_id/* on the JWT user being is_org_admin in the
    // requested org. Minting an is_org_admin group + adding the member are
    // super-admin operations (RD-1107). This is also what lets `rbac` (the
    // org-admin JWT) perform the per-org mutations below.
    try {
      const adminDid = await tryGetMockAdminDID();
      if (adminDid) {
        const users = await this.sa.listUsers(1000);
        const u = users.find((x) => x.external_id === adminDid);
        if (u) {
          const adminGroup = await this.sa.createGroup(org.id, {
            slug: this.slug('mock-admin'),
            name: 'E2E_HIDDEN_MOCK_ADMIN',
            is_org_admin: true,
          });
          this.groups.push({ orgId: org.id, group: adminGroup, viaSuper: true });
          const m = await this.sa.createMembership(u.id, { group_id: adminGroup.id });
          this.memberships.push({ userId: u.id, membership: m, viaSuper: true });
        }
      }
    } catch {
      // Best-effort: API-only tests don't import the UI helpers and should
      // continue to work. Failures here are non-fatal.
    }

    // Now that the mock admin is is_org_admin in this org, route per-org
    // mutations through their JWT.
    await this.ensureOrgAdminClient();

    return org;
  }

  /**
   * Create an organization and automatically assign the test user (by DID) as an org admin.
   */
  async createOrgWithAdmin(slugBase: string, userDid: string, name?: string): Promise<Organization> {
    const org = await this.createOrg(slugBase, name);

    // Find user (global lookup → super-admin)
    const users = await this.sa.listUsers(1000);
    const user = users.find((u) => u.external_id === userDid);
    if (!user) throw new Error(`User with DID ${userDid} not found`);

    // Create admin group + membership (minting an org admin → super-admin).
    const groupSlug = this.slug('admin');
    const group = await this.sa.createGroup(org.id, {
      slug: groupSlug,
      name: `E2E_HIDDEN_ADMIN`,
      is_org_admin: true,
    });
    this.groups.push({ orgId: org.id, group, viaSuper: true });

    const membership = await this.sa.createMembership(user.id, { group_id: group.id });
    this.memberships.push({ userId: user.id, membership, viaSuper: true });

    return org;
  }

  // === Group Methods ===

  /**
   * Create a (regular) group and track for cleanup. Per-org → org-admin JWT.
   */
  async createGroup(orgId: string, slugBase: string, opts?: {
    name?: string;
    description?: string;
    parentId?: string;
  }): Promise<Group> {
    const groupSlug = this.slug(slugBase);
    const group = await this.rbac.createGroup(orgId, {
      slug: groupSlug,
      name: opts?.name ?? `Test Group ${groupSlug}`,
      description: opts?.description ?? '',
      parent_id: opts?.parentId,
    });
    this.groups.push({ orgId, group, viaSuper: false });
    return group;
  }

  /**
   * Create an auto-created group (like those generated by deployer auto-grants).
   */
  async createAutoGroup(orgId: string, slugBase: string, opts?: {
    name?: string;
  }): Promise<Group> {
    const groupSlug = this.slug(slugBase);
    const group = await this.rbac.createGroup(orgId, {
      slug: groupSlug,
      name: opts?.name ?? `Auto Deploy ${groupSlug}`,
    });
    // auto_created is not accepted on create — set via update
    await this.rbac.updateGroup(orgId, group.id, { auto_created: true } as any);
    group.auto_created = true;
    this.groups.push({ orgId, group, viaSuper: false });
    return group;
  }

  /**
   * Create a complete group hierarchy from a tree definition.
   * Returns a map from slug to Group for easy access.
   */
  async createGroupHierarchy(orgId: string, nodes: HierarchyNode[]): Promise<Map<string, Group>> {
    const result = new Map<string, Group>();

    const createNode = async (node: HierarchyNode, parentId?: string): Promise<void> => {
      const group = await this.createGroup(orgId, node.slug, {
        name: node.name,
        parentId,
      });
      result.set(node.slug, group);

      // Set access settings if provided (per-org → org-admin JWT)
      if (node.access) {
        await this.rbac.setGroupAccess(orgId, group.id, node.access);
      }

      // Recursively create children
      if (node.children) {
        for (const child of node.children) {
          await createNode(child, group.id);
        }
      }
    };

    for (const node of nodes) {
      await createNode(node);
    }

    return result;
  }

  // === User Methods ===

  /**
   * Create a user by authenticating them (which creates the user via EnsureUserExists).
   * Returns the user after it's been created in the system.
   */
  async createUser(request: APIRequestContext, opts?: { kyc?: boolean; banned?: boolean }): Promise<{
    user: User;
    did: string;
    token: string;
  }> {
    const userDID = this.did();

    // Authenticate to create the user via EnsureUserExists
    const token = await getJWTToken(request, userDID);

    // Find the created user (global lookup → super-admin)
    const user = await this.sa.findUserByExternalId(userDID);
    if (!user) {
      throw new Error(`User not found after auth: ${userDID}`);
    }

    this.users.push(user);

    // Update KYC and banned status if specified. KYC/ban are global user
    // flags (not gated by RD-1107); keep on the super-admin client.
    if (opts?.kyc !== undefined || opts?.banned !== undefined) {
      const updated = await this.sa.updateUser(user.id, {
        kyc: opts?.kyc,
        banned: opts?.banned,
      });
      return { user: updated, did: userDID, token };
    }

    return { user, did: userDID, token };
  }

  /**
   * Create a user with a membership to a specific group.
   * By default, removes the auto-created default membership so only the custom group applies.
   */
  async createUserWithMembership(
    request: APIRequestContext,
    groupId: string,
    opts?: CreateUserOptions
  ): Promise<{
    user: User;
    did: string;
    token: string;
    membership: UserMembership;
  }> {
    const { user, did, token } = await this.createUser(request, {
      kyc: opts?.kyc ?? true,
      banned: opts?.banned ?? false,
    });

    // Remove default membership unless explicitly kept. The default group is
    // system infrastructure in the default org — removing the membership is a
    // super-admin op (RD-1107 exempts the default org/group).
    if (!opts?.keepDefaultMembership) {
      const memberships = await this.sa.listUserMemberships(user.id);
      for (const m of memberships) {
        if (m.membership.group_id === DEFAULT_GROUP_ID) {
          await this.sa.deleteMembership(user.id, m.membership.id);
        }
      }
    }

    // Create membership in the (regular) test group → org-admin JWT.
    const membership = await this.rbac.createMembership(user.id, {
      group_id: groupId,
    });
    this.memberships.push({ userId: user.id, membership, viaSuper: false });

    return { user, did, token, membership };
  }

  /**
   * Add an additional membership for an existing user (regular group → JWT).
   */
  async addMembership(
    userId: string,
    groupId: string
  ): Promise<UserMembership> {
    const membership = await this.rbac.createMembership(userId, {
      group_id: groupId,
    });
    this.memberships.push({ userId, membership, viaSuper: false });
    return membership;
  }

  // === Contract Methods ===

  /**
   * Create a contract and track for cleanup (per-org → org-admin JWT).
   */
  async createContract(
    orgId: string,
    opts?: {
      address?: string;
      name?: string;
    }
  ): Promise<Contract> {
    const address = opts?.address ?? this.contractAddress();
    const contract = await this.rbac.createContract(orgId, {
      address,
      name: opts?.name,
    });
    this.contracts.push({ orgId, address });
    return contract;
  }

  /**
   * Create a contract with an ABI and track for cleanup.
   */
  async createContractWithABI(
    orgId: string,
    opts: {
      address?: string;
      name?: string;
      abi: string;
    }
  ): Promise<Contract> {
    const contract = await this.createContract(orgId, {
      address: opts.address,
      name: opts.name,
    });
    const address = contract.address || contract.contract_address || '';
    await this.rbac.updateContractABI(orgId, address, opts.abi);
    contract.abi = opts.abi;
    return contract;
  }

  /**
   * Create a contract and grant it to a group.
   */
  async createContractWithGrant(orgId: string, groupId: string, opts?: {
    address?: string;
    name?: string;
  }): Promise<Contract> {
    const address = opts?.address ?? this.contractAddress();
    const contract = await this.createContract(orgId, {
      address,
      name: opts?.name ?? `Contract ${address.slice(0, 10)}`,
    });
    await this.rbac.createContractGrant(orgId, address, { group_id: groupId });
    return contract;
  }

  // === Cleanup ===

  /**
   * Clean up all tracked resources in reverse order of creation.
   * Routing mirrors RD-1107: regular per-org resources delete as the org admin
   * (JWT); is_org_admin groups / their memberships / orgs delete as super-admin.
   */
  async cleanup(): Promise<void> {
    // Delete contracts first (per-org → org-admin JWT)
    for (const { orgId, address } of [...this.contracts].reverse()) {
      try {
        await this.rbac.deleteContract(orgId, address);
      } catch {
        // Ignore cleanup errors
      }
    }

    // Delete memberships
    for (const { userId, membership, viaSuper } of [...this.memberships].reverse()) {
      try {
        await (viaSuper ? this.sa : this.rbac).deleteMembership(userId, membership.id);
      } catch {
        // Ignore cleanup errors
      }
    }

    // We don't delete users - they remain in the system
    // but are isolated by unique DIDs

    // Delete groups (children first due to reverse order)
    for (const { orgId, group, viaSuper } of [...this.groups].reverse()) {
      try {
        await (viaSuper ? this.sa : this.rbac).deleteGroup(orgId, group.id);
      } catch {
        // Ignore cleanup errors
      }
    }

    // Delete organizations last (super-admin)
    for (const org of [...this.orgs].reverse()) {
      try {
        await this.sa.deleteOrganization(org.id);
      } catch {
        // Ignore cleanup errors
      }
    }

    // Clear tracked resources
    this.contracts = [];
    this.memberships = [];
    this.users = [];
    this.groups = [];
    this.orgs = [];
  }
}
