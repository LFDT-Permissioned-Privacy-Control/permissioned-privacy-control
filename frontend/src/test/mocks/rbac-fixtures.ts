/**
 * Extended mock data fixtures for RBAC component tests.
 * These fixtures provide more complex scenarios than the basic mocks in handlers.ts.
 */

import type {
  Organization,
  Group,
  User,
  Contract,
  ContractGrant,
  GroupAccess,
  UserMembership,
  MembershipWithDetails,
  EffectivePermissions,
  Claim,
} from '@/types/rbac';

// ============================================================================
// ORGANIZATIONS
// ============================================================================

/**
 * Multiple organizations for testing org switching and multi-tenancy.
 */
export const mockOrganizations: Organization[] = [
  {
    id: 'org-1',
    slug: 'acme-corp',
    name: 'Acme Corporation',
    settings: { theme: 'dark' },
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'org-2',
    slug: 'globex',
    name: 'Globex Inc',
    settings: {},
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'org-3',
    slug: 'initech',
    name: 'Initech',
    settings: { max_users: 100 },
    created_at: '2024-02-01T00:00:00Z',
    updated_at: '2024-02-20T00:00:00Z',
  },
];

// ============================================================================
// GROUPS - Nested Hierarchy
// ============================================================================

/**
 * Nested group hierarchy for testing tree views and inheritance.
 * Structure:
 * - Root (depth 0)
 *   - Engineering (depth 1)
 *     - DevOps (depth 2)
 *     - Frontend (depth 2)
 *   - Operations (depth 1)
 */
export const mockGroupHierarchy: Group[] = [
  {
    id: 'group-root',
    org_id: 'org-1',
    parent_id: null,
    slug: 'root',
    name: 'Root',
    description: 'Organization root group',
    depth: 0,
    path: 'root',
    is_org_admin: true,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-01T00:00:00Z',
  },
  {
    id: 'group-engineering',
    org_id: 'org-1',
    parent_id: 'group-root',
    slug: 'engineering',
    name: 'Engineering',
    description: 'Engineering team',
    depth: 1,
    path: 'root.engineering',
    is_org_admin: false,
    created_at: '2024-01-02T00:00:00Z',
    updated_at: '2024-01-02T00:00:00Z',
  },
  {
    id: 'group-devops',
    org_id: 'org-1',
    parent_id: 'group-engineering',
    slug: 'devops',
    name: 'DevOps',
    description: 'DevOps and infrastructure',
    depth: 2,
    path: 'root.engineering.devops',
    is_org_admin: false,
    created_at: '2024-01-03T00:00:00Z',
    updated_at: '2024-01-03T00:00:00Z',
  },
  {
    id: 'group-frontend',
    org_id: 'org-1',
    parent_id: 'group-engineering',
    slug: 'frontend',
    name: 'Frontend',
    description: 'Frontend development team',
    depth: 2,
    path: 'root.engineering.frontend',
    is_org_admin: false,
    created_at: '2024-01-03T00:00:00Z',
    updated_at: '2024-01-03T00:00:00Z',
  },
  {
    id: 'group-operations',
    org_id: 'org-1',
    parent_id: 'group-root',
    slug: 'operations',
    name: 'Operations',
    description: 'Business operations',
    depth: 1,
    path: 'root.operations',
    is_org_admin: false,
    created_at: '2024-01-02T00:00:00Z',
    updated_at: '2024-01-02T00:00:00Z',
  },
];

/**
 * Single flat group (no hierarchy) for simple tests.
 */
export const mockFlatGroup: Group = {
  id: 'group-flat',
  org_id: 'org-1',
  parent_id: null,
  slug: 'members',
  name: 'Members',
  description: 'General members group',
  depth: 0,
  path: 'members',
  is_org_admin: false,
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// ============================================================================
// GROUP ACCESS
// ============================================================================

/**
 * Full group access configuration with all fields populated.
 */
export const mockGroupAccessFull: GroupAccess = {
  id: 'access-full',
  group_id: 'group-engineering',
  allowed_methods: [
    'eth_call',
    'eth_sendTransaction',
    'eth_getBalance',
    'eth_getTransactionCount',
    'eth_estimateGas',
    'eth_gasPrice',
    'eth_blockNumber',
    'eth_getBlockByNumber',
    'eth_getTransactionReceipt',
  ],
  claims: [] as Claim[],
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-15T00:00:00Z',
};

/**
 * Minimal read-only group access. No operational claims — read access
 * is method-gated via allowed_methods.
 */
export const mockGroupAccessReadOnly: GroupAccess = {
  id: 'access-readonly',
  group_id: 'group-operations',
  allowed_methods: ['eth_call', 'eth_getBalance', 'eth_blockNumber'],
  claims: [] as Claim[],
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

/**
 * Admin group access with all permissions.
 */
export const mockGroupAccessAdmin: GroupAccess = {
  id: 'access-admin',
  group_id: 'group-root',
  allowed_methods: ['*'], // All methods
  claims: ['admin', 'upgrade', 'deploy'] as Claim[],
  created_at: '2024-01-01T00:00:00Z',
  updated_at: '2024-01-01T00:00:00Z',
};

// ============================================================================
// USERS
// ============================================================================

/**
 * Multiple users with different states.
 */
export const mockUsers: User[] = [
  {
    id: 'user-1',
    external_id: 'did:polygonid:polygon:main:user123abc',
    kyc: true,
    banned: false,
    note: 'Primary test user',
    metadata: { role: 'developer' },
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'user-2',
    external_id: 'did:polygonid:polygon:main:user456def',
    kyc: false,
    banned: false,
    note: 'Pending KYC verification',
    metadata: {},
    created_at: '2024-01-10T00:00:00Z',
    updated_at: '2024-01-10T00:00:00Z',
  },
  {
    id: 'user-3',
    external_id: 'did:polygonid:polygon:main:user789ghi',
    kyc: true,
    banned: true,
    note: 'Banned for policy violation',
    metadata: { ban_reason: 'Spam' },
    created_at: '2024-01-05T00:00:00Z',
    updated_at: '2024-02-01T00:00:00Z',
  },
];

/**
 * User with all fields populated for detail view testing.
 */
export const mockUserFull: User = mockUsers[0];

/**
 * User without KYC for testing restricted access.
 */
export const mockUserNoKyc: User = mockUsers[1];

/**
 * Banned user for testing ban states.
 */
export const mockUserBanned: User = mockUsers[2];

// ============================================================================
// USER MEMBERSHIPS
// ============================================================================

/**
 * Multiple memberships for a single user across different groups.
 */
export const mockUserMemberships: UserMembership[] = [
  {
    id: 'membership-1',
    user_id: 'user-1',
    group_id: 'group-engineering',
    source: 'admin',
    zk_credential_ref: '',
    expires_at: null,
    created_at: '2024-01-05T00:00:00Z',
    updated_at: '2024-01-05T00:00:00Z',
  },
  {
    id: 'membership-2',
    user_id: 'user-1',
    group_id: 'group-devops',
    source: 'zk_attested',
    zk_credential_ref: 'cred:polygonid:credential:12345',
    expires_at: '2025-01-01T00:00:00Z',
    created_at: '2024-01-10T00:00:00Z',
    updated_at: '2024-01-10T00:00:00Z',
  },
  {
    id: 'membership-3',
    user_id: 'user-1',
    group_id: 'group-operations',
    source: 'admin',
    zk_credential_ref: '',
    expires_at: null,
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
];

/**
 * Memberships with full group details for UI display.
 */
export const mockMembershipsWithDetails: MembershipWithDetails[] = [
  {
    membership: mockUserMemberships[0],
    group: mockGroupHierarchy[1], // Engineering
  },
  {
    membership: mockUserMemberships[1],
    group: mockGroupHierarchy[2], // DevOps
  },
  {
    membership: mockUserMemberships[2],
    group: mockGroupHierarchy[4], // Operations
  },
];

/**
 * Single membership with details for simple tests.
 */
export const mockSingleMembershipWithDetails: MembershipWithDetails = mockMembershipsWithDetails[0];

// ============================================================================
// LINKED ETH ADDRESSES
// ============================================================================

/**
 * Linked Ethereum addresses for a user.
 */
export const mockLinkedAddresses = [
  {
    address: '0x1234567890123456789012345678901234567890',
    verified_at: '2024-01-05T10:30:00Z',
  },
  {
    address: '0xabcdefabcdefabcdefabcdefabcdefabcdefabcd',
    verified_at: '2024-01-10T14:45:00Z',
  },
  {
    address: '0x9876543210987654321098765432109876543210',
    verified_at: '2024-02-01T09:00:00Z',
  },
];

/**
 * Single linked address for simple tests.
 */
export const mockSingleLinkedAddress = mockLinkedAddresses[0];

// ============================================================================
// CONTRACTS
// ============================================================================

/**
 * Multiple contracts for testing contract management.
 */
export const mockContracts: Contract[] = [
  {
    id: 'contract-1',
    org_id: 'org-1',
    address: '0x1111111111111111111111111111111111111111',
    name: 'Token Contract',
    deployed_by_user_id: 'user-1',
    deployed_at: '2024-01-15T00:00:00Z',
    metadata: {
      type: 'ERC20',
      symbol: 'TKN',
      decimals: 18,
    },
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'contract-2',
    org_id: 'org-1',
    address: '0x2222222222222222222222222222222222222222',
    name: 'NFT Collection',
    deployed_by_user_id: 'user-1',
    deployed_at: '2024-01-20T00:00:00Z',
    metadata: {
      type: 'ERC721',
      name: 'Test NFTs',
    },
    created_at: '2024-01-20T00:00:00Z',
    updated_at: '2024-01-20T00:00:00Z',
  },
  {
    id: 'contract-3',
    org_id: 'org-1',
    address: '0x3333333333333333333333333333333333333333',
    name: 'Governance',
    deployed_by_user_id: null,
    deployed_at: null,
    metadata: {
      type: 'Governor',
      imported: true,
    },
    created_at: '2024-02-01T00:00:00Z',
    updated_at: '2024-02-01T00:00:00Z',
  },
];

/**
 * Contract without name (address-only display).
 */
export const mockContractNoName: Contract = {
  id: 'contract-noname',
  org_id: 'org-1',
  address: '0x4444444444444444444444444444444444444444',
  name: undefined,
  deployed_by_user_id: null,
  deployed_at: null,
  metadata: {},
  created_at: '2024-02-01T00:00:00Z',
  updated_at: '2024-02-01T00:00:00Z',
};

// ============================================================================
// CONTRACT GRANTS
// ============================================================================

/**
 * Contract grants linking groups to contracts.
 * Claims are inherited from the group's GroupAccess.claims.
 */
export const mockContractGrants: ContractGrant[] = [
  {
    id: 'grant-1',
    contract_id: 'contract-1',
    group_id: 'group-engineering',
    functions: null, // All functions
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: 'grant-2',
    contract_id: 'contract-1',
    group_id: 'group-operations',
    functions: ['0x70a08231', '0x18160ddd'], // balanceOf, totalSupply
    created_at: '2024-01-16T00:00:00Z',
    updated_at: '2024-01-16T00:00:00Z',
  },
  {
    id: 'grant-3',
    contract_id: 'contract-1',
    group_id: 'group-root',
    functions: null,
    created_at: '2024-01-15T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
];

/**
 * Grant with function restrictions for testing function-level access.
 */
export const mockGrantWithFunctions: ContractGrant = mockContractGrants[1];

// ============================================================================
// EFFECTIVE PERMISSIONS
// ============================================================================

/**
 * Full effective permissions with all fields populated.
 */
export const mockFullEffectivePermissions: EffectivePermissions = {
  id: 'eff-perms-full',
  user_id: 'user-1',
  org_id: 'org-1',
  allowed_methods: [
    'eth_call',
    'eth_sendTransaction',
    'eth_getBalance',
    'eth_getTransactionCount',
    'eth_estimateGas',
    'eth_gasPrice',
    'eth_blockNumber',
    'eth_getBlockByNumber',
    'eth_getTransactionReceipt',
    'eth_getLogs',
  ],
  contract_access: {
    '0x1111111111111111111111111111111111111111': {
      claims: ['admin'] as Claim[],
      functions: null,
    },
    '0x2222222222222222222222222222222222222222': {
      claims: [] as Claim[],
      functions: ['0x70a08231'], // balanceOf only
    },
  },
  claims: [] as Claim[],
  rate_limit_rps: 100,
  rate_limit_daily: 50000,
  computed_at: '2024-02-01T12:00:00Z',
  expires_at: '2024-02-01T12:30:00Z',
};

/**
 * Minimal effective permissions for read-only user.
 */
export const mockReadOnlyEffectivePermissions: EffectivePermissions = {
  id: 'eff-perms-readonly',
  user_id: 'user-2',
  org_id: 'org-1',
  allowed_methods: ['eth_call', 'eth_getBalance'],
  contract_access: {},
  claims: [] as Claim[],
  rate_limit_rps: 10,
  rate_limit_daily: 1000,
  computed_at: '2024-02-01T12:00:00Z',
  expires_at: '2024-02-01T12:30:00Z',
};

/**
 * Empty effective permissions (no access).
 */
export const mockEmptyEffectivePermissions: EffectivePermissions = {
  id: 'eff-perms-empty',
  user_id: 'user-new',
  org_id: 'org-1',
  allowed_methods: [],
  contract_access: {},
  claims: [] as Claim[],
  rate_limit_rps: 0,
  rate_limit_daily: 0,
  computed_at: '2024-02-01T12:00:00Z',
  expires_at: '2024-02-01T12:30:00Z',
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/**
 * Create a user with custom overrides.
 */
export function createMockUser(overrides: Partial<User> = {}): User {
  return {
    id: `user-${Date.now()}`,
    external_id: `did:polygonid:polygon:main:test${Date.now()}`,
    kyc: true,
    banned: false,
    note: '',
    metadata: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Create a group with custom overrides.
 */
export function createMockGroup(overrides: Partial<Group> = {}): Group {
  const slug = overrides.slug || `group-${Date.now()}`;
  return {
    id: `group-${Date.now()}`,
    org_id: 'org-1',
    parent_id: null,
    slug,
    name: overrides.name || `Test Group ${Date.now()}`,
    description: '',
    depth: 0,
    path: slug,
    is_org_admin: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Create a contract with custom overrides.
 */
export function createMockContract(overrides: Partial<Contract> = {}): Contract {
  return {
    id: `contract-${Date.now()}`,
    org_id: 'org-1',
    address: `0x${Date.now().toString(16).padStart(40, '0')}`,
    name: undefined,
    deployed_by_user_id: null,
    deployed_at: null,
    metadata: {},
    allow_visibleto_unlock: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Create an organization with custom overrides.
 */
export function createMockOrganization(overrides: Partial<Organization> = {}): Organization {
  const slug = overrides.slug || `org-${Date.now()}`;
  return {
    id: `org-${Date.now()}`,
    slug,
    name: overrides.name || `Test Org ${Date.now()}`,
    settings: {},
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}
