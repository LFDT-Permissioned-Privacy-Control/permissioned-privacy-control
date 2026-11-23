import { loadSourceProject, type SourceProject } from './sourceProject'
import type { SourceFile } from './workspace'
export const org = '11111111-1111-1111-1111-111111111111', group = '22222222-2222-2222-2222-222222222222', reader = '33333333-3333-4333-8333-333333333333'
export const contractID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', address = '0x' + '1'.repeat(40)
export const abi = [{ type: 'function', name: 'transfer', inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [], stateMutability: 'nonpayable' }, { type: 'event', name: 'Transfer', inputs: [{ name: 'from', type: 'address', indexed: true }, { name: 'to', type: 'address', indexed: true }, { name: 'amount', type: 'uint256' }], anonymous: false }]
export function sourceFile(path: string, value: unknown): SourceFile {
  const raw = typeof value === 'string' ? value : JSON.stringify(value)
  return { path, size: new TextEncoder().encode(raw).length, read: async () => raw }
}
export function fixtureDocuments() {
  return {
    'draft.json': { apiVersion: 'ops.policy-draft/v1alpha1', kind: 'PolicyDraft', environment: 'test', chainId: '31337', evaluatorVersion: 'policycore/native-v1alpha4', profile: 'catalog-runtime-creation-observed/v1', sourceRevision: 'fixture', organizations: [{ id: org, slug: 'bank', name: 'Bank' }], documents: ['groups', 'contract-registry', 'execution-rules'].map((kind, index) => ({ kind, organizationId: org, path: ['groups.json', 'registry.json', 'execution.json'][index] })), identityCatalog: { path: 'identity.json' } },
    'groups.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'groups', organizationId: org, spec: { groups: [
      { id: group, slug: 'deployer', name: 'Deployer', description: 'Deploy contracts', isOrgAdmin: false, isOrgReadonlyAdmin: false, allowedMethods: ['eth_call', 'eth_getBalance'], claims: ['member', 'deploy'], verboseErrors: false },
      { id: reader, slug: 'reader', name: 'Reader', description: 'Inspect records', isOrgAdmin: false, isOrgReadonlyAdmin: true, allowedMethods: ['eth_call'], claims: [], verboseErrors: false },
    ] } },
    'registry.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'contract-registry', organizationId: org, spec: { contracts: [{ id: contractID, name: 'Vault', address, abi, allowVisibleToUnlock: false, eventsAllowDynamicPayload: false, readGrants: [{ id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', groupId: reader, eventRules: { mode: 'all', rules: [] } }] }] } },
    'execution.json': { apiVersion: 'ops.policy-document/v1alpha1', kind: 'execution-rules', organizationId: org, spec: { policy: { apiVersion: 'privacy.gateway.fm/v1alpha4', kind: 'ContractExecutionPolicy', org, nestedCalls: 'requireOwnRule', bindings: [{ group, allow: [{ storageAddress: address, selector: '0xa9059cbb', abiDigest: '', maxDepth: 1, args: [{ index: 1, uintAtMost: '10000000000000000000000000000000000' }] }] }] } } },
    'identity.json': { apiVersion: 'ops.identity-catalog/v1alpha1', kind: 'IdentityCatalog', issuers: [], profiles: [{ id: 'bank-staff', kind: 'azure-human/v1', tenantId: org, factSource: 'appRoles' }], mappings: [{ id: 'staff-reader', profileId: 'bank-staff', organizationId: org, principalKind: 'human', fact: { kind: 'azure.role', value: 'payments' }, groupIds: [reader] }] },
  }
}
export function fixtureFiles(prefix = '', overrides: Record<string, unknown> = {}): SourceFile[] { return Object.entries({ ...fixtureDocuments(), ...overrides }).map(([path, value]) => sourceFile(prefix + path, value)) }
export async function fixtureProject(overrides: Record<string, unknown> = {}): Promise<SourceProject> { return loadSourceProject(fixtureFiles('', overrides)) }
export async function fixtureEnvelope(overrides: Record<string, unknown> = {}) { return { apiVersion: 'ops.ui-source-package/v1', roots: [{ id: 'source', files: await Promise.all(fixtureFiles('', overrides).map(async file => ({ path: file.path, dataBase64: btoa(unescape(encodeURIComponent(await file.read()))) }))) }] } }
