import { describe, expect, it } from 'vitest'
import { adminLocation, plainLoginLocation } from './routes'
import { getSourcePage, sourcePagePath, sourceSections, type SourcePageId } from './navigation'

describe('native Admin page allowlist', () => {
  it.each(['/account', '/admin', '/admin/account', '/admin/rbac', '/admin/rbac/organizations', '/admin/rbac/groups',
    '/admin/rbac?org=11111111-1111-1111-1111-111111111111', '/admin/rbac/groups?org=11111111-1111-1111-1111-111111111111',
    ...['contracts', 'execution-policy', 'configuration', 'identity-profiles', 'claim-mappings', 'azure-tenants', 'platform-configuration', 'compliance-source', 'disclosure-source'].map(p => '/admin/rbac/' + p),
    '/admin/compliance', '/admin/disclosure', '/admin/disclosures', '/admin/logs', '/admin/diagnostics', '/disclosures'])('accepts exact supported %s', path => {
    expect(adminLocation(new URL(path, 'https://ops.test'))).toBe(true)
  })
  it.each(['/account?org=11111111-1111-1111-1111-111111111111', '/administrator', '/admin/users', '/admin/rbac/groups/', '/admin/account?org=11111111-1111-1111-1111-111111111111',
    '/admin/rbac?', '/admin/rbac#ignored', '/admin/rbac?%6frg=11111111-1111-1111-1111-111111111111', '/admin/rbac?org=%31' + '1'.repeat(7) + '-1111-1111-1111-111111111111',
    '/admin/rbac?org=00000000-0000-0000-0000-000000000000', '/admin/rbac?org=11111111-1111-1111-1111-111111111111&org=11111111-1111-1111-1111-111111111111',
    '/admin/rbac?return=/admin', '/admin/rbac?org=AAAAAAAA-1111-1111-1111-111111111111'])('denies malformed or unsupported %s', path => {
    expect(adminLocation(new URL(path, 'https://ops.test'))).toBe(false)
  })
  it('keeps the ordinary account login page query-free', () => {
    expect(plainLoginLocation(new URL('https://ops.test/login'))).toBe(true)
    expect(plainLoginLocation(new URL('https://ops.test/login?'))).toBe(false)
    expect(plainLoginLocation(new URL('https://ops.test/login?return=/admin'))).toBe(false)
  })
})

const canonicalSourcePages: { id: SourcePageId; section: string; path: string; title: string }[] = [
  { id: 'organizations', section: 'rbac', path: '/admin/rbac/organizations', title: 'Organizations' },
  { id: 'groups', section: 'rbac', path: '/admin/rbac/groups', title: 'Groups' },
  { id: 'contracts', section: 'rbac', path: '/admin/rbac/contracts', title: 'Contracts' },
  { id: 'execution-policy', section: 'rbac', path: '/admin/rbac/execution-policy', title: 'Execution Policy' },
  { id: 'identity-profiles', section: 'identity', path: '/admin/identity/profiles', title: 'Profiles' },
  { id: 'claim-mappings', section: 'identity', path: '/admin/identity/claim-mappings', title: 'Claim mappings' },
  { id: 'platform-configuration', section: 'settings', path: '/admin/settings', title: 'Settings' },
  { id: 'disclosure-source', section: 'disclosure', path: '/admin/disclosure/rules', title: 'Disclosure rules' },
  { id: 'compliance-source', section: 'compliance', path: '/admin/compliance/policy', title: 'Compliance policy' },
  { id: 'configuration', section: 'rbac', path: '/admin/configuration', title: 'Source files' },
]
const newSourcePaths = ['/admin/identity/profiles', '/admin/identity/claim-mappings', '/admin/settings', '/admin/disclosure/rules', '/admin/compliance/policy', '/admin/configuration']
describe('regrouped source navigation', () => {
  it.each(canonicalSourcePages)('resolves $id to its canonical $path and section, retaining exact old source aliases', expected => {
    expect(getSourcePage(expected.path)).toMatchObject(expected)
    expect(sourcePagePath(expected.id)).toBe(expected.path)
    expect(getSourcePage('/admin/rbac/' + expected.id)).toMatchObject(expected)
    expect(getSourcePage(expected.path)?.description).toBeTruthy()
  })
  it('keeps landing defaults and merges the Azure compatibility page into all Profiles without changing its authoring ID', () => {
    expect(getSourcePage('/admin')?.id).toBe('organizations')
    expect(getSourcePage('/admin/rbac')?.id).toBe('organizations')
    expect(getSourcePage('/admin/rbac/azure-tenants')).toMatchObject({ id: 'identity-profiles', section: 'identity', path: '/admin/identity/profiles', title: 'Profiles' })
    expect(Object.keys(sourceSections)).toEqual(['rbac', 'identity', 'settings', 'disclosure', 'compliance', 'configuration'])
  })
  it.each(newSourcePaths)('accepts only the canonical organization query on %s', path => {
    expect(adminLocation(new URL(path, 'https://ops.test'))).toBe(true)
    expect(adminLocation(new URL(path + '?org=11111111-1111-1111-1111-111111111111', 'https://ops.test'))).toBe(true)
    for (const suffix of ['?', '#', '#ignored', '?org=', '?org=00000000-0000-0000-0000-000000000000', '?org=AAAAAAAA-1111-1111-1111-111111111111', '?org=11111111-1111-1111-1111-111111111111&org=11111111-1111-1111-1111-111111111111', '?%6frg=11111111-1111-1111-1111-111111111111', '?org=%311111111-1111-1111-1111-111111111111', '?org=11111111-1111-1111-1111-111111111111&return=/admin', '?return=/admin']) {
      expect(adminLocation(new URL(path + suffix, 'https://ops.test')), path + suffix).toBe(false)
    }
  })
  it.each(['/admin/identity', '/admin/identity/profiles/', '/admin/identity/profiles/deeper', '/admin/identity/azure-tenants', '/admin/settings/runtime', '/admin/configuration/groups', '/admin/compliance/policy/deeper', '/admin/disclosure/rules/', '/admin/identity/%70rofiles', '/admin/unknown'])('never treats an unknown prefix or encoded alias as source page %s', path => {
    expect(getSourcePage(path)).toBeNull()
    expect(adminLocation(new URL(path, 'https://ops.test'))).toBe(false)
  })
  it('keeps operational destinations separate from source pages and helpers pathname-only', () => {
    for (const path of ['/admin/compliance', '/admin/disclosure', '/admin/disclosures', '/admin/logs', '/admin/diagnostics', '/admin/account', '/disclosures']) expect(getSourcePage(path)).toBeNull()
    expect(getSourcePage('/admin/settings?org=11111111-1111-1111-1111-111111111111')).toBeNull()
    expect(getSourcePage('/admin/settings#anything')).toBeNull()
    expect(adminLocation(new URL('https://ops.test/admin#'))).toBe(false)
    expect(plainLoginLocation(new URL('https://ops.test/login#'))).toBe(false)
  })
})
