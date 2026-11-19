import { describe, expect, it } from 'vitest'
import { adminLocation, plainLoginLocation } from './routes'

describe('native Admin page allowlist', () => {
  it.each(['/admin', '/admin/account', '/admin/rbac', '/admin/rbac/organizations', '/admin/rbac/groups',
    '/admin/rbac?org=11111111-1111-1111-1111-111111111111', '/admin/rbac/groups?org=11111111-1111-1111-1111-111111111111',
    ...['contracts', 'execution-policy', 'configuration', 'identity-profiles', 'claim-mappings', 'azure-tenants', 'platform-configuration', 'compliance-source', 'disclosure-source'].map(p => '/admin/rbac/' + p),
    '/admin/compliance', '/admin/disclosure', '/admin/disclosures', '/admin/logs', '/admin/diagnostics', '/disclosures'])('accepts exact supported %s', path => {
    expect(adminLocation(new URL(path, 'https://ops.test'))).toBe(true)
  })
  it.each(['/administrator', '/admin/users', '/admin/rbac/groups/', '/admin/account?org=11111111-1111-1111-1111-111111111111',
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
