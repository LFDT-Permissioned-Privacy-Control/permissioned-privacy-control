import { session } from '../auth/protocol'

const sourcePages = ['organizations', 'groups', 'contracts', 'execution-policy', 'configuration', 'identity-profiles', 'claim-mappings', 'azure-tenants', 'platform-configuration', 'disclosure-source', 'compliance-source'].map(p => '/admin/rbac/' + p)
const operationalPages = ['/admin/compliance', '/admin/disclosure', '/admin/disclosures', '/admin/logs', '/admin/diagnostics', '/disclosures']
const adminPages = new Set(['/admin', '/admin/account', '/admin/rbac', ...sourcePages, ...operationalPages])
const scopedPages = new Set(['/admin/rbac', ...sourcePages, ...operationalPages])

// Match the server's exact page/query contract. No return URL, encoded alias,
// duplicate parameter, fragment, or generic /admin prefix is accepted.
type PageLocation = Pick<Location, 'pathname' | 'search' | 'hash'> & { href?: string }

export function adminLocation(value: PageLocation): boolean {
  if (!adminPages.has(value.pathname) || value.hash || value.href?.endsWith('?')) return false
  if (!value.search) return true
  return scopedPages.has(value.pathname) && value.search.startsWith('?org=') && session(value.search.slice(5))
}

export function plainLoginLocation(value: PageLocation): boolean {
  return value.pathname === '/login' && !value.search && !value.hash && !value.href?.endsWith('?')
}
