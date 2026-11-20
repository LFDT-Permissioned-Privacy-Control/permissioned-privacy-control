// Source navigation is local authoring context, never an authority or runtime
// endpoint catalog. Compatibility paths resolve to the same canonical page ID
// so moving between sections retains the source form's existing memory key.
export type SourcePageId = 'organizations' | 'groups' | 'contracts' | 'execution-policy' | 'identity-profiles' | 'claim-mappings' | 'platform-configuration' | 'disclosure-source' | 'compliance-source' | 'configuration'
export type SourceSectionId = 'rbac' | 'identity' | 'settings' | 'disclosure' | 'compliance' | 'configuration'
export interface SourcePage { id: SourcePageId; section: SourceSectionId; path: string; title: string; description: string }
export const sourceSections: Readonly<Record<SourceSectionId, { title: string; description: string }>> = {
  rbac: { title: 'Access Control', description: 'Organizations, groups, contracts and execution permissions from your policy source' },
  identity: { title: 'Identity', description: 'Verified identity profiles and group mappings from your policy source' },
  settings: { title: 'Settings', description: 'Runtime policy and authentication broker settings from your policy source' },
  disclosure: { title: 'Disclosure', description: 'Standing disclosure rules from your policy source' },
  compliance: { title: 'Compliance', description: 'Organization compliance settings, token prices and address thresholds from your policy source' },
  configuration: { title: 'Review & export', description: 'Inspect, repair and export your complete policy source proposal' },
}
export const sourcePages: readonly SourcePage[] = [
  { id: 'organizations', section: 'rbac', path: '/admin/rbac/organizations', title: 'Organizations', description: 'Organizations declared in the selected policy source' },
  { id: 'groups', section: 'rbac', path: '/admin/rbac/groups', title: 'Groups', description: 'Group methods, execution claims and organization administration' },
  { id: 'contracts', section: 'rbac', path: '/admin/rbac/contracts', title: 'Contracts', description: 'Registered contracts, public ABIs, read grants and event visibility' },
  { id: 'execution-policy', section: 'rbac', path: '/admin/rbac/execution-policy', title: 'Execution Policy', description: 'Native execution rules and hypothetical offline policy scenarios' },
  { id: 'identity-profiles', section: 'identity', path: '/admin/identity/profiles', title: 'Profiles', description: 'Public Azure and Privado verification profiles and assertion issuers' },
  { id: 'claim-mappings', section: 'identity', path: '/admin/identity/claim-mappings', title: 'Claim mappings', description: 'Map verified provider facts to organization groups' },
  { id: 'platform-configuration', section: 'settings', path: '/admin/settings', title: 'Settings', description: 'Runtime policy and authentication broker source settings' },
  { id: 'disclosure-source', section: 'disclosure', path: '/admin/disclosure/rules', title: 'Disclosure rules', description: 'Standing source rules used by separately authorized disclosure cases' },
  { id: 'compliance-source', section: 'compliance', path: '/admin/compliance/policy', title: 'Compliance policy', description: 'Configured compliance settings, token prices and address thresholds' },
  { id: 'configuration', section: 'configuration', path: '/admin/configuration', title: 'Review & export', description: 'Inspect and repair source files, then export a complete proposal' },
]
const pagesByPath = new Map(sourcePages.map(page => [page.path, page]))
for (const page of sourcePages) pagesByPath.set('/admin/rbac/' + page.id, page)
const organizations = sourcePages.find(page => page.id === 'organizations')!
pagesByPath.set('/admin', organizations)
pagesByPath.set('/admin/rbac', organizations)
pagesByPath.set('/admin/rbac/azure-tenants', sourcePages.find(page => page.id === 'identity-profiles')!)

// pathname must be the exact path component, with no query, fragment, encoded
// alias or prefix matching. The routes module separately fences whole URLs.
export function getSourcePage(pathname: string): SourcePage | null { return pagesByPath.get(pathname) ?? null }
export function sourcePagePath(id: SourcePageId): string {
  const page = sourcePages.find(page => page.id === id)
  if (!page) throw Error('Select a supported source page.')
  return page.path
}
