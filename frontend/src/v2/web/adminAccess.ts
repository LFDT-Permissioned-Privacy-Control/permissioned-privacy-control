import type { Self } from './protocol'

// These are verified organization roles from /api/v2/self. Execution claims,
// imported policy files and login-profile names do not grant console access.
export function hasAdminRole(self: Self | null): boolean {
  return self?.principalKind === 'human' && self.organizations.some(org => org.isOrgAdmin === true || org.isOrgReadonlyAdmin === true)
}

// Local proposal editing follows the familiar full-admin UI role. This grants
// no live policy authority; Git approval and deployment remain separate.
export function canEditSource(self: Self | null): boolean {
  return self?.principalKind === 'human' && self.organizations.some(org => org.isOrgAdmin === true)
}
