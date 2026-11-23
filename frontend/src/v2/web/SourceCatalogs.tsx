import { SourceFieldValue, SourceRecords, type SourceField } from './SourceRecords'
import { SourceContracts } from './SourceContracts'
import { SourceClaimMappings } from './SourceClaimMappings'
import { SourceComplianceSettings } from './SourceComplianceSettings'
import { documentValue, object, rootOf, type JSONObject, type SourceProject } from './sourceProject'
interface Props { project: SourceProject; root: string; organization: string; page: string }
const field = (key: string, label: string, kind?: SourceField['kind'], optional = false, help?: string): SourceField => ({ key, label, kind, optional, help })
const profileVariants: Record<string, string[]> = {
  'azure-human/v1': ['tenantId', 'issuer', 'apiAudience', 'clientId', 'delegatedScope', 'factSource'],
  'azure-service/v1': ['tenantId', 'issuer', 'apiAudience', 'allowedClientIds', 'factSource'],
  'privado-identity/v1': ['verifierId', 'network', 'identityStateContract'],
  'privado-role-query/v1': ['verifierId', 'network', 'identityStateContract', 'allowedCredentialIssuers', 'contextDigest', 'context', 'type', 'circuitId', 'predicates'],
}
const labels: Record<string, string> = { tenantId: 'Azure tenant ID', issuer: 'Azure issuer', apiAudience: 'API audience', clientId: 'Client ID', delegatedScope: 'Delegated scope', factSource: 'Fact source', verifierId: 'Privado verifier ID', network: 'Privado network', identityStateContract: 'Identity state contract', contextDigest: 'Context digest', context: 'Credential context', type: 'Credential type', circuitId: 'Circuit ID', allowedClientIds: 'Allowed client IDs', allowedCredentialIssuers: 'Allowed credential issuers', predicates: 'Verified predicates' }
const profileFields: SourceField[] = [field('id', 'Profile ID'), { ...field('kind', 'Verification kind'), options: Object.keys(profileVariants) }, ...Object.entries(labels).map(([key, label]): SourceField => ({
  ...field(key, label, key === 'predicates' ? 'json' : key.startsWith('allowed') ? 'list' : 'text'),
  onlyFor: Object.keys(profileVariants).filter(variant => profileVariants[variant].includes(key)),
  ...(key === 'factSource' ? { options: ['appRoles', 'groupIds'] } : {}),
}))]
const ruleFields: SourceField[] = [field('id', 'Rule ID'), field('dataOrganizationId', 'Data organization ID'), field('viewers', 'Permitted viewers', 'json', false, 'Group references {organizationId,groupId} and/or canonical verified actor IDs.'), field('targets', 'Permitted target actors', 'json'), field('resources', 'Permitted resources', 'list'), field('addresses', 'Address scope', 'json'), field('dataTime', 'Data time interval', 'json'), { ...field('maxLevel', 'Maximum detail'), options: ['redacted', 'pseudonymous', 'full'] }, field('validity', 'Rule validity', 'json'), field('maxCaseSeconds', 'Maximum case seconds', 'number')]
export function SourceCatalogs({ project, root, organization, page }: Props) {
  const source = rootOf(project, root)
  const get = (key: string) => source.draft[key] === undefined ? null : documentValue(project, root, String(object(source.draft[key]).path))
  const missing = (title: string) => <div className="space-y-3"><h3 className="text-sm font-medium">{title}</h3><p className="text-sm text-neutral-500">This configuration root has no {title.toLowerCase()} document.</p></div>
  if (page === 'contracts') return <SourceContracts project={project} root={root} organization={organization} />
  if (page === 'identity-profiles' || page === 'claim-mappings') {
    const catalog = get('identityCatalog')
    if (!catalog) return missing('Identity catalog')
    if (page === 'claim-mappings') return <SourceClaimMappings project={project} root={root} profiles={catalog.profiles as JSONObject[]} records={catalog.mappings as JSONObject[]} />
    return <div className="space-y-8"><SourceRecords title="Identity profiles" description="Public Azure and Privado verification profiles and trust bindings. No credentials are resolved and no provider calls are made here." records={catalog.profiles} fields={profileFields} />
      <SourceRecords title="Assertion issuers" description="Public signing keys and allowed verification profile IDs." records={catalog.issuers} fields={[field('id', 'Issuer ID'), field('issuer', 'Issuer'), field('audience', 'Audience'), field('allowedProfiles', 'Allowed profiles', 'list'), field('keys', 'Public JWK keys', 'json')]} />
    </div>
  }
  if (page === 'disclosure-source') {
    const catalog = get('disclosureCatalog')
    return catalog ? <SourceRecords title="Standing disclosure rules" description="Source limits for separately authorized disclosure cases. Viewing these rules neither approves them nor changes case permissions." records={catalog.rules} fields={ruleFields} /> : missing('Standing disclosure rules')
  }
  if (page === 'compliance-source') {
    const catalog = get('complianceCatalog')
    return catalog ? <div className="space-y-8"><SourceComplianceSettings records={catalog.organizations as JSONObject[]} organizations={source.draft.organizations} selectedOrganization={organization} />
      <SourceRecords title="Sanctions" records={catalog.sanctions} fields={[field('id', 'Sanction ID'), field('scope', 'Scope'), field('organizationId', 'Organization ID'), field('address', 'Address'), field('reason', 'Reason'), field('source', 'Source')]} /></div> : missing('Compliance policy')
  }
  const runtime = get('runtimeCatalog'), broker = get('authCatalog')
  return <div className="space-y-8">
    {runtime ? <SourceSettings title="Runtime policy" value={runtime} fields={[field('readProfile', 'Read profile'), field('nodeEvidenceProfile', 'Node evidence profile'), field('intraOrgGrantTracing', 'Trace intra-organization grants', 'boolean'), field('rawSubmissionMode', 'Signed submission Guard mode'), field('sharedInfrastructure', 'Shared infrastructure', 'json'), field('addressScopes', 'Address organization scopes', 'json'), field('priceFeed', 'Public price feed bindings', 'json')]} /> : missing('Runtime policy')}
    {broker && <><SourceSettings title="Authentication broker" value={broker} fields={[field('issuerId', 'Assertion issuer ID'), field('accessKeyId', 'Access signing key ID'), field('webOrigin', 'Web origin'), field('completionUri', 'Completion URI'), field('renewalKeys', 'Renewal key environment references', 'json'), field('encryptionKeys', 'Encryption key environment references', 'json')]} />
      {(['azureProfiles', 'privadoProfiles', 'privadoNetworks', 'pinnedDocuments'] as const).filter(key => broker[key] !== undefined).map(key => <SourceRecords key={key} title={{ azureProfiles: 'Azure provider bindings', privadoProfiles: 'Privado provider bindings', privadoNetworks: 'Privado networks', pinnedDocuments: 'Pinned public documents' }[key]} records={broker[key]}
        fields={key === 'azureProfiles' ? [field('profileId', 'Profile ID'), field('redirectUri', 'Redirect URI'), field('clientSecret', 'Client secret environment reference', 'json')]
          : key === 'privadoProfiles' ? [field('profileId', 'Profile ID')]
            : key === 'pinnedDocuments' ? [field('url', 'Public context URL'), field('path', 'Local source filename'), field('sha256', 'Exact byte SHA-256')]
              : [field('network', 'Network'), field('chainId', 'Chain ID'), field('stateContract', 'State contract'), field('rpcUrl', 'RPC URL'), field('allowPrivate', 'Allow configured private network', 'boolean'), field('credential', 'RPC credential environment reference', 'json')]} />)}</>}
    <p className="text-xs text-neutral-500">Public trust and environment references are shown as source content. The viewer does not resolve secrets, test providers or change the deployed service.</p>
  </div>
}
function SourceSettings({ title, value, fields }: { title: string; value: JSONObject; fields: SourceField[] }) {
  return <section className="space-y-3"><h3 className="text-sm font-medium">{title}</h3><dl className="grid gap-3 sm:grid-cols-2">{fields.map(field => <div key={field.key} className="rounded-lg border border-neutral-200 p-3"><dt className="text-xs text-neutral-500">{field.label}</dt><dd className="mt-2 min-w-0"><SourceFieldValue value={value[field.key]} label={field.label} /></dd></div>)}</dl></section>
}
