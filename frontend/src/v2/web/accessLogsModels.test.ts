import { expect, it } from 'vitest'
import { accessLogPage, accessLogsEndpoint, logTime, validAccessLogQuery } from './accessLogsModels'

const org = '11111111-1111-4111-8111-111111111111', digest = 'sha256:' + 'a'.repeat(64)
const query = { from: '2026-11-20T11:00:00.123456Z', to: '2026-11-20T11:00:00.123457Z', limit: 50 }
function page() { return { items: [{ requestReference: '22222222-2222-4222-8222-222222222222', observedAt: query.from, actorId: 'ops:p1:' + 'A'.repeat(43), organizationId: org, method: 'eth_call', outcome: 'denied', httpStatus: 200, rpcErrorCode: -32000, recordedStatus: 403, trustedIP: null, policyDigest: null, configurationDigest: digest, reason: 'not_recorded' }], next: null, source: { sourceId: org, generation: org, networkDigest: digest, configurationDigest: digest, headReference: digest, sourceAsOf: '2026-11-20T12:00:00Z', retainedFrom: '1970-01-01T00:00:00Z', population: 'SEALED_REQUEST_COMPLETIONS_AS_OF_CHAIN_HEAD', coverage: 'committed-sealed-prefix' } } }
it('compares RFC3339 fractions exactly and preserves the half-open microsecond interval', () => {
  expect(logTime(query.to) - logTime(query.from)).toBe(1000n)
  expect(logTime('2026-11-20T12:00:00.123456789+01:00')).toBe(logTime('2026-11-20T11:00:00.123456789Z'))
  expect(accessLogPage(page(), org, query).items[0].observedAt).toBe(query.from)
  const outside = page(); outside.items[0].observedAt = query.to
  expect(() => accessLogPage(outside, org, query)).toThrow('requested scope')
  for (const value of ['2026-02-31T00:00:00Z', '2026-11-20', '2026-11-20T24:00:00Z', '2026-11-20T11:00:00.1234567890Z']) expect(() => logTime(value)).toThrow()
})
it('requires real server-filter parameters and rejects legacy search, offsets, aliases and duplicate parameters', () => {
  const valid = new URL(accessLogsEndpoint(org, query), 'https://ops.test').searchParams
  expect(validAccessLogQuery(valid)).toBe(true)
  for (const mutate of [
    (value: URLSearchParams) => value.delete('from'), (value: URLSearchParams) => value.append('from', query.from),
    (value: URLSearchParams) => value.set('to', query.from), (value: URLSearchParams) => value.set('externalId', 'email@example.test'),
    (value: URLSearchParams) => value.set('offset', '50'), (value: URLSearchParams) => value.set('actorId', 'not-an-ops-actor'),
    (value: URLSearchParams) => value.set('outcome', 'all'), (value: URLSearchParams) => value.set('method', 'eth_call?ignored'),
    (value: URLSearchParams) => value.set('requestReference', 'client-provided-label'), (value: URLSearchParams) => value.set('limit', '101'),
  ]) { const value = new URLSearchParams(valid); mutate(value); expect(validAccessLogQuery(value)).toBe(false) }
})
it('rejects foreign-organization or malformed private records and unclaimed source completeness', () => {
  for (const mutate of [
    (value: ReturnType<typeof page>) => { value.items[0].organizationId = '33333333-3333-4333-8333-333333333333' },
    (value: ReturnType<typeof page>) => { value.items[0].recordedStatus = 200 },
    (value: ReturnType<typeof page>) => { value.items[0].rpcErrorCode = 2147483648 },
    (value: ReturnType<typeof page>) => { value.items[0].reason = 'invented_policy_reason' },
    (value: ReturnType<typeof page>) => { value.items.push(value.items[0]) },
    (value: ReturnType<typeof page>) => { value.source.coverage = 'complete' },
    (value: ReturnType<typeof page>) => { value.source.headReference = 'unverified' },
    (value: ReturnType<typeof page>) => { Object.assign(value.items[0], { calldata: 'never-render' }) },
  ]) { const value = page(); mutate(value); expect(() => accessLogPage(value, org, query)).toThrow() }
  expect(() => accessLogPage(page(), org, { ...query, method: 'eth_getLogs' })).toThrow('requested scope')
})

it('accepts only the closed recorded reason and outcome combinations', () => {
  for (const reason of ['sender_not_linked', 'method_not_allowed', 'policy_argument_constraint']) {
    const value = page(); value.items[0].reason = reason
    expect(accessLogPage(value, org, query).items[0].reason).toBe(reason)
  }
  for (const [reason, outcome] of [['sender_not_linked', 'success'], ['policy_invalid_context', 'denied'], ['policy_invented', 'denied'], ['', 'denied'], ['request_cancelled', 'denied']]) {
    const value = page(); value.items[0].reason = reason; value.items[0].outcome = outcome
    expect(() => accessLogPage(value, org, query)).toThrow()
  }
})
