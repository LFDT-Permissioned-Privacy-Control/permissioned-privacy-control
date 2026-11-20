import { object } from '../auth/protocol'
import type { CaseScope, ObjectValue } from './operationsModels'

const eventID = /^de1\.[A-Za-z0-9_-]{1,64}\.[A-Za-z0-9_-]{21}[AQgw]$/
const hash = /^0x[0-9a-f]{64}$/
const uint32 = (value: unknown) => typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= 4294967295
const nonzeroHash = (value: unknown) => typeof value === 'string' && hash.test(value) && value !== '0x' + '0'.repeat(64)

export function validateEventsPage(result: ObjectValue, level: CaseScope['level'], time: CaseScope['dataTime'], limit: number) {
  object(result, ['v', 'population', 'items', 'nextCursor'])
  if (result.v !== 1 || result.population !== 'EVENTS_FROM_DISCLOSED_TRANSACTIONS' ||
    !Number.isInteger(limit) || limit < 1 || limit > 100 || !Array.isArray(result.items) || result.items.length > limit ||
    result.nextCursor !== null && (typeof result.nextCursor !== 'string' || !/^[\x21-\x7e]{1,2048}$/.test(result.nextCursor))) throw Error('Invalid disclosed events page')
  const seen = new Set<string>()
  let previous: { block: bigint; transaction: number; log: number } | undefined
  for (const raw of result.items) {
    const item = object(raw, ['eventId', 'blockNumber', 'transactionIndex', 'logIndex', 'blockTime', 'emitter', 'payload',
      ...(level === 'full' ? ['transactionHash', 'blockHash', 'topics', 'data'] : [])])
    if (typeof item.eventId !== 'string' || !eventID.test(item.eventId) || seen.has(item.eventId) ||
      typeof item.blockNumber !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(item.blockNumber) || BigInt(item.blockNumber) > 9223372036854775807n ||
      !uint32(item.transactionIndex) || !uint32(item.logIndex) || Number(item.logIndex) > 2147483647 ||
      !Number.isSafeInteger(item.blockTime) || Number(item.blockTime) < time.start || Number(item.blockTime) > time.end ||
      typeof item.emitter !== 'string' || item.payload !== (level === 'full' ? 'disclosed' : 'withheld')) throw Error('Invalid or private disclosed event fields')
    if (level === 'full') {
      if (!/^0x[0-9a-f]{40}$/.test(item.emitter) || !nonzeroHash(item.transactionHash) || !nonzeroHash(item.blockHash) ||
        !Array.isArray(item.topics) || item.topics.length > 4 || item.topics.some(value => typeof value !== 'string' || !hash.test(value)) ||
        typeof item.data !== 'string' || item.data.length > 2 * 1024 * 1024 || !/^0x(?:[0-9a-f]{2})*$/.test(item.data)) throw Error('Invalid Full disclosed event payload')
    } else if (level === 'redacted' ? item.emitter !== '[PRIVATE]' : !/^Address-[A-Z2-7]{26}$/.test(item.emitter)) throw Error('Invalid private emitter display')
    const current = { block: BigInt(item.blockNumber), transaction: Number(item.transactionIndex), log: Number(item.logIndex) }
    if (previous && (current.block < previous.block || current.block === previous.block &&
      (current.transaction < previous.transaction || current.log <= previous.log))) throw Error('Invalid disclosed event order')
    previous = current
    seen.add(item.eventId)
  }
}
