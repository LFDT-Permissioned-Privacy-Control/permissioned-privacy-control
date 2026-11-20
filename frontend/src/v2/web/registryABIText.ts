import { closedJSON } from '../auth/protocol'
// Extract only the selected registry ABI's original JSON span. The existing
// closed parser validates grammar, duplicates and bounds first. No AST or number
// canonicalizer is constructed: e.g. 1.0 and 1e+3 reach Go unchanged. A single
// explicit LF terminates the exported file; the source span itself is untouched.
export function registryABIText(raw: string, contractIndex: number): string {
  closedJSON(raw, 1 << 20, 32)
  if (!Number.isSafeInteger(contractIndex) || contractIndex < 0 || contractIndex >= 4096) throw Error('Select a registry contract.')
  const space = (at: number) => { while (/\s/.test(raw[at] ?? '') && at < raw.length) at++; return at }
  const stringEnd = (at: number) => {
    if (raw[at] !== '"') throw Error('Expected a validated registry string.')
    for (let end = at + 1; end < raw.length; end++) { if (raw[end] === '\\') end++; else if (raw[end] === '"') return end + 1 }
    throw Error('The selected registry string is incomplete.')
  }
  const endOf = (at: number): number => {
    if (raw[at] === '"') return stringEnd(at)
    if (raw[at] !== '[' && raw[at] !== '{') { let end = at; while (end < raw.length && !/[\s,}\]]/.test(raw[end])) end++; return end }
    let depth = 0
    for (let end = at; end < raw.length; end++) {
      const char = raw[end]
      if (char === '"') { end = stringEnd(end) - 1; continue }
      if (char === '[' || char === '{') depth++
      else if (char === ']' || char === '}') { if (--depth === 0) return end + 1 }
    }
    throw Error('The selected registry value is incomplete.')
  }
  const member = (at: number, name: string): number => {
    if (raw[at] !== '{') throw Error('The selected registry path must be an object.')
    let cursor = space(at + 1)
    while (raw[cursor] !== '}') {
      const end = stringEnd(cursor), key: unknown = JSON.parse(raw.slice(cursor, end))
      cursor = space(end)
      if (raw[cursor] !== ':') throw Error('The selected registry member is invalid.')
      cursor = space(cursor + 1)
      if (key === name) return cursor
      cursor = space(endOf(cursor))
      if (raw[cursor] === ',') cursor = space(cursor + 1)
    }
    throw Error('The selected registry ABI path is unavailable.')
  }
  const array = member(member(space(0), 'spec'), 'contracts')
  if (raw[array] !== '[') throw Error('The registry contracts field must be an array.')
  let entry = space(array + 1)
  for (let index = 0; index < contractIndex; index++) { entry = space(endOf(entry)); if (raw[entry] !== ',') throw Error('The selected registry contract is unavailable.'); entry = space(entry + 1) }
  const start = member(entry, 'abi'), end = endOf(start)
  if (raw[start] !== '[') throw Error('The selected contract ABI must be an array.')
  return raw.slice(start, end) + '\n'
}
