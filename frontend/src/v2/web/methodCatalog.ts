export interface MethodEntry { name: string; canonical: string }
export interface MethodCatalog { version: string; methods: MethodEntry[] }
export type MethodCatalogState = { status: 'loading' | 'unavailable' } | { status: 'ready'; catalog: MethodCatalog }

export function parseMethodCatalog(value: unknown): MethodCatalog {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid method catalog')
  const catalog = value as Record<string, unknown>
  if (Object.keys(catalog).sort().join() !== 'methods,version' || typeof catalog.version !== 'string' || !catalog.version || catalog.version.length > 128 || !Array.isArray(catalog.methods) || catalog.methods.length > 4096) throw Error('Invalid method catalog')
  const seen = new Set<string>()
  const methods = catalog.methods.map(value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw Error('Invalid method catalog')
    const entry = value as Record<string, unknown>
    if (Object.keys(entry).sort().join() !== 'canonical,name' || typeof entry.name !== 'string' || !entry.name || entry.name.length > 256 || /[^\x21-\x7e]/.test(entry.name) || typeof entry.canonical !== 'string' || !entry.canonical || entry.canonical.length > 256 || /[^\x21-\x7e]/.test(entry.canonical) || seen.has(entry.name)) throw Error('Invalid method catalog')
    seen.add(entry.name)
    return { name: entry.name, canonical: entry.canonical }
  })
  return { version: catalog.version, methods }
}
