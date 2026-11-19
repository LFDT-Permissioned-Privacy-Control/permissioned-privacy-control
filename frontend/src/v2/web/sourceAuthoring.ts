import { createContext, useContext, useState } from 'react'
import { documentText, type SourceProject } from './sourceProject'

export interface AuthoringEntry {
  value: unknown; base: string; dirty: boolean
  source?: { root: string; path: string; text: string }
}
export type AuthoringState = Readonly<Record<string, AuthoringEntry>>
export interface SourceAuthoringContext {
  project: SourceProject | null; state: AuthoringState; prefix: string; root?: string; path?: string
  update(key: string, entry: AuthoringEntry): void; clear(prefix: string): void
}
export const Authoring = createContext<SourceAuthoringContext | null>(null)

// Values here are unfinished local UI input, never policy, credentials or live
// operational data. SourceDraftMemory owns their authorization and lifetime.
export function useClearAuthoring() {
  const context = useContext(Authoring)
  return (child?: string) => context?.clear(context.prefix + (child ? '/' + encodeURIComponent(child) : '') + '/')
}
export function useAuthoringState<T>(name: string, initial: T | (() => T), options: { draft?: boolean; base?: unknown; source?: boolean } = {}): [T, (value: T) => void] {
  const context = useContext(Authoring), base = JSON.stringify(options.base ?? null)
  const original = typeof initial === 'function' ? (initial as () => T)() : initial
  const [local, setLocal] = useState(original)
  if (!context) return [local, setLocal]
  const key = context.prefix + '/' + encodeURIComponent(name), entry = context.state[key]
  const source = options.source !== false && context.project && context.root && context.path
    ? { root: context.root, path: context.path, text: documentText(context.project, context.root, context.path) } : undefined
  const value = entry && entry.base === base && (!entry.source || source?.text === entry.source.text) ? entry.value as T : original
  return [value, replacement => context.update(key, { value: replacement, base, dirty: !!options.draft && JSON.stringify(replacement) !== JSON.stringify(original), source })]
}

export function retainAuthoring(state: AuthoringState, project: SourceProject): AuthoringState {
  return Object.fromEntries(Object.entries(state).filter(([, entry]) => {
    if (!entry.source) return true
    try { return documentText(project, entry.source.root, entry.source.path) === entry.source.text } catch { return false }
  }))
}
