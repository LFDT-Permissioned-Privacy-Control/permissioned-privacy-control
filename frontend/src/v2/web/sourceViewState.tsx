import { createContext, useContext, useState, type ReactNode } from 'react'
import type { ConfigurationViewer, ConfigurationView } from './configurationViewer'
interface Context { viewer: ConfigurationViewer; view: ConfigurationView; prefix: string }
const SourceView = createContext<Context | null>(null)
export function SourceViewProvider({ viewer, view, children }: { viewer: ConfigurationViewer; view: ConfigurationView; children: ReactNode }) {
  return <SourceView.Provider value={{ viewer, view, prefix: '' }}>{children}</SourceView.Provider>
}
export function SourceViewScope({ id, children }: { id: string; children: ReactNode }) {
  const parent = useContext(SourceView)
  return parent ? <SourceView.Provider value={{ ...parent, prefix: parent.prefix + '/' + encodeURIComponent(id) }}>{children}</SourceView.Provider> : <>{children}</>
}
export function useSourceViewState<T>(name: string, initial: T | (() => T)): [T, (value: T) => void] {
  const context = useContext(SourceView)
  const [local, setLocal] = useState(initial)
  if (!context) return [local, setLocal]
  const key = context.prefix + '/' + encodeURIComponent(name)
  const value = Object.prototype.hasOwnProperty.call(context.view.viewState, key) ? context.view.viewState[key] as T : typeof initial === 'function' ? (initial as () => T)() : initial
  return [value, replacement => context.viewer.setViewState(key, replacement, context.view.observation)]
}
export function useSourceObservation(): number { return useContext(SourceView)?.view.observation ?? 0 }
