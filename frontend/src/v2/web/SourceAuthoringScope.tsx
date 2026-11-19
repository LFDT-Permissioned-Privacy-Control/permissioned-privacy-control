import { useContext, type ReactNode } from 'react'
import { Authoring, type SourceAuthoringContext } from './sourceAuthoring'

export function SourceAuthoringProvider({ project, state, update, clear, children }: Omit<SourceAuthoringContext, 'prefix'> & { children: ReactNode }) {
  return <Authoring.Provider value={{ project, state, update, clear, prefix: '' }}>{children}</Authoring.Provider>
}
export function SourceAuthoringScope({ id, root, path, children }: { id: string; root?: string; path?: string; children: ReactNode }) {
  const parent = useContext(Authoring)
  return parent ? <Authoring.Provider value={{ ...parent, prefix: parent.prefix + '/' + encodeURIComponent(id), root: root ?? parent.root, path: path ?? parent.path }}>{children}</Authoring.Provider> : <>{children}</>
}
