export interface SourceFile {
  path: string
  size: number
  read(): Promise<string>
  readBytes?(): Promise<Uint8Array>
}
export interface DraftGroup {
  id: string; slug: string; name: string; description: string
  isOrgAdmin: boolean; isOrgReadonlyAdmin: boolean
  allowedMethods: string[]; claims: string[]; verboseErrors: boolean
  rpcCredential?: { fromEnv: string }
}
