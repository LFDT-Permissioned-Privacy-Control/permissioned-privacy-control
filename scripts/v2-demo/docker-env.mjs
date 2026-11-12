#!/usr/bin/env node
// Public local demo images never need the user's registry credentials/Keychain.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdir, writeFile, rename, appendFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..')
function docker(args, env = process.env) {
  const result = spawnSync('docker', args, { env, encoding: 'utf8', timeout: 15_000, maxBuffer: 1 << 20 })
  if (result.status !== 0) throw new Error('Cannot inspect the running local Docker daemon/plugins')
  return result.stdout.trim()
}
try {
  assert.ok(process.argv.length === 2 || process.argv.length === 3 && process.argv[2] === '--github-env', 'Usage: docker-env.mjs [--github-env]')
  // Context inspection and local daemon metadata do not access a registry.
  const host = process.env.DOCKER_HOST || docker(['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'])
  assert.ok(host.startsWith('unix:///') && !/[\r\n]/.test(host), 'The local demo requires a Unix-socket Docker daemon')
  const localEnv = { ...process.env, DOCKER_HOST: host }
  for (const key of ['DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'DOCKER_AUTH_CONFIG']) delete localEnv[key]
  const plugins = JSON.parse(docker(['info', '--format', '{{json .ClientInfo.Plugins}}'], localEnv))
  assert.ok(Array.isArray(plugins))
  const directories = [...new Set(plugins.map(plugin => {
    assert.ok(typeof plugin.Path === 'string' && path.isAbsolute(plugin.Path) && !/[\r\n]/.test(plugin.Path))
    return path.dirname(plugin.Path)
  }))]
  // Copy executable search paths only. Never copy config.json, auth entries,
  // credential helpers, context TLS material or saved Buildx credentials.
  const directory = path.join(root, '.tmp/v2-demo/docker-config')
  await mkdir(directory, { recursive: true, mode: 0o700 })
  const temporary = path.join(directory, 'config.json.' + randomUUID())
  // Docker auto-detects a platform helper when ContainsAuth() is false. A
  // credential-less entry for a reserved .invalid host prevents that discovery;
  // public registries still receive an empty file-store authentication result.
  await writeFile(temporary, JSON.stringify({ auths: { 'ops-v2-no-credentials.invalid': {} }, cliPluginsExtraDirs: directories }, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
  await rename(temporary, path.join(directory, 'config.json'))
  if (process.argv[2] === '--github-env') {
    assert.ok(process.env.GITHUB_ENV && !/[\r\n]/.test(directory), 'GitHub environment file required')
    await appendFile(process.env.GITHUB_ENV, `DOCKER_CONFIG=${directory}\nDOCKER_HOST=${host}\nDOCKER_CONTEXT=\nDOCKER_AUTH_CONFIG=\nDOCKER_TLS_VERIFY=\nDOCKER_CERT_PATH=\n`)
  }
  process.stdout.write(JSON.stringify({ directory, host }) + '\n')
} catch (error) { process.stderr.write(`V2 demo Docker setup: ${error.message}\n`); process.exitCode = 1 }
