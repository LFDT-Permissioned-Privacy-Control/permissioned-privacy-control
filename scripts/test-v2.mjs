#!/usr/bin/env node
// Finite native-release controls. Required cases must execute, not just compile.
import { spawn } from 'node:child_process'
import { createInterface } from 'node:readline'
import { mkdir, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { repositoryRoot } from '../tools/v2-test-wallet/artifacts.mjs'
import { verifyArtifacts } from './v2-test-prerequisites.mjs'

const commands = ['ops-v2', 'ops-v2-serve', 'ops-v2-identity-migrate', 'ops-v2-wallet-migrate',
  'ops-v2-admission-migrate', 'ops-v2-disclosure-migrate', 'ops-v2-namespace', 'ops-v2-sso-migrate',
  'ops-activity-admin', 'ops-creation-observer']
const suites = {
  core: {
    packages: [...commands.map(name => `./cmd/${name}`), './internal/archtest', './internal/policycore',
      './internal/runtimepolicy', './internal/policybundle', './internal/identity'],
    required: ['TestNativeV2ServingExcludesLegacyServerAndEVMPolicyBackend', 'TestPinnedArtifactRejectsMixedMissingAndUnexpectedFiles'],
  },
  identity: {
    packages: ['./internal/operational/identitysql'],
    required: ['TestActualPrivadoWalletSession', 'TestActualPrivadoWalletAuthOnlySession', 'TestActualPrivadoWalletStateChange'],
  },
  browser: {
    packages: ['./internal/operational/identitysql'],
    required: ['TestActualBuiltCentralAzureBrowser', 'TestActualBuiltCentralPrivadoBrowser',
      'TestActualAzureTwoTabBrowser', 'TestActualPrivadoTwoTabBrowser'],
  },
}
async function command(program, args, options = {}) {
  const child = spawn(program, args, { cwd: repositoryRoot, stdio: 'inherit', ...options })
  await new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`${program} failed (${signal ?? code})`)))
  })
}
async function run(name) {
  const suite = suites[name]
  if (name !== 'core') {
    await command('docker', ['info', '--format', '{{.ServerVersion}}'])
    await command('docker', ['image', 'inspect', 'postgres:16-alpine', '--format', '{{.Id}}'])
    if (!await verifyArtifacts()) throw new Error('Pinned public circuits missing: run npm run circuits in tools/v2-test-wallet first')
  }
  const args = ['test', '-json', '-p', '1', '-tags', 'production,prover_disabled', '-count=1', '-timeout', '10m']
  if (name !== 'core') args.push('-run', `^(${suite.required.join('|')})$`)
  args.push(...suite.packages)
  const child = spawn(process.env.GO ?? 'go', args, { cwd: repositoryRoot,
    env: { ...process.env, OPS_TEST_NODE: process.execPath, OPS_PRIVADO_WALLET_INTEGRATION: '1', OPS_PRIVADO_WALLET_DEMO: '0',
      OPS_BROWSER_INTEGRATION: name === 'browser' ? '1' : '0', GOMAXPROCS: process.env.GOMAXPROCS ?? '2' },
    stdio: ['ignore', 'pipe', 'inherit'] })
  const completed = new Set(), skipped = new Set(), failed = new Set()
  const records = []
  let malformed = false
  const lines = createInterface({ input: child.stdout, crlfDelay: Infinity })
  const reading = (async () => {
    for await (const line of lines) {
      try {
        const event = JSON.parse(line)
        records.push(event)
        if (event.Action === 'pass' && event.Test) completed.add(event.Test)
        if (event.Action === 'skip' && event.Test) skipped.add(event.Test)
        if (event.Action === 'fail') failed.add(event.Test ?? event.Package)
        if (event.Action === 'pass' && !event.Test) process.stdout.write(`PASS ${event.Package} (${event.Elapsed}s)\n`)
        if (event.Action === 'pass' && suite.required.includes(event.Test)) process.stdout.write(`PASS ${event.Test}\n`)
      } catch { malformed = true; process.stderr.write(line + '\n') }
    }
  })()
  const code = await new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve) })
  await reading
  const missing = suite.required.filter(test => !completed.has(test) || skipped.has(test))
  const output = path.resolve(process.env.OPS_V2_TEST_RESULTS ?? path.join(repositoryRoot, '.tmp/v2-test-results'))
  await mkdir(output, { recursive: true })
  await writeFile(path.join(output, `${name}.json`), JSON.stringify({ suite: name, exitCode: code,
    required: suite.required, passedRequired: suite.required.filter(test => completed.has(test)), missing,
    skipped: [...skipped], failed: [...failed], malformed }, null, 2) + '\n')
  await writeFile(path.join(output, `${name}.jsonl`), records.map(event => JSON.stringify(event)).join('\n') + '\n')
  if (code !== 0 || malformed || failed.size || missing.length) {
    process.stderr.write(records.filter(event => event.Output).map(event => event.Output).join('').slice(-16_384))
    throw new Error(`V2 ${name} failed; missing/skipped required cases: ${missing.join(', ') || 'none'}`)
  }
  process.stdout.write(`PASS V2 ${name}: ${suite.required.length} required controls executed.\n`)
}
try {
  const selected = process.argv[2] ?? 'all'
  if (process.argv.length > 3 || selected !== 'all' && !Object.hasOwn(suites, selected)) throw new Error('Usage: node scripts/test-v2.mjs [core|identity|browser|all]')
  for (const name of selected === 'all' ? Object.keys(suites) : [selected]) await run(name)
} catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1 }
