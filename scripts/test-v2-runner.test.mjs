import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, writeFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const required = ['TestNativeV2ServingExcludesLegacyServerAndEVMPolicyBackend', 'TestPinnedArtifactRejectsMixedMissingAndUnexpectedFiles']
for (const [name, events, want] of [
  ['zero executed cases is a failure', [], 1],
  ['skipped required case is a failure', required.map(Test => ({ Action: 'skip', Test })), 1],
  ['package failure after required passes is a failure', [...required.map(Test => ({ Action: 'pass', Test })), { Action: 'fail', Package: 'fixture' }], 1],
  ['every required case executed successfully', required.map(Test => ({ Action: 'pass', Test })), 0],
]) test(name, async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'ops-v2-runner-'))
  try {
    const fake = path.join(directory, 'go-fixture')
    await writeFile(fake, `#!${process.execPath}\nprocess.stdout.write(${JSON.stringify(events.map(e => JSON.stringify(e)).join('\n') + '\n')})\n`, { mode: 0o700 })
    const result = spawnSync(process.execPath, ['scripts/test-v2.mjs', 'core'], { cwd: root,
      env: { ...process.env, GO: fake, OPS_V2_TEST_RESULTS: path.join(directory, 'results') }, encoding: 'utf8', timeout: 10_000 })
    assert.equal(result.status, want, result.stderr)
  } finally { await rm(directory, { recursive: true, force: true }) }
})
