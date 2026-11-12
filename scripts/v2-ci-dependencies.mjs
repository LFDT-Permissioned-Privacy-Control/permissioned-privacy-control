#!/usr/bin/env node
// Use the same locked source resolver as the local demo; CI never accepts
// local worktree overrides or selects a fallback branch.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile, mkdir, appendFile, rm } from 'node:fs/promises'
import path from 'node:path'
import { repositoryRoot } from '../tools/v2-test-wallet/artifacts.mjs'

try {
  const lock = JSON.parse(await readFile(path.join(repositoryRoot, 'scripts/v2-demo/dependencies.json'), 'utf8'))
  assert.equal(lock.schemaVersion, 1)
  assert.deepEqual(Object.keys(lock.dependencies).sort(), ['explorer', 'indexer'])
  for (const entry of Object.values(lock.dependencies)) {
    assert.match(entry.overrideEnvironment, /^[A-Z][A-Z0-9_]*$/)
    assert.ok(!process.env[entry.overrideEnvironment], `Unset local override ${entry.overrideEnvironment} for remote CI checkout`)
  }
  const base = path.join(repositoryRoot, '.tmp/v2-ci-dependencies')
  await mkdir(base, { recursive: true })
  const selection = path.join(base, 'selection.json')
  // The local demo may remember an explicitly selected worktree. CI starts a
  // new selection instead; only its exact remote clone cache may be reused.
  await rm(selection, { force: true })
  const result = spawnSync(process.execPath, ['scripts/v2-demo/dependencies.mjs', selection], {
    cwd: repositoryRoot, stdio: 'inherit', timeout: 300_000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
  })
  if (result.status !== 0) throw new Error('Exact dependency checkout failed; required commits must be published and publicly readable. No fallback revision or private read credential is selected.')
  const selected = JSON.parse(await readFile(selection, 'utf8'))
  for (const [name, entry] of Object.entries(selected.dependencies)) {
    assert.equal(entry.commit, lock.dependencies[name].commit)
    assert.equal(entry.overrideEnvironment, lock.dependencies[name].overrideEnvironment)
    assert.ok(path.isAbsolute(entry.directory) && !/[\r\n]/.test(entry.directory))
    if (process.env.GITHUB_ENV) {
      await appendFile(process.env.GITHUB_ENV, `${entry.overrideEnvironment}=${entry.directory}\n`)
      if (name === 'explorer') await appendFile(process.env.GITHUB_ENV, `OPS_E2B_EXPLORER_ROOT=${entry.directory}\n`)
    }
  }
  process.stdout.write('Both exact dependency revisions are available and selected.\n')
} catch (error) { process.stderr.write(`Native V2 dependencies: ${error.message}\n`); process.exitCode = 1 }
