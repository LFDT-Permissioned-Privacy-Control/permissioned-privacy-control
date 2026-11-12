#!/usr/bin/env node
import { readFile, mkdir, rename, rm, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const lock = JSON.parse(await readFile(path.join(root, 'scripts/v2-demo/dependencies.json'), 'utf8'));
if (lock.schemaVersion !== 1 || Object.keys(lock.dependencies).sort().join() !== 'explorer,indexer') throw Error('Invalid V2 demo dependency lock');
const output = process.argv[2];
if (!output) throw Error('Output JSON path required');
let previous;
try { previous = JSON.parse(await readFile(output, 'utf8')); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
const destination = path.join(root, '.tmp/v2-demo/dependencies');
await mkdir(destination, { recursive: true });
const git = (args, cwd) => {
  // Locked repositories are public. Never ask a user's credential helper or
  // macOS Keychain to compensate for an unavailable/unpublished source pin.
  const env = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/usr/bin/false', SSH_ASKPASS: '/usr/bin/false' };
  const result = spawnSync('git', ['-c', 'credential.helper=', '-c', 'core.askPass=', ...args], { cwd, env, encoding: 'utf8', timeout: 120_000, maxBuffer: 2 << 20 });
  if (result.error || result.status !== 0) throw Error(`Git ${args[0]} failed: ${result.error?.message ?? result.stderr.trim()}`);
  return result.stdout.trim();
};
const selected = {};
for (const [name, entry] of Object.entries(lock.dependencies)) {
  if (!/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\.git$/.test(entry.repository) || !/^[0-9a-f]{40}$/.test(entry.commit) || !/^OPS_V2_DEMO_[A-Z_]+_SOURCE$/.test(entry.overrideEnvironment)) throw Error('Invalid pinned dependency');
  // Preserve a previously selected local checkout for ordinary up/down/up.
  // The lock and fresh HEAD/clean checks remain authoritative on every run.
  const cached = previous?.schemaVersion === 1 ? previous.dependencies?.[name] : undefined;
  const selectedBefore = cached?.commit === entry.commit && cached?.repository === entry.repository && typeof cached.directory === 'string' ? cached.directory : undefined;
  const override = process.env[entry.overrideEnvironment] || selectedBefore;
  const directory = override ? await realpath(override) : path.join(destination, `${name}-${entry.commit}`);
  if (!override) {
    let exists = false;
    try { git(['rev-parse', 'HEAD'], directory); exists = true; } catch {}
    if (!exists) {
      const temporary = directory + `.preparing-${process.pid}`;
      try {
        await mkdir(temporary);
        git(['init', '--quiet'], temporary);
        git(['remote', 'add', 'origin', entry.repository], temporary);
        git(['fetch', '--quiet', '--depth=1', 'origin', entry.commit], temporary);
        git(['checkout', '--quiet', '--detach', 'FETCH_HEAD'], temporary);
        await rename(temporary, directory);
      } catch (error) {
        await rm(temporary, { recursive: true, force: true });
        throw Error(`Pinned ${name} ${entry.commit} could not be fetched. Publish that commit or set ${entry.overrideEnvironment} to its exact clean checkout. No main-branch fallback. ${error.message}`);
      }
    }
  }
  if (git(['rev-parse', 'HEAD'], directory) !== entry.commit || git(['status', '--porcelain'], directory)) throw Error(`${name} must be a clean checkout at locked commit ${entry.commit}`);
  selected[name] = { ...entry, directory };
}
await writeFile(output, JSON.stringify({ schemaVersion: 1, dependencies: selected }, null, 2) + '\n', { mode: 0o600 });
console.log('Selected exact clean Explorer/indexer revisions.');
