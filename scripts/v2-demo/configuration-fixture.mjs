// External demo publisher for the read-only viewer. It never changes selected
// runtime artifacts, server configuration, credentials, identity state or DBs.
import assert from 'node:assert/strict';
import { lstat, mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const previewID = 'ui-parity-preview';
const publicFiles = {
  core: ['draft', 'groups', 'registry', 'execution', 'identity', 'runtime', 'compliance', 'disclosure'],
  broker: ['draft', 'groups', 'registry', 'execution', 'identity', 'auth', 'role-context'],
};
const absent = async target => {
  try { await lstat(target); return false; } catch (error) { if (error.code === 'ENOENT') return true; throw error; }
};
async function regular(target, directory = false) {
  const stat = await lstat(target);
  assert.ok(directory ? stat.isDirectory() : stat.isFile() && stat.size <= 1 << 20, 'Expected bounded regular public source');
}

async function nativeABIReport(abi) {
  const temporary = await mkdtemp(path.join(tmpdir(), 'ops-demo-viewer-abi-'));
  try {
    const file = path.join(temporary, 'abi.json'), raw = JSON.stringify(abi);
    assert.ok(Buffer.byteLength(raw) <= 1 << 20);
    await writeFile(file, raw, { flag: 'wx', mode: 0o600 });
    const result = spawnSync('ops-v2', ['policy', 'abi', '--file', file], { encoding: 'utf8', timeout: 10000, maxBuffer: 1 << 20 });
    assert.equal(result.status, 0, 'The existing offline ABI inspector must succeed');
    return JSON.parse(result.stdout);
  } finally { await rm(temporary, { recursive: true, force: true }); }
}

export async function publishPreview(directory, action, { inspectABI = nativeABIReport } = {}) {
  assert.ok(['add', 'update', 'remove'].includes(action), 'Expected add, update or remove');
  await regular(directory, true);
  const target = path.join(directory, previewID);
  if (action === 'remove') {
    if (!await absent(target)) { await regular(target, true); await rm(target, { recursive: true }); }
    return { action, id: previewID };
  }
  assert.equal(await absent(target), action === 'add', action === 'add' ? 'Preview already exists' : 'Add the preview first');
  const current = path.join(directory, 'current');
  await regular(current, true);
  const stage = await mkdtemp(path.join(directory, '.preview-stage-'));
  let previous;
  try {
    for (const [root, names] of Object.entries(publicFiles)) {
      await regular(path.join(current, root), true);
      await mkdir(path.join(stage, root), { mode: 0o700 });
      for (const name of names) {
        const input = path.join(current, root, name + '.json');
        await regular(input);
        let raw = await readFile(input);
        assert.ok(raw.length <= 1 << 20);
        const value = JSON.parse(raw.toString('utf8'));
        if (name === 'draft') {
          value.organizations[0].name = action === 'update' ? 'Demo Bank refreshed' : 'Demo Bank preview';
          raw = Buffer.from(JSON.stringify(value, null, 2) + '\n');
        } else if (name === 'groups') {
          const group = value.spec.groups.find(group => group.name === 'Deployer');
          assert.ok(group, 'The base demo includes Deployer');
          group.name = action === 'update' ? 'Deployer refreshed' : 'Deployer preview';
          raw = Buffer.from(JSON.stringify(value, null, 2) + '\n');
        }
        await writeFile(path.join(stage, root, name + '.json'), raw, { flag: 'wx', mode: 0o600 });
      }
    }
    // This preview demonstrates a concrete group→contract→function link. Use
    // the existing Go ABI inspector, not a second selector/digest implementation.
    // The tool only inspects the public ABI; it never evaluates or deploys policy.
    const registry = JSON.parse(await readFile(path.join(stage, 'core', 'registry.json'), 'utf8'));
    const ledger = registry.spec.contracts.find(contract => contract.name === 'Demo Ledger');
    assert.ok(ledger && Array.isArray(ledger.abi), 'The demo registers its public ledger ABI');
    const report = await inspectABI(ledger.abi);
    assert.match(report.abiDigest, /^[0-9a-f]{64}$/);
    assert.ok(Array.isArray(report.functions) && report.functions.length <= 1024);
    const func = report.functions.find(func => func.signature === 'set(address,uint256)');
    assert.ok(func); assert.match(func.selector, /^0x[0-9a-f]{8}$/);
    const groups = JSON.parse(await readFile(path.join(stage, 'core', 'groups.json'), 'utf8'));
    const group = groups.spec.groups.find(group => group.name === (action === 'update' ? 'Deployer refreshed' : 'Deployer preview'));
    const executionFile = path.join(stage, 'core', 'execution.json');
    const execution = JSON.parse(await readFile(executionFile, 'utf8'));
    const binding = execution.spec.policy.bindings.find(binding => binding.group === group?.id);
    const rule = binding?.allow.find(rule => rule.storageAddress?.toLowerCase() === ledger.address.toLowerCase() && rule.selector === '*');
    assert.ok(rule, 'The demo has a Deployer rule for its registered ledger');
    rule.selector = func.selector; rule.abiDigest = report.abiDigest;
    await writeFile(executionFile, JSON.stringify(execution, null, 2) + '\n', { mode: 0o600 });
    if (action === 'update') {
      await regular(target, true);
      previous = await mkdtemp(path.join(directory, '.preview-old-'));
      await rm(previous, { recursive: true });
      await rename(target, previous);
    }
    await rename(stage, target); // Target is absent; brief unavailability is allowed.
    if (previous) await rm(previous, { recursive: true });
    return { action, id: previewID };
  } catch (error) {
    if (previous && await absent(target)) await rename(previous, target);
    throw error;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(await publishPreview('/exports/configuration-sources', process.argv[2]))); }
  catch (error) { console.error('Demo viewer fixture: ' + error.message); process.exitCode = 1; }
}
