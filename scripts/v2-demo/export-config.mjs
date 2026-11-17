// Export an explicit set of public sources, preserving their exact file bytes.
import assert from 'node:assert/strict';
import { mkdir, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';

const allowed = new Set([
  ...['draft', 'groups', 'registry', 'execution', 'identity', 'runtime', 'compliance', 'disclosure'].map(x => 'core/' + x + '.json'),
  ...['draft', 'groups', 'registry', 'execution', 'identity', 'auth', 'role-context'].map(x => 'broker/' + x + '.json'),
]);
try {
  assert.ok(process.argv[2], 'Supply a new output directory');
  const root = process.env.OPS_V2_DEMO_ROOT, directory = process.env.OPS_V2_DEMO_CONTROL_DIR, project = process.env.OPS_V2_DEMO_PROJECT;
  assert.ok(root && directory && project);
  const result = spawnSync('docker', ['compose', '--env-file', path.join(directory, 'ports.env'), '-p', project,
    '-f', path.join(root, 'deploy/v2-demo/compose.yml'), 'run', '--rm', '--no-deps', '--pull', 'never', 'bootstrap', 'export', '--root', '/demo'],
  { encoding: 'utf8', timeout: 30_000, maxBuffer: 20 << 20 });
  assert.equal(result.status, 0, 'Cannot export public files; the demo tools image must support export');
  const source = JSON.parse(result.stdout);
  assert.equal(source.version, 1);
  assert.equal(Object.keys(source.files).length, allowed.size);
  for (const [name, content] of Object.entries(source.files)) {
    assert.ok(allowed.has(name) && typeof content === 'string' && Buffer.byteLength(content) <= 1 << 20);
    JSON.parse(content);
  }
  const output = path.resolve(process.argv[2]);
  await mkdir(output, { mode: 0o700 }); // Existing directories are never overwritten.
  for (const name of ['core', 'broker']) await mkdir(path.join(output, name), { mode: 0o700 });
  for (const [name, content] of Object.entries(source.files)) await writeFile(path.join(output, name), content, { flag: 'wx', mode: 0o600 });
  const groups = JSON.parse(source.files['core/groups.json']).spec.groups;
  const identities = JSON.parse(source.files['core/identity.json']);
  console.log('Public policy sources exported to ' + output);
  console.log('Organization: Demo Bank (' + source.organizationId + ')');
  for (const mapping of identities.mappings) console.log(mapping.profileId + ' / ' + mapping.fact.value + ' -> ' + mapping.groupIds.map(id => groups.find(g => g.id === id)?.name ?? id).join(', '));
  console.log('Only the identity catalog mappings are editable through apply-config; other sources are inspection examples.');
} catch (error) {
  console.error('Demo config export: ' + error.message);
  process.exitCode = 1;
}
