import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./export-config.mjs', import.meta.url));
function publicFiles() {
  const files = {};
  for (const name of ['draft', 'groups', 'registry', 'execution', 'identity', 'runtime', 'compliance', 'disclosure']) files['core/' + name + '.json'] = '{}\n';
  for (const name of ['draft', 'groups', 'registry', 'execution', 'identity', 'auth', 'role-context']) files['broker/' + name + '.json'] = '{}\n';
  files['core/groups.json'] = '{"spec":{"groups":[{"id":"reader","name":"Reader"}]}}\n';
  files['core/identity.json'] = '{"mappings":[{"profileId":"demo-reader","fact":{"value":"reader"},"groupIds":["reader"]}]}\n';
  files['broker/role-context.json'] = '{ "@context": {} }  \n';
  return { version: 1, organizationId: 'demo', files };
}
async function fixture(run) {
  const directory = await mkdtemp(path.join(tmpdir(), 'ops-v2-public-export-'));
  try {
    const bin = path.join(directory, 'bin'); await mkdir(bin);
    await writeFile(path.join(bin, 'docker'), '#!' + process.execPath + ' --\nprocess.stdout.write(process.env.EXPORTED_PUBLIC_FIXTURE)\n', { mode: 0o700 });
    await run(directory, (source, output) => spawnSync(process.execPath, [script, output], { encoding: 'utf8', timeout: 10_000,
      env: { ...process.env, PATH: bin + path.delimiter + process.env.PATH, OPS_V2_DEMO_ROOT: '/owned', OPS_V2_DEMO_CONTROL_DIR: '/owned/control', OPS_V2_DEMO_PROJECT: 'demo', EXPORTED_PUBLIC_FIXTURE: JSON.stringify(source) } }));
  } finally { await rm(directory, { recursive: true, force: true }); }
}
test('public export preserves exact pinned bytes and contains only the allowed source files', async () => {
  await fixture(async (directory, run) => {
    const output = path.join(directory, 'public'), source = publicFiles();
    const result = run(source, output);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(await readFile(path.join(output, 'broker/role-context.json'), 'utf8'), source.files['broker/role-context.json']);
    await assert.rejects(access(path.join(output, 'private/state.json')));
  });
});
test('unexpected private and escaping paths reject before creating the output', async () => {
  await fixture(async (directory, run) => {
    for (const name of ['private/state.json', '../escaped.json']) {
      const source = publicFiles(); delete source.files['broker/draft.json']; source.files[name] = '{"secret":"do-not-export"}';
      const output = path.join(directory, 'public');
      assert.notEqual(run(source, output).status, 0);
      await assert.rejects(access(output));
    }
    await assert.rejects(access(path.join(directory, 'escaped.json')));
  });
});
test('existing user edits are never overwritten', async () => {
  await fixture(async (directory, run) => {
    const output = path.join(directory, 'public'); await mkdir(output);
    await writeFile(path.join(output, 'my-edit.json'), 'preserve');
    assert.notEqual(run(publicFiles(), output).status, 0);
    assert.equal(await readFile(path.join(output, 'my-edit.json'), 'utf8'), 'preserve');
  });
});
