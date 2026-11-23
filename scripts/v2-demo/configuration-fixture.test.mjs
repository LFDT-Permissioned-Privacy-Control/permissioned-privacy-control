import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { publishPreview, previewID } from './configuration-fixture.mjs';

const ledgerAddress = '0x1111111111111111111111111111111111111111';
const ledgerABI = [{ type: 'function', name: 'set', inputs: [{ name: 'subject', type: 'address' }, { name: 'next', type: 'uint256' }], outputs: [], stateMutability: 'nonpayable' }];
// The unit boundary supplies an explicit compiler report. The real browser
// fixture invokes the existing Go CLI and checks its function with ethers.
const abiReport = { abiDigest: '12'.repeat(32), functions: [{ signature: 'set(address,uint256)', selector: '0xaabbccdd' }] };
const inspectABI = async abi => { assert.deepEqual(abi, ledgerABI); return abiReport; };

async function fixture(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'ops-viewer-publisher-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const expected = new Map();
  for (const [root, names] of Object.entries({ core: ['draft', 'groups', 'registry', 'execution', 'identity', 'runtime', 'compliance', 'disclosure'], broker: ['draft', 'groups', 'registry', 'execution', 'identity', 'auth', 'role-context'] })) {
    await mkdir(path.join(directory, 'current', root), { recursive: true });
    for (const name of names) {
      const value = name === 'draft' ? { organizations: [{ id: 'bank', name: 'Demo Bank' }] }
        : name === 'groups' ? { spec: { groups: [{ id: 'deployer', name: 'Deployer' }] } }
          : name === 'registry' ? { spec: { contracts: [{ id: 'ledger', name: 'Demo Ledger', address: ledgerAddress, abi: ledgerABI }] } }
            : name === 'execution' ? { spec: { policy: { bindings: [{ group: 'deployer', allow: [{ storageAddress: ledgerAddress, selector: '*', callTypes: ['call', 'staticcall'], maxDepth: 4 }] }] } } }
              : { name };
      const raw = JSON.stringify(value) + '\n';
      const file = path.join('current', root, name + '.json');
      expected.set(file, raw); await writeFile(path.join(directory, file), raw);
    }
  }
  await writeFile(path.join(directory, 'current', 'core', 'credentials.json'), '{"secret":"must-not-copy"}');
  await writeFile(path.join(directory, 'runtime-marker'), 'selected-runtime-untouched');
  return { directory, expected };
}

test('external add/update/remove affects only preview public files and keeps base/runtime bytes', async t => {
  const { directory, expected } = await fixture(t);
  await publishPreview(directory, 'add', { inspectABI });
  assert.equal(JSON.parse(await readFile(path.join(directory, previewID, 'core/draft.json'))).organizations[0].name, 'Demo Bank preview');
  assert.equal((await readdir(path.join(directory, previewID, 'core'))).includes('credentials.json'), false);
  await publishPreview(directory, 'update', { inspectABI });
  for (const root of ['core', 'broker']) {
    const draft = JSON.parse(await readFile(path.join(directory, previewID, root, 'draft.json')));
    const groups = JSON.parse(await readFile(path.join(directory, previewID, root, 'groups.json')));
    assert.equal(draft.organizations[0].id, 'bank'); assert.equal(draft.organizations[0].name, 'Demo Bank refreshed');
    assert.deepEqual(groups.spec.groups, [{ id: 'deployer', name: 'Deployer refreshed' }]);
  }
  const execution = JSON.parse(await readFile(path.join(directory, previewID, 'core', 'execution.json')));
  assert.deepEqual(execution.spec.policy.bindings, [{ group: 'deployer', allow: [{ storageAddress: ledgerAddress, selector: abiReport.functions[0].selector, abiDigest: abiReport.abiDigest, callTypes: ['call', 'staticcall'], maxDepth: 4 }] }], 'Exact preview keeps qualified rule fields and the native inspector pin');
  await publishPreview(directory, 'remove');
  assert.equal((await readdir(directory)).includes(previewID), false);
  for (const [file, raw] of expected) assert.equal(await readFile(path.join(directory, file), 'utf8'), raw);
  assert.equal(await readFile(path.join(directory, 'runtime-marker'), 'utf8'), 'selected-runtime-untouched');
  assert.deepEqual((await readdir(directory)).sort(), ['current', 'runtime-marker']);
});

test('invalid actions and symlinked seed files cannot publish a preview', async t => {
  const { directory } = await fixture(t);
  await assert.rejects(publishPreview(directory, 'apply', { inspectABI }), /Expected add/);
  const seed = path.join(directory, 'current', 'core', 'identity.json');
  await rm(seed); await symlink(path.join(directory, 'runtime-marker'), seed);
  await assert.rejects(publishPreview(directory, 'add', { inspectABI }), /regular public source/);
  assert.equal((await readdir(directory)).includes(previewID), false);
  assert.equal((await readdir(directory)).some(name => name.startsWith('.preview')), false);
});
