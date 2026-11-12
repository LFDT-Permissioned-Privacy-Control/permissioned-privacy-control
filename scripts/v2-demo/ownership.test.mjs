import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
const script = fileURLToPath(new URL('./ownership.mjs', import.meta.url));
async function run(volumes, containers = []) {
  const directory = await mkdtemp(path.join(tmpdir(), 'ops-v2-demo-ownership-'));
  try {
    await writeFile(path.join(directory, 'docker'), `#!${process.execPath}
const a=process.argv.slice(2),f=JSON.parse(process.env.OWNERSHIP_FIXTURE),kind=a[0]==='volume'?'volume':'container',items=f[kind];
if(a.includes('inspect')){const names=a.slice(a.indexOf('inspect')+1);console.log(JSON.stringify(names.map(n=>items.find(i=>i.Name===n))))}
else if(a.includes('--format'))console.log(items.map(i=>i.Name).join('\\n'));
else console.log(items.filter(i=>(i.Labels??i.Config.Labels)['com.docker.compose.project']==='test-demo').map(i=>i.Name).join('\\n'));
`, { mode: 0o700 });
    return spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 10_000, env: { ...process.env, PATH: directory + path.delimiter + process.env.PATH, OPS_V2_DEMO_PROJECT: 'test-demo', OPS_V2_DEMO_ROOT: '/owned/checkout', OWNERSHIP_FIXTURE: JSON.stringify({ volume: volumes, container: containers }) } });
  } finally { await rm(directory, { recursive: true, force: true }); }
}
const labels = { 'com.docker.compose.project': 'test-demo', 'com.gateway.ops-v2-demo.owner': '/owned/checkout', 'com.gateway.ops-v2-demo.project': 'test-demo' };
test('uninitialized selection has no resources and performs no mutation', async () => {
  const result = await run([]); assert.equal(result.status, 0); assert.equal(result.stdout.trim(), '0');
});
test('exact-name unlabeled volume collision refuses bootstrap reuse', async () => {
  const result = await run([{ Name: 'test-demo_state', Labels: {} }]); assert.notEqual(result.status, 0); assert.match(result.stderr, /owned by another checkout/);
});
test('exact-name foreign service collision refuses change', async () => {
  const result = await run([], [{ Name: 'test-demo-ops-1', Config: { Labels: {} } }]); assert.notEqual(result.status, 0); assert.match(result.stderr, /owned by another checkout/);
});
test('owned volumes and containers are accepted without selecting unrelated resources', async () => {
  const result = await run([{ Name: 'test-demo_state', Labels: labels }, { Name: 'another-project_state', Labels: {} }], [{ Name: 'test-demo-ops-1', Config: { Labels: labels } }]);
  assert.equal(result.status, 0); assert.equal(result.stdout.trim(), '2');
});
