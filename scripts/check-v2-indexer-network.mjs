#!/usr/bin/env node
// Finite network E2E using normal OPS/BFF/Indexer entrypoints and fresh state.
// This deliberately does not reuse, copy or reset a running demo's databases.
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const project = 'ops-v2-private-' + randomBytes(6).toString('hex');
const control = path.join(root, '.tmp/v2-network', project);
mkdirSync(control, { recursive: true, mode: 0o700 });
let phase = 'prerequisites', started = false;
const results = [];
const env = { ...process.env, DOCKER_CONFIG: path.join(root, '.tmp/v2-demo/docker-config') };
for (const key of ['DOCKER_CONTEXT', 'DOCKER_AUTH_CONFIG', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH']) delete env[key];
env.DOCKER_HOST ??= 'unix://' + path.join(process.env.HOME, '.orbstack/run/docker.sock');
const images = {};
for (const [key, target] of Object.entries({ OPS_V2_NETWORK_OPS_IMAGE: 'OPS_V2_IMAGE', OPS_V2_NETWORK_EXPLORER_IMAGE: 'OPS_EXPLORER_IMAGE', OPS_V2_NETWORK_INDEXER_IMAGE: 'OPS_INDEXER_IMAGE', OPS_V2_NETWORK_TOOLS_IMAGE: 'OPS_V2_TOOLS_IMAGE' })) {
  assert.ok(process.env[key], 'select ' + key); env[target] = process.env[key];
}
env.OPS_V2_CIRCUITS_DIRECTORY = path.join(root, '.tmp/v2-circuits');
assert.ok(existsSync(env.OPS_V2_CIRCUITS_DIRECTORY), 'existing hash-checked circuit directory required');
for (const [key, file] of Object.entries({ OPS_V2_ENV_FILE: 'ops.env', OPS_EXPLORER_ENV_FILE: 'explorer.env', OPS_INDEXER_ENV_FILE: 'indexer.env', OPS_OBSERVER_ENV_FILE: 'observer.env', OPS_INDEXER_POSTGRES_ENV_FILE: 'postgres.env', OPS_OPERATIONAL_POSTGRES_ENV_FILE: 'postgres.env', OPS_EXPLORER_POSTGRES_ENV_FILE: 'postgres.env', OPS_EXPLORER_ADMIN_ENV_FILE: 'explorer-admin.env' })) {
  env[key] = path.join(control, file); if (!existsSync(env[key])) writeFileSync(env[key], '', { mode: 0o600 });
}
env.OPS_V2_HOST_PORT = '0';
const composeArgs = ['compose', '-p', project, '-f', path.join(root, 'deploy/v2-private/compose.yml'), '-f', path.join(root, 'deploy/v2-private/test-fixture.yml')];
const docker = args => execFileSync('docker', args, { env, encoding: 'utf8', timeout: 180000, maxBuffer: 4 << 20, stdio: ['ignore', 'pipe', 'pipe'] });
const compose = args => docker([...composeArgs, ...args]);
const offline = args => compose(['run', '--rm', '--no-deps', '--pull', 'never', ...args]);
const exportFiles = () => offline(['--user', '0', '--entrypoint', 'sh', 'bootstrap', '/opt/v2-demo/export.sh']);
const copyOut = (source, name) => writeFileSync(path.join(control, name), offline(['--entrypoint', 'cat', 'bootstrap', source]), { mode: 0o600 });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const inspect = id => JSON.parse(docker(['inspect', id]))[0];
function snapshot(info) {
  return { id: info.Id, image: info.Image, running: info.State.Running, entrypoint: info.Config.Entrypoint, command: info.Config.Cmd,
    networkMode: info.HostConfig.NetworkMode, ports: info.HostConfig.PortBindings,
    networks: Object.fromEntries(Object.entries(info.NetworkSettings.Networks).map(([name, n]) => [name, { ipv4: n.IPAddress, ipv6: n.GlobalIPv6Address }])) };
}
function serviceID(service) { const ids = compose(['ps', '-q', service]).trim().split(/\s+/).filter(Boolean); assert.equal(ids.length, 1, service + ' must have one actual running container'); return ids[0]; }
function probe(id, target, mode = 'tcp', host = '') {
  const args = ['exec', id, '/tmp/ops-v2-network-probe', '--mode', mode, '--target', target];
  if (host) args.push('--host', host);
  const run = spawnSync('docker', args, { env, encoding: 'utf8', timeout: 6000 });
  const value = JSON.parse(run.stdout || '{}');
  assert.equal(typeof value.tcpConnected, 'boolean', 'probe did not execute normally');
  return { exit: run.status, ...value };
}
function endpoints(info) {
  return Object.entries(info.networks).flatMap(([network, n]) => [[network, n.ipv4], [network, n.ipv6]].filter(([, ip]) => ip).map(([network, ip]) => ({ network, ip })));
}
function target(ip, port) { return (ip.includes(':') ? '[' + ip + ']' : ip) + ':' + port; }
try {
  for (const kind of ['container', 'network', 'volume']) assert.equal(docker([kind, 'ls', '-q', '--filter', 'label=com.docker.compose.project=' + project]).trim(), '', 'fresh project already exists');
  for (const key of ['OPS_V2_IMAGE', 'OPS_EXPLORER_IMAGE', 'OPS_INDEXER_IMAGE', 'OPS_V2_TOOLS_IMAGE']) images[key] = JSON.parse(docker(['image', 'inspect', env[key]]))[0].Id;
  const arch = docker(['info', '--format', '{{.Architecture}}']).trim();
  assert.ok(['aarch64', 'arm64', 'x86_64', 'amd64'].includes(arch));
  const binary = path.join(control, 'probe');
  execFileSync(process.env.OPS_V2_TEST_GO || 'go', ['build', '-o', binary, './tools/v2-network-probe'], { cwd: root, env: { ...env, GOOS: 'linux', GOARCH: ['aarch64', 'arm64'].includes(arch) ? 'arm64' : 'amd64', CGO_ENABLED: '0', GOMAXPROCS: '2' }, timeout: 180000, stdio: 'pipe' });
  phase = 'fresh-state'; started = true;
  offline(['bootstrap', 'init', '--root', '/demo', '--private-network']);
  const runtime = JSON.parse(offline(['--entrypoint', 'cat', 'bootstrap', '/demo/runtime.json']));
  assert.equal(runtime.testOnly, true); assert.equal(runtime.privateNetwork, true);
  const p = runtime.ports;
  Object.assign(env, { OPS_V2_TLS_PORT: String(p.ops), OPS_INDEXER_GRPC_PORT: String(p.indexerGRPC), OPS_INDEXER_POSTGRES_PORT: String(p.postgres), OPS_OPERATIONAL_POSTGRES_PORT: String(p.postgres), OPS_EXPLORER_POSTGRES_PORT: String(p.postgres), OPS_V2_RETH_PORT: String(p.rpc), OPS_V2_ENGINE_PORT: String(p.engine) });
  copyOut('/demo/private/postgres.env', 'postgres.env'); exportFiles();
  offline(['--user', '0', '--entrypoint', 'sh', 'bootstrap', '-ec', 'cp -R /host-circuits/. /circuits/; chown -R 1000:1000 /circuits; find /circuits -type f -exec chmod 644 {} \\;']);
  compose(['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '90', 'operational-postgres', 'indexer-postgres', 'explorer-postgres']);
  compose(['up', '-d', '--no-build', '--pull', 'never', 'reth']);
  offline(['--entrypoint', 'node', 'bootstrap', 'scripts/v2-demo/wait-rpc.mjs']);
  compose(['up', '-d', '--no-build', '--pull', 'never', '--wait', '--wait-timeout', '90', 'demo-wallet']);
  offline(['bootstrap', 'configure', '--root', '/demo', '--prepare-databases']);
  copyOut('/demo/indexer.env', 'indexer.env');
  compose(['up', '-d', '--no-build', '--pull', 'never', 'indexer']);
  offline(['bootstrap', 'configure', '--root', '/demo', '--wallet-output', '/wallet-output/wallet-state']);
  for (const name of ['ops', 'explorer', 'observer']) copyOut('/demo/' + name + '/env', name + '.env');
  copyOut('/demo/private/explorer-admin.env', 'explorer-admin.env'); exportFiles();
  offline(['explorer-admin']);
  // The state is freshly initialized once, never a copy of the active demo.
  offline(['--entrypoint', '/bin/sh', 'explorer-admin', '-ec', 'exec sso-v2-admin --source /demo/explorer/source.json --sha256 "$(cat /demo/explorer/source.sha256)" --action initialize']);
  compose(['up', '-d', '--no-build', '--pull', 'never', 'observer', 'ops', 'explorer-api']);
  phase = 'normal-runtime-availability';
  const services = {};
  for (const service of ['ops', 'explorer-api', 'observer', 'indexer', 'indexer-postgres', 'operational-postgres', 'explorer-postgres', 'reth']) {
    const id = serviceID(service), info = inspect(id); assert.equal(info.State.Running, true);
    services[service] = snapshot(info);
    docker(['cp', binary, id + ':/tmp/ops-v2-network-probe']);
  }
  const apiNetwork = project + '_indexer-api';
  const members = JSON.parse(docker(['network', 'inspect', apiNetwork]))[0].Containers;
  assert.deepEqual(Object.keys(members).sort(), [services.ops.id, services.indexer.id].sort(), 'only actual OPS and Indexer may join the API network');
  for (const s of ['indexer', 'indexer-postgres']) assert.ok(!services[s].ports || Object.values(services[s].ports).every(v => !v?.length), s + ' must publish no ports');
  const apiIP = services.indexer.networks[apiNetwork].ipv4;
  const opsFrontIP = services.ops.networks[project + '_front'].ipv4;
  const bffFrontIP = services['explorer-api'].networks[project + '_front'].ipv4;
  const until = Date.now() + 60000;
  let positive, opsReady, bffReady;
  do {
    positive = probe(services.ops.id, target(apiIP, p.indexerGRPC), 'grpc');
    opsReady = probe(services.ops.id, target(opsFrontIP, p.ops), 'https', 'localhost:' + p.ops);
    bffReady = probe(services['explorer-api'].id, target(bffFrontIP, p.explorerAPI), 'http', 'localhost:' + p.explorer);
    if (positive.grpcHealthy && opsReady.httpHealthy && bffReady.httpHealthy) break;
    await sleep(500);
  } while (Date.now() < until);
  assert.equal(positive.grpcHealthy, true, 'actual Indexer API must be healthy from the OPS namespace');
  assert.equal(opsReady.httpHealthy, true, 'normal OPS runtime must be ready');
  assert.equal(bffReady.httpHealthy, true, 'normal Explorer BFF runtime must be ready');
  results.push({ case: 'real-api-and-normal-runtime-controls', passed: true });
  phase = 'numeric-IP-negative-matrix';
  for (const [source, info] of Object.entries(services)) {
    if (source === 'indexer') continue;
    for (const endpoint of endpoints(services.indexer)) {
      const expected = source === 'ops' && endpoint.network === apiNetwork;
      const observed = probe(info.id, target(endpoint.ip, p.indexerGRPC));
      assert.equal(observed.tcpConnected, expected, source + ' has unexpected raw Indexer connectivity via ' + endpoint.network);
      results.push({ case: 'indexer-port', source, targetNetwork: endpoint.network, ip: endpoint.ip, permitted: expected, passed: true });
    }
  }
  const dbIP = services['indexer-postgres'].networks[project + '_indexer-state'].ipv4;
  for (const source of ['ops', 'explorer-api', 'observer']) {
    assert.equal(probe(services[source].id, target(dbIP, p.postgres)).tcpConnected, false, source + ' reached private Indexer SQL');
    results.push({ case: 'indexer-private-storage', source, permitted: false, passed: true });
  }
  const nodeIP = services.reth.networks[project + '_chain'].ipv4;
  assert.equal(probe(services['explorer-api'].id, target(nodeIP, p.rpc)).tcpConnected, false, 'Explorer BFF reached the raw node RPC');
  assert.equal(probe(services.observer.id, target(nodeIP, p.rpc)).tcpConnected, true, 'observer cannot reach its configured node');
  results.push({ case: 'raw-node-boundary', source: 'explorer-api', permitted: false, passed: true });
  assert.equal(probe(services['explorer-api'].id, target(opsFrontIP, p.ops)).tcpConnected, true, 'BFF negative must not be caused by a dead namespace');
  phase = 'indexer-outage-recovery';
  compose(['stop', '--timeout', '10', 'indexer']);
  assert.equal(probe(services.ops.id, target(apiIP, p.indexerGRPC)).tcpConnected, false, 'Indexer outage control must actually disconnect');
  assert.equal(probe(services.ops.id, target(opsFrontIP, p.ops), 'https', 'localhost:' + p.ops).httpHealthy, true, 'Indexer outage must not block ordinary OPS readiness');
  assert.equal(inspect(services.ops.id).State.Running, true);
  results.push({ case: 'indexer-outage-ordinary-ops-ready', passed: true });
  compose(['start', 'indexer']);
  const recoverUntil = Date.now() + 60000;
  let recovered;
  do {
    recovered = probe(services.ops.id, target(apiIP, p.indexerGRPC), 'grpc');
    if (recovered.grpcHealthy) break;
    await sleep(500);
  } while (Date.now() < recoverUntil);
  assert.equal(recovered.grpcHealthy, true, 'Indexer must recover without restarting OPS');
  assert.equal(serviceID('ops'), services.ops.id, 'OPS must retain its original container');
  assert.equal(probe(services.ops.id, target(opsFrontIP, p.ops), 'https', 'localhost:' + p.ops).httpHealthy, true);
  results.push({ case: 'indexer-recovery-without-ops-restart', passed: true });
  for (const [name, info] of Object.entries(services)) assert.equal(inspect(info.id).State.Running, true, name + ' exited during the test');
  writeFileSync(path.join(control, 'results.json'), JSON.stringify({ passed: true, project, images, services, results, scope: 'Normal runtime containers, actual healthy Indexer gRPC/PostgreSQL/Reth, numeric-IP namespace connectivity; no Indexer authentication.' }, null, 2) + '\n', { mode: 0o600 });
  console.log('PASS V2 private Indexer network: ' + results.length + ' checks; evidence ' + path.join(control, 'results.json'));
} catch (error) {
  writeFileSync(path.join(control, 'failure-private.log'), String(error.stack ?? error) + '\n' + String(error.stderr ?? ''), { mode: 0o600 });
  if (started) {
    try { writeFileSync(path.join(control, 'runtime-private.log'), compose(['logs', '--no-color', '--tail', '40', 'ops', 'explorer-api', 'observer', 'indexer']), { mode: 0o600 }); } catch {}
  }
  writeFileSync(path.join(control, 'results.json'), JSON.stringify({ passed: false, phase, category: error.name, results }, null, 2) + '\n', { mode: 0o600 });
  console.error('FAIL V2 private Indexer network phase=' + phase + ' category=' + error.name); process.exitCode = 1;
} finally {
  if (started) {
    // Unique fresh project; no active demo, named external volume or shared
    // image is removed. Keep the private evidence after container teardown.
    try { compose(['down', '--volumes', '--remove-orphans', '--timeout', '15']); } catch { console.error('Owned network fixture cleanup incomplete: ' + project); process.exitCode = 1; }
  }
}
