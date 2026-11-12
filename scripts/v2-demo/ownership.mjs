// Refuse a Compose-name collision before operating on any existing resource.
import { spawnSync } from 'node:child_process';
const project = process.env.OPS_V2_DEMO_PROJECT, owner = process.env.OPS_V2_DEMO_ROOT;
if (!project || !owner) throw Error('Owned project selection required');
function docker(args) {
  const r = spawnSync('docker', args, { encoding: 'utf8', timeout: 30_000, maxBuffer: 4 << 20 });
  if (r.error || r.status !== 0) throw Error('Could not inspect demo resource ownership');
  return r.stdout.trim();
}
let count = 0;
for (const [kind, list] of [['container', ['ps', '-aq']], ['volume', ['volume', 'ls', '-q']]]) {
  const ids = new Set(docker([...list, '--filter', `label=com.docker.compose.project=${project}`]).split('\n').filter(Boolean));
  // Compose may reuse a pre-existing named volume after only a warning. Check
  // the exact names too, including resources with no Compose/ownership labels.
  const expected = kind === 'volume'
    ? ['state', 'wallet-config', 'ops-config', 'explorer-config', 'observer-config', 'reth-config', 'ops-spool', 'reth-data', 'postgres-data', 'circuits'].map(x => `${project}_${x}`)
    : ['bootstrap', 'postgres', 'reth', 'demo-wallet', 'indexer', 'ops', 'observer', 'explorer-api', 'explorer-admin', 'explorer-web'].map(x => `${project}-${x}-1`);
  const existing = new Set(docker([...list, '--format', kind === 'volume' ? '{{.Name}}' : '{{.Names}}']).split('\n').filter(Boolean));
  for (const name of expected) if (existing.has(name)) ids.add(name);
  if (!ids.size) continue;
  for (const item of JSON.parse(docker([kind, 'inspect', ...ids]))) {
    const labels = (kind === 'container' ? item.Config.Labels : item.Labels) ?? {};
    if (labels['com.gateway.ops-v2-demo.owner'] !== owner || labels['com.gateway.ops-v2-demo.project'] !== project) throw Error('Selected Compose project contains a resource owned by another checkout; refusing to change it');
    count++;
  }
}
console.log(count);
