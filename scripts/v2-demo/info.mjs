import { readFile } from 'node:fs/promises';
import path from 'node:path';
const directory = process.env.OPS_V2_DEMO_CONTROL_DIR;
try {
  const runtime = JSON.parse(await readFile(path.join(directory, 'runtime.json')));
  console.log('Organization: Demo Bank (' + runtime.organizationId + ')');
  for (const [label, value] of [['Explorer', runtime.explorerOrigin], ['OPS', runtime.opsOrigin + '/login'], ['Demo identity wallet', runtime.walletOrigin], ['Contract', runtime.targetContract]]) console.log(label + ': ' + value);
  let result;
  try { result = JSON.parse(await readFile(path.join(directory, 'check-results.json'))); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (result?.passed) {
    console.log('Sample transaction: ' + runtime.explorerOrigin + '/transactions/' + result.transaction);
    if (result.sharedTransaction) console.log('Shared with Reader: ' + runtime.explorerOrigin + '/transactions/' + result.sharedTransaction);
    if (result.disclosureUrl) console.log('Sample disclosure (expires): ' + result.disclosureUrl);
    if (result.deployerActorId) console.log('Deployer client actor ID for a new disclosure: ' + result.deployerActorId);
  } else console.log('Run make demo-v2-check-prepared to create and verify a sample transaction and disclosure.');
} catch { console.error('Demo information unavailable; resume the prepared demo first.'); process.exitCode = 1; }
