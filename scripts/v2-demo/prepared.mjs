// Check the existing installation only; never download, install or build.
import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { verifyArtifacts } from '../v2-test-prerequisites.mjs';
import { repositoryRoot as root, walletModules, circuitDirectory } from '../../tools/v2-test-wallet/artifacts.mjs';

try {
  assert.equal(Number(process.versions.node.split('.')[0]), 24, 'Use Node 24');
  const project = process.env.OPS_V2_DEMO_PROJECT, directory = process.env.OPS_V2_DEMO_CONTROL_DIR;
  assert.ok(project && directory, 'Select the demo through scripts/v2-demo.sh');
  assert.equal(walletModules, path.join(root, 'tools/v2-test-wallet/node_modules'), 'Cached demo uses its own installed wallet dependencies');
  for (const id of ['authV2', 'credentialAtomicQuerySigV2']) assert.equal(circuitDirectory(id), path.join(root, '.tmp/v2-circuits', id));
  assert.ok(await verifyArtifacts(), 'Pinned circuits missing or changed; initial setup is required');
  const expected = JSON.parse(await readFile(path.join(root, 'tools/v2-test-wallet/package.json')));
  for (const [name, version] of Object.entries(expected.dependencies)) {
    const installed = JSON.parse(await readFile(path.join(walletModules, name, 'package.json')));
    assert.equal(installed.version, version, 'Cached wallet dependency differs from its pin: ' + name);
  }
  const images = spawnSync('docker', ['compose', '--env-file', path.join(directory, 'ports.env'), '-p', project,
    '-f', path.join(root, 'deploy/v2-demo/compose.yml'), 'config', '--images'], { encoding: 'utf8', timeout: 15_000 });
  assert.equal(images.status, 0, 'Cannot select existing demo images');
  const inspect = spawnSync('docker', ['image', 'inspect', ...new Set(images.stdout.trim().split(/\s+/))], { stdio: 'ignore', timeout: 15_000 });
  assert.equal(inspect.status, 0, 'A cached demo image is missing; initial setup is required');
  if (process.argv[2] === 'browser') {
    const manifest = JSON.parse(await readFile(path.join(root, 'e2e/playwright/package.json')));
    const installed = JSON.parse(await readFile(path.join(root, 'e2e/playwright/node_modules/@playwright/test/package.json')));
    assert.equal(installed.version, manifest.devDependencies['@playwright/test']);
    const channel = process.env.OPS_TEST_BROWSER_CHANNEL ?? 'chrome';
    if (channel === 'chromium') {
      const require = createRequire(path.join(root, 'e2e/playwright/package.json'));
      await access(require('@playwright/test').chromium.executablePath());
    } else {
      assert.equal(channel, 'chrome', 'Cached walkthrough supports chrome or installed chromium');
      await access(process.platform === 'darwin' ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : '/opt/google/chrome/chrome');
    }
  } else assert.equal(process.argv[2], 'runtime');
  console.log('Existing demo prerequisites verified; no build or download performed.');
} catch (error) {
  console.error('Prepared demo: ' + error.message);
  process.exitCode = 1;
}
