import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { DemoScenarioManifest } from './types.js';

const manifestPath = resolve(
  process.env.DEMO_MANIFEST_PATH || 'test-results/demo-scenario.json',
);

export async function writeDemoManifest(manifest: DemoScenarioManifest): Promise<void> {
  await mkdir(dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
}

export async function readDemoManifest(): Promise<DemoScenarioManifest> {
  const raw = await readFile(manifestPath, 'utf8');
  const parsed = JSON.parse(raw) as DemoScenarioManifest;
  if (parsed.version !== 1) {
    throw new Error(`Unsupported demo manifest version: ${String(parsed.version)}`);
  }
  return parsed;
}

export function demoManifestPath(): string {
  return manifestPath;
}
