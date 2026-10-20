import { access } from 'node:fs/promises';
import { test } from '@playwright/test';
import { RBACApiClient } from '../../helpers/rbac-api';
import { demoManifestPath, readDemoManifest } from '../../helpers/demo/state';

test('remove the demo acceptance organizations', async ({ request }) => {
  try {
    await access(demoManifestPath());
  } catch {
    return;
  }
  const manifest = await readDemoManifest();
  const sa = new RBACApiClient(request);
  for (const orgId of [...manifest.cleanup.orgIds].reverse()) {
    await sa.deleteOrganization(orgId);
  }
});
