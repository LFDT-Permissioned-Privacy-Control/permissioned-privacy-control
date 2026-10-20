import { FullConfig } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const EXPLORER_URL = process.env.EXPLORER_URL || '';
const MAX_RETRIES = 30;
const RETRY_DELAY_MS = 1000;

async function waitForService(url: string, name: string): Promise<void> {
  console.log(`Waiting for ${name} at ${url}...`);

  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      const response = await fetch(url, { method: 'GET' });
      if (response.ok) {
        console.log(`${name} is ready!`);
        return;
      }
    } catch {
      // Service not ready yet
    }

    await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY_MS));
  }

  throw new Error(`${name} at ${url} did not become ready after ${MAX_RETRIES} retries`);
}

async function globalSetup(config: FullConfig): Promise<void> {
  console.log('Starting global setup...');

  // Wait for proxy backend health endpoint
  await waitForService(`${PROXY_URL}/health`, 'Open Privacy Suite');

  // Check if any UI tests are being run by examining the projects
  const hasUIProject = config.projects.some(p => p.name === 'ui');
  const hasDemoProject = config.projects.some(p =>
    p.name === 'demo' || p.name === 'demo-setup' || p.name === 'demo-cleanup'
  );

  // Wait for frontend service if FRONTEND_URL is set and UI tests are included
  if (hasUIProject && FRONTEND_URL) {
    try {
      await waitForService(FRONTEND_URL, 'Frontend (Vite)');
    } catch (error) {
      console.warn(`Warning: Frontend not available at ${FRONTEND_URL}. UI tests may fail.`);
      // Don't throw - allow API tests to still run
    }
  }

  // Unlike the legacy UI suite, the demo acceptance suite is a security gate:
  // every surface is a hard prerequisite and must never degrade to a warning.
  if (hasDemoProject) {
    await waitForService(FRONTEND_URL, 'Admin frontend');
    if (!EXPLORER_URL) {
      throw new Error('EXPLORER_URL is required for the demo acceptance project');
    }
    await waitForService(EXPLORER_URL, 'Block explorer frontend');
    await waitForService(`${EXPLORER_URL}/api/stats`, 'Block explorer BFF');

    console.log(
      `Acceptance revisions: proxy=${process.env.PROXY_GIT_COMMIT || 'unknown'} ` +
      `explorer=${process.env.EXPLORER_GIT_COMMIT || 'unknown'} ` +
      `indexer=${process.env.INDEXER_VERSION || 'unknown'}`,
    );
  }

  console.log('All services ready!');
}

export default globalSetup;
