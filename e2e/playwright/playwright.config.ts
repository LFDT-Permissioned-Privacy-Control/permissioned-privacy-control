import { defineConfig, devices, type PlaywrightTestConfig } from '@playwright/test';

const PROXY_URL = process.env.PROXY_URL || 'http://localhost:8080';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
const DEMO_E2E = process.env.DEMO_E2E === '1';
const IS_CI = /^(1|true|yes|on)$/i.test(process.env.CI || '');
const workerValue = process.env.E2E_PLAYWRIGHT_WORKERS || '1';
const WORKERS = Number.parseInt(workerValue, 10);
if (!Number.isInteger(WORKERS) || WORKERS < 1 || String(WORKERS) !== workerValue) {
  throw new Error('E2E_PLAYWRIGHT_WORKERS must be a positive integer');
}

const demoProjects: PlaywrightTestConfig['projects'] = DEMO_E2E ? [
  {
    name: 'demo-setup',
    testDir: './tests/demo',
    testMatch: /00-setup\.spec\.ts$/,
    teardown: 'demo-cleanup',
    use: { baseURL: PROXY_URL },
  },
  {
    name: 'demo',
    testDir: './tests/demo',
    testIgnore: /00-(?:setup|cleanup)\.spec\.ts$/,
    dependencies: ['demo-setup'],
    workers: 1,
    retries: 0,
    use: {
      ...devices['Desktop Chrome'],
      baseURL: process.env.EXPLORER_URL || 'http://localhost:3001',
      viewport: { width: 1440, height: 900 },
      actionTimeout: 15000,
      navigationTimeout: 30000,
      screenshot: 'only-on-failure',
      video: 'retain-on-failure',
    },
  },
  {
    name: 'demo-cleanup',
    testDir: './tests/demo',
    testMatch: /00-cleanup\.spec\.ts$/,
    use: { baseURL: PROXY_URL },
  },
] : [];

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: IS_CI,
  retries: IS_CI ? 2 : 0,
  workers: WORKERS,
  reporter: [
    ['html', { outputFolder: 'playwright-report' }],
    ['junit', { outputFile: 'test-results/junit.xml' }],
    ['list'],
  ],
  use: {
    trace: 'on-first-retry',
  },
  globalSetup: './global-setup.ts',
  timeout: 30000,
  expect: {
    timeout: 5000,
  },
  projects: [
    // API tests (existing)
    {
      name: 'api',
      testMatch: /^(?!.*\/(?:ui|demo)\/).*\.spec\.ts$/,
      use: {
        baseURL: PROXY_URL,
        extraHTTPHeaders: {
          'Content-Type': 'application/json',
          'X-Admin-Token': process.env.ADMIN_API_TOKEN || 'e2e-test-admin-token',
        },
      },
    },
    // UI tests (new)
    {
      name: 'ui',
      testDir: './tests/ui',
      use: {
        ...devices['Desktop Chrome'],
        baseURL: FRONTEND_URL,
        viewport: { width: 1280, height: 720 },
        actionTimeout: 10000,
        navigationTimeout: 15000,
        screenshot: 'only-on-failure',
        video: 'retain-on-failure',
      },
    },
    ...demoProjects,
  ],
});
