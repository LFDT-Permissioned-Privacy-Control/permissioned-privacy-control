import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for demo video recording.
 * Optimized for VERY HIGH QUALITY 1080p video capture.
 */
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: [["html", { open: "never" }], ["list"]],
  timeout: 180000, // 3 minutes for longer demos

  use: {
    baseURL: process.env.BASE_URL || "http://localhost:5173",
    trace: "on",
    screenshot: "on",
    video: {
      mode: "on",
      size: { width: 1920, height: 1080 },
    },
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1, // Prevent DPI scaling issues
    actionTimeout: 30000,  // Increased for high-res screenshots
    navigationTimeout: 30000,
  },

  projects: [
    {
      name: "recording",
      use: {
        ...devices["Desktop Chrome"],
        channel: "chrome",
        launchOptions: {
          args: [
            "--disable-blink-features=AutomationControlled",
            "--disable-infobars",
            "--start-maximized",
            // Stable rendering for macOS
            "--disable-gpu-vsync",
          ],
        },
      },
    },
  ],

  webServer: process.env.NO_SERVER
    ? undefined
    : {
        command: "cd ../../frontend && npm run dev",
        url: "http://localhost:5173",
        reuseExistingServer: !process.env.CI,
        timeout: 60000,
      },

  outputDir: "./test-results",
});
