import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false, // Sequential — shared DB state between tests
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  timeout: 60_000, // 60s per test — API calls may be slow
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://localhost:5174",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // API base for direct requests (login helper, etc.)
    extraHTTPHeaders: {
      Accept: "application/json",
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  // Re-use running dev server if available; otherwise start it
  webServer: {
    command: "pnpm dev",
    port: 5174,
    reuseExistingServer: true,
    timeout: 30_000,
  },
});
