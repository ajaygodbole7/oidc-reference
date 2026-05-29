import { defineConfig, devices, type PlaywrightTestConfig } from "@playwright/test";

// Test against chromium only — this is a BFF reference, not a
// browser-compat matrix. Cross-browser fidelity would be the SPA's job
// in a real product.
const config: PlaywrightTestConfig = {
  testDir: "./tests/e2e",
  outputDir: "./test-results",
  fullyParallel: true,
  // Fail CI if a test.only sneaks into a commit.
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: process.env.CI ? [["html", { open: "never" }], ["github"]] : "html",
  use: {
    baseURL: "http://127.0.0.1:5173",
    screenshot: "only-on-failure",
    trace: "retain-on-failure"
  },
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
};

// One worker on CI keeps the live-stack-auth gate predictable; the same
// applies whenever the full local stack is in play (E2E_FULL_STACK=1) —
// the authenticated-session tests log in to a single Keycloak realm/user
// and clobber each other under parallel workers. Locally without the
// full stack the default (cpus/2) is fine because the only test is the
// anonymous-home check. With exactOptionalPropertyTypes, omit the
// optional property instead of assigning undefined.
if (process.env.CI || process.env.E2E_FULL_STACK === "1") {
  config.workers = 1;
}

export default defineConfig(config);
