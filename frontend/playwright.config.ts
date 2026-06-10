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
    // trace captures DOM/network/console on failure without needing the ffmpeg
    // binary that `video` requires — keep observability, drop the dependency.
    trace: "retain-on-failure"
  },
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:5173",
    // The full-stack gate (scripts/e2e-auth.sh, E2E_FULL_STACK=1) starts ONE
    // persistent Vite that must survive past the Playwright run for the gateway
    // refresh tests (mint-real-session traverses the :5173 SPA origin). Reuse it
    // there instead of letting Playwright start/stop its own — otherwise the
    // gateway phase has no :5173 origin and mint cannot complete login.
    reuseExistingServer: !process.env.CI || process.env.E2E_FULL_STACK === "1"
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
