#!/usr/bin/env node
/**
 * Mint a real local BFF session through the Authorization Code + PKCE login
 * flow and print ONLY the opaque sid cookie value.
 *
 * This exists for the gateway refresh-delegation test. That test must not seed
 * a synthetic sess:{sid} with fake refresh_token material, because the Auth
 * Service correctly delegates refresh to the real IdP. A fake refresh_token
 * produces a 502 from /internal/refresh and proves only that the fixture is
 * impossible. This helper obtains a real Keycloak refresh token by completing
 * the login flow through APISIX.
 */

import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const requireFromFrontend = createRequire(
  new URL("../../frontend/package.json", import.meta.url)
);
const { chromium } = requireFromFrontend("@playwright/test");

const gatewayBase = process.env.GATEWAY_BASE ?? "http://127.0.0.1:9080";
const username = process.env.E2E_USERNAME ?? "alice";
const password = process.env.E2E_PASSWORD ?? "alice";
const realmName = process.env.E2E_REALM_NAME ?? "oidc-reference";
const headless = process.env.E2E_HEADLESS !== "0";

const authUrlPattern = process.env.E2E_AUTH_URL_PATTERN
  ? new RegExp(process.env.E2E_AUTH_URL_PATTERN)
  : new RegExp(
      `realms\\/${realmName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\/protocol\\/openid-connect\\/auth`
    );

function fail(message) {
  process.stderr.write(`${path.basename(fileURLToPath(import.meta.url))}: ${message}\n`);
  process.exit(1);
}

const browser = await chromium.launch({ headless });
try {
  const context = await browser.newContext();
  const page = await context.newPage();

  const returnTo = encodeURIComponent("/api/me");
  await page.goto(`${gatewayBase}/auth/login?return_to=${returnTo}`, {
    waitUntil: "domcontentloaded"
  });
  await page.waitForURL(authUrlPattern, { timeout: 30_000 });
  await page.fill("#username", username);
  await page.fill("#password", password);
  await Promise.all([
    page.waitForURL(`${gatewayBase}/api/me`, { timeout: 30_000 }),
    page.click("#kc-login")
  ]);

  const cookies = await context.cookies(gatewayBase);
  const sid = cookies.find((cookie) => cookie.name === "__Host-sid")
    ?? cookies.find((cookie) => cookie.name === "sid");
  if (!sid?.value) {
    fail("login completed but no sid cookie was issued");
  }

  process.stdout.write(sid.value);
} finally {
  await browser.close();
}
