#!/usr/bin/env node
/**
 * Mint a real local BFF session through the Authorization Code + PKCE login
 * flow and print ONLY the opaque sid cookie value.
 *
 * This exists for the gateway refresh-delegation test. That test must not seed
 * a synthetic sess:{sid} with fake refresh_token material, because the Auth
 * Service correctly delegates refresh to the real IdP. A fake refresh_token
 * produces a 502 from /internal/resolve and proves only that the fixture is
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
// The browser ORIGIN the login flow runs through. The Auth Service pins the
// OAuth redirect_uri to APP_BASE_URL (the SPA origin, 127.0.0.1:5173 locally),
// so login + callback must traverse that origin — driving the flow from the
// gateway origin (:9080) would have the callback redirect to :5173 and strand
// the browser. Defaults to the same value as APP_BASE_URL. Cookies are
// host-scoped (port-agnostic), so the minted sid is readable at gatewayBase
// regardless.
const appOrigin = process.env.E2E_APP_ORIGIN ?? "http://127.0.0.1:5173";
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
  await page.goto(`${appOrigin}/auth/login?return_to=${returnTo}`, {
    waitUntil: "domcontentloaded"
  });
  await page.waitForURL(authUrlPattern, { timeout: 30_000 });
  await page.fill("#username", username);
  await page.fill("#password", password);
  await page.click("#kc-login");

  // Poll for the session cookie rather than waiting for a specific landing URL.
  // The callback issues Set-Cookie on its 302; the exact final URL depends on
  // the saved_request and the pinned origin, so the cookie is the reliable
  // signal that login completed.
  const deadline = Date.now() + 30_000;
  let sid;
  while (Date.now() < deadline) {
    const cookies = await context.cookies([appOrigin, gatewayBase]);
    sid = cookies.find((cookie) => cookie.name === "__Host-sid")
      ?? cookies.find((cookie) => cookie.name === "sid");
    if (sid?.value) break;
    await page.waitForTimeout(250);
  }
  if (!sid?.value) {
    fail("login completed but no sid cookie was issued");
  }

  process.stdout.write(sid.value);
} finally {
  await browser.close();
}
