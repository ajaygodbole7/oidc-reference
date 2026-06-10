import { expect, test } from "@playwright/test";

// Fast, backend-free smoke. Runs under `npm run test:e2e` (scripts/
// verify-frontend.sh) against the Vite dev server ALONE — no Keycloak /
// Valkey / BFF / Resource Server required. It asserts the one thing the SPA
// must get right with no backend: the anonymous landing page exposes a
// return_to-bearing sign-in entry and holds zero browser-side token state.
//
// The full authenticated flow (login, saved-request replay, logout, the
// no-token-reaches-the-browser invariant under a real Keycloak login) is
// covered end-to-end against the live stack by reference-flow.spec.ts
// (stories 1/3/4/5/9), which the e2e-auth gate runs with E2E_FULL_STACK=1.
// This file deliberately does NOT duplicate that with an E2E_FULL_STACK
// branch: a test.skip gated on a flag this runner never sets would be a
// permanently-skipped block masquerading as coverage.
test("anonymous home shows sign-in entry without browser-side tokens", async ({
  page
}) => {
  await page.goto("/");

  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  // Per return-to-login contract: a user-visible Sign in link must include
  // `return_to`; a bare `/auth/login` link is forbidden. On the anonymous
  // home page, the current route is "/" so the encoded value is "%2F".
  await expect(page.getByTestId("sign-in-link")).toHaveAttribute(
    "href",
    `/auth/login?return_to=${encodeURIComponent("/")}`
  );

  const browserState = await page.evaluate(() => ({
    localStorageKeys: Object.keys(localStorage),
    sessionStorageKeys: Object.keys(sessionStorage),
    cookieHeader: document.cookie
  }));
  expect(browserState.localStorageKeys).toEqual([]);
  expect(browserState.sessionStorageKeys).toEqual([]);
  expect(browserState.cookieHeader).not.toMatch(/access_token|refresh_token|id_token/i);
});
