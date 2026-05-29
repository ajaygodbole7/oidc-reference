import { expect, test, type BrowserContext, type Page } from "@playwright/test";

type BrowserStorageState = {
  readonly localStorage: Record<string, string>;
  readonly sessionStorage: Record<string, string>;
  readonly cookieHeader: string;
  readonly indexedDBNames: readonly string[];
};

// Always-on: confirms the anonymous landing page has no browser-side state.
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

// Full-stack login → assert no tokens reach the browser. Requires the
// canonical local stack (Keycloak + Valkey + BFF + Resource Server) and
// E2E_FULL_STACK=1. Otherwise skipped.
test.describe("authenticated session", () => {
  test.skip(
    process.env.E2E_FULL_STACK !== "1",
    "Requires the full local stack; set E2E_FULL_STACK=1"
  );

  test("after Keycloak login, no token reaches the browser", async ({
    page,
    context
  }) => {
    await loginAsAlice(page);
    await assertNoBrowserTokens(page, context);

    // Belt and braces: the in-context check happened inside the helper. We
    // also assert sid attributes directly here so the contract is explicit.
    const cookies = await context.cookies();
    const sid = cookies.find((c) => c.name === "sid");
    expect(sid, "session cookie sid must be set").toBeDefined();
    expect(sid!.httpOnly).toBe(true);
    expect(sid!.sameSite).toBe("Lax");
  });

  test("unauthenticated API fetch returns 401 without OAuth redirect", async ({ page }) => {
    await page.goto("/");

    const result = await page.evaluate(async () => {
      const res = await fetch("/api/user-data", {
        credentials: "include",
        headers: { Accept: "application/json" }
      });
      return {
        status: res.status,
        redirected: res.redirected,
        responseUrl: res.url,
        pageUrl: window.location.href
      };
    });

    expect(result.status).toBe(401);
    expect(result.redirected).toBe(false);
    expect(result.responseUrl).toBe("http://127.0.0.1:5173/api/user-data");
    expect(result.pageUrl).toBe("http://127.0.0.1:5173/");
  });

  test("saved-request login returns to the protected URL", async ({ page, context }) => {
    // Per return-to-login contract: the browser never navigates directly to
    // /api/** to start login. It uses /auth/login?return_to=<protected path>.
    // The Auth Service validates return_to and persists it as saved_request
    // in tx:{state}; the callback replays only saved_request.
    await page.goto(`/auth/login?return_to=${encodeURIComponent("/api/user-data")}`);

    await page.waitForURL(/realms\/oidc-reference\/protocol\/openid-connect\/auth/);
    await page.fill("#username", "alice");
    await page.fill("#password", "alice");
    await Promise.all([
      page.waitForURL("http://127.0.0.1:5173/api/user-data"),
      page.click("#kc-login")
    ]);

    await expect(page).toHaveURL("http://127.0.0.1:5173/api/user-data");
    await expect(page.locator("body")).toContainText("user-data");
    await assertNoBrowserTokens(page, context);
  });

  test("logout clears the BFF session and returns unauthenticated", async ({
    page,
    context
  }) => {
    await loginAsAlice(page);
    await page.getByRole("button", { name: /sign out/i }).click();

    await page.waitForURL("http://127.0.0.1:5173/");
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

    const cookies = await context.cookies();
    expect(cookies.find((c) => c.name === "sid")).toBeUndefined();
    await assertNoBrowserTokens(page, context);
  });
});

async function loginAsAlice(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(/realms\/oidc-reference\/protocol\/openid-connect\/auth/);
  await page.fill("#username", "alice");
  await page.fill("#password", "alice");
  await Promise.all([
    page.waitForURL("http://127.0.0.1:5173/"),
    page.click("#kc-login")
  ]);
  await expect(page.getByText(/signed in as/i)).toBeVisible();
}

async function assertNoBrowserTokens(page: Page, context: BrowserContext) {
  const browserState = await page.evaluate(async (): Promise<BrowserStorageState> => {
    const localStorageValues: Record<string, string> = {};
    for (let i = 0; i < localStorage.length; i += 1) {
      const key = localStorage.key(i);
      if (key) localStorageValues[key] = localStorage.getItem(key) ?? "";
    }
    const sessionStorageValues: Record<string, string> = {};
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const key = sessionStorage.key(i);
      if (key) sessionStorageValues[key] = sessionStorage.getItem(key) ?? "";
    }
    let indexedDBNames: string[] = [];
    if (typeof indexedDB.databases === "function") {
      try {
        const dbs = await indexedDB.databases();
        indexedDBNames = dbs.map((d) => d.name ?? "").filter(Boolean);
      } catch {
        // ignore
      }
    }
    return {
      localStorage: localStorageValues,
      sessionStorage: sessionStorageValues,
      cookieHeader: document.cookie,
      indexedDBNames
    };
  });

  // JWS (3 segments) and JWE (5 segments) shapes, plus a length-based
  // catch for opaque tokens — refresh tokens are JWE in many IdPs and
  // would slip through a JWS-only check.
  const looksLikeJws = (v: string) =>
    /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
  const looksLikeJwe = (v: string) =>
    /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){4}$/.test(v);
  const looksLikeOpaqueToken = (v: string) =>
    v.length > 200 && /^[A-Za-z0-9_.-]+$/.test(v);
  const looksLikeTokenName = (v: string) =>
    /access_token|refresh_token|id_token/i.test(v);

  for (const [key, value] of Object.entries(browserState.localStorage)) {
    expect(looksLikeJws(value), `localStorage[${key}] looks like JWS`).toBeFalsy();
    expect(looksLikeJwe(value), `localStorage[${key}] looks like JWE`).toBeFalsy();
    expect(looksLikeOpaqueToken(value), `localStorage[${key}] looks like opaque token`).toBeFalsy();
    expect(looksLikeTokenName(key + value)).toBeFalsy();
  }
  for (const [key, value] of Object.entries(browserState.sessionStorage)) {
    expect(looksLikeJws(value), `sessionStorage[${key}] looks like JWS`).toBeFalsy();
    expect(looksLikeJwe(value), `sessionStorage[${key}] looks like JWE`).toBeFalsy();
    expect(looksLikeOpaqueToken(value), `sessionStorage[${key}] looks like opaque token`).toBeFalsy();
    expect(looksLikeTokenName(key + value)).toBeFalsy();
  }
  expect(browserState.indexedDBNames).toEqual([]);
  expect(browserState.cookieHeader).not.toMatch(/access_token|refresh_token|id_token/i);

  // Real HttpOnly proof: sid (if present) must be HttpOnly + SameSite=Lax.
  // document.cookie never sees HttpOnly cookies, so checking that string
  // for "sid=" would be a tautology — assert via the browser context API.
  // SameSite=Lax (not Strict) is required for the OAuth callback flow:
  // the browser's navigation chain originates cross-site from Keycloak,
  // and a Strict sid would not be sent on the final 302 hop to the
  // saved-request URL. See AuthController#sidCookie for the rationale.
  const cookies = await context.cookies();
  const sid = cookies.find((c) => c.name === "sid");
  if (sid) {
    expect(sid.httpOnly, "sid must be HttpOnly").toBe(true);
    expect(sid.sameSite).toBe("Lax");
  }
}
