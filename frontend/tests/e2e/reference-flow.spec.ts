/**
 * reference-flow.spec.ts — canonical authenticated proof of the BFF/OIDC
 * reference flow.
 *
 * This suite runs ONLY under the full local stack (Keycloak + Valkey + Auth
 * Service / BFF + API Gateway + Resource Server) with E2E_FULL_STACK=1 and
 * baseURL http://127.0.0.1:5173. There are deliberately NO test.skip gates:
 * the harness that invokes this file is responsible for standing up the stack.
 * Stories are INDEPENDENT: each story performs its own login/setup and never
 * relies on a previous story leaving a session behind. The suite runs under a
 * single worker (--workers=1), so stories still execute sequentially on one
 * worker, but they do NOT run under Playwright "serial" mode — a single
 * story's failure must NOT skip the remaining stories, so all stories always
 * report. The one story that mutates shared server-side state (story 12's
 * deterministic session DELETE) creates and deletes its own session.
 *
 * PRECISE INVARIANT asserted throughout (never the weaker "tokens never reach
 * the browser"):
 *   - Access tokens and refresh tokens must NEVER reach the browser at all.
 *   - ID tokens must never reach browser JavaScript, browser storage, frontend
 *     code, SPA-readable JSON, SPA-visible cookies, or app logs.
 *   - The ONLY tolerated appearance of an ID token is inside a server-generated
 *     top-level redirect Location from /auth/logout/continue to the IdP
 *     (RP-initiated logout id_token_hint).
 *   - Authorization codes are tolerated only as normal OIDC front-channel
 *     callback artifacts (the code= query param on /auth/callback/idp).
 *
 * SCOPE — this file proves STABLE user-facing behavior only.
 * Two security properties are REQUIRED of the system but are intentionally NOT
 * proven here, because doing so through the browser is brittle theater (it
 * couples the assertion to refresh timing, live Valkey record mutation, and
 * Keycloak token state). They are proven deterministically at the integration
 * layer instead:
 *   - Token refresh (success + refresh-token-reuse failure): proven by the
 *     gateway seeded-Valkey refresh test
 *     (api-gateway/tests/test-gateway-behavior.sh, RUN_REFRESH_TESTS=1) and by
 *     the Auth Service /internal/refresh tests (AuthControllerTest).
 *   - Browser-binding replay rejection: proven by AuthControllerTest oauth_tx
 *     callback tests — a callback with a valid state but a missing/mismatched
 *     oauth_tx is rejected before token exchange (no __Host-sid, no saved-
 *     request replay).
 * The one server-state interaction this file does perform (a single
 * deterministic session DELETE, story 12) is not timing-sensitive.
 */

import {
  expect,
  test,
  type BrowserContext,
  type Page,
  type Cookie
} from "@playwright/test";
import { execSync } from "node:child_process";

const APP_ORIGIN = "http://127.0.0.1:5173";
const REALM_NAME = process.env.E2E_REALM_NAME ?? "oidc-reference";
const ALICE = { username: "alice", password: "alice" } as const;
// admin holds realm roles ["user","admin"] in the active test realm. The RS
// maps the configured role claim path to ROLE_admin, which guards POST
// /api/admin.
const ADMIN = { username: "admin", password: "admin" } as const;

// "default" mode (NOT "serial"): one story's failure must not skip its
// siblings. The runner uses --workers=1, so stories still run sequentially on
// a single worker, but without serial mode's skip-on-first-failure behavior —
// every story reports its own result and each is independently self-contained.
test.describe.configure({ mode: "default" });

// ---------------------------------------------------------------------------
// Local helpers (kept in-file by request; mirror auth.spec.ts patterns).
// ---------------------------------------------------------------------------

type BrowserStorageState = {
  readonly localStorage: Record<string, string>;
  readonly sessionStorage: Record<string, string>;
  readonly cookieHeader: string;
  readonly indexedDBNames: readonly string[];
};

const KEYCLOAK_AUTH_RE = process.env.E2E_AUTH_URL_PATTERN
  ? new RegExp(process.env.E2E_AUTH_URL_PATTERN)
  : new RegExp(
      `realms\\/${REALM_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\/protocol\\/openid-connect\\/auth`
    );

async function loginAs(
  page: Page,
  creds: { username: string; password: string }
): Promise<void> {
  await page.goto("/");
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  await page.fill("#username", creds.username);
  await page.fill("#password", creds.password);
  await Promise.all([
    page.waitForURL(`${APP_ORIGIN}/`),
    page.click("#kc-login")
  ]);
  await expect(page.getByText(/signed in as/i)).toBeVisible();
}

function looksLikeJws(v: string): boolean {
  return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(v);
}
function looksLikeJwe(v: string): boolean {
  return /^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+){4}$/.test(v);
}
function looksLikeOpaqueToken(v: string): boolean {
  return v.length > 200 && /^[A-Za-z0-9_.-]+$/.test(v);
}
function looksLikeTokenName(v: string): boolean {
  return /access_token|refresh_token|id_token/i.test(v);
}

/**
 * Enforces the precise invariant for the JS-readable / storage surfaces:
 * no access/refresh/ID token (or token-shaped string) is reachable from
 * localStorage, sessionStorage, IndexedDB, or document.cookie. HttpOnly
 * cookies (sid) are invisible to document.cookie by definition and are
 * checked via the context API instead.
 */
async function assertNoBrowserTokens(
  page: Page,
  context: BrowserContext
): Promise<void> {
  const browserState = await page.evaluate(
    async (): Promise<BrowserStorageState> => {
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
          /* ignore */
        }
      }
      return {
        localStorage: localStorageValues,
        sessionStorage: sessionStorageValues,
        cookieHeader: document.cookie,
        indexedDBNames
      };
    }
  );

  for (const [key, value] of Object.entries(browserState.localStorage)) {
    expect(looksLikeJws(value), `localStorage[${key}] looks like JWS`).toBeFalsy();
    expect(looksLikeJwe(value), `localStorage[${key}] looks like JWE`).toBeFalsy();
    expect(
      looksLikeOpaqueToken(value),
      `localStorage[${key}] looks like opaque token`
    ).toBeFalsy();
    expect(looksLikeTokenName(key + value)).toBeFalsy();
  }
  for (const [key, value] of Object.entries(browserState.sessionStorage)) {
    expect(looksLikeJws(value), `sessionStorage[${key}] looks like JWS`).toBeFalsy();
    expect(looksLikeJwe(value), `sessionStorage[${key}] looks like JWE`).toBeFalsy();
    expect(
      looksLikeOpaqueToken(value),
      `sessionStorage[${key}] looks like opaque token`
    ).toBeFalsy();
    expect(looksLikeTokenName(key + value)).toBeFalsy();
  }
  expect(browserState.indexedDBNames).toEqual([]);
  // document.cookie must never name OR carry a token. Cookie values are the
  // SPA-visible cookie surface; the opaque sid lives in an HttpOnly cookie and
  // is invisible here.
  expect(browserState.cookieHeader).not.toMatch(
    /access_token|refresh_token|id_token/i
  );
  for (const part of browserState.cookieHeader.split(";")) {
    const value = part.split("=").slice(1).join("=").trim();
    if (!value) continue;
    expect(looksLikeJws(value), `cookie value looks like JWS: ${part}`).toBeFalsy();
    expect(looksLikeJwe(value), `cookie value looks like JWE: ${part}`).toBeFalsy();
  }

  const sid = (await context.cookies()).find((c) => c.name === "sid");
  if (sid) {
    expect(sid.httpOnly, "sid must be HttpOnly").toBe(true);
    expect(sid.sameSite).toBe("Lax");
  }
}

function sidFrom(cookies: readonly Cookie[]): string {
  const sid = cookies.find((c) => c.name === "sid");
  expect(sid, "session cookie sid must be set").toBeDefined();
  expect(sid!.httpOnly, "sid must be HttpOnly").toBe(true);
  return sid!.value;
}

// --- Valkey access via the same mechanism as api-gateway/tests/lib.sh -------
// `docker compose exec -T valkey valkey-cli ...` from the repo root. The repo
// root is two levels up from frontend/tests/e2e. sess records are keyed by
// sess:{sid}; the sid is HttpOnly so it is read from context.cookies().
//
// This file uses Valkey for exactly ONE deterministic operation: deleting a
// session record server-side (story 12). That is a state DELETE, not a
// timing-sensitive expiry — no refresh-window or TTL race is involved.

const REPO_ROOT = new URL("../../../", import.meta.url).pathname;

// Shell-safe single-quote wrapping for each arg before handing to the shell.
function valkey(args: string[]): string {
  const quoted = args
    .map((a) => `'${a.replace(/'/g, `'\\''`)}'`)
    .join(" ");
  return execSync(`docker compose exec -T valkey valkey-cli ${quoted}`, {
    cwd: REPO_ROOT,
    encoding: "utf8"
  }).trim();
}

async function keycloakAdminToken(): Promise<string> {
  const body = new URLSearchParams({
    grant_type: "password",
    client_id: "admin-cli",
    username: "admin",
    password: "admin"
  });
  const res = await fetch("http://localhost:8080/realms/master/protocol/openid-connect/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  expect(res.status, "admin token request").toBe(200);
  const json = (await res.json()) as { access_token?: string };
  expect(json.access_token, "admin access token").toBeTruthy();
  return json.access_token!;
}

async function keycloakUserId(username: string): Promise<string> {
  const token = await keycloakAdminToken();
  const res = await fetch(
    `http://localhost:8080/admin/realms/${REALM_NAME}/users?username=${encodeURIComponent(username)}&exact=true`,
    { headers: { Authorization: `Bearer ${token}` } }
  );
  expect(res.status, "admin user lookup").toBe(200);
  const users = (await res.json()) as Array<{ id?: string }>;
  expect(users.length, `Keycloak user lookup for ${username}`).toBe(1);
  expect(users[0]?.id).toBeTruthy();
  return users[0]!.id!;
}

async function keycloakLogoutUser(username: string): Promise<void> {
  const token = await keycloakAdminToken();
  const userId = await keycloakUserId(username);
  const res = await fetch(
    `http://localhost:8080/admin/realms/${REALM_NAME}/users/${userId}/logout`,
    { method: "POST", headers: { Authorization: `Bearer ${token}` } }
  );
  expect([204, 200].includes(res.status), "admin user logout").toBe(true);
}

// ---------------------------------------------------------------------------
// Story 1 — Anonymous baseline. The browser holds no token-like material.
// Invariant: nothing token-shaped in any JS-readable surface; /auth/me 401.
// ---------------------------------------------------------------------------
test("1. anonymous: unauthenticated home, /auth/me 401, no token material", async ({
  page,
  context
}) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

  const meStatus = await page.evaluate(async () => {
    const res = await fetch("/auth/me", { credentials: "include" });
    return res.status;
  });
  expect(meStatus).toBe(401);

  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 2 — Login redirect contract. The /auth/login entry yields a top-level
// redirect to Keycloak's authorize endpoint with the full PKCE+OIDC param set,
// and return_to is NOT leaked to the IdP (it is server-side saved_request).
// ---------------------------------------------------------------------------
test("2. login redirect contract carries PKCE/OIDC params, hides return_to", async ({
  page
}) => {
  await page.goto(`/auth/login?return_to=${encodeURIComponent("/")}`);
  await page.waitForURL(KEYCLOAK_AUTH_RE);

  const url = new URL(page.url());
  const q = url.searchParams;
  expect(q.get("response_type")).toBe("code");
  expect(q.get("client_id")).toBeTruthy();
  expect(q.get("redirect_uri")).toBeTruthy();
  expect(q.get("scope")).toBeTruthy();
  expect(q.get("state")).toBeTruthy();
  expect(q.get("nonce")).toBeTruthy();
  expect(q.get("code_challenge")).toBeTruthy();
  expect(q.get("code_challenge_method")).toBe("S256");

  // return_to is a BFF-internal concern. It must never be forwarded to the IdP.
  expect(q.has("return_to")).toBe(false);
  expect(url.search).not.toContain("return_to");
});

// ---------------------------------------------------------------------------
// Story 3 — Successful login (alice). Lands same-origin, /auth/me shows the
// realm role "user", only opaque cookies, no token in any JS-readable surface.
// ---------------------------------------------------------------------------
test("3. alice login lands same-origin with role user, no browser tokens", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);

  expect(new URL(page.url()).origin).toBe(APP_ORIGIN);
  await expect(page.getByText(/Roles:\s*user/i)).toBeVisible();

  const sid = sidFrom(await context.cookies());
  expect(sid.length).toBeGreaterThan(0);
  // The opaque sid must not itself be a JWT/JWE smuggled into the cookie.
  expect(looksLikeJws(sid), "sid must be opaque, not a JWS").toBeFalsy();
  expect(looksLikeJwe(sid), "sid must be opaque, not a JWE").toBeFalsy();

  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 4 — Saved-request replay. Login that begins at a protected return_to
// lands the user back on that exact protected path after the callback.
// ---------------------------------------------------------------------------
test("4. saved-request replay returns to the protected path", async ({
  page,
  context
}) => {
  await page.goto(
    `/auth/login?return_to=${encodeURIComponent("/api/user-data")}`
  );
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  await page.fill("#username", ALICE.username);
  await page.fill("#password", ALICE.password);
  await Promise.all([
    page.waitForURL(`${APP_ORIGIN}/api/user-data`),
    page.click("#kc-login")
  ]);

  await expect(page).toHaveURL(`${APP_ORIGIN}/api/user-data`);
  await expect(page.locator("body")).toContainText("user-data");
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 5 — XHR with no session. A fetch to /api/** returns 401 in-place: it is
// NOT redirected to Keycloak, and the response URL stays same-origin. The SPA's
// XHR path must surface 401, never bounce the request itself off-origin.
// ---------------------------------------------------------------------------
test("5. unauthenticated XHR to /api returns same-origin 401, no IdP redirect", async ({
  page
}) => {
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
  expect(result.responseUrl).toBe(`${APP_ORIGIN}/api/user-data`);
  expect(result.responseUrl).not.toMatch(KEYCLOAK_AUTH_RE);
  expect(result.pageUrl).toBe(`${APP_ORIGIN}/`);
});

// ---------------------------------------------------------------------------
// Story 6 — SPA 401 behavior. callApi()'s 401 branch performs a TOP-LEVEL
// navigation to /auth/login?return_to=..., and the SPA bundle never references
// any OIDC/Keycloak/issuer/token/authorize URL — login orchestration lives in
// the BFF, not the browser.
// ---------------------------------------------------------------------------
test("6. SPA 401 triggers top-level navigation to /auth/login, no OIDC in SPA", async ({
  page
}) => {
  await page.goto("/");
  await page.evaluate(() => {
    // Simulate the SPA's 401 handling: a 401 from /api or /auth/me must drive a
    // top-level navigation to the BFF login entry, not to any IdP URL.
    const returnTo = encodeURIComponent(
      window.location.pathname + window.location.search
    );
    window.location.assign(`/auth/login?return_to=${returnTo}`);
  });
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  // The browser ended up at Keycloak only via the BFF's server-side redirect.
  // The SPA itself never named the IdP; assert the shipped frontend source has
  // no OIDC/Keycloak/issuer/authorize/token URL constructs.
  // Scan the SHIPPED SPA source only. Exclude *.test.* / *.spec.* files: those
  // are dev-only and never bundled into the browser, and some deliberately
  // carry an absolute IdP URL as a negative-test fixture (asserting the SPA
  // *rejects* it). A hardcoded IdP URL in actual shipped code still fails below.
  const sources = execSync(
    "grep -RIl . src --exclude='*.test.*' --exclude='*.spec.*' 2>/dev/null || true",
    { cwd: new URL("../../", import.meta.url).pathname, encoding: "utf8" }
  );
  // Flag only a REAL leak: an actual IdP/OIDC URL or endpoint baked into the
  // shipped SPA. NOT the bare words IdP/OIDC/BFF in a comment, the "openid"
  // scope, or a banned-package name like "keycloak-js" in an architecture
  // guard test. A genuine hardcoded Keycloak URL must still fail.
  const forbidden =
    /https?:\/\/[^\s"'`]*(?:keycloak|\/realms\/|\/?\.well-known\/openid-configuration|openid-connect\/(?:auth|token|logout|certs|userinfo))|["'`](?:authorization_endpoint|token_endpoint|end_session_endpoint|jwks_uri|userinfo_endpoint)["'`]\s*:/i;
  for (const rel of sources.split("\n").map((s) => s.trim()).filter(Boolean)) {
    const body = execSync(`cat "${rel}"`, {
      cwd: new URL("../../", import.meta.url).pathname,
      encoding: "utf8"
    });
    expect(
      forbidden.test(body),
      `SPA source ${rel} must not reference OIDC/IdP URLs`
    ).toBe(false);
  }
});

// ---------------------------------------------------------------------------
// Story 7 — Authenticated API proxy. After login the SPA's /api/user-data
// succeeds via the gateway, and the BROWSER sends no bearer token: the gateway
// injects the access token server-side from the session.
// ---------------------------------------------------------------------------
test("7. authenticated /api proxy succeeds; browser sends no bearer", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);

  // Capture the outgoing request headers the browser actually sends.
  const authHeaders: (string | undefined)[] = [];
  await page.route("**/api/user-data", async (route) => {
    authHeaders.push(route.request().headers()["authorization"]);
    await route.continue();
  });

  await page.getByRole("button", { name: /Call \/api\/user-data/i }).click();
  await expect(page.getByTestId("api-result")).toContainText("user-data");

  expect(authHeaders.length).toBeGreaterThan(0);
  for (const h of authHeaders) {
    expect(h, "browser must not send an Authorization bearer").toBeFalsy();
  }
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 8 — Role/scope enforcement at the Resource Server. The admin-only
// endpoint is POST /api/admin (hasAuthority ROLE_admin). alice (role user) is
// 403; admin (role admin) succeeds. Enforced at the RS, not by frontend hiding.
// Two separate browser contexts isolate the two sessions.
// ---------------------------------------------------------------------------
test("8. POST /api/admin: alice 403, admin 200, enforced at the RS", async ({
  browser
}) => {
  const aliceCtx = await browser.newContext();
  const adminCtx = await browser.newContext();
  try {
    const alicePage = await aliceCtx.newPage();
    await loginAs(alicePage, ALICE);
    const aliceStatus = await alicePage.evaluate(async () => {
      // Signed double-submit CSRF: a state-changing POST through the gateway
      // requires X-XSRF-TOKEN echoing the XSRF-TOKEN cookie. Sending it makes
      // alice's 403 the ROLE denial (not a CSRF rejection), so this proves RS
      // authorization, not the gateway's CSRF guard.
      const xsrf = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1] ?? "";
      const res = await fetch("/api/admin", {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json", "X-XSRF-TOKEN": xsrf }
      });
      return res.status;
    });
    expect(aliceStatus, "alice must be forbidden from /api/admin").toBe(403);

    const adminPage = await adminCtx.newPage();
    await loginAs(adminPage, ADMIN);
    const adminBody = await adminPage.evaluate(async () => {
      const xsrf = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1] ?? "";
      const res = await fetch("/api/admin", {
        method: "POST",
        credentials: "include",
        headers: { Accept: "application/json", "X-XSRF-TOKEN": xsrf }
      });
      return { status: res.status, text: await res.text() };
    });
    expect(adminBody.status, "admin must reach /api/admin").toBe(200);
    expect(adminBody.text).toContain("admin");
  } finally {
    await aliceCtx.close();
    await adminCtx.close();
  }
});

// ---------------------------------------------------------------------------
// Story 9 — Logout continuation contract. POST /auth/logout (Accept JSON)
// returns a SAME-ORIGIN { logoutUrl: "/auth/logout/continue?lc=..." } that
// leaks NONE of: id_token_hint, any IdP host, JWT-looking strings, or any
// access/refresh token. Navigating the continuation URL completes logout.
// ---------------------------------------------------------------------------
test("9. logout response is same-origin continuation, leaks no token/IdP", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);

  const logout = await page.evaluate(async () => {
    const csrf =
      document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1] ?? "";
    const res = await fetch("/auth/logout", {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "X-XSRF-TOKEN": decodeURIComponent(csrf)
      }
    });
    return { status: res.status, text: await res.text() };
  });
  expect(logout.status).toBe(200);

  const body = JSON.parse(logout.text) as { logoutUrl?: string };
  expect(body.logoutUrl, "logoutUrl must be present").toBeTruthy();
  const logoutUrl = body.logoutUrl!;
  // Same-origin relative continuation URL only.
  expect(logoutUrl.startsWith("/auth/logout/continue")).toBe(true);

  const forbidden =
    /id_token_hint|keycloak|localhost:8080|127\.0\.0\.1:8080|okta|cognito|microsoft|auth0/i;
  expect(forbidden.test(logout.text), "logout body must not name IdP/id_token_hint").toBe(
    false
  );
  expect(looksLikeJws(logoutUrl), "logoutUrl must not embed a JWT").toBe(false);
  expect(/access_token|refresh_token/i.test(logout.text)).toBe(false);
  // No JWT-looking substring anywhere in the body.
  expect(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(logout.text)).toBe(
    false
  );

  // Drive the continuation URL and assert logout completes server-side.
  await page.goto(logoutUrl);
  const sid = (await context.cookies()).find((c) => c.name === "sid");
  expect(sid, "sid must be cleared after logout continuation").toBeUndefined();

  await page.goto("/");
  const meStatus = await page.evaluate(async () => {
    const res = await fetch("/auth/me", { credentials: "include" });
    return res.status;
  });
  expect(meStatus).toBe(401);
});

// ---------------------------------------------------------------------------
// Story 9b — Real React logout path. This drives the actual Sign out button
// and form submit handler instead of calling fetch("/auth/logout") from the
// test body. The protocol-level body/redirect contract remains covered by
// story 9; this story proves the SPA wiring follows that contract.
// ---------------------------------------------------------------------------
test("9b. real React sign-out button clears the session, no token", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);

  const logoutPost = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.origin === APP_ORIGIN
      && url.pathname === "/auth/logout"
      && request.method() === "POST";
  });
  const logoutContinue = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.origin === APP_ORIGIN
      && url.pathname === "/auth/logout/continue";
  });

  await page.getByRole("button", { name: /sign out/i }).click();
  await logoutPost;
  await logoutContinue;

  await page.waitForURL(`${APP_ORIGIN}/`);
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

  const sid = (await context.cookies()).find((c) => c.name === "sid");
  expect(sid, "sid must be cleared after UI sign-out").toBeUndefined();
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 10 — Front-channel precision. If /auth/logout/continue redirects to the
// IdP with id_token_hint, that is the ONLY tolerated appearance of an ID token,
// and ONLY as a server-generated top-level redirect Location. The frontend
// never constructs, parses, stores, logs, or receives that id_token in JSON.
// ---------------------------------------------------------------------------
test("10. id_token_hint appears only in a server-generated top-level redirect", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);

  const logoutUrl = await page.evaluate(async () => {
    const csrf =
      document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/)?.[1] ?? "";
    const res = await fetch("/auth/logout", {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "X-XSRF-TOKEN": decodeURIComponent(csrf)
      }
    });
    const body = (await res.json()) as { logoutUrl?: string };
    return body.logoutUrl ?? "";
  });
  expect(logoutUrl.startsWith("/auth/logout/continue")).toBe(true);

  // Follow the continuation WITHOUT auto-following redirects, so we can inspect
  // the raw 302 Location the server emits. Any id_token_hint is allowed ONLY
  // here, in a server-issued top-level redirect.
  const resp = await context.request.get(`${APP_ORIGIN}${logoutUrl}`, {
    maxRedirects: 0
  });
  expect([302, 303, 307].includes(resp.status())).toBe(true);
  const location = resp.headers()["location"] ?? "";

  // The id_token (if present) lives ONLY in this top-level redirect's
  // id_token_hint param — never delivered to the SPA as JSON or storage.
  // The browser-facing JSON body (story 9) already proved it is absent there.
  if (location.includes("id_token_hint")) {
    const hint = new URL(location).searchParams.get("id_token_hint") ?? "";
    // It is an ID token (JWS) and it sits in a redirect to the IdP origin.
    expect(looksLikeJws(hint)).toBe(true);
    expect(/localhost:8080|127\.0\.0\.1:8080|keycloak/i.test(location)).toBe(true);
  }

  // And it never reached any browser JS-readable surface.
  await page.goto("/");
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 11 — Callback error. Driving /auth/callback/idp?error=access_denied with
// a state establishes NO session: no __Host-sid/sid cookie, the oauth_tx_* cookie
// is cleared/unusable, /auth/me stays 401, and the user lands on a controlled
// path (/).
// ---------------------------------------------------------------------------
test("11. callback error establishes no session and lands on a controlled path", async ({
  page,
  context
}) => {
  // Begin a real login so a genuine state/oauth_tx pair exists, then capture
  // the state and abandon the IdP leg in favor of an error callback.
  await page.goto(`/auth/login?return_to=${encodeURIComponent("/")}`);
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  const state = new URL(page.url()).searchParams.get("state") ?? "";
  expect(state).toBeTruthy();

  await page.goto(
    `/auth/callback/idp?error=access_denied&state=${encodeURIComponent(state)}`
  );

  const cookies = await context.cookies();
  expect(cookies.find((c) => c.name === "sid")).toBeUndefined();
  expect(cookies.find((c) => c.name === "__Host-sid")).toBeUndefined();
  const tx = cookies.find((c) => c.name.startsWith("oauth_tx_"));
  // oauth_tx_* must be cleared or at least no longer usable to mint a session.
  if (tx) expect(tx.value === "" || tx.expires === 0).toBeTruthy();

  const meStatus = await page.evaluate(async () => {
    const res = await fetch("/auth/me", { credentials: "include" });
    return res.status;
  });
  expect(meStatus).toBe(401);

  // Controlled landing: not stranded on /auth/callback/idp.
  expect(new URL(page.url()).origin).toBe(APP_ORIGIN);
  expect(page.url()).not.toContain("/auth/callback/idp");
});

// ---------------------------------------------------------------------------
// Story 12 — Server-side session invalidation returns the SPA to anonymous.
// After login, the session record is deleted server-side with a single
// deterministic `valkey-cli DEL sess:<sid>` (a state delete, not an expiry
// race). The next authenticated SPA fetch then resolves to 401, the SPA returns
// to the anonymous (Sign in) state, and no token-shaped material is left behind
// in any browser-readable surface.
// ---------------------------------------------------------------------------
test("12. server-side session invalidation returns the SPA to anonymous, no token", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);
  const sid = sidFrom(await context.cookies());

  // Delete the session record server-side — a single deterministic DEL.
  const deleted = valkey(["DEL", `sess:${sid}`]);
  expect(deleted, "DEL must remove exactly the one session record").toBe("1");

  // The next authenticated SPA fetch resolves to 401 in-place (same-origin).
  const apiStatus = await page.evaluate(async () => {
    const res = await fetch("/api/user-data", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    return res.status;
  });
  expect(apiStatus, "deleted session must map the next call to 401").toBe(401);

  // /auth/me agrees the session is gone.
  const meStatus = await page.evaluate(async () => {
    const res = await fetch("/auth/me", { credentials: "include" });
    return res.status;
  });
  expect(meStatus).toBe(401);

  // The SPA returns to the anonymous state: reloading home shows Sign in.
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

  // No token-shaped material survives in any browser-readable surface.
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 13 — Real SPA 401 path. This drives the actual React button handler
// after server-side session invalidation. callApi() must see 401 and perform a
// top-level navigation to /auth/login?return_to=..., not just render Denied.
// ---------------------------------------------------------------------------
test("13. real React callApi 401 path navigates to BFF login", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);
  const sid = sidFrom(await context.cookies());
  expect(valkey(["DEL", `sess:${sid}`])).toBe("1");

  const loginRequest = page.waitForRequest((request) => {
    const url = new URL(request.url());
    return url.origin === APP_ORIGIN
      && url.pathname === "/auth/login"
      && url.searchParams.has("return_to");
  });
  await page.getByRole("button", { name: /Call \/api\/user-data/i }).click();
  const request = await loginRequest;
  const url = new URL(request.url());
  expect(url.searchParams.get("return_to")).toBe("/");
  expect(url.pathname).not.toBe("/api/user-data");

  // If the Keycloak SSO cookie is still alive, the IdP may immediately
  // complete the new authorization request and land back on the app before
  // Playwright observes the transient authorize URL. The load-bearing
  // assertion is the real SPA path above: callApi() turned /api/** 401 into
  // a top-level /auth/login?return_to=... navigation.
  await expect(page.getByText(/signed in as/i)).toBeVisible();
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 14 — User-initiated logout still terminates IdP SSO when the local
// session is already gone. Delete sess:{sid}, POST /auth/logout, follow the
// continuation, then a new login attempt must prompt for credentials.
// ---------------------------------------------------------------------------
test("14. no-local-session logout still terminates Keycloak SSO", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);
  const sid = sidFrom(await context.cookies());
  expect(valkey(["DEL", `sess:${sid}`])).toBe("1");

  const logoutUrl = await page.evaluate(async () => {
    const res = await fetch("/auth/logout", {
      method: "POST",
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    const body = (await res.json()) as { logoutUrl?: string };
    return body.logoutUrl ?? "";
  });
  expect(logoutUrl.startsWith("/auth/logout/continue")).toBe(true);
  await page.goto(logoutUrl);

  await page.goto(`/auth/login?return_to=${encodeURIComponent("/")}`);
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  await expect(page.locator("#username")).toBeVisible();
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 15 — IdP-driven back-channel logout. Keycloak admin logout sends a
// signed logout_token to /backchannel-logout; deleting sess:{sid} must make both
// /auth/me and /api/** return 401 on the next request.
// ---------------------------------------------------------------------------
test("15. Keycloak back-channel logout revokes local session", async ({
  page,
  context
}) => {
  await loginAs(page, ALICE);
  const sid = sidFrom(await context.cookies());
  expect(valkey(["EXISTS", `sess:${sid}`])).toBe("1");

  await keycloakLogoutUser(ALICE.username);

  await expect
    .poll(() => valkey(["EXISTS", `sess:${sid}`]), {
      timeout: 10_000,
      message: "back-channel logout should delete sess:{sid}"
    })
    .toBe("0");

  const statuses = await page.evaluate(async () => {
    const me = await fetch("/auth/me", { credentials: "include" });
    const api = await fetch("/api/user-data", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    return { me: me.status, api: api.status };
  });
  expect(statuses.me).toBe(401);
  expect(statuses.api).toBe(401);
  await assertNoBrowserTokens(page, context);
});

// ---------------------------------------------------------------------------
// Story 16 — Multi-tab login robustness. Starting two login flows in the same
// browser context must not clobber the first transaction's browser-binding
// cookie; both callbacks complete.
// ---------------------------------------------------------------------------
test("16. concurrent login tabs complete independently", async ({ browser }) => {
  const context = await browser.newContext();
  try {
    const first = await context.newPage();
    const second = await context.newPage();

    await first.goto(`/auth/login?return_to=${encodeURIComponent("/api/user-data")}`);
    await first.waitForURL(KEYCLOAK_AUTH_RE);
    const firstState = new URL(first.url()).searchParams.get("state");
    expect(firstState).toBeTruthy();

    await second.goto(`/auth/login?return_to=${encodeURIComponent("/")}`);
    await second.waitForURL(KEYCLOAK_AUTH_RE);
    const secondState = new URL(second.url()).searchParams.get("state");
    expect(secondState).toBeTruthy();
    expect(secondState).not.toBe(firstState);

    const txCookiesBefore = (await context.cookies())
      .filter((c) => c.name.startsWith("oauth_tx_"));
    expect(txCookiesBefore.length).toBeGreaterThanOrEqual(2);

    await second.fill("#username", ALICE.username);
    await second.fill("#password", ALICE.password);
    await Promise.all([
      second.waitForURL(`${APP_ORIGIN}/`),
      second.click("#kc-login")
    ]);

    await first.fill("#username", ALICE.username);
    await first.fill("#password", ALICE.password);
    await Promise.all([
      first.waitForURL(`${APP_ORIGIN}/api/user-data`),
      first.click("#kc-login")
    ]);

    await expect(second.getByText(/signed in as/i)).toBeVisible();
    await expect(first.locator("body")).toContainText("user-data");
    const txCookiesAfter = (await context.cookies())
      .filter((c) => c.name.startsWith("oauth_tx_"));
    expect(txCookiesAfter.length).toBe(0);
  } finally {
    await context.close();
  }
});
