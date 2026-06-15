/**
 * Distributed cross-replica BROWSER gate (on-demand; NOT in the default e2e).
 *
 * Driven by scripts/e2e-distributed-browser.sh, which stands up TWO auth-service
 * replicas behind APISIX under a DETERMINISTIC split:
 *
 *   browser cookie -> Vite (:5173) -> APISIX (:9080) ->
 *     /auth/*          -> auth-service   (replica-1): writes tx:{state} + sess:{sid}
 *     /api/** resolve  -> auth-service-2 (replica-2): reads sess:{sid} CROSS-REPLICA
 *
 * So every /api/user-data 200 with the correct identity proves replica-2
 * resolved a session that replica-1 created, off shared Valkey — the full real
 * path, not a scripted /internal/resolve. (The same-session refresh-collapse
 * contention case is the scripted gate, scripts/e2e-distributed-lock.sh.)
 *
 * Parallelism: each Playwright worker logs into one shared realm and would
 * clobber the others under the full stack (see playwright.config.ts, which forces
 * --workers=1 when E2E_FULL_STACK=1). So the N parallel "users" here are
 * intra-test isolated browser contexts run with Promise.all, not workers — N
 * distinct replica-1 sessions resolved concurrently on replica-2, each asserted
 * to see ONLY its own identity.
 */
import { expect, test, type BrowserContext, type Page } from "@playwright/test";

const APP_ORIGIN = "http://127.0.0.1:5173";
const REALM_NAME = process.env.E2E_REALM_NAME ?? "oidc-reference";
const ALICE = { username: "alice", password: "alice" } as const;
const ADMIN = { username: "admin", password: "admin" } as const;
// Parallel users (default 4 -> 2 alice + 2 admin) and per-user /api rounds.
// Default kept modest because the proof is "N concurrent cross-replica resolves
// with no cross-talk", and N concurrent COLD browser logins are the expensive
// part on a loaded box; raise E2E_USERS on a beefier machine.
const USERS = Math.max(2, Number(process.env.E2E_USERS ?? "4"));
const ROUNDS = Math.max(1, Number(process.env.E2E_ROUNDS ?? "3"));

const KEYCLOAK_AUTH_RE = new RegExp(
  `realms\\/${REALM_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\/protocol\\/openid-connect\\/auth`
);

async function loginAs(
  page: Page,
  creds: { username: string; password: string }
): Promise<void> {
  await page.goto("/");
  await page.getByRole("link", { name: /sign in/i }).click();
  await page.waitForURL(KEYCLOAK_AUTH_RE);
  await page.fill("#username", creds.username);
  await page.fill("#password", creds.password);
  await Promise.all([page.waitForURL(`${APP_ORIGIN}/`), page.click("#kc-login")]);
  await expect(page.getByText(/signed in as/i)).toBeVisible();
}

type Json = Record<string, unknown> | null;

async function fetchJson(
  page: Page,
  path: string
): Promise<{ status: number; body: Json }> {
  return page.evaluate(async (p) => {
    const res = await fetch(p, {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    return { status: res.status, body: body as Json };
  }, path);
}

test.describe.configure({ mode: "default" });

test("parallel users: replica-1 sessions resolve cross-replica on replica-2 with no identity cross-talk", async ({
  browser
}) => {
  test.skip(
    process.env.E2E_FULL_STACK !== "1",
    "requires the two-replica full stack — run scripts/e2e-distributed-browser.sh"
  );
  // N concurrent cold browser logins through Keycloak are the slow part on a
  // loaded machine; scale the ceiling with the user count (~60s/user, floor 120s).
  test.setTimeout(Math.max(120_000, USERS * 60_000));

  const roster = Array.from({ length: USERS }, (_, i) =>
    i % 2 === 0 ? ALICE : ADMIN
  );

  // Phase 1 — establish N sessions. Logins are SEQUENTIAL on purpose: N
  // concurrent COLD Keycloak logins contend badly on a loaded box (4 simultaneous
  // logins timed out where one takes ~8s), and login — writing tx:{state} +
  // sess:{sid} on replica-1 — is setup, not the property under test. Each
  // isolated context keeps its own __Host-sid.
  const sessions: Array<{
    context: BrowserContext;
    page: Page;
    username: string;
    index: number;
  }> = [];
  for (const [index, creds] of roster.entries()) {
    const context = await browser.newContext();
    const page = await context.newPage();
    await loginAs(page, creds); // /auth/* -> replica-1 (writes the session)
    sessions.push({ context, page, username: creds.username, index });
  }

  try {
    // Phase 2 — the actual concurrent cross-replica test: all N users hit
    // /auth/me + /api/user-data SIMULTANEOUSLY. Each /api resolve crosses to
    // replica-2, so N at once proves replica-2 resolves N distinct replica-1
    // sessions concurrently with no identity cross-talk.
    const results = await Promise.all(
      sessions.map(async ({ page, username, index }) => {
        const calls: Array<{
          me: { status: number; body: Json };
          ud: { status: number; body: Json };
        }> = [];
        for (let r = 0; r < ROUNDS; r++) {
          const me = await fetchJson(page, "/auth/me"); // replica-1 (passthrough)
          const ud = await fetchJson(page, "/api/user-data"); // replica-2 (cross-replica resolve)
          calls.push({ me, ud });
        }
        return { username, index, calls };
      })
    );

    for (const { username, index, calls } of results) {
      for (const [r, { me, ud }] of calls.entries()) {
        const where = `user[${index}]=${username} round ${r}`;

        // /auth/me: identity served by replica-1 (the replica that created it).
        expect(me.status, `${where}: /auth/me status`).toBe(200);
        expect(me.body?.preferred_username, `${where}: /auth/me identity`).toBe(
          username
        );

        // /api/user-data: identity served only after replica-2 resolved this
        // replica-1 session cross-replica. A 200 with the right username is the
        // cross-replica proof; a wrong username would be cross-talk; a 5xx would
        // be a resolve failure.
        expect(
          ud.status,
          `${where}: /api/user-data status (cross-replica resolve on replica-2)`
        ).toBe(200);
        expect(
          ud.body?.username,
          `${where}: /api/user-data identity (cross-replica)`
        ).toBe(username);

        // Role isolation: only admin carries the admin role; alice must never
        // see it on either surface (no leakage between concurrent sessions).
        const meRoles = (me.body?.roles as string[] | undefined) ?? [];
        const udRoles = (ud.body?.roles as string[] | undefined) ?? [];
        if (username === "admin") {
          expect(meRoles, `${where}: admin role present on /auth/me`).toContain(
            "admin"
          );
        } else {
          expect(
            meRoles,
            `${where}: alice must NOT see admin role (/auth/me)`
          ).not.toContain("admin");
          expect(
            udRoles,
            `${where}: alice must NOT see admin role (/api/user-data)`
          ).not.toContain("admin");
        }
      }
    }
  } finally {
    await Promise.all(sessions.map((s) => s.context.close()));
  }
});
