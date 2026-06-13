import { beforeEach, describe, expect, it, vi } from "vitest";
import { callApi, fetchMe, signOut, stepUpHref } from "./auth";

describe("BFF auth client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("GET (default) uses same-origin credentials, sends NO CSRF header, and navigates to /auth/login?return_to=<current route> on API 401", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(null, { status: 401 })
    );
    const navigate = vi.fn();

    // jsdom default location is http://localhost/, so current route is "/".
    // Backward-compat: the navigate callback is now the THIRD arg; options
    // defaults to {} so a default GET is unchanged for existing callers.
    const res = await callApi("/api/user-data", {}, navigate);

    expect(res.status).toBe(401);
    // Default GET omits `method` (fetch defaults to GET), matching the
    // original bare-GET request shape exactly.
    expect(fetchSpy).toHaveBeenCalledWith("/api/user-data", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    // A safe method must NEVER carry the CSRF header.
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(init.headers).not.toHaveProperty("X-XSRF-TOKEN");
    expect(init).not.toHaveProperty("body");
    // The 401 must NOT navigate to the API URL — it must navigate to the
    // login entry carrying the URL-encoded current route as return_to.
    expect(navigate).toHaveBeenCalledWith(
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
  });

  it("bare callApi(path) still works (no options, no navigate) and issues a default GET", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({ ok: true })
    );

    const res = await callApi("/api/user-data");

    expect(res.ok).toBe(true);
    expect(fetchSpy).toHaveBeenCalledWith("/api/user-data", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
  });

  it("POST attaches X-XSRF-TOKEN equal to the XSRF-TOKEN cookie and JSON-encodes an object body", async () => {
    document.cookie = "XSRF-TOKEN=csrf-abc";
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({ created: true }, { status: 201 })
    );
    const navigate = vi.fn();

    const res = await callApi(
      "/api/user-data",
      { method: "POST", body: { note: "hello" } },
      navigate
    );

    expect(res.status).toBe(201);
    expect(fetchSpy).toHaveBeenCalledWith("/api/user-data", {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        "X-XSRF-TOKEN": "csrf-abc"
      },
      body: JSON.stringify({ note: "hello" })
    });
    expect(navigate).not.toHaveBeenCalled();
  });

  it("the 401-no-navigate-to-API contract holds for unsafe methods too", async () => {
    document.cookie = "XSRF-TOKEN=csrf-abc";
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(null, { status: 401 })
    );
    const navigate = vi.fn();

    const res = await callApi(
      "/api/user-data",
      { method: "DELETE" },
      navigate
    );

    expect(res.status).toBe(401);
    // Unsafe method still carries the CSRF header...
    const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>)["X-XSRF-TOKEN"]).toBe("csrf-abc");
    // ...and a 401 still routes to /auth/login, NEVER to the API URL.
    expect(navigate).toHaveBeenCalledWith(
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
  });

  it("routes an RFC 9470 step-up challenge (401 insufficient_user_authentication) to /auth/step-up, not /auth/login", async () => {
    document.cookie = "XSRF-TOKEN=csrf-abc";
    // The Resource Server accepted the token's authorization but its last
    // interactive authentication is too old. The challenge says "elevate",
    // not "log in again" — the SPA must route to the step-up entry so the
    // user re-authenticates without losing their session.
    vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(null, {
        status: 401,
        headers: {
          "WWW-Authenticate":
            'Bearer error="insufficient_user_authentication", max_age=300'
        }
      })
    );
    const navigate = vi.fn();

    await callApi("/api/admin", { method: "POST" }, navigate);

    expect(navigate).toHaveBeenCalledWith(
      `/auth/step-up?return_to=${encodeURIComponent("/")}`
    );
    expect(navigate).not.toHaveBeenCalledWith(
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
  });

  it("a plain 401 (no step-up challenge) still routes to /auth/login", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(new Response(null, { status: 401 }));
    const navigate = vi.fn();

    await callApi("/api/user-data", {}, navigate);

    expect(navigate).toHaveBeenCalledWith(
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
  });

  it("stepUpHref carries the URL-encoded current route as return_to", () => {
    expect(stepUpHref()).toBe(`/auth/step-up?return_to=${encodeURIComponent("/")}`);
  });

  it("surfaces auth_time and acr from /auth/me into the User DTO", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(Response.json({
      sub: "alice",
      preferred_username: "alice",
      roles: ["user"],
      auth_time: 1781305692,
      acr: "1"
    }));

    const user = await fetchMe();

    expect(user?.auth_time).toBe(1781305692);
    expect(user?.acr).toBe("1");
  });

  it("returns null on /auth/me 401 WITHOUT navigating (anonymous home must be reachable)", async () => {
    // The probe-on-mount path in App calls fetchMe(); a 401 from the
    // Auth Service means "no session", which is the steady state for an
    // anonymous user landing on /. Auto-redirecting here would defeat
    // the anonymous landing page and ALSO push the browser to Keycloak
    // for every cold page load. Login is initiated by user action via
    // the Sign in button (which already produces /auth/login?return_to=).
    // fetchMe no longer accepts a `navigate` callback — its absence is
    // the type-level guarantee that this path cannot auto-redirect.
    const fetchSpy = vi.spyOn(global, "fetch")
      .mockResolvedValue(new Response(null, { status: 401 }));

    const user = await fetchMe();

    expect(user).toBeNull();
    expect(fetchSpy).toHaveBeenCalledWith("/auth/me", expect.objectContaining({
      credentials: "include",
    }));
  });

  it("sanitizes /auth/me to the allowlisted User DTO", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(Response.json({
      sub: "alice",
      preferred_username: "alice",
      roles: ["user"],
      access_token: "must-not-enter-spa-state"
    }));

    const user = await fetchMe();

    expect(user).toEqual({
      sub: "alice",
      preferred_username: "alice",
      name: undefined,
      email: undefined,
      roles: ["user"]
    });
    expect(user).not.toHaveProperty("access_token");
  });

  it("posts logout with the double-submit CSRF header and performs top-level navigation", async () => {
    document.cookie = "XSRF-TOKEN=csrf-123";
    // The Auth Service returns only a SAME-ORIGIN, opaque continuation handle —
    // never the IdP URL and never the id_token. The server emits the IdP
    // end-session redirect itself at /auth/logout/continue, so JS never sees a
    // token. The SPA just performs a top-level navigation to the handle.
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({ logoutUrl: "/auth/logout/continue?lc=opaque-handle" })
    );
    const navigate = vi.fn();

    await signOut(navigate);

    expect(fetchSpy).toHaveBeenCalledWith("/auth/logout", {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "X-XSRF-TOKEN": "csrf-123"
      }
    });
    expect(navigate).toHaveBeenCalledWith("/auth/logout/continue?lc=opaque-handle");
  });

  it("falls back home when logout returns malformed JSON", async () => {
    vi.spyOn(global, "fetch").mockResolvedValue(
      new Response("not-json", {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    const navigate = vi.fn();

    await signOut(navigate);

    expect(navigate).toHaveBeenCalledWith("/");
  });

  it("rejects a backslash-prefixed logoutUrl (open-redirect bypass) and falls back home", async () => {
    // A tampered/compromised Auth Service returns "/\\evil.com". It starts
    // with a single "/" and not "//", so the naive relative-path check would
    // accept it — but browsers normalize "\" to "/", resolving it to the
    // protocol-relative "//evil.com" (off-origin). It must be rejected like
    // any other off-origin URL, leaving navigation at the home fallback.
    vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({ logoutUrl: "/\\evil.com" })
    );
    const navigate = vi.fn();

    await signOut(navigate);

    expect(navigate).toHaveBeenCalledWith("/");
  });

  it("rejects an absolute IdP logoutUrl (the SPA is IdP-oblivious) and falls back home", async () => {
    // The server now returns only a same-origin continuation handle. If a
    // tampered/compromised Auth Service tries to smuggle an absolute IdP URL
    // back to the browser, the SPA must reject it — it must never navigate to
    // an off-origin IdP endpoint. Navigation falls back to the home route.
    vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({
        logoutUrl: "http://localhost:8080/realms/app/protocol/openid-connect/logout"
      })
    );
    const navigate = vi.fn();

    await signOut(navigate);

    expect(navigate).toHaveBeenCalledWith("/");
  });
});
