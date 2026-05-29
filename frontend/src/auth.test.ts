import { beforeEach, describe, expect, it, vi } from "vitest";
import { callApi, signOut } from "./auth";

describe("BFF auth client", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("uses same-origin credentials and navigates to /auth/login?return_to=<current route> on API 401", async () => {
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      new Response(null, { status: 401 })
    );
    const navigate = vi.fn();

    // jsdom default location is http://localhost/, so current route is "/".
    const res = await callApi("/api/user-data", navigate);

    expect(res.status).toBe(401);
    expect(fetchSpy).toHaveBeenCalledWith("/api/user-data", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
    // The 401 must NOT navigate to the API URL — it must navigate to the
    // login entry carrying the URL-encoded current route as return_to.
    expect(navigate).toHaveBeenCalledWith(
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
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
    const { fetchMe } = await import("./auth");
    const fetchSpy = vi.spyOn(global, "fetch")
      .mockResolvedValue(new Response(null, { status: 401 }));

    const user = await fetchMe();

    expect(user).toBeNull();
    expect(fetchSpy).toHaveBeenCalledWith("/auth/me", expect.objectContaining({
      credentials: "include",
    }));
  });

  it("posts logout with the double-submit CSRF header and performs top-level navigation", async () => {
    document.cookie = "XSRF-TOKEN=csrf-123";
    const fetchSpy = vi.spyOn(global, "fetch").mockResolvedValue(
      Response.json({ logoutUrl: "http://localhost:8080/realms/oidc-reference/protocol/openid-connect/logout" })
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
    expect(navigate).toHaveBeenCalledWith("http://localhost:8080/realms/oidc-reference/protocol/openid-connect/logout");
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
});
