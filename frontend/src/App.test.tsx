import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

// URL-keyed mock router so tests don't depend on the order the component
// happens to fire requests in. Each handler is responsible for one route;
// unknown URLs throw loudly so we never silently fall through to a real
// network call.
function setupFetch(routes: Record<string, () => Response | Promise<Response>>) {
  return vi.spyOn(global, "fetch").mockImplementation(async (input) => {
    const url =
      typeof input === "string"
        ? input
        : input instanceof URL
          ? input.href
          : input.url;
    const handler = routes[url];
    if (!handler) throw new Error(`unhandled fetch: ${url}`);
    return handler();
  });
}

const aliceClaims = {
  sub: "alice-123",
  preferred_username: "alice",
  roles: ["user"]
};

describe("App", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the anonymous sign-in entry when /auth/me returns 401", async () => {
    setupFetch({
      "/auth/me": () => new Response(null, { status: 401 })
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /sign in/i })).toBeInTheDocument()
    );
    // Per return-to-login contract: a bare `/auth/login` link is forbidden.
    // The Sign in link must include `return_to=<current route>`. jsdom's
    // default location yields pathname "/", so the encoded value is "%2F".
    expect(screen.getByTestId("sign-in-link")).toHaveAttribute(
      "href",
      `/auth/login?return_to=${encodeURIComponent("/")}`
    );
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("renders authenticated identity when /auth/me returns claims", async () => {
    setupFetch({
      "/auth/me": () => Response.json(aliceClaims)
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByText(/signed in as/i)).toBeInTheDocument()
    );
    expect(screen.getByText(/alice/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("calls /api/me through the BFF and renders the result", async () => {
    const fetchSpy = setupFetch({
      "/auth/me": () => Response.json(aliceClaims),
      "/api/me": () => Response.json({ subject: "alice-123" })
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /call \/api\/me/i })).toBeInTheDocument()
    );
    fireEvent.click(screen.getByRole("button", { name: /call \/api\/me/i }));

    await waitFor(() =>
      expect(screen.getByTestId("api-result")).toHaveTextContent("alice-123")
    );
    expect(fetchSpy).toHaveBeenLastCalledWith("/api/me", {
      credentials: "include",
      headers: { Accept: "application/json" }
    });
  });

  it("renders API denial honestly", async () => {
    setupFetch({
      "/auth/me": () => Response.json(aliceClaims),
      "/api/user-data": () => new Response(null, { status: 403 })
    });

    render(<App />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /call \/api\/user-data/i })).toBeInTheDocument()
    );
    fireEvent.click(screen.getByRole("button", { name: /call \/api\/user-data/i }));

    await waitFor(() =>
      expect(screen.getByTestId("api-result")).toHaveTextContent("Denied (403)")
    );
  });
});
