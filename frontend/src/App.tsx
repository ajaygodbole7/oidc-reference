import { useEffect, useMemo, useState } from "react";
import { callApi, fetchMe, loginHref, signOut, type User } from "./auth";

type LoadState = "loading" | "anonymous" | "authenticated";

export function App() {
  const [state, setState] = useState<LoadState>("loading");
  const [user, setUser] = useState<User | null>(null);
  const [apiResult, setApiResult] = useState<string | null>(null);
  // Captures the route the user was on when login became required so
  // the callback can replay it. Computed once on mount: loginHref()
  // reads window.location, which is stable for this SPA (no client-side
  // router), and the anonymous panel only renders for state="anonymous"
  // — by then the URL has not changed since mount.
  const signInHref = useMemo(() => loginHref(), []);

  useEffect(() => {
    const controller = new AbortController();
    let alive = true;
    fetchMe(controller.signal)
      .then((u) => {
        if (!alive) return;
        if (u) {
          setUser(u);
          setState("authenticated");
        } else {
          setState("anonymous");
        }
      })
      .catch(() => {
        if (alive) setState("anonymous");
      });
    return () => {
      alive = false;
      controller.abort();
    };
  }, []);

  // Wrap async onClick handlers so a transport failure (fetch reject —
  // DNS, network, CORS preflight rejection) becomes a visible error
  // state rather than an unhandled promise rejection silently lost by
  // React's synthetic event system.
  const callAndRender = async (path: string) => {
    try {
      const res = await callApi(path);
      setApiResult(res.ok ? await res.text() : `Denied (${res.status})`);
    } catch (e) {
      setApiResult(`Network error: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleUserData = () => { void callAndRender("/api/user-data"); };
  const handleApiMe    = () => { void callAndRender("/api/me"); };

  return (
    <main className="app-shell">
      <section className="auth-panel">
        <p className="eyebrow">OIDC Reference</p>
        <h1>BFF Session Pattern</h1>

        {state === "loading" && <p>Loading…</p>}

        {state === "anonymous" && (
          <>
            <p>The browser holds no tokens. Sign in to start a BFF session.</p>
            <a href={signInHref} data-testid="sign-in-link">
              Sign in
            </a>
          </>
        )}

        {state === "authenticated" && user && (
          <>
            <p>
              Signed in as <strong>{user.preferred_username ?? user.sub}</strong>
            </p>
            <p>Roles: {(user.roles ?? []).join(", ") || "(none)"}</p>
            <button type="button" onClick={handleApiMe}>
              Call /api/me
            </button>
            <button type="button" onClick={handleUserData}>
              Call /api/user-data
            </button>
            {apiResult !== null && (
              <pre data-testid="api-result">{apiResult}</pre>
            )}
            <form
              onSubmit={(event) => {
                event.preventDefault();
                void signOut();
              }}
            >
              <button type="submit">Sign out</button>
            </form>
          </>
        )}
      </section>
    </main>
  );
}
