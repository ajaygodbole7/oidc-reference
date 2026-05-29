// Thin BFF client. There is no OAuth/OIDC library in the browser — the BFF
// owns the flow. Tokens never reach this file or any browser-side storage.

export type User = {
  readonly sub: string;
  readonly preferred_username?: string;
  readonly name?: string;
  readonly email?: string;
  readonly roles?: readonly string[];
};

function isUser(value: unknown): value is User {
  if (value === null || typeof value !== "object") return false;
  const v = value as Record<string, unknown>;
  if (typeof v.sub !== "string" || v.sub.length === 0) return false;
  if (v.roles !== undefined && !(Array.isArray(v.roles) && v.roles.every((r) => typeof r === "string"))) {
    return false;
  }
  for (const key of ["preferred_username", "name", "email"] as const) {
    if (v[key] !== undefined && typeof v[key] !== "string") return false;
  }
  return true;
}

type Navigate = (path: string) => void;

const browserNavigate: Navigate = (path) => window.location.assign(path);

// Build a /auth/login URL with a URL-encoded return_to derived from the
// current browser location. Per the return-to-login contract, a bare
// `/auth/login` is forbidden — every login entry must carry `return_to`.
export function loginHref(): string {
  return `/auth/login?return_to=${encodeURIComponent(currentRoute())}`;
}

// Compute the relative route for `return_to`. If pathname is missing or
// malformed (does not start with "/"), fall back to "/" per the contract.
function currentRoute(): string {
  if (typeof window === "undefined" || !window.location) return "/";
  const { pathname, search, hash } = window.location;
  if (!pathname || !pathname.startsWith("/")) return "/";
  return `${pathname}${search ?? ""}${hash ?? ""}`;
}

// fetchMe used to take a `navigate` callback so it could redirect to
// /auth/login on 401. That auto-redirect made the anonymous landing
// page unreachable as soon as auth-service was up (every cold load
// 401ed, every 401 redirected to Keycloak). Login is now driven by
// user action — the Sign In button uses loginHref() — and protected-
// route guards (not present in this SPA yet) would call loginHref()
// themselves. Keeping the parameter would mislead callers into thinking
// fetchMe still redirects.
export async function fetchMe(signal?: AbortSignal): Promise<User | null> {
  const init: RequestInit = signal ? { credentials: "include", signal } : { credentials: "include" };
  const res = await fetch("/auth/me", init);
  if (res.status === 401) {
    return null;
  }
  if (!res.ok) throw new Error(`/auth/me failed: ${res.status}`);
  const body = (await res.json()) as unknown;
  if (!isUser(body)) throw new Error("/auth/me returned an unrecognized shape");
  return body;
}

export async function callApi(path: string, navigate: Navigate = browserNavigate): Promise<Response> {
  const res = await fetch(path, {
    credentials: "include",
    headers: { Accept: "application/json" }
  });
  if (res.status === 401) {
    // Per contract: a 401 from /api/** must NOT navigate to the API URL.
    // It triggers a top-level navigation to /auth/login?return_to=<current route>.
    navigate(loginHref());
  }
  return res;
}

export async function signOut(navigate: Navigate = browserNavigate): Promise<void> {
  const res = await fetch("/auth/logout", {
    method: "POST",
    credentials: "include",
    headers: {
      Accept: "application/json",
      "X-XSRF-TOKEN": readCsrfCookie()
    }
  });
  // 401 here means the server already considers us logged out (session
  // evicted server-side between mount and click). The user-visible
  // intent is "send me to the logged-out state" — throwing would
  // bubble into the unhandled-rejection channel and leave the
  // authenticated panel rendered with no feedback. Treat 401 as
  // "already done" and route to / so the App's next fetchMe call
  // settles into the anonymous state.
  if (res.status === 401) {
    navigate("/");
    return;
  }
  if (!res.ok) throw new Error(`/auth/logout failed: ${res.status}`);
  const text = await res.text();
  const body = parseLogoutResponse(text);
  navigate(body.logoutUrl ?? "/");
}

function parseLogoutResponse(text: string): { logoutUrl?: string } {
  if (!text) return {};
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object") return {};
    const raw = (parsed as Record<string, unknown>).logoutUrl;
    if (typeof raw !== "string" || raw.length === 0) return {};
    // Defense in depth: the Auth Service builds logoutUrl from the
    // discovered Keycloak end_session_endpoint. If the discovery
    // document were tampered with (or the Auth Service compromised),
    // an arbitrary URL could redirect the user off-origin. Only accept
    // same-origin relative paths or the configured IdP origin.
    return safeLogoutUrl(raw) ? { logoutUrl: raw } : {};
  } catch {
    return {};
  }
}

function safeLogoutUrl(value: string): boolean {
  if (value.startsWith("/") && !value.startsWith("//")) {
    return true;  // same-origin relative
  }
  try {
    const url = new URL(value);
    return ALLOWED_LOGOUT_ORIGINS.has(url.origin);
  } catch {
    return false;
  }
}

// Allowed IdP origins for the logout redirect. The reference targets
// a single Keycloak; an environment-specific build can extend this set
// (e.g. from import.meta.env). Hardcoded here so a misbehaving server
// response cannot smuggle an arbitrary origin past the SPA.
const ALLOWED_LOGOUT_ORIGINS = new Set<string>([
  "http://localhost:8080",
  "http://127.0.0.1:8080"
]);

function readCsrfCookie(): string {
  const m = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]+)/);
  const raw = m?.[1];
  if (!raw) return "";
  // decodeURIComponent throws URIError on malformed percent-encoding; fall
  // back to the raw value so signOut never crashes mid-flight.
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}
