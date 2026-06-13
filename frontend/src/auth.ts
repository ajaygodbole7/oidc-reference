// Thin BFF client. There is no OAuth/OIDC library in the browser — the BFF
// owns the flow. Tokens never reach this file or any browser-side storage.

export type User = {
  readonly sub: string;
  readonly preferred_username?: string;
  readonly name?: string;
  readonly email?: string;
  readonly roles?: readonly string[];
  // Step-up assurance, surfaced from /auth/me when the IdP emits them.
  // auth_time = epoch seconds of the last interactive authentication; the SPA
  // can use it to reflect how recently the user authenticated. acr is the
  // authentication context class reference when configured.
  readonly auth_time?: number;
  readonly acr?: string;
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
  if (v.auth_time !== undefined && typeof v.auth_time !== "number") return false;
  if (v.acr !== undefined && typeof v.acr !== "string") return false;
  return true;
}

function sanitizeUser(value: User): User {
  return {
    sub: value.sub,
    ...(value.preferred_username !== undefined ? { preferred_username: value.preferred_username } : {}),
    ...(value.name !== undefined ? { name: value.name } : {}),
    ...(value.email !== undefined ? { email: value.email } : {}),
    ...(value.roles !== undefined ? { roles: [...value.roles] } : {}),
    ...(value.auth_time !== undefined ? { auth_time: value.auth_time } : {}),
    ...(value.acr !== undefined ? { acr: value.acr } : {})
  };
}

type Navigate = (path: string) => void;

const browserNavigate: Navigate = (path) => window.location.assign(path);

// Build a /auth/login URL with a URL-encoded return_to derived from the
// current browser location. Per the return-to-login contract, a bare
// `/auth/login` is forbidden — every login entry must carry `return_to`.
export function loginHref(): string {
  return `/auth/login?return_to=${encodeURIComponent(currentRoute())}`;
}

// Step-up entry. Reached when a sensitive /api call returns an RFC 9470
// insufficient_user_authentication challenge: the user is still logged in but
// must re-authenticate to raise assurance. Same return_to contract as login.
export function stepUpHref(): string {
  return `/auth/step-up?return_to=${encodeURIComponent(currentRoute())}`;
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
// page unreachable as soon as the gateway was up (every cold load
// 401ed, every 401 redirected away). Login is now driven by
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
  return sanitizeUser(body);
}

export type CallApiOptions = {
  readonly method?: string;
  readonly body?: unknown;
  readonly headers?: Readonly<Record<string, string>>;
};

// Methods that never carry a CSRF requirement at the gateway (RFC 7231 safe /
// idempotent reads). Anything else is "unsafe" and must echo the double-submit
// XSRF-TOKEN cookie as X-XSRF-TOKEN, or the gateway rejects it.
const SAFE_METHODS: ReadonlySet<string> = new Set(["GET", "HEAD", "OPTIONS"]);

// Thin client for /api/** through the gateway. GET by default — backward
// compatible with bare `callApi(path)` callers. For unsafe methods (POST/PUT/
// PATCH/DELETE/...) it attaches the double-submit CSRF header from the existing
// XSRF-TOKEN cookie, and JSON-encodes an object body with Content-Type set.
export async function callApi(
  path: string,
  options: CallApiOptions = {},
  navigate: Navigate = browserNavigate
): Promise<Response> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...options.headers
  };

  let body: BodyInit | undefined;
  if (options.body !== undefined) {
    if (typeof options.body === "string" || options.body instanceof FormData) {
      body = options.body;
    } else {
      body = JSON.stringify(options.body);
      headers["Content-Type"] = "application/json";
    }
  }

  if (!SAFE_METHODS.has(method)) {
    // Double-submit CSRF: echo the cookie value the gateway minted. Unsafe
    // methods without this header are rejected by the gateway CSRF contract.
    headers["X-XSRF-TOKEN"] = readCsrfCookie();
  }

  const init: RequestInit = { credentials: "include", headers };
  // Omit `method` for the GET default so the bare-GET request shape stays
  // identical to fetch's own default (method defaults to GET); only set it
  // for explicit non-GET methods.
  if (method !== "GET") init.method = method;
  if (body !== undefined) init.body = body;

  const res = await fetch(path, init);
  if (res.status === 401) {
    // Per contract: a 401 from /api/** must NOT navigate to the API URL. It
    // triggers a top-level navigation. RFC 9470: if the challenge is a step-up
    // (error="insufficient_user_authentication"), the session is still valid —
    // route to /auth/step-up to re-authenticate and raise assurance, not to a
    // full /auth/login. Any other 401 is a no-session and routes to login.
    const challenge = res.headers.get("WWW-Authenticate") ?? "";
    navigate(
      challenge.includes("insufficient_user_authentication") ? stepUpHref() : loginHref()
    );
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
    // Defense in depth: the SPA is IdP-oblivious. The Auth Service returns a
    // same-origin, opaque continuation handle (/auth/logout/continue?lc=...)
    // and performs the upstream sign-out redirect itself; JS never sees an absolute
    // IdP URL. Accept ONLY same-origin relative paths — reject absolute URLs
    // (including any IdP origin) so a misbehaving or compromised server
    // response cannot redirect the user off-origin.
    return safeLogoutUrl(raw) ? { logoutUrl: raw } : {};
  } catch {
    return {};
  }
}

function safeLogoutUrl(value: string): boolean {
  // Accept ONLY a same-origin relative path: a single leading "/" whose next
  // character is neither "/" nor "\". Browsers normalize "\" to "/", so
  // "/\evil.com" and "/\/evil.com" resolve to the protocol-relative
  // "//evil.com" — an off-origin redirect that a naive `!startsWith("//")`
  // check would let through. Everything else (absolute URLs, protocol-relative
  // URLs, anything not beginning with "/") is rejected.
  if (!value.startsWith("/")) return false;
  const second = value.charAt(1);
  return second !== "/" && second !== "\\";
}

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
