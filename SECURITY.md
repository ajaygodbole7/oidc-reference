# Security

This document is the navigation surface for this repo's security posture.
The depth lives in:

- [`docs/architecture/architecture-decisions.md`](docs/architecture/architecture-decisions.md)
  §B (cookies/sessions/CSRF) and §C (OAuth/OIDC) — rationale for the
  load-bearing controls.
- [`OIDC-compliance.md`](OIDC-compliance.md) — conformance matrix against
  OpenID Connect Core 1.0 / Discovery / RP-Initiated Logout.
- [`RFC9700-compliance.md`](RFC9700-compliance.md) — control-by-control
  status against RFC 9700 (OAuth 2.0 Security BCP, also the OAuth 2.1
  baseline).
- [`docs/specs/SPEC-0001-core-oidc-flows.md`](docs/specs/SPEC-0001-core-oidc-flows.md)
  §"Threat Model" and §"Trust Boundaries".

## Scope

This is a local reference implementation of the BFF session pattern
for OAuth 2.1 / OpenID Connect. It runs on a developer machine via
Docker Compose to demonstrate the protocol mechanics and the control
surface.

What that means for security claims:

- These controls are implemented and tested at this revision:
  browser-token boundary, OIDC validation, refresh-rotation + reuse
  detection, signed CSRF, browser binding, redirect-URI pinning,
  rate-limit, and the audit-log discipline below.
- These are documented non-goals for the local reference: local HTTP,
  default sentinel secrets, in-process refresh lock, no encryption-at-rest
  on Valkey, no DPoP / mTLS, no central session termination.
  See [README "What's deliberately not here"](README.md#whats-deliberately-not-here)
  and [`docs/architecture/architecture-decisions.md`](docs/architecture/architecture-decisions.md)
  §F for the reconsideration triggers.

The reference is not a deployable production system. Adapting it for
production requires the items in "Production hardening" below.

## Threat model

Threats grouped by surface. Each row names the threat, the implemented
mitigation, and the residual risk after the mitigation. The "Reference"
column points at the architecture-decisions §, RFC 9700 row, or OIDC
Core § that owns the deeper discussion.

### Browser ↔ Auth Service / API Gateway

| # | Threat | Mitigation | Residual | Reference |
|---|---|---|---|---|
| B-1 | XSS in SPA exfiltrates tokens | Browser holds no tokens. Session identity is opaque `__Host-sid` with `HttpOnly`. | An XSS can still impersonate the user for the lifetime of the session by issuing same-origin XHRs that ride the sid cookie. The browser-token boundary does not defend against in-page session abuse. | ADR §A1 |
| B-2 | CSRF on state-changing `/api/**` | Session-bound signed double-submit: `XSRF-TOKEN` carries `<value>.<HMAC-SHA256(value + ":" + sid)>`. The SPA echoes it as `X-XSRF-TOKEN`; both sides validate signature with the shared key and the request sid. | An attacker with `document.cookie` write on a sibling subdomain cannot forge a valid signature for the victim sid; pre-XSS access to the page can still issue same-origin requests (B-1). | ADR §B4 |
| B-3 | Login CSRF / cross-user session fixation — attacker initiates an OAuth flow, captures `(code, state)`, and induces the victim's browser to load the callback URL | `oauth_tx` browser-binding cookie (`HttpOnly`, `Path=/auth/callback/idp`). HMAC of cookie value stored in `tx:{state}`; callback fails closed when the victim's browser does not present the attacker's cookie. | None within the modelled attack chain. | ADR §B3 |
| B-4 | Authorization code interception / replay | PKCE S256 with per-request `code_verifier`; `tx:{state}` consumed atomically (`GETDEL`); Keycloak revokes codes on reuse. | None. | OIDC Core §3.1.3, RFC 9700 §4.2 / §4.3 / §4.5 |
| B-5 | ID-token tampering or substitution | Nimbus `IDTokenValidator`: signature (RS256 pinned), `iss`, `aud`, `exp`, `nonce` validated. `at_hash` validated when present. | None within the spec; key rotation handled by `JWKSourceBuilder` refresh-ahead + outage-tolerant cache. | OIDC Core §3.1.3.7 |
| B-6 | Authorization Server mix-up (multi-AS) | Single AS locally; `AuthController#callback` validates the RFC 9207 `iss` query parameter against the configured issuer when present. | Multi-AS deployments must add per-issuer `tx:{state}` binding. Out of scope here. | RFC 9700 §4.4, RFC 9207 |
| B-7 | Open redirector via `?return_to=` | `AuthController#isValidReturnTo`: same-origin relative path only. Rejects absolute / `//` / missing leading slash / overlong / encoded backslash / control chars. | None. | RFC 9700 §4.11 |
| B-8 | Open redirector via Host-header injection on `redirect_uri` | `app.base-url` config pins the public origin. When set, X-Forwarded-* is ignored entirely. | Production deployments MUST set `app.base-url`. Dev fall-back to forwarded headers is correct only when the gateway is the sole inbound path. | ADR §A6 (forwarded-header discipline) |
| B-9 | Click-jacking of the SPA | `X-Frame-Options: DENY` via Spring Security defaults. | None. | — |

### Refresh and session lifecycle

| # | Threat | Mitigation | Residual | Reference |
|---|---|---|---|---|
| S-1 | Refresh-token leakage from server-side store | Tokens stored only in `sess:{sid}` after ID-token validation; `SecurityAudit` log lines hash subject + sid; no token bytes ever logged. | Local Valkey runs without AUTH / TLS / encryption-at-rest — production must add these (see "Production hardening"). | RFC 9700 §4.9 |
| S-2 | Refresh-token reuse | Realm: `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`. `InternalRefreshController` surfaces Keycloak's `invalid_grant` as a 409 + `DEL sess:{sid}` + audit event. Rotation policy and the per-provider matrix: [`docs/reference/refresh-rotation.md`](docs/reference/refresh-rotation.md). | None within the rotation contract. | RFC 9700 §4.14 |
| S-3 | Concurrent refresh race producing reuse-detection false positives | Per-session `ReentrantLock` keyed on `sid`; under-lock re-read of `sess:{sid}` collapses two callers to one upstream refresh. | Clustered deployments need a state-store-backed lock (`SET NX EX`). Single-instance only here. | ADR §C2 |
| S-4 | Session lives past intended ceiling | `SessionRecord.absoluteExpiresAt` enforces an 8 h hard cap (kept ≤ the IdP SSO max session lifespan; Keycloak default 10 h). Both `AuthController#session` and `InternalRefreshController` `DEL sess:{sid}` when the ceiling is crossed (including the race window during a refresh round-trip). | None within the contract. | SPEC-0001 §7.2 |
| S-5 | Sub-session fixation: attacker who observed the sid cookie keeps it valid across token refreshes | Sid rotates only at initial callback, not on refresh. | Deliberately deferred. An attacker who had read access to the sid at any point retains that access for the absolute-TTL window. | See "Production hardening" below + ADR §F. |

### API Gateway and internal RPC

| # | Threat | Mitigation | Residual | Reference |
|---|---|---|---|---|
| G-1 | Attacker forges the upstream `Authorization` header by including one in the inbound request | `bff-session.lua` `HOP_BY_HOP` table strips inbound `authorization` before injecting the gateway-controlled bearer. | None. | `bff-session.lua` |
| G-2 | SSRF via `/api/**` to arbitrary upstream paths | APISIX route table is an explicit per-path allowlist (`/api/me`, `/api/user-data`, `/api/admin`). Off-allowlist paths return 404 before the plugin runs. | Adding an RS endpoint requires updating the gateway allowlist. | RFC 9700 §"chokepoint" guidance; ADR §C4 |
| G-3 | Inbound request bypasses CSRF on state-changing `/api/**` | Lua plugin `csrf_ok` validates `XSRF-TOKEN` cookie + `X-XSRF-TOKEN` header HMAC bound to the request sid for `POST` / `PUT` / `PATCH` / `DELETE`. | Same as B-1 — an XSS issuing same-origin requests can still read the JS-readable XSRF cookie and echo it. The signed-CSRF defense is against cookie-injection, not XSS. | ADR §B4 |
| G-4 | `/internal/resolve` reachable from the browser | APISIX route table does not expose `/internal/*`; only the in-cluster Lua plugin calls it. Auth Service Order-1 filter chain requires a valid Client-Credentials bearer with `aud=oidc-reference-auth-internal`. | None within the local topology. | SPEC-0001 §7.1 |
| G-5 | Attacker forges a Client-Credentials bearer for `/internal/resolve` | `SecurityConfig` + `InternalRefreshController` validate: signature (RS256), `iss`, `exp`, `aud` contains `oidc-reference-auth-internal`, `azp` or `client_id` is `oidc-reference-api-gateway`. | None. | SPEC-0001 §7.1 |
| G-6 | Client-credentials token cache stampede after expiry | `lua-resty-lock` around the token fetch — the loser of the race blocks until the winner has populated the cache, then re-reads. | None. | `bff-session.lua` `fetch_cc_token` |
| G-7 | Forged-IP burst against `/auth/login` exhausts `tx:{state}` entries | APISIX `limit-req` plugin per remote_addr on `/auth/login` and `/auth/callback/idp` (rate 5/s, burst 10). | A distributed attacker pool with different source IPs would still consume entries; `tx:{state}` TTL is 5 min, so steady-state burst impact is bounded. | `apisix.yaml.template` |

### Storage (Valkey)

| # | Threat | Mitigation | Residual | Reference |
|---|---|---|---|---|
| V-1 | `tx:{state}` replay | Atomic `GETDEL` consumes the record on first use — success or failure. | None. | `RedisStateStore#getAndDelete` |
| V-2 | `sess:{sid}` exposure via logs | `SecurityAudit` hashes subject + sid (SHA-256 truncated to 96 bits, base64url) for correlation; no raw sid, no token bytes. | None in the implementation. Operators MUST NOT add unstructured `log.info(session)` calls — would violate the contract. | `SecurityAudit` |
| V-3 | Unauthenticated network access to Valkey in production | Local stack runs Valkey unauthenticated on `127.0.0.1:6379` (inner-loop dev only). | Deferred for local; production must add AUTH + TLS + network isolation (see "Production hardening"). | SPEC-0001 §"Local Assumptions" |

### Deployment / secrets

| # | Threat | Mitigation | Residual | Reference |
|---|---|---|---|---|
| D-1 | Local-dev sentinel secrets ship to production | `SecretSentinelValidator` (Java) fails closed at boot — refuses to start — when `AUTH_CLIENT_SECRET` carries the `CHANGE_BEFORE_DEPLOY` marker or `APP_COOKIE_SIGNING_KEY` is the known dev base64, unless an explicit `local` / `dev` / `test` Spring profile is active. No active profile is treated as not-local and aborts boot, so a copied artifact cannot ship a dev sentinel with only a log line. Mirror guard in `bff-session.lua` emits a WARN at plugin load when its config carries either sentinel. The gateway secret never reaches the Java validator, so its fail-closed gate is at render time: `render-apisix-config.sh` refuses to emit the route file when `REQUIRE_NONDEV_SECRETS=1` and `GATEWAY_CLIENT_SECRET`/`CSRF_SIGNING_KEY` are still dev sentinels. | Production deploys MUST set the env vars explicitly and render with `REQUIRE_NONDEV_SECRETS=1`. APISIX `check_schema` cannot fail a route load, so the Lua guard only WARNs; the fail-closed boundaries are `SecretSentinelValidator` (Java, at boot) and `render-apisix-config.sh` (gateway secret, at render). | `SecretSentinelValidator`, `render-apisix-config.sh` |
| D-2 | Realm import contains known dev secrets | Realm JSON ships `LOCAL_DEV_*_CHANGE_BEFORE_DEPLOY` literals so a grep across the repo locates every place to rotate before any deploy. | The realm import IS the realm seed; production deploys swap to a managed Keycloak (or different IdP entirely) with its own client provisioning. | `authorization-server/realm/oidc-reference-realm.json` |

## Crypto primitives

| Use | Algorithm | Key size | Where |
|---|---|---|---|
| Signed CSRF token | HMAC-SHA256 | 256-bit shared key, standard-base64 (`CSRF_SIGNING_KEY` env) | `SignedCsrfSupport.hmacSha256` (Java), `bff-session.lua` `csrf_ok` |
| `oauth_tx` browser binding | HMAC-SHA256 | Same key as signed CSRF | `OAuthTxBinding` |
| Audit-log subject hash | SHA-256, truncated to 96 bits, base64url | — | `SecurityAudit.hashSub` |
| Audit-log sid hash | SHA-256, truncated to 96 bits, base64url | — | `SecurityAudit.hashSid` |
| ID-token signature verification | RS256 (pinned via `JWSVerificationKeySelector`) | Keycloak realm key (2048-bit RSA default) | `JwtOidcIdTokenValidator` |
| PKCE | S256 (SHA-256 challenge method, base64url) | — | Nimbus `CodeVerifier` + `CodeChallenge` |
| Opaque tokens (sid, state, nonce, CSRF value, oauth_tx) | `SecureRandom`, base64url, no padding | ≥128 bits each | `CryptoSupport.randomUrlToken` |

## Key handling

| Key | Used by | Local default | Detection of misuse |
|---|---|---|---|
| `AUTH_CLIENT_SECRET` | Auth Service ↔ Keycloak (OAuth client secret) | `LOCAL_DEV_AUTH_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY` | `SecretSentinelValidator` |
| `APP_COOKIE_SIGNING_KEY` / `CSRF_SIGNING_KEY` | Auth Service signer ↔ APISIX plugin validator | 32 zero-bytes base64-encoded | `SecretSentinelValidator` (Java) + `bff-session.lua` `warn_on_dev_sentinels` (Lua) |
| `GATEWAY_CLIENT_SECRET` | APISIX plugin ↔ Keycloak (Client-Credentials secret for `/internal/resolve`) | `LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY` | `render-apisix-config.sh` (`REQUIRE_NONDEV_SECRETS`, fail-closed at render) + `bff-session.lua` `warn_on_dev_sentinels` (WARN) |
| `SERVICE_CLIENT_SECRET` | External service clients ↔ Keycloak | `LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY` | Realm seed grep |

All four keys must be rotated before any non-local deployment. The
sentinel-marker scheme exists so that grep finds every reference in
one pass.

## Audit logging surface

`SecurityAudit.event(request, status, event, reason, [subject])` emits
single-line key=value records to the `security.audit` logger. Events
emitted today:

| Event | When | Reason values |
|---|---|---|
| `login_started` | `/auth/login` accepted | `ok` |
| `login_rejected` | `/auth/login` rejected | `invalid_return_to` |
| `callback_succeeded` | `/auth/callback/idp` minted `sess:{sid}` | `ok` |
| `callback_failed` | `/auth/callback/idp` rejected | `invalid_state`, `missing_tx_binding`, `missing_tx_cookie`, `tx_cookie_mismatch`, `iss_mismatch`, `token_exchange_failed` |
| `logout_succeeded` | `/auth/logout` accepted | `ok` |
| `auth_denied` | Authenticated request without a session, or CSRF mismatch | `no_session`, `csrf_invalid`, `missing_bearer`, `bearer_audience_or_client_mismatch` |
| `refresh_succeeded` | `/internal/resolve` rotated tokens on the near-expiry path | `ok` |
| `refresh_rejected` | Pre-refresh validation failed | `missing_sid`, `no_such_session`, `session_absolute_expired`, `session_absolute_expired_post_refresh`, `session_deleted_during_refresh`, `refresh_token_expired` |
| `refresh_failed` | Keycloak unreachable or other transient error | `authorization_server_unreachable` |
| `refresh_token_rejected` | Keycloak returned `invalid_grant` on refresh (reuse, expiry, revocation, or SSO max — not distinguishable at the RP) | `session_invalidated` |
| `backchannel_logout_succeeded` | `/backchannel-logout` accepted a valid `logout_token` | `session_deleted`, `no_matching_session` |
| `backchannel_logout_rejected` | `/backchannel-logout` rejected the token | `invalid_logout_token`, `missing_logout_token` |

The lock-free fresh path of `/internal/resolve` (access token still inside the
no-refresh window — the common case, taken on the majority of `/api/**`
requests) emits **no** audit event by design: one security-audit line per API
request is pure noise. Audit events fire only on a refresh attempt or a
rejection.

Never logged: access token, refresh token, ID token, raw `sid`,
raw `state`, raw `XSRF-TOKEN` value, raw `oauth_tx` value, client
secrets, request bodies.

Hashed for correlation: subject (`sub_hash=`), sid (`sid_hash=`).
Both are SHA-256 truncated to 96 bits, base64url. This is long enough
to make collision impractical at this scale, and short enough that the
hash alone is not session-recovery material.

## Production hardening

Items called out as "Production-only" or 🔄 in `RFC9700-compliance.md`
and `OIDC-compliance.md`. Address before any non-local deployment:

- HTTPS everywhere — `Secure` cookies require it; `__Host-sid` cookie
  prefix requires it.
- Set `app.base-url` to the public origin so `redirect_uri` is pinned
  and X-Forwarded-* is ignored.
- Set every `*_CLIENT_SECRET` and `CSRF_SIGNING_KEY` env var to a real
  value; rotate the Keycloak realm secrets.
- Run with a Spring profile of `prod` or `production` so
  `SecretSentinelValidator` fails closed if any sentinel survives.
- Valkey: enable AUTH, TLS, encryption-at-rest, and network isolation
  to the Auth Service + API Gateway only.
- Keycloak: production-mode start, real database, TLS, hardened admin
  console exposure.
- Distributed refresh lock (`SET NX EX` against the state store) if
  more than one Auth Service replica.
- Consider DPoP or mTLS for sender-constrained access tokens if the
  Resource Server is exposed to multi-tenant or untrusted callers
  (RFC 9700 §2.2.1, §4.9.3, §4.10.1).
- Consider asymmetric client authentication (`private_key_jwt` or
  mTLS) for FAPI / PSD2 (RFC 9700 §2.5).
- Add `Referrer-Policy: no-referrer` and a baseline CSP to every
  response, not only the logout 302 and callback errors.
- Sid rotation on token refresh if the threat model values defending
  against an attacker who briefly observed the sid.

## Reporting a vulnerability

This is a reference repo, not a hosted service.

For vulnerabilities in this implementation, open a private GitHub
Security Advisory via the repo's [Security tab](../../security/advisories/new).
Public issues are fine for general bugs. Use the private advisory
channel for anything you would not want to disclose before a fix is
published.

For vulnerabilities in the upstream libraries this reference depends
on (Spring Boot, Spring Security, Nimbus `oauth2-oidc-sdk`, Keycloak,
APISIX, Valkey, `lua-resty-http`, `lua-resty-lock`), report to the
respective project's published security channel.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
