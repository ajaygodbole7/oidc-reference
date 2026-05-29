# RFC 9700 Compliance

Status of this reference implementation against
[RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/).

Read the canonical flow first: root `README.md` (sequence diagram) and
`docs/specs/SPEC-0001-core-oidc-flows.md` (build contract).

## Status Legend

| Symbol | Meaning |
|---|---|
| ✅ | Verified by an executable check, concrete local config, or test. |
| 🟡 | Partial — covered in some surface only, or implemented but not asserted. |
| 🚫 | Not applicable to this reference's architecture (single AS, no in-browser tokens, etc.). |
| 🔄 | Production-only concern; called out in spec, not enforced locally over HTTP. |
| ⏳ | Known gap, deliberately deferred. See "Known Gaps" + README "What's deliberately not here". |

## Summary

Rows are intentionally not hand-counted. The status icon on each row is the
source of truth; when code is generated, rows move from 🧾 to ✅ only after an
executable gate proves them.

---

## §2.1 — Protecting Redirect-Based Flows

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1, 4.1.3 | Exact redirect-URI matching (`MUST`) | ✅ | Realm: `oidc-reference-bff` `redirectUris: ["http://127.0.0.1:5173/auth/callback/idp"]` (no wildcards; registration name is the generic `idp`, not the IdP brand). URI is the SPA origin so the OAuth callback flows through the Vite proxy and the session cookie binds to that origin. Smoke test asserts exact value. |
| 2.1, 4.11 | No open redirectors (`MUST NOT`) | ✅ | `AuthController#isValidReturnTo` validates the saved-request URL: same-origin relative path only, rejects absolute / `//` / missing leading slash / overlong / encoded backslash / control chars. Logout post-logout redirect is fixed. Asserted by `AuthControllerTest` return-to negative cases. |
| 2.1 | CSRF prevention (`MUST`) | ✅ | Login CSRF: `state` (server-side validated against `tx:{state}`), PKCE S256, ID-token `nonce`, and `oauth_tx` browser-binding cookie. State-changing calls: `__Host-sid` (`SameSite=Lax`) + signed HMAC-SHA256 double-submit on `XSRF-TOKEN` / `X-XSRF-TOKEN`. Naive double-submit is rejected — `SignedCsrfSupport` enforces signature compare. |
| 2.1, 4.4 | Mix-up defense (`REQUIRED` when ≥2 AS) | ✅ | Single Keycloak issuer locally, but `AuthController#callback` validates the RFC 9207 `iss` query parameter against the configured issuer when present (defense-in-depth even with one AS). |
| 2.1 | Credential forwarding prevention | ✅ | Keycloak default — user credentials live in the Keycloak session and are never forwarded to clients. |

## §2.1.1 — Authorization Code Grant

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1.1 | Public-client PKCE (`MUST`) | 🚫 | No public client exists. The BFF is confidential — see `oidc-reference-bff` (`publicClient: false`). |
| 2.1.1 | Confidential-client PKCE (`RECOMMENDED`) | ✅ | Enabled anyway: `attributes."pkce.code.challenge.method": "S256"` on the BFF client. |
| 2.1.1 | OIDC `nonce` alternative (`MAY`) | ✅ | `JwtOidcIdTokenValidator` delegates to Nimbus `IDTokenValidator.validate(parsed, new Nonce(transaction.nonce()))`; mismatch throws `BadCredentialsException`. Asserted by `JwtOidcIdTokenValidatorTest#nonceMismatchIsRejected`. |
| 2.1.1 | Transaction-specific PKCE/nonce (`MUST`) | ✅ | Per-request `code_verifier` and `nonce` generated in `AuthController#beginLogin` and written to `tx:{state}` via `OAuthTransaction`. `state` validated server-side via atomic `getAndDelete`. |
| 2.1.1 | Constant-value detection on AS | 🟡 | Keycloak does not expose this knob; our client never generates constants. Risk lives upstream. |
| 2.1.1 | `S256` challenge method (`SHOULD`) | ✅ | Realm requires `S256`; `plain` rejected. |
| 2.1.1 | AS supports PKCE (`MUST`) | ✅ | Keycloak supports PKCE; discovery exposes `code_challenge_methods_supported`. |
| 2.1.1 | AS enforces `code_verifier` when `code_challenge` sent (`MUST`) | ✅ | Keycloak default when PKCE required on client. |
| 2.1.1, 4.8.2 | PKCE downgrade prevention (`MUST`) | ✅ | Keycloak enforces — BFF client has PKCE required at registration. |
| 2.1.1 | Publish PKCE support in metadata (`MUST`) | ✅ | Keycloak discovery includes `code_challenge_methods_supported: ["plain","S256"]`. |

## §2.1.2 — Implicit Grant

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1.2 | Implicit grant (`SHOULD NOT`) | ✅ | Disabled on both clients (`implicitFlowEnabled: false`). Smoke test asserts. |
| 2.1.2 | Prefer code response type (`SHOULD`) | ✅ | Only `authorization_code` and `client_credentials` enabled. |

## §2.2 — Token Replay Prevention

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.2.1 | Sender-constrained tokens via mTLS/DPoP (`SHOULD`) | ⏳ | Not implemented. BFF holds tokens server-side (mitigates browser-leakage primary motivation) but tokens are bearer at the wire. See "Known Gaps". |
| 2.2.2, 4.14 | Public-client refresh tokens must be sender-constrained OR rotated (`MUST`) | ✅ | No public client. Confidential clients also rotate refresh tokens: realm `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`. |

## §2.3 — Access-Token Privilege Restriction

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.3 | Least privilege (`SHOULD`) | ✅ | BFF default scopes: `openid profile email roles api.audience api.read` (no admin/write by default). Service client default scopes: `api.audience service.jobs`. |
| 2.3 | Audience restriction (`SHOULD`); RS verifies (`MUST`) | ✅ | `api.audience` client scope's `oidc-audience-mapper` adds `oidc-reference-api` to `aud`. Resource Server's `application.yml` configures `spring.security.oauth2.resourceserver.jwt.audiences`. Wrong-audience rejection asserted by `ApiSecurityTest`. |
| 2.3 | Resource/action restriction (scope or `authorization_details`) | ✅ | Scopes used: `api.read`, `api.write`, `admin.read`, `service.jobs`. RAR (RFC 9396) not used. |

## §2.4 — ROPC

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.4 | ROPC grant (`MUST NOT`) | ✅ | `directAccessGrantsEnabled: false` on both clients. Smoke test asserts. |

## §2.5 — Client Authentication

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.5 | Enforce client authentication (`SHOULD`) | ✅ | Both clients confidential; secrets required. |
| 2.5 | Asymmetric auth (mTLS / Private Key JWT) (`RECOMMENDED`) | ⏳ | Using `client_secret_basic`. Private Key JWT / mTLS deferred — see "Known Gaps". |

## §2.6 — Other Recommendations

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.6 | Publish AS metadata (RFC 8414) | ✅ | Keycloak publishes `.well-known/openid-configuration`. BFF + RS consume via `issuer-uri`. Smoke test verifies. |
| 2.6, 4.15 | Restrict client influence over `client_id` (`SHOULD NOT`) | ✅ | Client IDs are realm-immutable. |
| 2.6 | End-to-end TLS (`RECOMMENDED`) | 🔄 | Local HTTP for dev; production guidance in SPEC-0001 ("Local Assumptions"). |
| 2.6 | No unencrypted authz response transport (`MUST NOT`) | 🔄 | Same — local exception, production HTTPS required. |
| 2.6, 4.16 | No HTTP redirect URIs except loopback (`MUST NOT`) | ✅ | All redirect URIs are `localhost`/`127.0.0.1` loopback (RFC-permitted exception). Production: HTTPS required, documented in spec. |
| 2.6, 4.17 | In-browser message verification (`MUST`) | 🚫 | No `postMessage` flows; HTTP redirects only. |
| 2.6 | CORS — never at authz endpoint (`MUST NOT`) | ✅ | Authz endpoint is `redirect`-driven, not fetched. RS `CorsConfigurationSource` denies all browser origins (defense in depth). BFF is same-origin to SPA via Vite proxy. |

## §4.1 — Insufficient Redirect-URI Validation

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.1.3 | Exact string comparison (`MUST`) | ✅ | See §2.1 above. |
| 4.1.3 | Web servers hosting redirect URI: no open redirector (`MUST NOT`) | ✅ | BFF callback handler is Spring's framework filter; no user-supplied URL. |
| 4.1.3 | Fragment reattachment prevention (`MAY`) | 🚫 | Using `code` response type; no fragment-bearing response. |
| 4.1.3 | Prefer code response type (`SHOULD`) | ✅ | Only `code` used. |
| 4.1.3 | Origin verification via RFC 9101 / RFC 9126 (`MAY`) | ⏳ | JAR / PAR not used. Acceptable per BCP (MAY). Deferred. |

## §4.2 — Credential Leakage via Referer

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.2.4 | No third-party resources on authz pages (`SHOULD NOT`) | ✅ | Keycloak login page is self-hosted in the local profile. SPA loads no third-party scripts. |
| 4.2.4 | `Referrer-Policy` header | 🟡 | `Referrer-Policy: no-referrer` set explicitly on the logout 302 (id_token_hint carries PII) and on callback error responses; not yet on every response. Other security headers via Spring's defaults. |
| 4.2.4 | Code response type over access-token types | ✅ | Covered. |
| 4.2.4 | Code bound to client or PKCE | ✅ | Confidential client + PKCE both. |
| 4.2.4 | Code invalidated on first use (`MUST`) | ✅ | Keycloak default. |
| 4.2.4 | Revoke tokens issued from a re-used code (`SHOULD`) | ✅ | Keycloak default on code reuse. |
| 4.2.4 | State invalidated after first use (`SHOULD`) | ✅ | `AuthController#callback` does `stateStore.getAndDelete(txKey)` atomically (Redis `GETDEL`). Asserted by `AuthControllerTest#callbackConsumesTransaction*` cases. |
| 4.2.4 | `form_post` response mode | 🚫 | Default `query` mode. Code is short-lived and PKCE-bound; both core mitigations already apply. |

## §4.3 — Credential Leakage via Browser History

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.3.1 | Code replay prevention | ✅ | Codes single-use (Keycloak); BFF stores PKCE verifier per transaction in the Redis-compatible state store. |
| 4.3.2 | No access tokens in URI query (`MUST NOT`) | ✅ | Tokens never reach the browser. BFF uses `Authorization: Bearer` header to RS. |

## §4.4 — Mix-Up Attacks

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.4.2 | Bind issuer to authz request | 🚫 | Single AS. |
| 4.4.2.1 | RFC 9207 `iss` parameter / `iss` in ID Token (`MUST`) | ✅ | ID Token `iss` validated by Nimbus `IDTokenValidator` on every callback. `AuthController#callback` also validates the RFC 9207 `iss` query parameter against the configured issuer when present (defense-in-depth even on single-AS). Asserted by `AuthControllerTest#callbackRejectsIssParamFromWrongIssuer`. |
| 4.4.2.2 | Distinct redirect URI per issuer (`MUST`) | 🚫 | Single AS, single redirect URI. |

## §4.5 — Authorization Code Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.5.3.1 | PKCE for code injection (`REQUIRED` as countermeasure) | ✅ | Enforced. |
| 4.5.3.2 | Validate `nonce` in ID Token from token endpoint (`MUST`); ignore tokens until validated (`MUST`) | ✅ | `AuthorizationCodeTokenExchangeClient` validates the ID token via `JwtOidcIdTokenValidator` (Nimbus) — signature, iss, aud, exp, nonce, and `at_hash` when present — *before* `SessionRecord` is constructed. `sess:{sid}` only persists after validation succeeds. |
| 4.5.4 | Prevent authorization-response read | ✅ | HTTPS in prod (documented); short-lived code + PKCE bind. |

## §4.6 — Access Token Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.6.1 | `at_hash` mitigation | ✅ | OIDC Core §3.1.3.7 step 7: `JwtOidcIdTokenValidator#enforceAtHash` validates `at_hash` via Nimbus `AccessTokenValidator` whenever the ID token carries the claim (Keycloak's ID tokens do in this flow). Mismatch throws `BadCredentialsException`. Asserted by `JwtOidcIdTokenValidatorTest#atHashMismatchIsRejected`. |

## §4.7 — CSRF

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.7.1 | CSRF token in `state` (or PKCE) | ✅ | `state` validated server-side against `tx:{state}` (atomic `getAndDelete`); PKCE S256 enforced; ID-token `nonce` validated by `JwtOidcIdTokenValidator`. `oauth_tx` cookie adds browser binding for the inverse threat where the attacker initiated the OAuth flow. See `architecture-decisions.md` §B3. |
| 4.7.1 | Verify AS supports PKCE before relying on it (`MUST`) | ✅ | BFF reads discovery via `issuer-uri`; Spring fails closed if endpoints missing. |
| 4.7.1 | Protect `state` content if it carries app state (`MUST`) | ✅ | We do not embed app state in `state` — Spring's opaque random. |
| 4.7.1 | PKCE robustness | ✅ | Used. |

## §4.8 — PKCE Downgrade

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.8.2 | Reject `code_verifier` when no `code_challenge` was sent (`MUST`) | ✅ | Keycloak enforces because PKCE is required on the client. |

## §4.9 — Access Token Leakage at Resource Server

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.9.3 | Sender-constrained tokens to prevent replay | ⏳ | Not implemented. See "Known Gaps". |
| 4.9.3 | Audience restriction | ✅ | Asserted by `ApiSecurityTest` — wrong/missing audience tokens are rejected at the RS. |
| 4.9.3 | Treat tokens as secrets; no plaintext store/transfer (`MUST`) | ✅ | RS does not persist tokens. Auth Service stores tokens in `sess:{sid}` only after ID-token validation succeeds. `SecurityAudit` log lines hash subject + sid; no token bytes ever logged. Production guidance still requires Valkey AUTH + TLS + encryption-at-rest (SPEC-0001 Threat Model). |

## §4.10 — Misuse of Stolen Tokens

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.10.1 | mTLS (RFC 8705) or DPoP (RFC 9449) | ⏳ | Deferred — see "Known Gaps". |
| 4.10.2 | AS binds token to RS; RS verifies (`MUST` refuse on failure) | ✅ | `api.audience` mapper binds `aud=oidc-reference-api`; RS rejects mismatched audience. Asserted by `ApiSecurityTest`. |
| 4.10.2 | Resource indicator (RFC 8707) `resource` parameter | 🟡 | Not used. We use scope-based audience binding via the `api.audience` scope, which is BCP-acceptable. |
| 4.10.2 | Express audience as the URL the client calls (not logical name) | 🟡 | Using logical name `oidc-reference-api`. Defensible for a single-RS reference; for multi-RS, switch to URL form. |

## §4.11 — Open Redirection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.11.1 | Client open redirector (`MUST NOT`) | ✅ | `AuthController#isValidReturnTo` enforces same-origin relative path; anything else falls back to `/`. Asserted by `AuthControllerTest` return-to negative cases (`%5C`, `//`, absolute, control-char, overlong). |
| 4.11.2 | AS no auto-redirect on bad `client_id`/`redirect_uri` (`MUST NOT`) | ✅ | Keycloak default. |
| 4.11.2 | AS always authenticate user before redirect (`MUST`) | ✅ | Keycloak default. |
| 4.11.2 | AS only auto-redirect if URI trusted (`SHOULD`) | ✅ | Keycloak default — only matched registered URIs. |

## §4.12 — 307 Redirect

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.12 | No HTTP 307 for credential-bearing requests (`MUST NOT`); use 303 | ✅ | Spring Security and Keycloak use 302/303 for OAuth redirects. |

## §4.13 — TLS-Terminating Reverse Proxies

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.13 | Secure handling when TLS terminated at proxy | 🔄 | Production-only; BFF sets `server.forward-headers-strategy: framework` so it honors `X-Forwarded-*` from a trusted proxy. Document trust boundary in production guidance. |

## §4.14 — Refresh-Token Protection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.14 | Rotation with reuse detection | ✅ | Realm: `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`. `AuthorizationCodeTokenRefreshClient` surfaces Keycloak's `invalid_grant` as `InvalidRefreshTokenException`; `InternalRefreshController` deletes `sess:{sid}` and returns 409. Per-session refresh serialized via `ReentrantLock` keyed on `sid`. Asserted by `InternalRefreshControllerTest`. |
| 4.14 | Audit on reuse | ✅ | `InternalRefreshController` emits `SecurityAudit.event(... "refresh_token_reuse", "session_invalidated", subjectClaim)` with `sid_hash` (not raw sid) before the 409. Asserted by `InternalRefreshControllerTest`. |

## §4.15 — Client Impersonating Resource Owner

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.15 | Restrict client influence over claims (`SHOULD NOT`) | ✅ | Keycloak default; client_id and core claims are server-controlled. |

## §4.17 — In-Browser Communication Flows

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.17.2 | Strict verification of `postMessage` initiator/receiver (`MUST`) | 🚫 | No `postMessage` flows. |

---

## Known Gaps

Tracked items where the reference is intentionally short of the BCP and what
would close them. Each item must also have a backlog entry.

| Gap | Why | What closes it |
|---|---|---|
| Sender-constrained access tokens (DPoP or mTLS) — §2.2.1, §4.9.3, §4.10.1 | The BFF removes the primary browser-leakage motivation but tokens are bearer at the gateway → RS hop. | Reconsider when the RS is exposed to multi-tenant or untrusted callers. See README "What's deliberately not here". |
| Asymmetric client authentication — §2.5 | All confidential clients use `client_secret_basic`. | Reconsider for FAPI / PSD2 compliance regimes. |
| Global `Referrer-Policy: no-referrer` + CSP baseline — §4.2.4 | Set explicitly on the logout 302 and callback error responses; not yet on every response. | Add a `HeaderWriter` in `SecurityConfig` once the production-hardening pass starts. |
| Audience as URL form — §4.10.2.2 | Using logical `oidc-reference-api`. | If multi-RS is added, switch the audience mapper to the RS base URL per BCP guidance. |
| JAR (RFC 9101) / PAR (RFC 9126) / RAR (RFC 9396) | Not used; exact-match redirect URI + PKCE + state + nonce + `oauth_tx` cover the demonstrated flow. | Reconsider for multiple authorization servers or structured per-resource grants. |

## Architecture Notes

Several BCP items are satisfied not by adding mechanism but by the BFF
session pattern itself:

- **Browser never holds tokens** → §4.3.2, §4.9.3 baseline confidentiality,
  and §4.6 (no token injection into a JS context) are addressed
  architecturally. The browser cannot replay what it never receives.
- **PKCE + confidential client + secret + rotation** are all stacked on the
  BFF↔Keycloak hop — defense in depth on the only OAuth surface that exists.
- **Resource Server is not browser-reachable** in the canonical Compose
  stack; CORS denial on `/api/**` is defense in depth.

The same-origin pattern has two consistent ingress shapes: the full
Compose stack uses **APISIX** as a path-routing ingress (`/auth/*` →
Auth Service, `/api/**` → API Gateway), and the frontend dev loop uses
the **Vite proxy** with the same path-routing. Both forward
`X-Forwarded-*` headers; the upstream Spring services run with
`forward-headers-strategy: framework`. This is the cookie-binding
guarantee that makes the BFF model work: the registered redirect URI is
the single browser-visible origin, so the callback flows through the
ingress, `Set-Cookie` is bound to that origin, and subsequent
same-origin fetches carry the cookie automatically.

RFC 9700 compliance is IdP-agnostic. Keycloak is the local reference;
any OIDC-compliant authorization server with equivalent configuration
preserves these items. See SPEC-0001 §"Authorization Server Portability".

## How to update this file

Re-run the §2 and §4 mapping when any of the following change:

- Realm JSON (`authorization-server/realm/oidc-reference-realm.json`).
- Auth Service `SecurityConfig` / `AuthController` / `JwtOidcIdTokenValidator`
  (`auth-service/src/main/java/...`).
- Resource Server `application.yml` JWT decoder config or
  `ApiController` security annotations.
- Lua gateway plugin (`api-gateway/plugins/bff-session.lua`) when it
  changes CSRF or session-read behavior.
- Any token endpoint behavior (refresh rotation, audience mapping).

Cite the RFC section number and link the changed file path.
