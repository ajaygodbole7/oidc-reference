# RFC 9700 Compliance

Status of this reference implementation against
[RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/).

RFC 9700 is the security BCP that OAuth 2.1
([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))
consolidates into the protocol baseline. A row marked ✅ here is also
satisfied for the corresponding OAuth 2.1 requirement.

Canonical sources for the implementation: `README.md` (flow diagrams) and
`docs/specs/SPEC-0001-core-oidc-flows.md` (build contract).

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Verified by an executable check, concrete local config, or test. |
| 🟡 | Partial — covered in some surface only, or implemented but not asserted. |
| 🚫 | Not applicable to this reference's architecture (single AS, no in-browser tokens, etc.). |
| 🔄 | Production-only concern; documented but not enforced over local HTTP. |
| ⏳ | Deliberately deferred. See "Known gaps" + README "What's deliberately not here". |

---

## §2.1 — Protecting Redirect-Based Flows

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1, 4.1.3 | Exact redirect-URI matching (`MUST`) | ✅ | Realm: `oidc-reference-auth` `redirectUris: ["http://127.0.0.1:5173/auth/callback/idp"]` (no wildcards; client-registration name is the generic `idp`, not the IdP brand). Realm-static-checks smoke asserts the exact value. |
| 2.1, 4.11 | No open redirectors (`MUST NOT`) | ✅ | `AuthController#isValidReturnTo` validates the saved-request URL: same-origin relative path only, rejects absolute / `//` / missing leading slash / overlong / encoded backslash / control chars. Logout post-logout redirect is fixed. Asserted by `AuthControllerTest` return-to negative cases. |
| 2.1 | CSRF prevention (`MUST`) | ✅ | Login CSRF: `state` validated against `tx:{state}`, PKCE S256, ID-token `nonce`, and `oauth_tx` browser-binding cookie. State-changing calls: `__Host-sid` (`SameSite=Lax`) + signed HMAC-SHA256 double-submit on `XSRF-TOKEN` / `X-XSRF-TOKEN`. Naive double-submit is rejected by `SignedCsrfSupport`. |
| 2.1, 4.4 | Mix-up defense (`REQUIRED` when ≥2 AS) | ✅ | Single Keycloak issuer locally; `AuthController#callback` validates the RFC 9207 `iss` query parameter against the configured issuer when present (defense-in-depth on a single AS). |
| 2.1 | Credential forwarding prevention | ✅ | User credentials live in the Keycloak session and are never forwarded to clients (Keycloak default). |

## §2.1.1 — Authorization Code Grant

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1.1 | Public-client PKCE (`MUST`) | 🚫 | No public client. The Auth Service is confidential (`publicClient: false`). |
| 2.1.1 | Confidential-client PKCE (`RECOMMENDED`) | ✅ | Enforced on the realm client: `pkce.code.challenge.method: S256`. |
| 2.1.1 | OIDC `nonce` alternative (`MAY`) | ✅ | `JwtOidcIdTokenValidator` delegates to Nimbus `IDTokenValidator.validate(parsed, new Nonce(transaction.nonce()))`; mismatch throws `BadCredentialsException`. Asserted by `JwtOidcIdTokenValidatorTest#nonceMismatchIsRejected`. |
| 2.1.1 | Transaction-specific PKCE/nonce (`MUST`) | ✅ | Per-request `code_verifier` and `nonce` generated in `AuthController#beginLogin` and persisted in `tx:{state}` via `OAuthTransaction`. `state` validated server-side via atomic `getAndDelete`. |
| 2.1.1 | Constant-value detection on AS | 🟡 | Keycloak does not expose this knob; the client never generates constants. Risk lives upstream. |
| 2.1.1 | `S256` challenge method (`SHOULD`) | ✅ | Realm requires `S256`; `plain` rejected. |
| 2.1.1 | AS supports PKCE (`MUST`) | ✅ | Keycloak discovery exposes `code_challenge_methods_supported`. |
| 2.1.1 | AS enforces `code_verifier` when `code_challenge` sent (`MUST`) | ✅ | Keycloak default when PKCE required on client. |
| 2.1.1, 4.8.2 | PKCE downgrade prevention (`MUST`) | ✅ | Keycloak enforces — client has PKCE required at registration. |
| 2.1.1 | Publish PKCE support in metadata (`MUST`) | ✅ | Discovery includes `code_challenge_methods_supported: ["plain","S256"]`. |

## §2.1.2 — Implicit Grant

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1.2 | Implicit grant (`SHOULD NOT`) | ✅ | Disabled on all clients (`implicitFlowEnabled: false`). Smoke test asserts. |
| 2.1.2 | Prefer code response type (`SHOULD`) | ✅ | Only `authorization_code` and `client_credentials` enabled. |

## §2.2 — Token Replay Prevention

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.2.1 | Sender-constrained tokens via mTLS/DPoP (`SHOULD`) | ⏳ | Tokens are bearer at the API Gateway → Resource Server hop. The BFF pattern removes the browser-leakage motivation. |
| 2.2.2, 4.14 | Public-client refresh tokens must be sender-constrained OR rotated (`MUST`) | ✅ | No public client. Confidential clients rotate: realm `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`. |

## §2.3 — Access-Token Privilege Restriction

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.3 | Least privilege (`SHOULD`) | ✅ | Auth Service client default scopes: `openid profile email roles api.audience api.read` (no admin/write by default). Service client default scopes: `api.audience service.jobs`. |
| 2.3 | Audience restriction (`SHOULD`); RS verifies (`MUST`) | ✅ | `api.audience` client scope's `oidc-audience-mapper` adds `oidc-reference-api` to `aud`. Resource Server validates `aud` with a custom `JwtClaimValidator` on `app.audience` (env `OIDC_AUDIENCE`, default `oidc-reference-api`) in `SecurityConfig`, accepting both the RFC-7519 string and array shapes. Wrong-audience rejection asserted by `ApiSecurityTest`. |
| 2.3 | Resource/action restriction (scope or `authorization_details`) | ✅ | Scopes: `api.read`, `api.write`, `admin.read`, `service.jobs`. RAR (RFC 9396) not used. |

## §2.4 — ROPC

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.4 | ROPC grant (`MUST NOT`) | ✅ | `directAccessGrantsEnabled: false` on all clients. Smoke test asserts. |

## §2.5 — Client Authentication

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.5 | Enforce client authentication (`SHOULD`) | ✅ | All clients confidential; secrets required. |
| 2.5 | Asymmetric auth (mTLS / Private Key JWT) (`RECOMMENDED`) | ⏳ | Using `client_secret_basic`. |

## §2.6 — Other Recommendations

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.6 | Publish AS metadata (RFC 8414) | ✅ | Keycloak publishes `.well-known/openid-configuration`. Auth Service + RS consume via `issuer-uri`. Smoke test verifies. |
| 2.6, 4.15 | Restrict client influence over `client_id` (`SHOULD NOT`) | ✅ | Client IDs are realm-immutable. |
| 2.6 | End-to-end TLS (`RECOMMENDED`) | 🔄 | Local HTTP for dev; production guidance in SPEC-0001 §"Local Assumptions". |
| 2.6 | No unencrypted authz response transport (`MUST NOT`) | 🔄 | Local exception; production HTTPS required. |
| 2.6, 4.16 | No HTTP redirect URIs except loopback (`MUST NOT`) | ✅ | All redirect URIs are `localhost`/`127.0.0.1` (RFC-permitted loopback exception). |
| 2.6, 4.17 | In-browser message verification (`MUST`) | 🚫 | No `postMessage` flows; HTTP redirects only. |
| 2.6 | CORS — never at authz endpoint (`MUST NOT`) | ✅ | Authz endpoint is redirect-driven, not fetched. Resource Server CORS denies all browser origins (defense in depth — the RS is not browser-reachable in any case). |

## §4.1 — Insufficient Redirect-URI Validation

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.1.3 | Exact string comparison (`MUST`) | ✅ | See §2.1. |
| 4.1.3 | Web servers hosting redirect URI: no open redirector (`MUST NOT`) | ✅ | Auth Service callback handler does not accept a user-supplied URL beyond the validated `return_to`. |
| 4.1.3 | Fragment reattachment prevention (`MAY`) | 🚫 | Using `code` response type; no fragment-bearing response. |
| 4.1.3 | Prefer code response type (`SHOULD`) | ✅ | Only `code` used. |
| 4.1.3 | Origin verification via RFC 9101 / RFC 9126 (`MAY`) | ⏳ | JAR / PAR not used (acceptable per BCP `MAY`). |

## §4.2 — Credential Leakage via Referer

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.2.4 | No third-party resources on authz pages (`SHOULD NOT`) | ✅ | Keycloak login page is self-hosted. SPA loads no third-party scripts. |
| 4.2.4 | `Referrer-Policy` header | 🟡 | `Referrer-Policy: no-referrer` set on the logout 302 (id_token_hint carries PII) and on callback error responses. Other responses use Spring's defaults. |
| 4.2.4 | Code response type over access-token types | ✅ | Covered. |
| 4.2.4 | Code bound to client or PKCE | ✅ | Confidential client + PKCE. |
| 4.2.4 | Code invalidated on first use (`MUST`) | ✅ | Keycloak default. |
| 4.2.4 | Revoke tokens issued from a re-used code (`SHOULD`) | ✅ | Keycloak default on code reuse. |
| 4.2.4 | State invalidated after first use (`SHOULD`) | ✅ | `AuthController#callback` does `stateStore.getAndDelete(txKey)` atomically (Redis `GETDEL`). |
| 4.2.4 | `form_post` response mode | 🚫 | Default `query` mode. Code is short-lived and PKCE-bound. |

## §4.3 — Credential Leakage via Browser History

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.3.1 | Code replay prevention | ✅ | Codes single-use (Keycloak); PKCE verifier kept per transaction in `tx:{state}`. |
| 4.3.2 | No access tokens in URI query (`MUST NOT`) | ✅ | Tokens never reach the browser. API Gateway injects `Authorization: Bearer` on upstream calls. |

## §4.4 — Mix-Up Attacks

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.4.2 | Bind issuer to authz request | 🚫 | Single AS. |
| 4.4.2.1 | RFC 9207 `iss` parameter / `iss` in ID Token (`MUST`) | ✅ | ID Token `iss` validated by Nimbus `IDTokenValidator` on every callback. `AuthController#callback` also validates the RFC 9207 `iss` query parameter against the configured issuer when present. Asserted by `AuthControllerTest#callbackRejectsIssParamFromWrongIssuer`. |
| 4.4.2.2 | Distinct redirect URI per issuer (`MUST`) | 🚫 | Single AS, single redirect URI. |

## §4.5 — Authorization Code Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.5.3.1 | PKCE for code injection (`REQUIRED` countermeasure) | ✅ | Enforced. |
| 4.5.3.2 | Validate `nonce` in ID Token from token endpoint (`MUST`); ignore tokens until validated (`MUST`) | ✅ | `AuthorizationCodeTokenExchangeClient` validates the ID token via `JwtOidcIdTokenValidator` (signature, `iss`, `aud`, `exp`, `nonce`, `at_hash` when present) *before* `SessionRecord` is constructed. `sess:{sid}` persists only after validation succeeds. |
| 4.5.4 | Prevent authorization-response read | ✅ | Short-lived code + PKCE bind. HTTPS in production. |

## §4.6 — Access Token Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.6.1 | `at_hash` mitigation | ✅ | OIDC Core §3.1.3.7 step 7: `JwtOidcIdTokenValidator#enforceAtHash` validates `at_hash` via Nimbus `AccessTokenValidator` whenever the ID token carries the claim. Mismatch throws `BadCredentialsException`. Asserted by `JwtOidcIdTokenValidatorTest#atHashMismatchIsRejected`. |

## §4.7 — CSRF

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.7.1 | CSRF token in `state` (or PKCE) | ✅ | `state` validated server-side against `tx:{state}` (atomic `getAndDelete`); PKCE S256 enforced; ID-token `nonce` validated. `oauth_tx` cookie adds browser binding for the inverse threat (attacker-initiated OAuth flow + induced victim callback). See `architecture-decisions.md` §B3. |
| 4.7.1 | Verify AS supports PKCE before relying on it (`MUST`) | ✅ | `OidcProviderMetadata.discover()` fails closed at startup if the discovery document is missing required endpoints. |
| 4.7.1 | Protect `state` content if it carries app state (`MUST`) | ✅ | `state` is an opaque random token (`CryptoSupport.randomUrlToken(32)`). No app state embedded. |
| 4.7.1 | PKCE robustness | ✅ | S256, transaction-specific. |

## §4.8 — PKCE Downgrade

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.8.2 | Reject `code_verifier` when no `code_challenge` was sent (`MUST`) | ✅ | Keycloak enforces because PKCE is required on the client. |

## §4.9 — Access Token Leakage at Resource Server

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.9.3 | Sender-constrained tokens to prevent replay | ⏳ | DPoP / mTLS not implemented. |
| 4.9.3 | Audience restriction | ✅ | Wrong-audience tokens rejected at the RS. Asserted by `ApiSecurityTest`. |
| 4.9.3 | Treat tokens as secrets; no plaintext store/transfer (`MUST`) | ✅ | RS does not persist tokens. Auth Service stores tokens in `sess:{sid}` only after ID-token validation succeeds. `SecurityAudit` log lines hash subject + sid; no token bytes ever logged. Production guidance still requires Valkey AUTH + TLS + encryption-at-rest. |

## §4.10 — Misuse of Stolen Tokens

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.10.1 | mTLS (RFC 8705) or DPoP (RFC 9449) | ⏳ | Deferred. |
| 4.10.2 | AS binds token to RS; RS verifies (`MUST` refuse on failure) | ✅ | `api.audience` mapper binds `aud=oidc-reference-api`; RS rejects mismatched audience. Asserted by `ApiSecurityTest`. |
| 4.10.2 | Resource indicator (RFC 8707) `resource` parameter | 🟡 | Not used. Scope-based audience binding via the `api.audience` scope is BCP-acceptable. |
| 4.10.2 | Express audience as the URL the client calls (not logical name) | 🟡 | Using logical name `oidc-reference-api`. Defensible for a single-RS reference; switch to URL form for multi-RS. |

## §4.11 — Open Redirection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.11.1 | Client open redirector (`MUST NOT`) | ✅ | `AuthController#isValidReturnTo` enforces same-origin relative path. Asserted by `AuthControllerTest` return-to negative cases (`%5C`, `//`, absolute, control-char, overlong). |
| 4.11.2 | AS no auto-redirect on bad `client_id`/`redirect_uri` (`MUST NOT`) | ✅ | Keycloak default. |
| 4.11.2 | AS always authenticate user before redirect (`MUST`) | ✅ | Keycloak default. |
| 4.11.2 | AS only auto-redirect if URI trusted (`SHOULD`) | ✅ | Keycloak default — only matched registered URIs. |

## §4.12 — 307 Redirect

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.12 | No HTTP 307 for credential-bearing requests (`MUST NOT`); use 303 | ✅ | Spring and Keycloak use 302/303 for OAuth redirects. |

## §4.13 — TLS-Terminating Reverse Proxies

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.13 | Secure handling when TLS terminated at proxy | 🔄 | Auth Service sets `server.forward-headers-strategy: framework` to honor `X-Forwarded-*` from a trusted proxy. `app.base-url` pins the redirect URI when set, ignoring forwarded headers entirely. |

## §4.14 — Refresh-Token Protection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.14 | Rotation with reuse detection | ✅ | Realm: `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`. `AuthorizationCodeTokenRefreshClient` surfaces Keycloak's `invalid_grant` as `InvalidRefreshTokenException`; `InternalRefreshController` deletes `sess:{sid}` and returns 409. Per-session refresh serialized via `ReentrantLock` keyed on `sid`. Asserted by `InternalRefreshControllerTest`. |
| 4.14 | Audit on refresh rejection (incl. reuse) | ✅ | `InternalRefreshController` emits `SecurityAudit.event(... "refresh_token_rejected", "session_invalidated", subjectClaim)` with `sid_hash` (never the raw sid) before the 409. `invalid_grant` is not provably reuse at the RP (RFC 6749 §5.2), so the event is labeled honestly; reuse still invalidates the session. |

## §4.15 — Client Impersonating Resource Owner

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.15 | Restrict client influence over claims (`SHOULD NOT`) | ✅ | Keycloak default; `client_id` and core claims are server-controlled. |

## §4.17 — In-Browser Communication Flows

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.17.2 | Strict verification of `postMessage` initiator/receiver (`MUST`) | 🚫 | No `postMessage` flows. |

---

## Known gaps

Items where the reference is short of the BCP, with the
trigger for reconsidering.

| Gap | Why | When to revisit |
|---|---|---|
| Sender-constrained access tokens (DPoP or mTLS) — §2.2.1, §4.9.3, §4.10.1 | Tokens are bearer on the API Gateway → Resource Server hop. The BFF removes the browser-leakage motivation. | RS exposed to multi-tenant or untrusted callers. |
| Asymmetric client authentication — §2.5 | All confidential clients use `client_secret_basic`. | FAPI / PSD2 compliance regimes. |
| Global `Referrer-Policy: no-referrer` + CSP baseline — §4.2.4 | Set explicitly on the logout 302 and callback error responses; not on every response. | Production hardening. |
| Audience as URL form — §4.10.2.2 | Using logical name `oidc-reference-api`. | Multiple Resource Servers. |
| JAR (RFC 9101) / PAR (RFC 9126) / RAR (RFC 9396) | Exact-match redirect URI + PKCE + state + nonce + `oauth_tx` cover the demonstrated flow. | Multiple authorization servers, untrusted-network authorization request handling, or structured per-resource grants. |

## Architecture notes

Several BCP items are satisfied by the BFF session pattern itself rather
than by an added mechanism:

- **Tokens never reach the browser.** §4.3.2 (no access tokens in URI),
  §4.6 (no access-token injection into a JS context), and the baseline
  confidentiality property of §4.9.3 are addressed architecturally.
- **PKCE + confidential client + secret + rotation** stack on the
  Auth Service ↔ Keycloak hop, the only OAuth surface in the system.
- **Resource Server is not browser-reachable.** The Compose topology
  keeps the RS on the internal network; the API Gateway is the only
  inbound path. CORS denial on `/api/**` is defense in depth.

RFC 9700 compliance is IdP-agnostic. Keycloak is the local IdP; any
OIDC-compliant authorization server with equivalent realm configuration
preserves these rows. See SPEC-0001 Appendix A.

## Updating this file

Revisit the §2 and §4 mappings when any of these change:

- Realm JSON (`authorization-server/realm/oidc-reference-realm.json`).
- Auth Service `SecurityConfig`, `AuthController`, or
  `JwtOidcIdTokenValidator`.
- Resource Server `application.yml` JWT-decoder config or `ApiController`
  authorization checks.
- API Gateway plugin (`api-gateway/plugins/bff-session.lua`) — CSRF or
  session-read behavior.
- Token-endpoint behavior (refresh rotation, audience mapping).

Cite the RFC section and link the changed file path.
