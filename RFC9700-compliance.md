# RFC 9700 Compliance

Status of this reference implementation against
[RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/).

Read the canonical flow first: root `README.md` (sequence diagram) and
`docs/specs/SPEC-0001-core-oidc-flows.md` (build contract).

## Status Legend

> **Spec-first note.** This project is in spec-first phase. `🧾` below means
> the contract is established but runtime verification is still pending.
> `✅` is reserved for behavior proven by an executable check or concrete
> local configuration.

| Symbol | Meaning |
|---|---|
| ✅ | Verified by an executable check or concrete local config. |
| 🧾 | Specified in the contract; implementation or runtime verification is still pending. |
| 🟡 | Partial — covered in some surface only, or spec-but-not-realm. |
| 📋 | Documented as future work; not yet wired into a concrete contract. |
| 🚫 | Not applicable to this reference's architecture (single AS, no in-browser tokens, etc.). |
| 🔄 | Production-only concern; called out in spec, not enforced locally over HTTP. |
| ⏳ | Known gap; tracked in `tasks/backlog.md`. |

## Summary

Rows are intentionally not hand-counted. The status icon on each row is the
source of truth; when code is generated, rows move from 🧾 to ✅ only after an
executable gate proves them.

---

## §2.1 — Protecting Redirect-Based Flows

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1, 4.1.3 | Exact redirect-URI matching (`MUST`) | ✅ | Realm: `oidc-reference-bff` `redirectUris: ["http://127.0.0.1:5173/auth/callback/idp"]` (no wildcards; registration name is the generic `idp`, not the IdP brand). URI is the SPA origin so the OAuth callback flows through the Vite proxy and the session cookie binds to that origin. Smoke test asserts exact value. |
| 2.1, 4.11 | No open redirectors (`MUST NOT`) | 🧾 | Auth Service saved-request replay accepts a user-influenced URL only after same-origin validation and falls back to `/` on failure; the validated value is replayed via a direct `302` from the callback. Logout uses a fixed post-logout redirect. Runtime proof belongs in the Auth Service saved-request tests. |
| 2.1 | CSRF prevention (`MUST`) | 🧾 | Login CSRF is mitigated by `state` (server-side validated against `tx:{state}`), PKCE code-verifier (S256), and ID-token `nonce` validation per RFC 9700 §4.7. State-changing calls use a `SameSite=Lax` session cookie plus **signed** double-submit CSRF (`XSRF-TOKEN` HMAC-signed or session-bound, echoed as `X-XSRF-TOKEN`). Naive double-submit (unsigned cookie/header match) is explicitly rejected — it is defeated by cookie injection from a sibling-subdomain XSS. |
| 2.1, 4.4 | Mix-up defense (`REQUIRED` when ≥2 AS) | 🚫 | Single Keycloak realm/issuer. If a second AS is added, Spring Security supports RFC 9207 `iss` parameter. |
| 2.1 | Credential forwarding prevention | ✅ | Keycloak default — user credentials live in the Keycloak session and are never forwarded to clients. |

## §2.1.1 — Authorization Code Grant

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 2.1.1 | Public-client PKCE (`MUST`) | 🚫 | No public client exists. The BFF is confidential — see `oidc-reference-bff` (`publicClient: false`). |
| 2.1.1 | Confidential-client PKCE (`RECOMMENDED`) | ✅ | Enabled anyway: `attributes."pkce.code.challenge.method": "S256"` on the BFF client. |
| 2.1.1 | OIDC `nonce` alternative (`MAY`) | 🧾 | BFF callback must validate the ID Token `nonce`; runtime proof depends on the TASK-0007 callback tests. |
| 2.1.1 | Transaction-specific PKCE/nonce (`MUST`) | 🧾 | Per-request `code_verifier` and `nonce` written to the Redis-compatible state store under `tx:{state}` (separate keyspace); `state` is server-side validated against the stored record on callback. TASK-0008 tracks runtime implementation. |
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
| 2.3 | Audience restriction (`SHOULD`); RS verifies (`MUST`) | 🧾 | `api.audience` client scope with `oidc-audience-mapper` adds `oidc-reference-api` to `aud`. RS must validate via a configured audience validator; runtime proof belongs in RS negative JWT tests. |
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
| 4.2.4 | No third-party resources on authz pages (`SHOULD NOT`) | 🧾 | Keycloak login page is self-hosted in the local profile. SPA third-party resource checks belong in frontend/security gates. |
| 4.2.4 | `Referrer-Policy` header | 🟡 | Spring Security adds defaults but `Referrer-Policy: no-referrer` not explicitly set. Recommend in spec. |
| 4.2.4 | Code response type over access-token types | ✅ | Covered. |
| 4.2.4 | Code bound to client or PKCE | ✅ | Confidential client + PKCE both. |
| 4.2.4 | Code invalidated on first use (`MUST`) | ✅ | Keycloak default. |
| 4.2.4 | Revoke tokens issued from a re-used code (`SHOULD`) | ✅ | Keycloak default on code reuse. |
| 4.2.4 | State invalidated after first use (`SHOULD`) | 🧾 | `tx:{state}` must be deleted on callback success or failure; TASK-0007 requires tests for this behavior. |
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
| 4.4.2.1 | RFC 9207 `iss` parameter / `iss` in ID Token (`MUST`) | 🚫 | Single AS. ID Token still carries `iss`, validated by Spring Security on every callback. |
| 4.4.2.2 | Distinct redirect URI per issuer (`MUST`) | 🚫 | Single AS, single redirect URI. |

## §4.5 — Authorization Code Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.5.3.1 | PKCE for code injection (`REQUIRED` as countermeasure) | ✅ | Enforced. |
| 4.5.3.2 | Validate `nonce` in ID Token from token endpoint (`MUST`); ignore tokens until validated (`MUST`) | 🧾 | BFF callback must validate ID Token signature, issuer, `aud` = BFF client id, expiry, and `nonce` before creating `sess:{sid}`. Runtime proof belongs in callback tests. |
| 4.5.4 | Prevent authorization-response read | ✅ | HTTPS in prod (documented); short-lived code + PKCE bind. |

## §4.6 — Access Token Injection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.6.1 | `at_hash` mitigation (OIDC hybrid) | 🚫 | We use `code` flow, not hybrid. `at_hash` not in code-flow ID tokens. PKCE addresses the underlying threat for our shape. |

## §4.7 — CSRF

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.7.1 | CSRF token in `state` (or PKCE) | 🧾 | Authorization response CSRF is covered by `state` (server-side validated against `tx:{state}`), PKCE code-verifier (S256), and ID-token `nonce` validation; callback must reject any of the three failing. |
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
| 4.9.3 | Audience restriction | 🧾 | Required by the realm and RS contracts; verified only when real tokens with wrong/missing audience are rejected by RS tests. |
| 4.9.3 | Treat tokens as secrets; no plaintext store/transfer (`MUST`) | 🧾 | RS must not persist tokens. BFF stores tokens in custom Redis-compatible `sess:{sid}` keys created only after callback; production guidance requires AUTH, TLS, encryption at rest (SPEC-0001 Threat Model). Runtime proof belongs in storage/logging tests. |

## §4.10 — Misuse of Stolen Tokens

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.10.1 | mTLS (RFC 8705) or DPoP (RFC 9449) | ⏳ | Deferred — see "Known Gaps". |
| 4.10.2 | AS binds token to RS; RS verifies (`MUST` refuse on failure) | 🧾 | Audience mapper plus RS audience validation are required; wrong-audience rejection must be proven by executable tests. |
| 4.10.2 | Resource indicator (RFC 8707) `resource` parameter | 🟡 | Not used. We use scope-based audience binding via the `api.audience` scope, which is BCP-acceptable. |
| 4.10.2 | Express audience as the URL the client calls (not logical name) | 🟡 | Using logical name `oidc-reference-api`. Defensible for a single-RS reference; for multi-RS, switch to URL form. |

## §4.11 — Open Redirection

| RFC § | Practice | Status | Where / How |
|---|---|---|---|
| 4.11.1 | Client open redirector (`MUST NOT`) | 🧾 | BFF saved-request replay is user-influenced but constrained: only same-origin saved URLs are honored; anything else falls back to `/`. |
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
| 4.14 | Rotation with reuse detection | 🧾 | Realm requires `revokeRefreshToken: true`, `refreshTokenMaxReuse: 0`; BFF must serialize refresh and invalidate session on reuse. TASK-0007 and BFF tests provide runtime proof. |
| 4.14 | Audit on reuse | 🟡 | Reuse causes session invalidation; explicit audit-log event not yet wired in the BFF. Tracked in "Known Gaps". |

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
| Sender-constrained access tokens (DPoP or mTLS) — §2.2.1, §4.9.3, §4.10.1 | Bearer tokens at the BFF↔RS hop; the BFF mitigates the browser-leakage primary motivation but not wire-level replay if the RS is reached directly. | Add Spring Security DPoP support on the BFF (`OAuth2AuthorizedClientManager` w/ DPoP provider) and on the RS (`DPoPAuthenticationProvider`). Add a `dpop` profile so the local stack can demonstrate it. |
| Asymmetric client authentication — §2.5 | Both confidential clients use `client_secret_basic`. | Switch the BFF and service client to `private_key_jwt`; ship a local-dev keypair generator script; document key rotation. |
| `Referrer-Policy: no-referrer` — §4.2.4 | Defensive header not set explicitly on BFF responses. | Add a `HeaderWriter` in BFF `SecurityConfig` setting `Referrer-Policy: no-referrer` and a baseline CSP. |
| Audit log on refresh-token reuse — §4.14 | Session invalidates on reuse but no explicit audit event. | Add an `ApplicationListener<AbstractAuthenticationFailureEvent>` (or a wrapper around the `OAuth2AuthorizedClientManager` refresh provider) that emits a security audit event when Keycloak returns `invalid_grant` for a refresh attempt. |
| Audience as URL form — §4.10.2.2 | Using logical `oidc-reference-api`. | If multi-RS is added, switch audience mapper to the RS base URL (e.g., `http://localhost:8082`) per BCP guidance. |
| JAR (RFC 9101) / PAR (RFC 9126) | Not used; the BCP marks origin verification via JAR/PAR as `MAY`. | Optional follow-up if the reference wants to demonstrate the more advanced origin-verification options. |

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
- BFF `SecurityConfig` (`bff/src/main/java/com/example/oidcreference/bff/SecurityConfig.java`).
- RS `SecurityConfig` (`backend-resource-server/src/main/java/com/example/oidcreference/SecurityConfig.java`).
- Any token endpoint behavior (refresh, rotation, audience mapping).

Cite the RFC section number and link the changed file path.
