# OpenID Connect Compliance

Status of this reference implementation against the OpenID Connect
standards. The OIDC family is published as Final 1.0 specs; OAuth 2.1
([draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/))
is the OAuth consolidation referenced by recent OIDC drafts. (There is
no "OIDC 2.1" version.)

This reference implements:

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) (Authorization Code flow only).
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html).
- [OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).
- OAuth 2.1 (via [RFC 9700 BCP](https://datatracker.ietf.org/doc/rfc9700/)) — see
  `RFC9700-compliance.md` for the per-control matrix on the security side.

Canonical sources for the implementation: `README.md` (flow diagrams) and
`docs/specs/SPEC-0001-core-oidc-flows.md` (build contract).

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Verified by an executable check, concrete local config, or test. |
| 🟡 | Partial — covered in some surface only, or implemented but not asserted. |
| 🚫 | Not applicable to this reference's architecture (code flow only, single AS, etc.). |
| 🔄 | Production-only concern; documented but not enforced over local HTTP. |
| ⏳ | Deliberately deferred. See "Out of scope" + README "What's deliberately not here". |

---

## OpenID Connect Core 1.0

### §2 — ID Token

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §2 | `iss` claim (`REQUIRED`) | ✅ | Issued by Keycloak; validated by Nimbus `IDTokenValidator` against the configured issuer. |
| §2 | `sub` claim (`REQUIRED`) | ✅ | Issued by Keycloak; surfaced by `JwtOidcIdTokenValidator#userClaims` as `sub` in the session record. |
| §2 | `aud` claim (`REQUIRED`) | ✅ | Mapped by realm to include the Auth Service client ID. Validated by Nimbus on every callback. |
| §2 | `exp` claim (`REQUIRED`) | ✅ | Issued by Keycloak; validated by Nimbus. |
| §2 | `iat` claim (`REQUIRED`) | ✅ | Issued by Keycloak; validated by Nimbus. |
| §2 | `auth_time` claim (`OPTIONAL` unless `max_age` or `auth_time` essential) | 🚫 | `max_age` not requested; `auth_time` claim not required for this reference. |
| §2 | `nonce` claim (`REQUIRED` if present in auth request) | ✅ | `AuthController#beginLogin` always sends `nonce`. `JwtOidcIdTokenValidator` passes the expected nonce to Nimbus, which fails closed on mismatch. Asserted by `JwtOidcIdTokenValidatorTest#nonceMismatchIsRejected`. |
| §2 | `acr` claim (`OPTIONAL`) | 🚫 | `acr_values` not requested. |
| §2 | `amr` claim (`OPTIONAL`) | 🚫 | Not validated; not required for this reference. |
| §2 | `azp` claim semantics (`OPTIONAL`, required when ID Token has single `aud` not equal to client_id; required when multiple `aud`) | ✅ | Validated inside Nimbus's `IDTokenValidator`. |

### §3.1 — Authorization Code Flow

#### §3.1.2 — Authorization Endpoint

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §3.1.2.1 | `scope` includes `openid` (`REQUIRED`) | ✅ | Auth Service requests `openid profile email roles api.audience api.read`. |
| §3.1.2.1 | `response_type=code` (`REQUIRED` for this flow) | ✅ | `AuthController#beginLogin` builds the authorize URL with `response_type=code`. |
| §3.1.2.1 | `client_id` (`REQUIRED`) | ✅ | From discovery / config. |
| §3.1.2.1 | `redirect_uri` (`REQUIRED`) | ✅ | Computed by `AuthController#redirectUri`. Pinned via `app.base-url` when configured; otherwise derived from `X-Forwarded-*` (dev). |
| §3.1.2.1 | `state` (`RECOMMENDED`) | ✅ | `state` generated server-side (`CryptoSupport.randomUrlToken(32)`), used as the `tx:{state}` key, validated on callback. |
| §3.1.2.1 | `nonce` (`OPTIONAL` for code flow but used here) | ✅ | Generated per-request, stored in `tx:{state}`, validated in the ID Token. |
| §3.1.2.1 | `prompt`, `max_age`, `ui_locales`, `id_token_hint`, `login_hint`, `acr_values` (`OPTIONAL`) | 🚫 | Not used in this reference. |
| §3.1.2.1 | `display` (`OPTIONAL`) | 🚫 | Not used. |
| §3.1.2.2 | Authorization Request validation (`MUST` reject malformed) | ✅ | Keycloak default. |
| §3.1.2.3 | Authorization Server authenticates the end-user (`MUST`) | ✅ | Keycloak login. |
| §3.1.2.4 | Authorization Server obtains consent when needed (`MUST`) | ✅ | Keycloak default (skipped when consent is not required by the realm config). |
| §3.1.2.5 | Successful Authentication Response uses `code` (`MUST` for this flow) | ✅ | Keycloak default. |
| §3.1.2.6 | Authentication Error Response shape | ✅ | Keycloak emits per-spec error responses; the callback never proceeds past `getAndDelete` if `state` is missing. |

#### §3.1.3 — Token Endpoint

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §3.1.3.1 | Token Request: `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id` (`REQUIRED`) | ✅ | `AuthorizationCodeTokenExchangeClient` builds a Nimbus `TokenRequest` with `AuthorizationCodeGrant` + PKCE `CodeVerifier`. |
| §3.1.3.2 | Token Endpoint authentication (`MUST` per client auth method) | ✅ | `ClientSecretBasic` (HTTP Basic over TLS in production). |
| §3.1.3.3 | Successful Token Response (`access_token`, `token_type`, `id_token`, `expires_in`, `refresh_token`) | ✅ | Parsed via Nimbus `OIDCTokenResponseParser`. |
| §3.1.3.4 | Token Error Response | ✅ | Surfaced as `IllegalStateException` upstream; the callback returns 401 with `application/problem+json`. |
| §3.1.3.5 | Token Response Validation | ✅ | Performed by Nimbus parser plus the `at_hash` check in `JwtOidcIdTokenValidator#enforceAtHash`. |
| §3.1.3.6 | ID Token (`REQUIRED` for this flow) | ✅ | Present in the response. |
| §3.1.3.7 | **ID Token Validation** | ✅ | See the dedicated table below. |
| §3.1.3.8 | Access Token Validation (`at_hash` when present) | ✅ | `JwtOidcIdTokenValidator#enforceAtHash` runs whenever the ID token carries `at_hash`. Mismatch throws `BadCredentialsException`. Asserted by `JwtOidcIdTokenValidatorTest#atHashMismatchIsRejected`. |

#### §3.1.3.7 — ID Token Validation (the 11 steps)

The single most-cited OIDC-conformance checklist.

| Step | Requirement | Status | Where / How |
|---|---|---|---|
| 1 | If the ID Token is encrypted, decrypt it (`MUST` if encryption was negotiated) | 🚫 | Negotiation does not request JWE; ID tokens are signed only. |
| 2 | `iss` Claim must match the Issuer used during discovery (`MUST`) | ✅ | Nimbus `IDTokenValidator` constructed with `new Issuer(md.issuer())`; mismatch throws. |
| 3 | `aud` Claim must contain the client_id (`MUST`); other audiences allowed only if known and trusted (`MUST` reject if untrusted) | ✅ | Nimbus `IDTokenValidator` constructed with `new ClientID(md.clientId())`. |
| 4 | If multiple `aud` values, `azp` Claim must be present (`MUST`) | ✅ | Enforced inside Nimbus's validator. |
| 5 | If `azp` is present, it must equal the client_id (`MUST`) | ✅ | Enforced inside Nimbus's validator. |
| 6 | If ID Token came directly from token endpoint over TLS (this flow), TLS itself MAY substitute for explicit `alg` check on the client side, but `alg` must still be one of the registered values | ✅ | `JWSVerificationKeySelector` is constructed with `JWSAlgorithm.RS256` only — alg-confusion classes (e.g. HS256-as-RS256, alg=none) are rejected before signature verification. Asserted by `JwtOidcIdTokenValidatorTest#algNoneIsRejected` and `#algConfusionHs256IsRejected`. |
| 7 | `alg` must be the default `RS256` or the value negotiated in `id_token_signed_response_alg` (`MUST`) | ✅ | Pinned to RS256 as above. Discovery exposes `id_token_signing_alg_values_supported`. |
| 8 | If `alg` is MAC (HS256 etc.), client_secret is the key — UTF-8-encoded (`MUST`) | 🚫 | Not used; MAC algorithms rejected by the RS256 allowlist. |
| 9 | `exp` must be in the future (`MUST` reject if expired) | ✅ | Enforced by Nimbus. Asserted by `JwtOidcIdTokenValidatorTest#expiredIsRejected`. |
| 10 | `iat` must not be unreasonably far in the past (`MAY` define a limit) | ✅ | Enforced by Nimbus with its default skew window. |
| 11 | `nonce` must match the value sent in the authorization request (`MUST` reject on mismatch) | ✅ | Passed via `new Nonce(transaction.nonce())`. Asserted by `JwtOidcIdTokenValidatorTest#nonceMismatchIsRejected`. |
| §3.1.3.8 | `at_hash` validation when present (`MUST` if present in the ID Token) | ✅ | `JwtOidcIdTokenValidator#enforceAtHash` via Nimbus `AccessTokenValidator`. |

### §3.2 — Implicit Flow / §3.3 — Hybrid Flow

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §3.2 | Implicit Flow | 🚫 | Disabled on all clients. RFC 9700 deprecates it; see `RFC9700-compliance.md` §2.1.2. |
| §3.3 | Hybrid Flow | 🚫 | Not used. `c_hash` (hybrid-only) does not apply. |

### §5 — Standard Claims

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §5.1 | Profile claims (`name`, `preferred_username`, `email`, etc.) | ✅ | Requested via `profile` + `email` scopes. `JwtOidcIdTokenValidator#userClaims` surfaces `sub`, `preferred_username`, `name`, `email`. |
| §5.2 | Claim languages and scripts (`#xx-YY` suffix) | 🚫 | Not used. |
| §5.3 | UserInfo Endpoint | 🚫 | Not used. The reference's `/auth/me` returns claims from `sess:{sid}` rather than calling Keycloak's UserInfo endpoint per request. Documented in SPEC-0001 §"Auth Service Endpoints". |
| §5.4 | Requesting Claims using `scope` (`SHOULD`) | ✅ | Scopes used to request claims: `openid profile email roles`. |
| §5.5 | Requesting Claims using the `claims` Parameter | 🚫 | Not used. |
| §5.6 | Claim Types (`Normal`, `Aggregated`, `Distributed`) | 🚫 | Only `Normal` Claims used. |
| §5.7 | Claim Stability and Uniqueness (`sub` stable per issuer/audience) | ✅ | Keycloak provides stable `sub`. |

### §6 — Passing Request Parameters as JWTs

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §6 | Request Object (JAR / `request` / `request_uri`) | 🚫 | Not used. The exact-match `redirect_uri` + PKCE + `state` + `nonce` + `oauth_tx` defense set covers the demonstrated flow without it. |

### §8 — Subject Identifier Types

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §8.1 | `public` subject type | ✅ | Keycloak realm default. |
| §8.2 | `pairwise` subject type | 🚫 | Not used. |

### §9 — Client Authentication

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §9 | `client_secret_basic` (`MAY`) | ✅ | Used by `AuthorizationCodeTokenExchangeClient` via Nimbus `ClientSecretBasic`. |
| §9 | `client_secret_post` (`MAY`) | 🚫 | Not used. |
| §9 | `client_secret_jwt` (`MAY`) | 🚫 | Not used. |
| §9 | `private_key_jwt` (`MAY`) | ⏳ | Recommended by RFC 9700 §2.5; deferred. Reconsider for FAPI / PSD2. |
| §9 | `none` (only for clients not authenticating, e.g. public clients) | 🚫 | No public client. |

### §10 — Signatures and Encryption

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §10.1.1 | Signing algorithms (`RS256` `REQUIRED`) | ✅ | Pinned. |
| §10.1.2 | Encryption algorithms (`OPTIONAL`) | 🚫 | Not used. |
| §10.2 | Signature key rotation via JWKS (`SHOULD`) | ✅ | Nimbus `JWKSourceBuilder` with refresh-ahead cache (300s), outage tolerance (900s), retry, and force-refresh on unknown `kid`. |

### §12 — Using Refresh Tokens

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §12.1 | Refresh Token Request shape (`grant_type=refresh_token`, `refresh_token`, `scope`) | ✅ | `AuthorizationCodeTokenRefreshClient` via Nimbus `RefreshTokenGrant`. |
| §12.2 | Successful Refresh Response | ✅ | New `access_token`, ID token, and rotated `refresh_token`. |
| §12.3 | Refresh Error Response | ✅ | `invalid_grant` surfaces as `InvalidRefreshTokenException`; session invalidated. |

### §15 — Implementation Considerations

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §15.1 | Mandatory to Implement Features (Discovery, Dynamic Registration, OAuth Response Types) | ✅ | Discovery used; Dynamic Registration not used (static realm); `code` response type used. |
| §15.4 | UTC time for `exp`, `iat`, `nbf` | ✅ | Spring `Instant` (UTC). APISIX container pinned to `TZ=UTC` so the Lua plugin's `os.time` math is offset-free. |
| §15.5 | Symmetric Key Entropy (when MAC algorithms used) | 🚫 | MAC algorithms not used. |
| §15.6 | Need for Encrypted Requests / Responses | 🚫 | Not used. |
| §15.7 | UserInfo Endpoint Security | 🚫 | UserInfo endpoint not called by this reference. |

### §16 — Security Considerations

Covered in detail by `RFC9700-compliance.md`. The Core §16 items map to
the RFC 9700 BCP; no new requirements beyond what that doc tracks.

---

## OpenID Connect Discovery 1.0

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §4 | Issuer well-known location: `<issuer>/.well-known/openid-configuration` | ✅ | Auth Service calls `OIDCProviderConfigurationRequest` at startup via `OidcProviderMetadata#discover`. |
| §4.2 | Required metadata: `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, `subject_types_supported`, `id_token_signing_alg_values_supported` | ✅ | All present in Keycloak's discovery document and consumed by `OidcProviderMetadata`. |
| §5 | Discovery via WebFinger | 🚫 | Not used. Single hard-configured issuer per environment. |

## OpenID Connect RP-Initiated Logout 1.0

| Spec | Requirement | Status | Where / How |
|---|---|---|---|
| §2 | Logout Request to `end_session_endpoint` | ✅ | `AuthController#logout` builds the request via Nimbus `UriComponentsBuilder` against `md.endSessionEndpoint()` (from discovery). |
| §2 | `id_token_hint` (`RECOMMENDED`) | ✅ | Included. |
| §2 | `post_logout_redirect_uri` (`OPTIONAL`) | ✅ | Included; pre-registered in the realm. |
| §2 | `state` (`OPTIONAL` but recommended) | ✅ | `CryptoSupport.randomUrlToken(32)`. |
| §2 | `client_id` (`OPTIONAL`) | ✅ | Included. |
| §3 | Logout endpoint discovery via `end_session_endpoint` metadata | ✅ | Read from discovery. |

---

## Out of scope

These OIDC specs are intentionally not implemented. The reasoning lives
in `docs/architecture/architecture-decisions.md` §F.

| Spec | Status | Reason / when to revisit |
|---|---|---|
| [OIDC Dynamic Registration 1.0](https://openid.net/specs/openid-connect-registration-1_0.html) | 🚫 | Static realm configuration. Reconsider when integrating with SaaS IdPs that mint per-tenant clients dynamically. |
| [OIDC Session Management 1.0](https://openid.net/specs/openid-connect-session-1_0.html) | 🚫 | Requires the SPA to embed an iframe pointed at the OP; the BFF session model is the canonical state. |
| [OIDC Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html) | 🚫 | Same; RP-initiated logout covers user-driven logout. |
| [OIDC Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | ✅ | Implemented at the Auth Service with signed logout-token validation, replay detection, and `sid`/`sub` session invalidation semantics. Production deployments still need a trusted route from the OP to the Auth Service. |
| OIDC Form Post Response Mode | 🚫 | `query` response mode used; PKCE + short-lived code cover the threats `form_post` mitigates. |
| OIDC CIBA, Self-Issued OP, JARM | 🚫 | Out of scope for a browser-app reference. |

---

## Architecture notes

- **ID-token validation surface is explicit code.** OIDC Core §3.1.3.7
  is implemented in `JwtOidcIdTokenValidator` rather than inside
  framework auto-config. This is a teaching property of the reference —
  the validator's 11-step checklist maps line-for-line to spec steps.
- **Conformance is IdP-agnostic.** Keycloak is the local IdP; any
  conformant OIDC OP with equivalent realm configuration preserves
  these rows. See SPEC-0001 Appendix A for the per-vendor swap matrix.
- **No in-browser OIDC client.** The browser holds no tokens; the SPA
  never parses an ID token, calls a UserInfo endpoint, or handles a
  refresh-token rotation. All OIDC conformance is server-side, which
  removes an entire class of browser-side conformance footguns
  (storage-tier leakage, alg confusion via attacker-supplied JOSE
  headers, etc.).

## Updating this file

Revisit when:

- `JwtOidcIdTokenValidator` or its Nimbus `IDTokenValidator` construction
  changes.
- `AuthController#beginLogin` or `#callback` changes the authorize URL
  parameters or the callback validation pipeline.
- `AuthorizationCodeTokenExchangeClient` or `AuthorizationCodeTokenRefreshClient`
  changes the token-endpoint contract.
- Realm JSON changes signing algorithms, supported scopes, or audience
  mappers.
- `OidcProviderMetadata` discovery semantics change.

Cite the OIDC section number and link the changed file path.
