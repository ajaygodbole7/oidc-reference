# Bring Your Own IdP

This project is IdP-agnostic at the application boundary: the Frontend calls
only the API Gateway, the Auth Service is the confidential OIDC client, and the
Resource Server validates standard JWT claims. Keycloak is the local reference
Authorization Server, not a code dependency.

The promise is configuration-only provider swap for a standard OIDC provider.
If an IdP requires application-code branches by provider brand, that provider
is outside the current reference contract.

## Supported Configuration Surface

Set these values through Compose environment, deployment configuration, or a
provider-specific overlay.

| Setting | Component | Purpose |
|---|---|---|
| `OIDC_ISSUER_URI` | Auth Service, Resource Server | Canonical issuer expected in ID/access tokens. This is the public issuer, not necessarily the container backchannel URL. |
| `APP_AUTHORIZATION_URI` | Auth Service | Browser-facing authorization endpoint. Optional when discovery from `OIDC_ISSUER_URI` works from the service runtime. |
| `APP_TOKEN_URI` | Auth Service | Backchannel token endpoint. Use when service-to-IdP traffic uses a private DNS name. |
| `APP_JWKS_URI` | Auth Service | Backchannel JWKS endpoint for ID-token validation and internal bearer validation. |
| `APP_END_SESSION_URI` | Auth Service | Browser-facing RP-initiated logout endpoint. Optional; if absent, logout is local-session only. |
| `AUTH_CLIENT_ID` | Auth Service | Confidential OIDC client ID. |
| `AUTH_CLIENT_SECRET` | Auth Service | Confidential OIDC client secret. |
| `OIDC_SCOPES` | Auth Service | Comma-separated requested scopes. Defaults to the local Keycloak scopes. |
| `OIDC_ROLES_CLAIM_PATH` | Auth Service, Resource Server | Comma-separated claim path for roles/groups, for example `realm_access,roles` or `groups`. |
| `OIDC_AUDIENCE` | Resource Server | Required access-token audience for `/api/**`. |
| `GATEWAY_CLIENT_SECRET` | APISIX | API Gateway client-credentials secret for `/internal/refresh`. |
| `CSRF_SIGNING_KEY` | Auth Service, APISIX | Shared 256-bit Base64 HMAC key for signed double-submit CSRF. |

Local Keycloak uses this split:

```text
OIDC_ISSUER_URI=http://localhost:8080/realms/oidc-reference
APP_AUTHORIZATION_URI=http://localhost:8080/realms/oidc-reference/protocol/openid-connect/auth
APP_TOKEN_URI=http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token
APP_JWKS_URI=http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/certs
APP_END_SESSION_URI=http://localhost:8080/realms/oidc-reference/protocol/openid-connect/logout
```

The issuer remains browser-visible and stable; internal endpoints may use
service DNS.

## Enforced Portability Proof

The repo's required portability proof is hermetic:

```sh
sh scripts/e2e-portability.sh
```

That script starts the same local topology against
`oidc-reference-alt`, a second Keycloak realm imported into the same Keycloak
container. It proves the provider boundary without third-party credentials by
changing only provider-shaped configuration:

- roles are emitted as a top-level `groups` claim, so
  `OIDC_ROLES_CLAIM_PATH=groups` must drive both `/auth/me` and
  Resource Server authorization;
- access tokens carry `aud=oidc-reference-alt-api`, so `OIDC_AUDIENCE` must
  drive Resource Server validation.

The default Keycloak flow remains untouched. The alt realm exists to prove the
configuration surface is real, not to model a second production IdP.

## Provider Matrix

These are starting points, not substitutes for checking the provider's current
admin UI and OIDC metadata.

| Provider | Issuer Shape | Roles Claim | Audience Notes | Logout Notes |
|---|---|---|---|---|
| Keycloak | `https://idp.example/realms/{realm}` | `realm_access,roles` | Custom audience mapper can emit API audience. | Standard OIDC end-session works. |
| Okta | `https://{org}.okta.com/oauth2/{serverId}` | `groups` | Use a custom authorization server for API audience/scopes. | Standard end-session is available on OIDC apps. |
| Auth0 | `https://{tenant}.auth0.com/` | namespaced claim, for example `https://example.com/roles` | API Identifier becomes access-token audience. Auth0 often needs an `audience` request parameter, which is not implemented as a first-class config knob yet. |
| Microsoft Entra ID | `https://login.microsoftonline.com/{tenant}/v2.0` | `roles` or `groups` | App ID URI, often `api://{app-id}`, is the audience. Group overage can replace inline groups with references. |
| AWS Cognito | `https://cognito-idp.{region}.amazonaws.com/{userPoolId}` | `cognito:groups` | Access-token audience behavior differs from API-audience providers. Validate with real tokens before relying on RS rules. |
| Google | `https://accounts.google.com` | none by default | Google ID/access tokens are not a good fit for role-based RS authorization without an app-side role source. | Treat upstream logout as local-only unless tested for your account type. |
| Ping / PingOne | tenant/environment issuer | commonly `groups` | Configure API resource/audience in the provider. | Standard OIDC end-session is commonly available. |

## Readiness Checklist

For a provider to pass the reference's portability bar:

1. Discovery or explicit endpoint configuration starts Auth Service without code changes.
2. Login uses Authorization Code + PKCE and returns through `/auth/callback/idp`.
3. ID token validates: `iss`, `aud=AUTH_CLIENT_ID`, signature, `exp`, and nonce.
4. Access token validates at the Resource Server: `iss`, signature, `exp`,
   `aud=OIDC_AUDIENCE`, standard `scope` / `scp` authorities, and configured
   role claim path.
5. API Gateway obtains a client-credentials token that Auth Service accepts for `/internal/refresh`.
6. Refresh behavior is understood:
   - Keep `APP_REFRESH_REQUIRE_ROTATION=true` for providers with refresh-token rotation and reuse detection.
   - Set it false only for a provider that does not rotate refresh tokens, and document that downgrade.
7. Logout behavior is tested. If the provider does not support compatible RP-initiated logout, keep local logout only and document that the IdP session remains alive.
8. Session lifetimes are coordinated: the BFF absolute ceiling
   (`SessionRecord.ABSOLUTE_TTL`, 8h) MUST stay **≤ the provider's SSO max
   session lifespan**. If the IdP ceiling is lower, an active session is
   ejected early when the next refresh returns `invalid_grant`; lower the BFF
   ceiling to match. (Keycloak `ssoSessionMaxLifespan` defaults to 10h; Okta,
   Auth0, and Entra differ — check the provider's session policy.)
9. `sh scripts/e2e-auth.sh` or an equivalent provider-backed full-stack proof passes.

## Known Portability Gaps

- A live Okta run is documented but non-gating because it requires tenant
  credentials and network access. See `provider-overlays/okta.md`.
- Auth0-style `audience` request parameter is documented but not yet exposed as
  a first-class Auth Service config setting.
- Cognito and Google need provider-specific validation before claiming full
  parity with the Keycloak reference.
- Back-channel logout, PAR, JAR, DPoP, mTLS, and `private_key_jwt` are not part
  of this reference. See `docs/architecture/architecture-decisions.md`.

## What Must Not Change

- No tokens in browser JavaScript, browser storage, or SPA-readable cookies.
- Frontend calls only `/auth/*` and `/api/**` on the gateway origin.
- Provider-specific behavior stays in config or docs, not `if provider == ...`
  branches.
- Resource Server continues to reject issuer-only trust; audience and algorithm
  checks remain mandatory.
