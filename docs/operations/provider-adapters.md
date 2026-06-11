# Bring Your Own IdP

This project is IdP-agnostic at the application boundary: the Frontend calls
only the API Gateway, the Auth Service is the confidential OIDC client, and the
Resource Server validates standard JWT claims. Keycloak is the local reference
Authorization Server, not a code dependency.

A provider swap is configuration-only for a standard OIDC provider. The
following are all env-configurable:

- the issuer, endpoints, audience, scopes, and role-claim path;
- the internal trust identifiers: the gateway's client id, the internal-refresh
  audience, and the Resource Server's service-account allowlist.

No provider-facing identifier is baked into Java or APISIX. The alternate-claim
Keycloak realm gate (`just e2e-portability`) proves a config-only swap of the
token shape end-to-end. If an IdP requires application-code branches by provider
brand, that provider is outside the current reference contract.

### Portability scope

Everything an IdP swap touches is configuration. The defaults are this
reference's local Keycloak names. Real IdPs (Okta/Auth0/Entra) assign client
ids you don't choose, so the trust identifiers are knobs, not constants.

| Config knob | Default | Env var |
|---|---|---|
| Issuer / endpoints | local Keycloak | `OIDC_ISSUER_URI`, `APP_*_URI` |
| API audience | `oidc-reference-api` | `OIDC_AUDIENCE` |
| Role-claim path / scopes | `realm_access,roles` / Keycloak scopes | `OIDC_ROLES_CLAIM_PATH`, `OIDC_SCOPES` |
| Gateway client id | `oidc-reference-api-gateway` | `GATEWAY_CLIENT_ID` (Auth Service + APISIX render) |
| Internal-refresh audience | `oidc-reference-auth-internal` | `INTERNAL_REFRESH_AUDIENCE` (Auth Service) |
| RS service-account allowlist | `oidc-reference-api-gateway,oidc-reference-service` | `RS_SERVICE_CLIENT_IDS` |
| RS jobs client id | `oidc-reference-service` | `RS_JOBS_CLIENT_ID` |

What stays Keycloak-specific is provisioning *format*, not identity values. The
realm seed JSON and the Keycloak smoke script are replaced by the target IdP's
own provisioning (Terraform, Management API, etc.).

These knobs are the relying party's half of the contract. The IdP must also be
configured to issue matching values. For example, setting
`INTERNAL_REFRESH_AUDIENCE` on the Auth Service does not make Okta, Entra, or
Keycloak emit that audience. The provider-side client/scope/audience mapper must
move with it. The same is true for `OIDC_AUDIENCE`, `GATEWAY_CLIENT_ID`, and role
claim mappers.

Roles are read from two tokens and must agree. The Auth Service reads them
from the `id_token` for `/auth/me`. The Resource Server reads them from the
`access_token` for `/api/**` authorization. They line up only because the realm
maps roles into both tokens, so an IdP swap MUST configure both mappers (the
alt-realm portability proof already does). The `/auth/me` roles are
display-only; the access token is the sole authorization source.

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
| `GATEWAY_CLIENT_ID` | Auth Service, APISIX | Client id the gateway authenticates as for `/internal/refresh`, and the value the Auth Service requires in the caller's `azp`/`client_id`. Set in both. Default `oidc-reference-api-gateway`. |
| `INTERNAL_REFRESH_AUDIENCE` | Auth Service | Audience the gateway's Client-Credentials token must carry for `/internal/refresh`. Default `oidc-reference-auth-internal`. |
| `RS_SERVICE_CLIENT_IDS` | Resource Server | Comma-separated client ids treated as service accounts (denied on `/api/me`). Default `oidc-reference-api-gateway,oidc-reference-service`. |
| `RS_JOBS_CLIENT_ID` | Resource Server | The single service client authorized to `POST /api/jobs`. Default `oidc-reference-service`. |
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
changing only provider-shaped configuration.

- Roles are emitted as a top-level `groups` claim, so
  `OIDC_ROLES_CLAIM_PATH=groups` must drive both `/auth/me` and
  Resource Server authorization.
- Access tokens carry `aud=oidc-reference-alt-api`, so `OIDC_AUDIENCE` must
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
8. Session lifetimes are coordinated. The BFF absolute ceiling
   (`SessionRecord.ABSOLUTE_TTL`, 8h) MUST stay ≤ the provider's SSO max
   session lifespan. If the IdP ceiling is lower, an active session is
   ejected early when the next refresh returns `invalid_grant`; lower the BFF
   ceiling to match. (Keycloak `ssoSessionMaxLifespan` defaults to 10h. Okta,
   Auth0, and Entra differ; check the provider's session policy.)
9. `sh scripts/e2e-auth.sh` or an equivalent provider-backed full-stack proof passes.

## Known Portability Gaps

- A live Okta run is documented but non-gating because it requires tenant
  credentials and network access. See `provider-overlays/okta.md`.
- Auth0-style `audience` request parameter is documented but not yet exposed as
  a first-class Auth Service config setting.
- Cognito and Google need provider-specific validation before claiming full
  parity with the Keycloak reference.
- Back-channel logout is implemented for providers that support the standard
  logout-token contract and can reach the Auth Service. PAR, JAR, DPoP, mTLS,
  and `private_key_jwt` remain out of scope for the local reference. See
  `docs/architecture/architecture-decisions.md`.

## What Must Not Change

- No tokens in browser JavaScript, browser storage, or SPA-readable cookies.
- Frontend calls only `/auth/*` and `/api/**` on the gateway origin.
- Provider-specific behavior stays in config or docs, not `if provider == ...`
  branches.
- Resource Server continues to reject issuer-only trust; audience and algorithm
  checks remain mandatory.
