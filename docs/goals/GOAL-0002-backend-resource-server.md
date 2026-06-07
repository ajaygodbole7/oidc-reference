# GOAL-0002: Spring Boot Resource Server (JWT Validation)

## Directory

`backend-resource-server/`

## Goal

Deliver a Spring Boot Resource Server that validates Keycloak JWT access
tokens against issuer, signature, expiration, algorithm allowlist, audience
(`oidc-reference-api`), scopes, and roles (`realm_access.roles` mapped to
`ROLE_*`), exposes the documented endpoints, returns RFC 7807 errors,
emits security audit events, and is reachable only from the API Gateway
(browser flow) or the service client (Client Credentials). The RS has no
knowledge of cookies, sessions, or Valkey.

## Purpose

The RS is the security enforcement point for protected APIs. Every spec
acceptance criterion that says "the API rejects X" lives here.

## Owned Paths

- `backend-resource-server/`
- Backend tests under `backend-resource-server/`
- RS-specific docs and task packets

## Avoid Paths

- `auth-service/`, `api-gateway/`
- `frontend/`
- `authorization-server/` (read-only inspection only)
- Shared root config unless explicitly coordinated

## Required Technology

- Java 25.
- Spring Boot `4.1.0-RC1`.
- Spring Security OAuth2 Resource Server (`spring-security-oauth2-jose`).
- Virtual threads enabled (`spring.threads.virtual.enabled: true`).
- Maven.
- JUnit + Spring test support.

## Required Endpoints

- `GET /api/public` — no auth.
- `GET /api/me` — authenticated user token; returns `{subject: sub}`.
- `GET /api/user-data` — scope `api.read`.
- `POST /api/admin` — authority `ROLE_admin`.
- `POST /api/jobs` — scope `service.jobs`.

## Token Validation Requirements

- Issuer (from `OIDC_ISSUER_URI`).
- Signature via the AS's JWKS (discovered from
  `/.well-known/openid-configuration`).
- Expiration; `nbf` when present.
- Algorithm allowlist: `RS256` only.
- Audience contains `oidc-reference-api` (custom `JwtClaimValidator`).
- Standard `scope` / `scp` claim → `SCOPE_*` authorities (default Spring
  converter behavior).
- Role claim → `ROLE_*` authorities (custom converter). Claim path is
  IdP-specific config (`app.roles-claim-path`): Keycloak
  `realm_access.roles` (default); Cognito `cognito:groups`; Entra ID
  `roles`; Auth0 namespaced. See SPEC-0001 §"Authorization Server
  Portability".

## Required Rejections

- Missing, malformed, expired tokens.
- Wrong issuer, wrong audience, wrong algorithm.
- Token missing required scope.
- User token on `/api/jobs`.
- Service token on `/api/me` when user identity absent.

## API Behavior

- Stateless.
- CORS denies browser origins (the RS is not browser-facing).
- Inbound paths in the canonical stack: the APISIX **API Gateway** proxies
  browser-originated requests (`/api/me`, `/api/user-data`, `/api/admin`)
  after reading `sess:{sid}` and injecting `Authorization: Bearer`; the
  service client calls `/api/jobs` directly (Client Credentials, no
  ingress); `/api/public` is anonymous and reachable either way. The RS
  sees no `Cookie` header in either flow — the API Gateway strips it
  before forwarding, and the service client never sets one. The Auth
  Service does **not** call the RS on the request path. (Prior to the
  Frame B reshape this responsibility belonged to a combined BFF; the
  cookie-header-absent contract is unchanged.)
- Errors as `application/problem+json` via Spring `ProblemDetail`.
- Security audit log on denied access and validation failure: timestamp,
  endpoint, requestor metadata (non-secret), reason.
- Never log raw tokens, codes, cookies, secrets.

## Acceptance Criteria

- `./mvnw test` green.
- App starts locally on port `8082` and reads issuer/JWKS from
  `application.yml` / env.
- Every endpoint enforces the spec authority.
- Negative tests prove fail-closed for each rejection above.
- Problem-Details bodies returned on 401/403.

## Required Tests

- All five endpoints, positive and negative.
- Wrong issuer / audience / algorithm rejected.
- Expired token rejected.
- `realm_access.roles=["admin"]` reaches `/api/admin`.
- Token with only `realm_access.roles=["user"]` rejected from `/api/admin`.
- 401 and 403 produce `application/problem+json` bodies.
- Tests use `@MockitoBean(JwtDecoder.class)` to swap the decoder before
  context creation; prevents eager OIDC discovery in test runs.

## Evidence For Completion

- Backend test output.
- Startup logs showing issuer + JWKS resolution (no secrets).
- Sample responses (success + failure) checked into docs.

## Blocked Conditions

Stop and report if:

- Spring Boot `4.1.0-RC1` artifacts are unavailable.
- Java 25 cannot compile or run the chosen baseline.
- Keycloak JWKS endpoint is unreachable.
- Realm tokens do not contain `aud=oidc-reference-api` or
  `realm_access.roles` in the documented shape.
