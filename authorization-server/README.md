# Authorization Server

Local Keycloak authorization server for the OIDC reference project.

This directory owns Keycloak startup, realm import, clients, users, roles,
scopes, audience mappers, local secrets, and authorization-server smoke
tests.

## Required Commands

```bash
# Keycloak-only (for auth-server iteration)
docker compose -f compose.yaml config
docker compose -f compose.yaml up -d

# Full local stack (Keycloak + Valkey + gateway + services) from repo root
cd ..
docker compose up -d

tests/smoke.sh
../scripts/verify-idp.sh
```

## Local Contract

- Issuer: `http://localhost:8080/realms/oidc-reference`
- Discovery:
  `http://localhost:8080/realms/oidc-reference/.well-known/openid-configuration`
- Auth Service client (confidential): `oidc-reference-auth`
  (redirects `http://127.0.0.1:5173/auth/callback/idp` for Vite-dev and
  `http://127.0.0.1:9080/auth/callback/idp` for APISIX-fronted local
  harnesses)
- API Gateway client (confidential, Client Credentials only):
  `oidc-reference-api-gateway` — authenticates to `/internal/refresh`.
- Service client (confidential): `oidc-reference-service`
- API audience: `oidc-reference-api` via the `api.audience` client scope
  protocol mapper.
- Required users: `alice` (`user`) and `admin` (`user`, `admin`).
- Required realm roles: `user`, `admin`, `auditor`.

## Secrets

Realm JSON ships placeholder dev secrets that all carry the sentinel
marker `CHANGE_BEFORE_DEPLOY`:

- `LOCAL_DEV_AUTH_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY`
- `LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY`
- `LOCAL_DEV_SERVICE_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY`

These are local-only bootstrap values. `SecretSentinelValidator` in the
Auth Service refuses to boot whenever any of these sentinels survive into a
`prod` or `production` Spring profile.

Rotate before any non-local use. Supply real values via env vars, and never
commit replacements.

## Harness Requirements

- `compose.yaml` starts Keycloak locally with embedded H2 (`KC_DB=dev-file`,
  rebuilt from the realm seed on each cold `compose up`).
- The root `../compose.yaml` brings up Keycloak plus Valkey, the API Gateway,
  and the application services.
- `realm/oidc-reference-realm.json` is source-controlled.
- `tests/smoke.sh` checks realm static shape, discovery, JWKS, real token
  issuance for the service client, and audience/scope claims on the issued
  token.
