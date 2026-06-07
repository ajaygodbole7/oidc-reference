# Okta Provider Overlay

This is a credentialed, non-gating portability runbook. The enforced gate is
`scripts/e2e-portability.sh`, which is hermetic and re-runnable without
third-party credentials. Okta is the external validation artifact: it proves
the same config surface against a real enterprise IdP.

## Why Okta First

Okta supports standard OIDC Authorization Code + PKCE and standard
RP-initiated logout. That matches this reference's logout invariant:
`id_token_hint` may leave the server only in a server-generated top-level
redirect to the provider's end-session endpoint. Auth0 is deliberately not the
first external proof because its common logout path is provider-specific.

## Required Okta Setup

Use a custom authorization server, not only the Okta org authorization server,
so API audience, API scopes, and groups claims are under your control.

- Authorization server issuer:
  `https://{yourOktaDomain}/oauth2/{authorizationServerId}`
- Confidential web app for the Auth Service:
  - Client ID maps to `AUTH_CLIENT_ID`.
  - Client secret maps to `AUTH_CLIENT_SECRET`.
  - Sign-in redirect URI:
    `http://127.0.0.1:9080/auth/callback/idp`
  - Sign-out redirect URI:
    `http://127.0.0.1:9080/`
  - Authorization Code enabled.
  - Refresh tokens enabled if you want to run the refresh proof.
- Service app for the API Gateway:
  - Client Credentials enabled.
  - Client secret maps to `GATEWAY_CLIENT_SECRET`.
  - Token must carry audience `oidc-reference-auth-internal` or whatever
    value the Auth Service internal-resource-server validator expects.
- API audience for the Resource Server:
  - Configure an audience value such as `api://oidc-reference-api`.
  - Set the same value in `OIDC_AUDIENCE`.
- Groups claim:
  - Emit a top-level `groups` claim in ID tokens and access tokens.
  - Set `OIDC_ROLES_CLAIM_PATH=groups`.
  - Ensure test users map to `user` and `admin` groups equivalent to the
    local `alice` and `admin` users.

## Local Overlay Values

Set these through an untracked environment file or shell export. Do not commit
real Okta tenant URLs or secrets.

```sh
OIDC_ISSUER_URI=https://{yourOktaDomain}/oauth2/{authorizationServerId}
APP_AUTHORIZATION_URI=https://{yourOktaDomain}/oauth2/{authorizationServerId}/v1/authorize
APP_TOKEN_URI=https://{yourOktaDomain}/oauth2/{authorizationServerId}/v1/token
APP_JWKS_URI=https://{yourOktaDomain}/oauth2/{authorizationServerId}/v1/keys
APP_END_SESSION_URI=https://{yourOktaDomain}/oauth2/{authorizationServerId}/v1/logout

AUTH_CLIENT_ID={okta-web-client-id}
AUTH_CLIENT_SECRET={okta-web-client-secret}
GATEWAY_CLIENT_SECRET={okta-gateway-client-secret}

OIDC_SCOPES=openid,profile,email,groups,api.read
OIDC_ROLES_CLAIM_PATH=groups
OIDC_AUDIENCE=api://oidc-reference-api
APP_REFRESH_REQUIRE_ROTATION=true
```

Okta tenant policy decides whether refresh-token rotation is enabled and how
reuse is handled. Keep `APP_REFRESH_REQUIRE_ROTATION=true` only when that
policy actually rotates refresh tokens; otherwise document the downgrade before
setting it false.

## Manual Run

1. Start from a clean tree and a clean local stack.
2. Render APISIX with the Okta token endpoint:

   ```sh
   GATEWAY_CLIENT_SECRET="$GATEWAY_CLIENT_SECRET" \
     CSRF_SIGNING_KEY="$CSRF_SIGNING_KEY" \
     APISIX_IDP_TOKEN_URL="$APP_TOKEN_URI" \
     sh scripts/render-apisix-config.sh
   ```

3. Start the same Compose topology with environment overrides for the Auth
   Service and Resource Server. Use a local, untracked Compose override or
   shell exports; do not commit tenant-specific values.
4. Run the browser proof:

   ```sh
   cd frontend
   E2E_FULL_STACK=1 \
     E2E_AUTH_URL_PATTERN='oauth2/.*/v1/authorize' \
     VITE_AUTH_TARGET=http://127.0.0.1:9080 \
     VITE_API_TARGET=http://127.0.0.1:9080 \
     npx playwright test tests/e2e/reference-flow.spec.ts --workers=1
   ```

## Evidence

Fill this section after a real Okta run.

- Date:
- Okta issuer:
- Roles claim:
- API audience:
- Refresh rotation policy:
- Browser proof result:
- Gateway refresh proof result:
- Logout result:
- Notes or provider-specific caveats:
