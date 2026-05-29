# Provider Adapters — Last Phase

**Audience.** The architect executing the final phase of the reference,
after `TASK-0008` (Auth Service) and `TASK-0009` (API Gateway) have
landed working code.

**Purpose.** Turn the "BFF + RS are IdP-agnostic" claim (decision A4)
into a verifiable promise: a user with Entra ID, AWS Cognito, Okta,
Auth0, Google, or Ping credentials should be able to clone this
repository, follow a numbered walkthrough for their provider, and run
the full reference stack against their real authorization server in
under 30 minutes. No application code changes; configuration only.

**Phase positioning.** This is the **last phase** of the reference.
Prerequisites:

- `TASK-0008` (Auth Service) is implemented and green.
- `TASK-0009` (API Gateway) is implemented and green.
- The Keycloak walkthrough (the local-default path) works end-to-end.
- The provider-adapter configuration surface defined in §3 below is
  fully implemented in code.

Until those are true, this phase cannot be completed honestly — there
is no way to verify that a provider adapter actually works without
running it.

> **Verification discipline.** Every per-provider walkthrough in §4 must
> be cross-checked against the provider's current official documentation
> before being relied upon. IdP admin consoles, screen labels, and
> endpoint conventions change on a quarterly cadence; the steps here
> reflect the state of each provider at the time of writing. Each
> walkthrough lists the official-docs pointer to verify against.
>
> If a walkthrough diverges from the official docs, the official docs
> win — patch the walkthrough and add a dated note recording the
> divergence.

---

## 1. The promise

A real user with an Entra tenant in hand should be able to:

1. `git clone` the reference repository.
2. Open `docs/providers/entra.md` (or their provider's equivalent).
3. Follow the numbered admin-console steps (~10–15 clicks).
4. Copy four to six lines into `.env`.
5. `docker compose up -d valkey traefik auth-service api-gateway
   resource-server frontend` (omitting `keycloak` and `postgres` —
   their IdP replaces Keycloak).
6. Open the browser to the app and complete the real login flow
   against their real IdP.

The components that change vs the Keycloak default: **zero application
code**. Three places of configuration: `.env`, the provider section
of `application.yml`, and (in some cases) the `app.auth.logout-style`
enum. Per-provider role-claim path is also configurable per A4 and
C5.

If a user cannot achieve this, the promise is broken and the
provider-adapter phase is incomplete.

---

## 2. What does NOT change per provider

These are the things every provider walkthrough preserves. The
architect implementing provider adapters must not regress any of them.

- The BFF session pattern (A1): tokens stay server-side regardless of
  provider.
- The split: Auth Service handles login, API Gateway handles proxy.
- The custom Valkey repositories (`tx:{state}`, `sess:{sid}`).
- `SameSite=Lax` on the session cookie + signed double-submit CSRF.
- `state` + PKCE S256 + ID-token `nonce` for login-CSRF defense.
- Per-session refresh lock + reuse audit event.
- The single wildcard `/api/**` allowlist at the Gateway.
- The Resource Server's explicit JWT validation (issuer, signature,
  expiration, algorithm, audience, scope, roles).
- The internal RPC `/internal/refresh` with Client Credentials.
- Virtual threads on all Spring services.

Provider adapters are **purely configuration**. If a provider would
require any of the above to change, the provider is not adoptable as-is
and the change is a separate engineering item.

---

## 3. The provider adapter configuration surface

The application code reads exactly this surface. Every per-provider
walkthrough fills exactly this surface. Nothing else varies.

### 3.1 Environment variables (per `.env`)

| Variable | Meaning | Example (Keycloak) | Example (Entra) |
|---|---|---|---|
| `OIDC_ISSUER_URI` | OIDC issuer URL; discovery happens at `{this}/.well-known/openid-configuration` | `http://localhost:8080/realms/oidc-reference` | `https://login.microsoftonline.com/{tenant-id}/v2.0` |
| `OIDC_CLIENT_ID` | The Auth Service's confidential OIDC client ID at the provider | `oidc-reference-auth` | Application (client) ID from app registration |
| `OIDC_CLIENT_SECRET` | The Auth Service's client secret | (env-injected) | Client secret value (not the ID) from app registration |
| `OIDC_SCOPES` | Space-separated scopes requested at authorization | `openid profile email roles api.audience api.read` | `openid profile email offline_access api://{api-id}/api.read` |
| `OIDC_API_AUDIENCE` | The audience value the RS expects in access tokens | `oidc-reference-api` | The API's Application ID URI (e.g., `api://{api-id}`) |
| `OIDC_ROLES_CLAIM` | Dotted path to the roles claim in the token | `realm_access.roles` | `roles` (App Roles) or `groups` |
| `OIDC_LOGOUT_STYLE` | One of `oidc-standard`, `cognito`, `auth0`, `none` | `oidc-standard` | `oidc-standard` |
| `API_GATEWAY_CLIENT_ID` | The API Gateway's Client Credentials client ID (for `/internal/refresh`) | `oidc-reference-api-gateway` | (separate app registration — see §4.1) |
| `API_GATEWAY_CLIENT_SECRET` | Its secret | (env-injected) | (env-injected) |
| `API_GATEWAY_AUDIENCE` | Expected audience on the Gateway's service token | `oidc-reference-auth-internal` | (a scope or App ID URI on the Auth Service app reg) |

### 3.2 The `OIDC_LOGOUT_STYLE` enum

Not every IdP implements RP-initiated logout the same way. The Auth
Service's logout handler must select an implementation by this enum:

| Value | Used for | Behavior |
|---|---|---|
| `oidc-standard` | Keycloak, Entra, Okta (Custom AS), Ping, Google* | `302` to discovered `end_session_endpoint` with `id_token_hint` and `post_logout_redirect_uri`. |
| `cognito` | AWS Cognito | `302` to `{cognito-domain}/logout` with `client_id` and `logout_uri` query params. Cognito does not implement standard OIDC end-session. |
| `auth0` | Auth0 | `302` to `https://{tenant}.auth0.com/v2/logout` with `client_id` and `returnTo` query params. Auth0's standard end-session was added later but `/v2/logout` remains the canonical path. |
| `none` | Google* (no RP-initiated logout), legacy AS | Local session deletion only; no upstream logout call. SPA must clearly indicate to users that they remain logged in at the IdP. |

\* Google publishes an `end_session_endpoint` but its behavior is
inconsistent across account types. Use `oidc-standard` if your testing
confirms it works for your account type; otherwise `none`.

### 3.3 What the Auth Service implementation must support

The `TASK-0008` Auth Service must, by the time provider adapters are
exercised:

- Read all variables in §3.1 from the environment.
- Use `OIDC_ISSUER_URI` for discovery; do not hard-code any endpoint.
- Pass `OIDC_API_AUDIENCE` through to the RS's expected `aud` value
  (or, for providers that don't allow custom audience, accept the
  default the IdP issues — see per-provider sections).
- Implement four `logout-style` handlers: `oidc-standard`, `cognito`,
  `auth0`, `none`. Select by env at startup; fail fast on unrecognized
  values.
- Implement `OIDC_ROLES_CLAIM` as a configurable dotted path; the RS's
  `JwtAuthenticationConverter` must read this path rather than the
  hard-coded `realm_access.roles`.
- Tolerate the absence of optional claims (e.g., `email` if a provider
  doesn't issue it) without crashing.

---

## 4. Per-provider walkthroughs

Each walkthrough below is the template for the corresponding
`docs/providers/{name}.md` file the architect must create. Length
target: a non-expert can complete the walkthrough in 30 minutes with
no prior knowledge of the provider.

### 4.1 Microsoft Entra ID (Azure AD)

**Difficulty: easy.** Entra implements OIDC cleanly; standard logout
works; App Roles map directly to the roles claim.

> **Important: this is the OIDC path, not SAML.** Entra supports both
> SAML SSO and OpenID Connect / OAuth 2.0 against the same tenant. The
> reference uses **OIDC exclusively**. Configure via **Microsoft Entra
> ID → App registrations** (the OIDC / OAuth surface). Do **not**
> configure via **Enterprise applications → Single sign-on → SAML**
> — that is a separate protocol surface and the reference will not
> work against it.
>
> Concretely: a reader who arrives at a screen titled "SAML
> Certificate," "SAML Signing Certificate," "Identifier (Entity ID),"
> or "Reply URL (Assertion Consumer Service URL)" has navigated into
> the SAML configuration by mistake. Back out and return to **App
> registrations**.
>
> The walkthrough below uses Entra's v2.0 OIDC endpoint
> (`/v2.0/.well-known/openid-configuration`). The v1.0 endpoint is
> the legacy OAuth 2.0 surface and is not what the reference targets.

**Official docs to verify against:**

- [Quickstart: Register an application with the Microsoft identity
  platform](https://learn.microsoft.com/entra/identity-platform/quickstart-register-app)
- [App roles in Microsoft Entra ID](https://learn.microsoft.com/entra/identity-platform/howto-add-app-roles-in-apps)
- [OpenID Connect on the Microsoft identity
  platform](https://learn.microsoft.com/entra/identity-platform/v2-protocols-oidc)

**Steps in the Azure Portal.**

1. Sign in to the Azure Portal as a tenant admin.
2. Open **Microsoft Entra ID** → **App registrations** → **New
   registration**.
3. Name: `oidc-reference-auth`. Supported account types: "Accounts in
   this organizational directory only" (single-tenant) for the
   reference. Redirect URI type: **Web**. Redirect URI:
   `http://127.0.0.1:5173/auth/callback/idp` (for the frontend-dev
   case) — register all hostnames you intend to use.
4. Record the **Application (client) ID** and the **Directory
   (tenant) ID** shown on the Overview page.
5. **Certificates & secrets** → **New client secret**. Description:
   `oidc-reference-auth dev`. Expiry: 90 days. Record the secret
   **value** (not the ID).
6. **Expose an API** → **Set** to set the Application ID URI; accept
   the default `api://{client-id}` or set a custom value. Record it
   as `OIDC_API_AUDIENCE`.
7. **Add a scope**: name `api.read`, who can consent: Admins and users,
   admin consent display name + description: arbitrary. Enable. Repeat
   for `api.write` if needed.
8. **App roles** → **Create app role**. Display name: `admin`. Allowed
   member types: Users/Groups. Value: `admin`. Description: arbitrary.
   Enable. Repeat for `user`, `auditor`.
9. **API permissions** → **Add a permission** → **My APIs** → select
   this same app → **Delegated permissions** → check `api.read`. Grant
   admin consent.
10. **Token configuration** → **Add optional claim**. Token type:
    **ID**. Select `email`, `preferred_username`. Add. Repeat for
    Access token if needed.
11. Repeat steps 2–5 for a **second** app registration:
    `oidc-reference-api-gateway`. This one needs Client Credentials
    only — no redirect URI required. Same Application ID URI pattern
    as step 6 but on the `oidc-reference-auth` app, expose a scope
    `internal.refresh` and grant it (as an Application permission, not
    Delegated) to `oidc-reference-api-gateway`.
12. **Enterprise applications** → find `oidc-reference-auth` → **Users
    and groups** → assign yourself with the `admin` app role for
    testing.

**`.env`:**

```
OIDC_ISSUER_URI=https://login.microsoftonline.com/{tenant-id}/v2.0
OIDC_CLIENT_ID={oidc-reference-auth Application (client) ID}
OIDC_CLIENT_SECRET={secret value from step 5}
OIDC_SCOPES=openid profile email offline_access api://{auth-client-id}/api.read
OIDC_API_AUDIENCE=api://{auth-client-id}
OIDC_ROLES_CLAIM=roles
OIDC_LOGOUT_STYLE=oidc-standard
API_GATEWAY_CLIENT_ID={oidc-reference-api-gateway Application (client) ID}
API_GATEWAY_CLIENT_SECRET={its secret value}
API_GATEWAY_AUDIENCE=api://{auth-client-id}/internal.refresh
```

**Gotchas:**

- The `roles` claim is added to access tokens only if you assign users
  to the App Role via Enterprise Applications. Users with no
  assignment will not have a `roles` claim and the RS's role-based
  checks will fail with no diagnostic — log it loudly.
- The token v1.0 vs v2.0 distinction matters. The `v2.0` issuer URL
  is what the spec assumes; do not omit `/v2.0`.
- Multi-tenant apps require `OIDC_ISSUER_URI` to be
  `https://login.microsoftonline.com/organizations/v2.0` and the
  Auth Service's issuer validation must accept the tenant-specific
  issuer in the ID token (`tid` claim). For the reference, recommend
  single-tenant.

### 4.2 AWS Cognito (User Pools)

**Difficulty: medium.** OIDC is largely standard; logout is non-
standard (use `logout-style=cognito`); the audience model is different
from every other provider.

**Official docs to verify against:**

- [Cognito User Pools — App client settings](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-app-idp-settings.html)
- [Using the LOGOUT endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html)
- [Using tokens with user pools](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-with-identity-providers.html)
- [Resource servers and custom scopes](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html)

**Steps in the AWS Console.**

1. Open **Amazon Cognito** → **User Pools** → **Create user pool**.
2. Sign-in options: email (or as needed). Other settings: defaults
   acceptable for the reference.
3. After creation, open the user pool. Note the **User pool ID** and
   the **AWS region** — together they form the issuer URL.
4. **App integration** → **App clients** → **Create app client**.
   - App type: **Confidential client**.
   - Name: `oidc-reference-auth`.
   - Generate a client secret: **yes**.
   - Authentication flows: leave the `ALLOW_USER_*_AUTH` flows
     **disabled** — those are for the direct AdminInitiateAuth /
     InitiateAuth APIs (username + password). The reference uses
     the OAuth Authorization Code flow only, which is configured
     under the **Hosted UI** / **OAuth 2.0 grants** section below.
   - Hosted UI settings: enable.
   - Allowed callback URLs: `http://127.0.0.1:5173/auth/callback/idp`.
   - Allowed sign-out URLs: `http://127.0.0.1:5173/`.
   - OAuth 2.0 grant types: check **Authorization code grant** only.
   - OpenID Connect scopes: `openid`, `profile`, `email`.
5. **App integration** → **Domain** → create either a Cognito domain
   (`{prefix}.auth.{region}.amazoncognito.com`) or a custom domain.
   The Cognito domain is sufficient for the reference. The hosted UI
   and OAuth endpoints live under this domain.
6. **App integration** → **Resource servers** → **Create resource
   server**.
   - Name: `oidc-reference-api`.
   - Identifier: `oidc-reference-api` (this becomes the prefix for
     scope strings).
   - Custom scopes: `api.read`, `api.write`, `admin.read`.
7. Return to the `oidc-reference-auth` app client → **Edit hosted UI
   settings** → add the custom scopes from step 6 to allowed scopes.
   The scope strings the Auth Service requests are now
   `oidc-reference-api/api.read`, etc.
8. **Groups** → create groups `admin`, `user`, `auditor`. Assign users
   to groups for testing.
9. Repeat steps 4–7 for a **second** app client:
   `oidc-reference-api-gateway`. Confidential, Client Credentials
   only, no callback URLs needed, custom scope `internal.refresh`
   (defined on the same resource server or a new one
   `oidc-reference-auth-internal`).

**`.env`:**

```
OIDC_ISSUER_URI=https://cognito-idp.{region}.amazonaws.com/{user-pool-id}
OIDC_CLIENT_ID={oidc-reference-auth client ID}
OIDC_CLIENT_SECRET={its client secret}
OIDC_SCOPES=openid profile email oidc-reference-api/api.read
OIDC_API_AUDIENCE={oidc-reference-auth client ID}
OIDC_ROLES_CLAIM=cognito:groups
OIDC_LOGOUT_STYLE=cognito
OIDC_COGNITO_DOMAIN=https://{prefix}.auth.{region}.amazoncognito.com
API_GATEWAY_CLIENT_ID={oidc-reference-api-gateway client ID}
API_GATEWAY_CLIENT_SECRET={its client secret}
API_GATEWAY_AUDIENCE={oidc-reference-api-gateway client ID}
```

**Gotchas:**

- **Audience model.** Cognito's access tokens have `aud` set to the app
  client ID, not a custom value. The RS's `JwtClaimValidator` must
  accept whatever `OIDC_API_AUDIENCE` is configured to — for Cognito,
  this is the Auth Service's client ID, not the resource server
  identifier. Custom scopes serve the role of "resource binding"
  instead. This is a real conceptual difference; document it loudly in
  the walkthrough.
- **Logout endpoint.** Cognito's `/logout` is non-standard. Query
  params: `client_id` and `logout_uri`. There is no `id_token_hint`
  parameter. The `OIDC_LOGOUT_STYLE=cognito` handler must construct
  the URL as
  `{OIDC_COGNITO_DOMAIN}/logout?client_id={cid}&logout_uri={post-logout}`.
- **Discovery URL** uses the user pool path, not a region-level path.
- **`cognito:groups`** is an array; the reference's role mapper must
  treat it as such.
- **Cognito does NOT support `prompt=none` reliably.** Silent renewal
  via iframe (not used in the BFF reference, but called out for
  context) is unreliable on Cognito.

### 4.3 Okta

**Difficulty: medium.** Strongly prefer using a Custom Authorization
Server (not the default org AS). Standard OIDC otherwise.

**Official docs to verify against:**

- [Create an OIDC app integration](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/)
- [Customize tokens (custom claims, audience)](https://developer.okta.com/docs/guides/customize-tokens-returned-from-okta/main/)
- [Create an authorization server](https://developer.okta.com/docs/guides/customize-authz-server/main/)

**Two paths.** Okta exposes two authorization servers:

- **Org AS** (`https://{org}.okta.com`). Limited claim customization.
  Does NOT support custom audience for access tokens.
- **Custom AS** (`https://{org}.okta.com/oauth2/{auth-server-id}`).
  Full claim customization, custom audience, custom scopes. **Use
  this**.

**Steps in the Okta Admin Console.**

1. Sign in to your Okta org as an admin.
2. **Security** → **API** → **Authorization Servers** → **Add
   Authorization Server**.
   - Name: `oidc-reference`.
   - Audience: `oidc-reference-api`.
   - Description: arbitrary.
3. Open the new AS → **Scopes** → **Add Scope**. Repeat for
   `api.read`, `api.write`, `admin.read`, `service.jobs`. Mark each
   with appropriate user-consent settings.
4. **Claims** → **Add Claim**.
   - Name: `groups`.
   - Include in token type: **Access Token** (or ID Token; the
     reference reads from access token).
   - Value type: **Groups**.
   - Filter: **Matches regex** `.*` (to include all groups; tighten
     for production).
5. **Access Policies** → **Add Policy** → assign to all your apps; add
   a rule that allows the relevant grant types (Authorization Code,
   Client Credentials) for selected scopes.
6. **Applications** → **Create App Integration** → **OIDC - OpenID
   Connect** → **Web Application**.
   - Name: `oidc-reference-auth`.
   - Grant types: Authorization Code + Refresh Token.
   - Sign-in redirect URIs: `http://127.0.0.1:5173/auth/callback/idp`.
   - Sign-out redirect URIs: `http://127.0.0.1:5173/`.
   - Assignments: limited or all users.
7. Record **Client ID** and **Client Secret** from the General tab.
8. **Groups** → create `admin`, `user`, `auditor` (or use existing
   groups). Assign users.
9. Repeat step 6 for a **second** app: `oidc-reference-api-gateway`.
   Application type: **Service** (Machine-to-Machine). Grant type:
   Client Credentials only. Assign the appropriate scope (e.g., a new
   `internal.refresh` scope on the same AS or a separate AS).
10. Bind both apps to the Custom AS via the Access Policies on the AS.

**`.env`:**

```
OIDC_ISSUER_URI=https://{org}.okta.com/oauth2/{auth-server-id}
OIDC_CLIENT_ID={oidc-reference-auth client ID}
OIDC_CLIENT_SECRET={its client secret}
OIDC_SCOPES=openid profile email api.read offline_access
OIDC_API_AUDIENCE=oidc-reference-api
OIDC_ROLES_CLAIM=groups
OIDC_LOGOUT_STYLE=oidc-standard
API_GATEWAY_CLIENT_ID={oidc-reference-api-gateway client ID}
API_GATEWAY_CLIENT_SECRET={its client secret}
API_GATEWAY_AUDIENCE=oidc-reference-auth-internal
```

**Gotchas:**

- **Do not use the org AS.** It cannot issue access tokens with custom
  audiences; the RS's audience validation will fail.
- **Refresh tokens are off by default** on some Okta tiers. Enable the
  Refresh Token grant explicitly on the app + the access policy rule.
- **Reuse detection** is a paid feature on some tiers. Without it, the
  reference's reuse-audit guarantee is not enforced at the AS — the
  reference still emits the audit event when the BFF detects a
  rotation mismatch, but the AS-side enforcement is absent. Document
  this trade-off if applicable.
- **Token lifetimes** are configured per Access Policy Rule on the
  Custom AS, not per app.

### 4.4 Auth0

**Difficulty: medium.** Standard OIDC mostly. Custom audience is via
the `audience` parameter, not a scope. Logout is non-standard
(`/v2/logout`).

**Official docs to verify against:**

- [Configure Applications](https://auth0.com/docs/get-started/applications)
- [Register APIs](https://auth0.com/docs/get-started/apis)
- [Create custom claims with Actions](https://auth0.com/docs/customize/actions/flows-and-triggers/login-flow)
- [Logout endpoint](https://auth0.com/docs/authenticate/login/logout)
- [Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)

**Steps in the Auth0 Dashboard.**

1. Sign in to your Auth0 tenant as admin.
2. **Applications** → **Create Application**.
   - Name: `oidc-reference-auth`.
   - Type: **Regular Web Application**.
3. Open the new application → **Settings**.
   - Allowed Callback URLs:
     `http://127.0.0.1:5173/auth/callback/idp`.
   - Allowed Logout URLs: `http://127.0.0.1:5173/`.
   - Token Endpoint Authentication Method: `Post` (client secret in
     body) or `Basic`. The Auth Service supports both.
   - Grant Types: Authorization Code + Refresh Token (un-check
     Implicit and Password).
   - Refresh Token: Rotation enabled (Settings → Refresh Token
     Rotation toggle) + Reuse Detection enabled.
4. Record **Client ID** and **Client Secret**.
5. **APIs** → **Create API**.
   - Name: `oidc-reference-api`.
   - Identifier: `oidc-reference-api` (this is what becomes the
     `aud` claim on access tokens).
   - Signing algorithm: RS256.
6. Open the API → **Permissions** → add `api.read`, `api.write`,
   `admin.read`. (Auth0 calls these "permissions" but they appear as
   scopes in tokens.)
7. **Actions** → **Library** → **Build Custom** action. Trigger:
   "Login / Post Login". Code:

   ```javascript
   exports.onExecutePostLogin = async (event, api) => {
     const namespace = 'https://oidc-reference.local/';
     if (event.authorization && event.authorization.roles) {
       api.idToken.setCustomClaim(`${namespace}roles`,
                                   event.authorization.roles);
       api.accessToken.setCustomClaim(`${namespace}roles`,
                                       event.authorization.roles);
     }
   };
   ```

   Deploy and add to the Login flow.
8. **User Management** → **Roles** → create `admin`, `user`,
   `auditor`. Assign users.
9. Repeat step 2 for a second application:
   `oidc-reference-api-gateway`. Type: **Machine to Machine
   Applications**. Authorize it for the Auth0 Management API only if
   you need provisioning; for the reference's `/internal/refresh`,
   you need a second API in Auth0
   (`oidc-reference-auth-internal`, identifier the same) and grant the
   M2M app the necessary scope.

**`.env`:**

```
OIDC_ISSUER_URI=https://{tenant}.auth0.com/
OIDC_CLIENT_ID={oidc-reference-auth client ID}
OIDC_CLIENT_SECRET={its client secret}
OIDC_SCOPES=openid profile email offline_access api.read
OIDC_AUDIENCE_REQUEST=oidc-reference-api
OIDC_API_AUDIENCE=oidc-reference-api
OIDC_ROLES_CLAIM=https://oidc-reference.local/roles
OIDC_LOGOUT_STYLE=auth0
OIDC_AUTH0_TENANT=https://{tenant}.auth0.com
API_GATEWAY_CLIENT_ID={oidc-reference-api-gateway client ID}
API_GATEWAY_CLIENT_SECRET={its client secret}
API_GATEWAY_AUDIENCE=oidc-reference-auth-internal
```

**Gotchas:**

- **`audience` parameter required.** Auth0 only issues a JWT access
  token (rather than an opaque token) when the authorization request
  includes the `audience` parameter naming an API. The Auth Service's
  request builder must include `audience={OIDC_AUDIENCE_REQUEST}` for
  this provider. This is a NEW configuration item beyond the standard
  OIDC scopes/claims surface — it's an Auth0-specific quirk.
- **Custom claims must be namespaced.** Auth0 strips non-namespaced
  custom claims from tokens. The `https://oidc-reference.local/`
  namespace in the Action is required.
- **Logout endpoint.** `/v2/logout` with `returnTo` (not
  `post_logout_redirect_uri`). The `returnTo` URL must be in the
  Allowed Logout URLs list.
- **Trailing slash on issuer URL** matters for Auth0; the discovery
  document is at `{issuer}/.well-known/openid-configuration` and the
  issuer in tokens includes the trailing slash. Match it exactly.

### 4.5 Google Identity Platform

**Difficulty: hard for a full reference; easy for "Sign in with
Google".** Google is excellent for federated authentication but
limited for "use as your AS for a custom app." App Roles do not exist
natively; there is no clean way to express custom audiences or
scopes; RP-initiated logout is unreliable.

**Official docs to verify against:**

- [OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [Setting up OAuth 2.0](https://support.google.com/cloud/answer/6158849)
- [Using OAuth 2.0 for Web Server Applications](https://developers.google.com/identity/protocols/oauth2/web-server)

**Recommendation.** Document Google as a partial-fit reference: it
works for the login flow, but the access-control story is degraded
unless you layer your own claim-issuance on top.

**Steps in the Google Cloud Console.**

1. Create or select a Google Cloud project.
2. **APIs & Services** → **OAuth consent screen** → configure (User
   Type: External or Internal).
3. **APIs & Services** → **Credentials** → **Create Credentials** →
   **OAuth client ID** → Application type: **Web application**.
   - Name: `oidc-reference-auth`.
   - Authorized redirect URIs:
     `http://127.0.0.1:5173/auth/callback/idp`.
4. Record **Client ID** and **Client Secret**.

**`.env`:**

```
OIDC_ISSUER_URI=https://accounts.google.com
OIDC_CLIENT_ID={client ID}.apps.googleusercontent.com
OIDC_CLIENT_SECRET={client secret}
OIDC_SCOPES=openid profile email
OIDC_API_AUDIENCE={client ID}.apps.googleusercontent.com
OIDC_ROLES_CLAIM=
OIDC_LOGOUT_STYLE=none
API_GATEWAY_CLIENT_ID=(not supported — see gotchas)
```

**Gotchas (each is significant):**

- **No App Roles or Groups in tokens.** `OIDC_ROLES_CLAIM` is empty;
  the reference's role-based authorization will not work against
  Google. To get roles, you must integrate Google Workspace + Cloud
  Identity, or layer a Custom Claims service on top of Google. Out of
  scope for the reference's provider walkthrough.
- **`aud` is the client ID.** Same model as Cognito — there is no
  custom audience.
- **No useful Client Credentials.** Google's service-to-service auth
  is via service accounts and signed JWTs, not the OAuth Client
  Credentials grant. The reference's `/internal/refresh` pattern
  cannot run against Google without significant adaptation. For the
  reference, fall back to a shared-secret internal auth in dev when
  using Google as the user-AS.
- **RP-initiated logout is inconsistent.** Use
  `OIDC_LOGOUT_STYLE=none` and inform the user.
- **Refresh tokens** are only issued if the application requests
  `access_type=offline` AND the user consents. The Auth Service must
  send `access_type=offline` and `prompt=consent` to obtain a refresh
  token reliably.

**Honest assessment.** Google is best treated as "sign in with Google,
then authorize via your own backend's records." The reference's
audience+roles model does not map cleanly onto Google as the sole AS.
Document this in the walkthrough; do not pretend otherwise.

### 4.6 Ping (PingOne and PingFederate)

**Difficulty: easy.** Ping implements OIDC carefully and predictably.
Two products with the same OIDC story:

- **PingOne** — cloud-hosted; closest analog to Auth0/Okta cloud.
- **PingFederate** — self-hosted; closest analog to Keycloak.

The walkthrough for PingOne is given here. PingFederate is similar.

> **Issuer URL hedge.** The PingOne issuer URL format below
> (`https://auth.pingone.com/{env-id}/as`) reflects PingOne for
> Workforce / PingOne for Customers at time of writing. The exact
> format varies by PingOne product family and region (`pingone.com`,
> `pingone.eu`, `pingone.asia`, `pingone.com.au`). Verify against
> your tenant's discovery document
> (`{issuer}/.well-known/openid-configuration`) before relying on it.

**Official docs to verify against:**

- [PingOne — Connecting an OIDC application](https://docs.pingidentity.com/r/en-us/pingone/pingone_t_add_an_application_worker)
- [PingFederate — OAuth 2.0 / OIDC overview](https://docs.pingidentity.com/r/en-us/pingfederate-112/pf_oauth_oidc)

**Steps in the PingOne Admin Console.**

1. Sign in to your PingOne environment.
2. **Applications** → **Add Application** → **OIDC Web App**.
   - Name: `oidc-reference-auth`.
   - Grant Type: Authorization Code, Refresh Token.
   - Redirect URIs:
     `http://127.0.0.1:5173/auth/callback/idp`.
   - Token Endpoint Authentication Method: Client Secret Post or
     Basic.
3. **Resources** → **Add Resource** → name `oidc-reference-api`,
   audience `oidc-reference-api`. Add scopes `api.read`, `api.write`,
   `admin.read`.
4. Grant the application access to the resource and its scopes.
5. **Identities** → **Groups** → create `admin`, `user`, `auditor`.
   Assign users.
6. **Applications** → app → **Configuration** → **Attribute Mappings**
   → add a custom claim `groups` mapped from user groups.
7. Repeat for a second application: `oidc-reference-api-gateway`,
   Worker (machine-to-machine), Client Credentials only.

**`.env`:**

```
OIDC_ISSUER_URI=https://auth.pingone.com/{environment-id}/as
OIDC_CLIENT_ID={oidc-reference-auth client ID}
OIDC_CLIENT_SECRET={its client secret}
OIDC_SCOPES=openid profile email api.read
OIDC_API_AUDIENCE=oidc-reference-api
OIDC_ROLES_CLAIM=groups
OIDC_LOGOUT_STYLE=oidc-standard
API_GATEWAY_CLIENT_ID={api-gateway client ID}
API_GATEWAY_CLIENT_SECRET={its client secret}
API_GATEWAY_AUDIENCE=oidc-reference-auth-internal
```

**Gotchas:**

- Region matters in the issuer URL
  (`https://auth.pingone.com`, `https://auth.pingone.eu`,
  `https://auth.pingone.asia`).
- Custom claim mapping is configured per-application, not at the
  environment level.

---

## 5. Live-provider smoke check

`scripts/verify-cross-service.sh` gains a `RUN_LIVE_PROVIDER` mode:

```bash
RUN_LIVE_PROVIDER=entra ./scripts/verify-cross-service.sh
```

The mode:

1. Reads provider-specific env vars from `.env`.
2. Performs a Client Credentials flow against the configured provider
   (using the API Gateway's credentials), asserting a token is issued
   and that its `aud` and the requested scope are present.
3. Optionally drives the user-flow via Playwright if a test-user
   credential set is provided via env (`PROVIDER_TEST_USER`,
   `PROVIDER_TEST_PASSWORD`). This is best-effort and may be skipped
   for providers that require MFA or hardware keys.
4. Asserts the resulting access token reaches the RS and is accepted
   (audience, scope, roles).

Defaults to **off**. Opt-in only when the user has real provider
credentials in env. Failures must include the provider name and a
non-secret summary of what failed (claim missing, audience mismatch,
discovery unreachable).

---

## 6. Provider matrix at a glance

| Provider | Difficulty | Custom audience | Roles claim | Logout style | Refresh rotation | Notes |
|---|---|---|---|---|---|---|
| Keycloak (local) | trivial | yes (audience-mapper) | `realm_access.roles` | `oidc-standard` | yes (realm setting) | The reference's default; baseline for every other adapter. |
| Entra ID | easy | yes (Application ID URI) | `roles` (App Roles) | `oidc-standard` | yes | Cleanest cloud option. |
| Cognito | medium | no — `aud` = client ID | `cognito:groups` | `cognito` | yes | Different audience model. |
| Okta (Custom AS) | medium | yes | `groups` (custom claim) | `oidc-standard` | yes (paid tiers for reuse detection) | Must use Custom AS, not Org AS. |
| Auth0 | medium | yes (`audience` param) | namespaced custom claim | `auth0` | yes | Logout non-standard; custom claims must be namespaced. |
| Google | hard for full reference | no | none (or via Workspace) | `none` | yes (with `access_type=offline`) | Partial fit; sign-in only. |
| PingOne / PingFederate | easy | yes | configurable (e.g., `groups`) | `oidc-standard` | yes | Predictable, well-behaved. |

---

## 7. New scope additions for code (TASK-0008 / TASK-0009)

The provider-adapter phase requires four changes the implementing
architect must add to the Auth Service and API Gateway during
TASK-0008 and TASK-0009:

1. **Configurable `OIDC_ROLES_CLAIM`** — the RS's
   `JwtAuthenticationConverter` reads a dotted claim path from
   config, not a hard-coded `realm_access.roles`.
2. **`OIDC_LOGOUT_STYLE` enum + four handlers** (`oidc-standard`,
   `cognito`, `auth0`, `none`). The Auth Service selects at startup;
   fails fast on unknown values.
3. **`OIDC_AUDIENCE_REQUEST`** — if non-empty, the Auth Service adds
   `audience={value}` to the authorization request (Auth0
   requirement; ignored by other providers).
4. **Tolerant claim presence** — the Auth Service must not crash if
   optional claims (`email`, `preferred_username`, `name`) are
   missing from the ID token. Map to null and surface via `/auth/me`
   as such.

These four items are small but real. They are listed here so they
appear in TASK-0008 / TASK-0009 Done Criteria before this phase
becomes possible.

---

## 8. Acceptance criteria for the provider-adapter phase

The phase is complete when, for each of {Keycloak, Entra, Cognito,
Okta, Auth0, PingOne}:

- A walkthrough exists at `docs/providers/{name}.md` matching the
  template in §4.
- A reviewer following the walkthrough from a fresh tenant completes
  the login flow against the real provider in under 30 minutes.
- `RUN_LIVE_PROVIDER={name} ./scripts/verify-cross-service.sh` passes
  with credentials from that provider's tenant.
- The resulting access token reaches the RS, is accepted, and the
  role-based authorization (`POST /api/admin`) works for a user
  assigned the `admin` role at that provider.
- Logout via the configured `OIDC_LOGOUT_STYLE` returns the user to
  the SPA root in a logged-out state.

Google is documented but exempt from the acceptance criterion because
of the structural limitations in §4.5. Mark Google as "partial fit;
sign-in only" in the matrix and the README.

---

## 9. Open questions

1. **Multi-tenant Entra.** The walkthrough above assumes single-tenant.
   Multi-tenant requires the Auth Service to accept multiple issuer
   values (one per tenant) and to validate the `tid` claim. Out of
   scope for the first provider-adapter phase; backlog item.
2. **mTLS client authentication** (RFC 8705) on providers that support
   it (Ping, some Okta tiers). The reference uses `client_secret_*`;
   mTLS adoption is a separate decision flagged in
   `architecture-decisions.md` Section F as not adopted.
3. **DPoP token binding** on providers that support it (some Ping,
   Okta beta). Same status as mTLS — F-section non-adoption.
4. **Federated identity behind the IdP.** If a tenant has SAML or
   social federation set up at the IdP, the reference's flow works
   unchanged (the IdP handles federation; the BFF sees a normal OIDC
   token). Worth a one-line note in each walkthrough confirming this.
5. **Provisioning automation.** Each walkthrough is currently
   click-driven. For repeated test setups, each provider has its own
   IaC story (Terraform providers for Entra and Auth0; CDK/CloudFormation
   for Cognito; Okta provider). Out of scope for the reference, but
   worth a parenthetical pointer per provider.

---

## 10. Stopping line

This phase is the bridge between "interesting OIDC reference" and
"reference an engineer with Entra credentials can actually run." It
is the final phase because everything else must be settled first —
the spec, the split architecture, the working code, the security
choices, the audit hooks. Once this phase lands, the reference's
adoption claim is verifiable, not aspirational.

It is also the phase where the reference earns the right to be cited
in real design reviews: not as "look at this clean BFF pattern" but as
"plug your IdP in and run."
