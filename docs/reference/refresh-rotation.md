# Refresh-Token Rotation Policy

The Auth Service treats refresh-token rotation as a security invariant by
default. A refresh-grant response that omits a new `refresh_token`, or
returns the same value as the one we sent, is treated as a rotation
failure: the controller invalidates the session, deletes `sess:{sid}`,
emits the `security_audit refresh_token_rejected` event, and returns 409 —
the same path Keycloak's own reuse-detection chain takes when it sees a
replayed refresh token.

This default exists because silently accepting an un-rotated refresh
token is indistinguishable, from the BFF's perspective, from a stolen
token being replayed. There is no signal at the application layer to
tell those apart, so the safer default is to fail.

## Configuration

| Property                            | Default | Purpose                                                                                |
|-------------------------------------|---------|----------------------------------------------------------------------------------------|
| `app.refresh-require-rotation`      | `true`  | Treat missing or unchanged `refresh_token` as `invalid_grant`.                         |
| `APP_REFRESH_REQUIRE_ROTATION` (env) | `true`  | Environment override for the same value (Spring relaxed binding).                      |

Set to `false` only when paired with an authorization server that does
not rotate refresh tokens. With rotation disabled, the legacy permissive
behavior kicks in: the old refresh token is reused for the next grant.

## Provider matrix

The recommendation below assumes each provider's default configuration.
If your IdP deployment has changed the rotation behavior at the
client/realm level, treat that as authoritative over this table.

| Provider                                  | Rotates by default? | Recommended setting              |
|-------------------------------------------|---------------------|----------------------------------|
| Keycloak (this reference)                 | Yes (when enabled at the realm — the bundled `oidc-reference` realm has it on) | `true` |
| Auth0                                     | Yes (when "Rotation" is enabled on the application; default for SPAs and native apps) | `true` |
| Okta                                      | Yes (default for all OAuth/OIDC apps when refresh tokens are enabled)            | `true` |
| Microsoft Entra ID (Azure AD)             | Yes (refresh tokens rotate; old ones invalidated after a grace window)            | `true` |
| AWS Cognito                               | No (returns the same refresh token across the refresh window unless rotation is explicitly enabled)            | `false` (unless the user pool has refresh rotation turned on) |
| Google Identity                           | No (refresh tokens are long-lived and do not rotate per request)                  | `false` |
| GitHub OAuth Apps                         | No (no refresh tokens at all under the standard flow)                            | N/A    |
| Apple Sign In                             | No (refresh tokens are stable; rotation is not part of the protocol)              | `false` |

When the column says "No", setting `app.refresh-require-rotation=true`
will cause every refresh attempt to invalidate the session — visible as
the user being kicked out 60s before the access token would have
expired (the `session-refresh-window`).

## Why this is configurable rather than hard-wired

The BFF reference targets Keycloak with rotation on; that is the
security posture being demonstrated. The escape hatch exists so the
reference can be re-pointed at a non-rotating provider for a demo or
migration without rewriting the refresh client. Production deployments
should pick the value once and pin it; flipping at runtime is not part
of the contract.

If you are running this against a non-rotating provider and want the
defense-in-depth equivalent, layer it elsewhere — for example,
shortening `session-refresh-window` so the access token expires inside
the BFF rather than at the gateway, or adding a refresh-token-age
ceiling outside the OAuth grant chain.
