# RFC 9470 Compliance — OAuth 2.0 Step Up Authentication Challenge Protocol

Control-by-control status of this reference against
[RFC 9470](https://datatracker.ietf.org/doc/rfc9470/) (OAuth 2.0 Step Up
Authentication Challenge Protocol).

**Scope of step-up in this reference.** Step-up is enforced on the sensitive
route `POST /api/admin` using **`auth_time` freshness** (`max_age` semantics) —
the portable mechanism that needs no IdP Level-of-Authentication (LoA) config.
The companion ACR mechanism (`acr_values` / `acr`) is the **planned** assurance
axis: this realm emits no `acr` today, and the realm LoA mapping is
provider-specific config (as the `auth_time` mapper already is). Where RFC 9470
offers both `max_age` and `acr_values`, this reference implements the `max_age`
half today and records the `acr_values` half as the planned companion (request
`acr_values`, RS verifies `acr`, mirroring the `auth_time` gate — see the SPEC
step-up §). See also
[`OIDC-compliance.md`](OIDC-compliance.md) §2 (`auth_time`/`acr`) and §3.1.2.1
(`prompt`), and [SPEC-0001 §"Step-up authentication"](docs/specs/SPEC-0001-core-oidc-flows.md).

## Status legend

| Symbol | Meaning |
|---|---|
| ✅ | Verified by an executable check, concrete local config, or test. |
| 🟡 | Partial — implemented, with a documented deviation or not asserted on every surface. |
| ⏳ | Planned companion, not yet built (the ACR/LoA mechanism). See the SPEC step-up §. |

## §3 — Authentication Requirements Challenge (Resource Server → client)

| RFC § | Requirement | Status | Where / How |
|---|---|---|---|
| §3 | The protected resource signals step-up with an HTTP `401` carrying a `WWW-Authenticate: Bearer` challenge | ✅ | RS `ApiController#handleStepUpRequired` returns `401` for `POST /api/admin` when `now − auth_time > app.step-up.max-age` (or `auth_time` is absent). Asserted by `ApiSecurityTest#adminWithStaleAuthTimeChallengesForStepUp`. |
| §3 | The challenge uses the new error code `error="insufficient_user_authentication"` | ✅ | Emitted verbatim in the `WWW-Authenticate` header and echoed as `"error":"insufficient_user_authentication"` in the `application/problem+json` body. |
| §3 | Distinct from `insufficient_scope` — the token IS authorized; only its authentication recency is insufficient | ✅ | Scope/role failures remain a `403` `insufficient_scope` (Spring `AccessDeniedHandler`); step-up is a separate `401` path. The `ROLE_admin` check still runs first (`SecurityConfig`), so an unauthorized caller never reaches the step-up gate. |
| §3 | The challenge MAY include `max_age` indicating the maximum acceptable authentication age | ✅ | `max_age=<app.step-up.max-age in seconds>` is included in the challenge. |
| §3 | The challenge MAY include `error_description` | ✅ | `error_description="A more recent authentication is required"`. |
| §3 | The challenge MAY include `acr_values` indicating a required ACR | ⏳ | Not emitted — freshness is enforced via `auth_time`/`max_age`, not ACR/LoA (no LoA mapping in the realm). Planned companion (SPEC step-up §). |

## §4 — Client behavior on receiving the challenge

| RFC § | Requirement | Status | Where / How |
|---|---|---|---|
| §4 | On `insufficient_user_authentication`, the client makes a new authorization request that satisfies the stated requirement | 🟡 | The SPA (`auth.ts#callApi`) detects `insufficient_user_authentication` in `WWW-Authenticate` and performs a top-level navigation to `/auth/step-up` instead of a full `/auth/login`. The Auth Service forces a fresh re-authentication with **`prompt=login`** (OIDC Core §3.1.2.1) — a *superset* of the challenge's `max_age` (it always re-authenticates), so the resulting `auth_time` satisfies any advertised `max_age`. The client does not echo the challenge's `max_age` verbatim; the deviation is deliberate (`prompt=login` is portable; Keycloak treats `max_age=0` as unset). Asserted by `auth.test.ts` ("routes an RFC 9470 step-up challenge … to /auth/step-up") and live by `reference-flow.spec.ts` story 18. |
| §4 | The new tokens carry authentication information meeting the requirement | ✅ | The re-auth bumps `auth_time`; the rotated access token carries the fresh value, which the RS accepts on retry. The Auth Service callback additionally fails closed (`401`) unless the returned `auth_time` post-dates the step-up request. |

## §5 — Conveying authentication information via the access token

| RFC § | Requirement | Status | Where / How |
|---|---|---|---|
| §5 | `auth_time` is available to the resource server to evaluate `max_age` | ✅ | The realm carries an `auth_time` protocol mapper (`oidc-usersessionmodel-note-mapper`, `AUTH_TIME` → `auth_time`) on the Auth Service client, emitting `auth_time` in the **access token** (and ID token). The RS reads the standard claim — provider-agnostic. |
| §5 | `acr` is available to the resource server to evaluate `acr_values` | ⏳ | `acr` is surfaced into the session/`/auth/me` when the IdP emits it (`JwtOidcIdTokenValidator`) but is neither requested nor enforced — the ACR/LoA mechanism is the planned companion to the `auth_time` mechanism above (SPEC step-up §). |

## §6 / §7 — Security considerations & IANA

| RFC § | Requirement | Status | Where / How |
|---|---|---|---|
| §6 | Step-up must not weaken the surrounding flow | ✅ | `/auth/step-up` reuses the full login machinery — PKCE S256, `state`, `nonce`, and the `oauth_tx` browser-binding cookie — and the callback enforces `auth_time` freshness before minting a session. |
| §7 | Use the IANA-registered `insufficient_user_authentication` OAuth error code | ✅ | Used as the challenge error code, distinct from `insufficient_scope`. |

## Out of scope (companion ACR / LoA mechanism)

RFC 9470 supports two interchangeable requirement axes: authentication **recency**
(`max_age` / `auth_time`) and authentication **strength** (`acr_values` / `acr`).
This reference implements the recency axis end to end and defers the strength
axis, because ACR values are provider-specific and require Level-of-Authentication
configuration at the IdP (e.g., a Keycloak `acr-to-LoA` map plus an authentication
flow that steps the level up). Reconsider when a deployment needs MFA-strength
gating (e.g., "require `acr=mfa` before payment") rather than recency gating.
