# Session changelog — Nimbus swap

**Date**: 2026-05-25
**Branch**: `feature/nimbus-portable-bff` (HEAD: see `git log --oneline -5`)
**Status**: ✅ All slices landed. Branch parked per the original instruction — do NOT merge to `master`.

---

## What changed

The BFF's OAuth 2.1 / OIDC client implementation was swapped from
Spring Security 7.1's `oauth2-client` starter onto the Nimbus
`oauth2-oidc-sdk` directly, while keeping the controller flow shape
unchanged (per CLAUDE.md: the controllers own the spec, not Spring).

### Slice-by-slice commits

| Slice | Commit | What |
| --- | --- | --- |
| 1 | `64e7510` | Add `com.nimbusds:oauth2-oidc-sdk` dep + extend `BffProperties` with `issuerUri`, `clientId`, `clientSecret`, `scopes`. |
| 2 | `8411358` | New `OidcProviderMetadata` record + `discover(BffProperties)` factory using Nimbus `OIDCProviderConfigurationRequest`. Bean wiring deferred to Slice 6. |
| 3-6 | `b9fb582` | One bundled commit (BFF only compiles end-to-end once every consumer has moved off `ClientRegistration`): `JwtOidcIdTokenValidator` on Nimbus `IDTokenValidator` + `JWKSourceBuilder`; `AuthorizationCodeTokenExchangeClient` on Nimbus `TokenRequest` + `AuthorizationCodeGrant` + `OIDCTokenResponseParser`; `AuthorizationCodeTokenRefreshClient` on Nimbus `RefreshTokenGrant`; `AuthController` swapped off `ClientRegistration` onto `OidcProviderMetadata`; `spring-boot-starter-oauth2-client` dropped from pom; `spring.security.oauth2.client.*` block dropped from `application.yml` and `BffFlowTest`; `HttpClients` shrunk (kept `RestClient.Builder` with timeouts for the proxy, dropped the `OAuth2AccessTokenResponseHttpMessageConverter`). |

Slices 3, 4, and 5 were authored in parallel by three subagents (one
file each). Slice 6 was authored centrally because it touched files
multiple slices needed to converge on (`AuthController`, pom, yaml,
test). All slices landed inside a single end-to-end test cycle, on
the user's explicit instruction to skip per-slice gates.

### Two fixes the agents didn't catch (caught at the final test cycle)

1. **`IDTokenValidator(Issuer, ClientID, JWSAlgorithm, JWKSource)`** is not a real Nimbus constructor — there's a `(…, JWSAlgorithm, JWKSet)` and a `(…, JWSKeySelector, JWEKeySelector)` overload. Wrapped the `JWKSource<SecurityContext>` in `JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwks)` and used the `(Issuer, ClientID, JWSKeySelector, null)` constructor.
2. **`validator.validate(jwt, nonce)`** returns `IDTokenClaimsSet`, not `JWTClaimsSet`. Updated the userClaims helper signature and used `claims.getSubject().getValue()` (Subject is the typed wrapper, not a String).

### One Nimbus invariant worth knowing

`JWKSourceBuilder` enforces:

> cache time-to-live > refresh-ahead time + cache refresh timeout

If you call only `.refreshAheadCache(300_000L, true)` without also
calling `.cache(ttl, refreshTimeout)`, the cache TTL defaults to the
refresh-ahead time and the invariant fails at startup with:

```
The sum of the refresh-ahead time (300000ms) and the cache refresh
timeout (15000ms) must not exceed the time-to-lived time (300000ms)
```

Fix: explicitly set `.cache(600_000L, 15_000L)` before the
`.refreshAheadCache(300_000L, true)` call. (BFF currently runs with
TTL=10min, refresh-ahead=5min, refresh-timeout=15s.)

---

## Final verification

```
cd bff && ./mvnw test
→ 21 / 21 passing
  RestClientResourceServerProxyTest  1 / 1
  BffFlowTest                       17 / 17
  SecurityConfigTest                 3 / 3

RESET_KEYCLOAK_REALM=1 ./scripts/verify-full-stack-auth.sh
→ realm static checks passed
  discovery checks passed
  real-token claim checks passed (aud, scope)
  cross-service contract checks passed
  Playwright e2e: 4 / 4 passed (10.8s)
  full-stack auth verification passed
```

`grep -rn "org.springframework.security.oauth2" bff/src/main/java
bff/src/test/java` is empty. `spring-boot-starter-oauth2-client` is
not in `bff/pom.xml`. `spring-boot-starter-security` stays
(`SecurityFilterChain` + headers).

---

## What did not change

- `backend-resource-server/` — untouched. Still on Spring Security
  JWT resource-server filters.
- `frontend/` — untouched.
- `authorization-server/` — untouched (same Keycloak realm).
- Controllers' wire shape — the authorize URL and end-session URL
  are still hand-built with `UriComponentsBuilder.encode()` because
  the spec / RFC define the request shape, not Spring or Nimbus
  helpers. We just read from `OidcProviderMetadata` now instead of
  `ClientRegistration.getProviderDetails()`.
- The `tx:{state}` + `sess:{sid}` Valkey-backed `StateStore` design
  is unchanged.

---

## Do not merge

This branch is the durable "Nimbus / Quarkus-ready" reference. It is
parked here until a real `bff-quarkus/` (or equivalent) variant is
added, at which point this branch becomes the portable comparison
baseline alongside `master`'s Spring path.
