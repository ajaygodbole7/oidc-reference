# Framework-portable BFF — Nimbus alternative

**Status**: research / design sketch
**Date**: 2026-05-25
**Companion branch**: `feature/nimbus-portable-bff` (implementation; do not merge until a Quarkus/Micronaut variant is being actively built)

## Why this doc exists

The BFF on `master` uses `spring-boot-starter-oauth2-client` (Spring Security 7.1) for its OAuth/OIDC machinery. That works, is RFC-correct, and was hardened in the audit slice that landed on 2026-05-25 (`SESSION-CHANGELOG-2026-05-25-1137.md`).

But: the repo's stated goal is to be a **reference** that someone can lift into Quarkus, Micronaut, Helidon, Vert.x, or plain servlets without re-deriving the OAuth flow. `spring-security-oauth2-client` is hard-coupled to Spring — types like `ClientRegistration`, `OAuth2AuthorizationExchange`, and `RestClientAuthorizationCodeTokenResponseClient` cannot leave Spring.

This document captures the result of a three-agent research pass into whether the OAuth/OIDC helper layer **could** be made framework-portable, and what that would look like. The companion branch `feature/nimbus-portable-bff` proves the swap is mechanical.

---

## TL;DR

**Drop `spring-boot-starter-oauth2-client`. Adopt `com.nimbusds:oauth2-oidc-sdk` + `com.nimbusds:nimbus-jose-jwt` directly.**

- Both are already on the classpath as transitive dependencies of Spring Security.
- The OAuth/OIDC helper layer goes from ~263 LOC (Spring-wrapped Nimbus) to ~180 LOC (Nimbus direct). ~12% net shrink.
- Controller flow shape (`AuthController.beginLogin` / `callback` / `logout`) is unchanged — only the helpers underneath move.
- The same helper code drops into Quarkus / Micronaut / Helidon with only the DI annotations and HTTP request type changing.
- Correctness is at parity or better: `JWKSourceBuilder` has more sophisticated JWKS rotation handling than Spring's `NimbusJwtDecoder` wrapper.

---

## Library survey

### OAuth2 client layer

| Library | Verdict | Why |
|---|---|---|
| **Nimbus `oauth2-oidc-sdk` 11.37.2** | ✅ winner | Already transitive. Pure POJO. Spec-broadest in JVM (OAuth 2.1 draft, OIDC, RP-logout, PKCE, JARM, DPoP, mTLS, FAPI, PAR, CIBA). Spring Security, pac4j, Micronaut, MSAL4J all delegate to it under the hood. |
| pac4j 6.x (`pac4j-oidc`) | ❌ | **Misadvertised as framework-agnostic** — `pac4j-oidc/pom.xml` declares hard compile-time deps on `org.springframework:spring-core` and `com.google.guava:guava`. Auth model is built around `WebContext` / `SessionStore` / `UserProfile` abstractions that would fight a hand-rolled BFF. CVE-2026-29000 landed March 2026. |
| Google `google-oauth-client` 1.39.x | ❌ | Maintenance mode. No first-class OIDC ID-token validator outside Google issuers. |
| Authlete Java SDKs | ❌ | Wrong category — these are AS-side SDKs for *building* an authorization server. |
| Quarkus `quarkus-oidc-client` | ❌ | Hard Quarkus + CDI + Vert.x. That's the framework we're trying to be portable across. |
| Micronaut Security OAuth2 | ❌ | Hard Micronaut DI + filters. Same problem. |
| MicroProfile JWT-Auth | ❌ | Wrong layer — resource-server-side JWT validation, not OAuth client flow. |
| Apache Oltu | ❌ | Apache Attic since 2018. No PKCE, no OIDC Core. |
| Spring Security 7.1 OAuth2 Client (current) | baseline | Wraps Nimbus internally. Couples to Spring. |

### JWT / JOSE layer

| Library | Verdict | Why |
|---|---|---|
| **Nimbus `nimbus-jose-jwt` 10.6** | ✅ winner | Already transitive. Most spec-complete (JWS/JWE/JWK/JWA/RFC 7638/8725). `JWKSourceBuilder` is uniquely sophisticated: refresh-ahead caching, rate limiting, retry, outage tolerance, force-refresh on unknown `kid`. Spring Security, Keycloak, AWS Cognito SDK, Hashicorp Vault all wrap it. |
| jose4j | secondary | Conservative, smaller community, slower release cadence. Used inside Quarkus/SmallRye. BouncyCastle native-image pain is the historic friction point. |
| jjwt (`io.jsonwebtoken:jjwt-*`) | secondary | Cleanest fluent API but narrower spec coverage (JWE only landed in 0.13). No built-in remote JWKS source. |
| Auth0 `java-jwt` | ❌ | Not a JOSE library — JWE and full JWK out of scope. `jwks-rsa-java` cache capped at 5 keys. |
| Google Tink JWT | ❌ | Refuses JWE entirely, forces Tink keyset model — conceptual mismatch with OIDC's JWKS convention. |
| smallrye-jwt | ❌ | Wrong layer — Jakarta/CDI MP-JWT runtime that internally uses jose4j. |

---

## What the swap looks like

### `pom.xml` delta

```xml
<!-- DROP -->
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>

<!-- ADD -->
<dependency>
  <groupId>com.nimbusds</groupId>
  <artifactId>oauth2-oidc-sdk</artifactId>
  <version>11.37.2</version>
</dependency>
```

`spring-boot-starter-security` stays for the no-op SecurityFilterChain (STATELESS + default headers + the deny-all guard for unknown paths). Removing that too is possible but means replacing those defaults with a 20-LOC `DefaultHeadersFilter` — out of scope for the first swap.

### LOC delta per file

| file | before | after | delta |
|---|---|---|---|
| `AuthorizationCodeTokenExchangeClient.java` | 81 | ~50 | -31 |
| `AuthorizationCodeTokenRefreshClient.java` | 78 | ~45 | -33 |
| `JwtOidcIdTokenValidator.java` | 59 | ~50 | -9 |
| `HttpClients.java` | 43 | 0 (deleted; Nimbus uses its own `HTTPRequest.send`) | -43 |
| `SecurityConfig.java` | 30 | ~20 (or kept as is) | -10 |
| `OidcProviderMetadata.java` | 0 | ~35 (new) | +35 |
| `BffProperties.java` | 36 | ~40 | +4 |
| `AuthController.java` | 329 | ~330 (Nimbus builders slightly more verbose than `UriComponentsBuilder` for the authorize URI) | +1 |
| **net Java LOC** | 656 | ~575 | **-81 (~12% shrink)** |

### Sample of the new code

**Token exchange client** (~50 LOC, framework-free):

```java
final class NimbusTokenExchangeClient implements TokenExchangeClient {
  private final OidcProviderMetadata md;
  private final IdTokenValidator idTokenValidator;
  private final HTTPRequestSender httpSender;

  @Override
  public SessionRecord exchange(String code, String state, String redirectUri, OAuthTransaction tx) {
    var grant = new AuthorizationCodeGrant(
        new AuthorizationCode(code), URI.create(redirectUri), new CodeVerifier(tx.verifier()));
    var auth = new ClientSecretBasic(new ClientID(md.clientId()), new Secret(md.clientSecret()));
    var req = new TokenRequest.Builder(md.tokenEndpoint(), auth, grant).build();
    var resp = OIDCTokenResponseParser.parse(req.toHTTPRequest().send(httpSender));
    if (!resp.indicatesSuccess()) {
      throw new IllegalStateException("token endpoint: " + resp.toErrorResponse().getErrorObject());
    }
    var tokens = ((OIDCTokenResponse) resp).getOIDCTokens();
    // ... build SessionRecord from tokens + idTokenValidator.validate(idToken, tx)
  }
}
```

**ID-token validator** (~50 LOC, full OIDC Core §3.1.3.7):

```java
JWKSource<SecurityContext> jwks = JWKSourceBuilder
    .create(md.jwksUri().toURL())
    .retrying(true)
    .rateLimited(60_000L)
    .refreshAheadCache(300_000L, true)
    .outageTolerant(900_000L)
    .build();
this.validator = new IDTokenValidator(
    new Issuer(md.issuer()), new ClientID(md.clientId()), JWSAlgorithm.RS256, jwks);

// per request:
JWTClaimsSet claims = validator.validate(JWTParser.parse(idToken), new Nonce(tx.nonce()));
```

`IDTokenValidator.validate(jwt, nonce)` is **atomic** — does sig + iss + aud + azp + exp + iat + nonce in one call. Same coverage as Spring's `OidcIdTokenValidator` in roughly half the code.

---

## Correctness deltas

| Capability | Spring (current) | Nimbus (proposed) |
|---|---|---|
| `expires_in` as string OR number | ✅ via `OAuth2AccessTokenResponseHttpMessageConverter` | ✅ via `AccessToken.getLifetime()` |
| `client_secret_basic` vs `_post` dispatch | ✅ from `ClientRegistration.getClientAuthenticationMethod()` | ✅ via `ClientAuthentication` subclass selection |
| Multi-aud `azp` rule (OIDC §3.1.3.7) | ✅ | ✅ (built into `IDTokenValidator`) |
| Single-aud `azp` when present | ✅ | ✅ |
| `iat` recency + `auth_time` vs `max_age` | ✅ | ✅ |
| Narrow `scope` on refresh | ✅ | ✅ |
| JWKS rotation on unknown `kid` | basic | **better** — `JWKSourceBuilder` force-refreshes |
| JWKS outage tolerance | none | up to 15 min stale-serve via `outageTolerant(...)` |
| RP-Initiated Logout `client_id` + `state` | manual (we hand-build) | `LogoutRequest` builder |

---

## What we lose

| Capability lost | Impact | Replacement |
|---|---|---|
| Spring Boot auto-config of `ClientRegistration` from `spring.security.oauth2.client.*` | medium | New `OidcProviderMetadata` record + `.discover()` factory using `OIDCProviderConfigurationRequest` at startup (~30 LOC) |
| `OAuth2AuthorizationException.getError().getErrorCode()` taxonomy | low | Nimbus exposes `ErrorObject` with the same RFC 6749 codes; our `InvalidRefreshTokenException` mapping shrinks to a 3-line `if` |
| `OAuth2AuthorizedClientManager` / `OAuth2AuthorizedClientService` | none | We never used them — the BFF stores tokens in Valkey, not in Spring's client store |
| `OidcUserService` / `SecurityContextHolder` integration | none | We never used them — the BFF uses cookie sessions, not the Spring security context |
| Future Spring Security CVE patches | small but real | Nimbus has its own CVE channel and ships patches faster than Spring usually adopts them |
| `BadCredentialsException` type | trivial (soft dep) | Replace with project-specific `IdTokenValidationException` |

Net: nothing security-relevant is lost. The architecture-decision explicitness goes UP — OIDC Core §3.1.3.7 logic becomes visible code rather than buried framework behavior, which is appropriate for a reference repo.

---

## Portability check

The Nimbus helper classes (`NimbusTokenExchangeClient`, `NimbusTokenRefreshClient`, `NimbusJwtOidcIdTokenValidator`, `OidcProviderMetadata`) have **zero framework imports** beyond `java.*`, `com.nimbusds.*`, and `jakarta.validation.*`. They lift as-is.

| Target | Effort to port the OAuth layer | What changes |
|---|---|---|
| **Quarkus 3** | ~2 hours mechanical | DI annotations (`@Component` → `@ApplicationScoped`), `@ConfigurationProperties` → `@ConfigMapping`, controller annotations → JAX-RS. OAuth/OIDC code unchanged. |
| **Micronaut 4** | comparable | DI + controller annotations + `HttpRequest` type. OAuth/OIDC code unchanged. |
| **Helidon Nima 4** | highest (manual routing) | Programmatic `HttpRouting` + no DI by default. OAuth/OIDC code unchanged. |
| **Plain Vert.x / servlets** | medium | JAX-RS or raw servlet handlers. OAuth/OIDC code unchanged. |

**Critical caveat**: do NOT pull `quarkus-oidc-client` / `micronaut-security-oauth2` in those ports — they'd re-introduce the framework-owned filter chain we're paying to avoid.

---

## Recommendation

**GO conditionally — keep this as a documentation deliverable + branch artifact for now.**

Rationale:
- The current Spring Security 7.1 path was just hardened (closed ~30 audit findings on 2026-05-25). Re-doing this work on `master` risks regressing things that were just stabilized.
- The repo is a **reference**. Its value is in showing one canonical way clearly. Two parallel paths (Spring Security + Nimbus) on `master` would confuse the audience.
- Quarkus / Micronaut / Helidon ports aren't on the GOAL list — the four directories the repo ships today are Spring Boot, Keycloak, React, Valkey.
- But the **architectural property** — that the OAuth/OIDC code path could be lifted to any host framework with mechanical work — is exactly what a reference is supposed to demonstrate. Documenting it (this file + a green feature branch) achieves that without forking the production path.

Concrete plan:
1. This document lives on `master`.
2. `feature/nimbus-portable-bff` carries the implementation. The 4/4 Playwright e2e gate is green on the branch. The branch is **not merged**.
3. If a real Quarkus reference variant is ever added (new `bff-quarkus/` directory), copy from that branch and ship both side-by-side with a README explaining the portable layer.
4. Until then, the current Spring Security 7.1 BFF is the production path.

---

## Risk register

| risk | severity | mitigation |
|---|---|---|
| Discovery (`OIDCProviderConfigurationRequest`) must succeed at startup before any login works | medium | Fail-fast in `OidcProviderMetadata.discover()`; cache discovery JSON to disk for offline dev |
| Nimbus `IDTokenValidator` defaults to RS256 only; Azure AD ships PS256 in some tenants | low | Read `id_token_signing_alg_values_supported` from discovery; pick highest-pref RS*/PS*/ES*; fall back to RS256 |
| `JWKSourceBuilder` cache defaults differ from Spring's `NimbusJwtDecoder` defaults | low | Document; expose via `BffProperties.jwksCacheTtl` if needed |
| `HTTPRequest.send()` uses a new `HttpClient` per call by default (no pooling) | low | Provide a shared `JdkHttpClientSender` adapter (~15 LOC) reusing one `HttpClient` |
| `BadCredentialsException` removal breaks any tests catching it | low | Grep + replace with `IdTokenValidationException` |
| 4/4 Playwright gate must stay green through the swap | high | Branch-only; full live-stack gate runs on the branch before any merge discussion |

---

## See also

- `SESSION-CHANGELOG-2026-05-25-1137.md` — the Spring Security 7.1 audit slice this swap would replace.
- `docs/specs/SPEC-0001-core-oidc-flows.md` — the build contract that controllers own end-to-end. Both Spring and Nimbus paths satisfy it.
- `CLAUDE.md` — the operating contract that says "controllers own the spec, not the framework." Both paths honor it; the Nimbus path honors it more literally.
