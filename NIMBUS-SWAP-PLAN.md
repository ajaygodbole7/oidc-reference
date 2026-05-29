# Nimbus Swap — Implementation Plan

**Branch**: `feature/nimbus-portable-bff` (cut from `master` @ `d4efc59`)
**Companion doc**: `docs/architecture/nimbus-portable-bff.md` (research synthesis, already on master)
**Status**: branch created, no code changes yet.

This file is the executable plan for swapping the BFF's Spring Security OAuth client for Nimbus's `oauth2-oidc-sdk` + `nimbus-jose-jwt` direct, while keeping the controller flow shape unchanged.

---

## Why this is on a branch (not master)

Per `docs/architecture/nimbus-portable-bff.md` §"Recommendation": the current Spring Security 7.1 path on master was just hardened in the 2026-05-25 audit slice. Two parallel paths on master would confuse the reference audience. The branch proves the swap is mechanical and parks the implementation until a real Quarkus/Micronaut variant is being built.

---

## Order of operations (commit per slice)

### Slice 1 — Dependency + BffProperties record extension
Files:
- `bff/pom.xml` — add `com.nimbusds:oauth2-oidc-sdk:11.37.2`. **Keep** `spring-boot-starter-oauth2-client` for now (we'll drop in Slice 6 after the call sites are migrated, so the build stays green between commits).
- `bff/src/main/java/com/example/oidcreference/bff/BffProperties.java` — add:
  - `@NotNull URI issuerUri`
  - `@NotBlank String clientId`
  - `@NotBlank String clientSecret`
  - `@NotEmpty Set<String> scopes` (or `List<String>`)
- `bff/src/main/resources/application.yml` — add the `app.*` keys mapped to the new fields. **Keep** `spring.security.oauth2.client.*` until Slice 6.
- `bff/src/test/java/com/example/oidcreference/bff/RestClientResourceServerProxyTest.java` — update the `new BffProperties(...)` ctor call (one place).

Verify: `./mvnw test-compile`. No behavioral change yet; existing tests still pass.

### Slice 2 — `OidcProviderMetadata` record + discovery factory
New file: `bff/src/main/java/com/example/oidcreference/bff/OidcProviderMetadata.java`. ~35 LOC.

```java
record OidcProviderMetadata(
    String clientId, String clientSecret,
    URI authorizationEndpoint, URI tokenEndpoint, URI jwksUri,
    URI endSessionEndpoint, String issuer, Set<String> scopes) {

  static OidcProviderMetadata discover(BffProperties props) {
    try {
      var req = new OIDCProviderConfigurationRequest(new Issuer(props.issuerUri().toString()));
      var m = OIDCProviderMetadata.parse(req.toHTTPRequest().send().getBodyAsJSONObject());
      return new OidcProviderMetadata(
          props.clientId(), props.clientSecret(),
          m.getAuthorizationEndpointURI(),
          m.getTokenEndpointURI(),
          m.getJWKSetURI(),
          m.getEndSessionEndpointURI(),
          m.getIssuer().getValue(),
          props.scopes());
    } catch (Exception e) {
      throw new IllegalStateException("OIDC discovery failed at " + props.issuerUri(), e);
    }
  }
}
```

Wire as `@Bean` in `BffApplication` (or a new `@Configuration` class) that calls `OidcProviderMetadata.discover(props)` once at startup.

Verify: `./mvnw test`. Still 20 / 20 — this bean isn't consumed yet.

### Slice 3 — Rewrite `JwtOidcIdTokenValidator` against Nimbus directly
File: `bff/src/main/java/com/example/oidcreference/bff/JwtOidcIdTokenValidator.java` (~58 LOC → ~50 LOC).

Replace `OidcIdTokenDecoderFactory().createDecoder(registration)` with:

```java
JWKSource<SecurityContext> jwks = JWKSourceBuilder
    .create(md.jwksUri().toURL())
    .retrying(true)
    .rateLimited(60_000L)
    .refreshAheadCache(300_000L, true)
    .outageTolerant(900_000L)
    .build();
this.validator = new IDTokenValidator(
    new Issuer(md.issuer()),
    new ClientID(md.clientId()),
    JWSAlgorithm.RS256,
    jwks);
```

`validate()` becomes:
```java
JWTClaimsSet claims = validator.validate(JWTParser.parse(idToken), new Nonce(tx.nonce()));
return userClaims(claims);  // adapt from current code (jwt.getStringClaim → claims.getStringClaim)
```

Drop `ClientRegistrationRepository` from the constructor. Take `OidcProviderMetadata md` instead.

Verify: `./mvnw test`. BffFlowTest stubs `IdTokenValidator` via `@Primary`, so its tests stay green. Live e2e (Slice 7) will exercise this path.

### Slice 4 — Rewrite token exchange client against Nimbus
File: `bff/src/main/java/com/example/oidcreference/bff/AuthorizationCodeTokenExchangeClient.java` (~81 LOC → ~50 LOC). Code sketch in `docs/architecture/nimbus-portable-bff.md` §"Token exchange client".

Key points:
- Takes `OidcProviderMetadata md, IdTokenValidator v, HttpClient http`.
- Builds `AuthorizationCodeGrant(code, redirectUri, new CodeVerifier(tx.verifier()))`.
- Auth via `new ClientSecretBasic(new ClientID(md.clientId()), new Secret(md.clientSecret()))`.
- Parses with `OIDCTokenResponseParser.parse(req.toHTTPRequest().send(sender))`.
- ID token from `tokens.getIDTokenString()`.
- `refresh_expires_in` from `getCustomParameters()` (Keycloak-specific).

Drop `ClientRegistrationRepository` + `RestClientAuthorizationCodeTokenResponseClient` + `RestClient.Builder`.

Verify: `./mvnw test`. BffFlowTest stubs `TokenExchangeClient` so passes; this code only runs in the live gate.

### Slice 5 — Rewrite refresh client against Nimbus
File: `bff/src/main/java/com/example/oidcreference/bff/AuthorizationCodeTokenRefreshClient.java` (~78 LOC → ~45 LOC).

```java
var grant = new RefreshTokenGrant(new RefreshToken(session.refreshToken()));
var auth = new ClientSecretBasic(...);
var resp = OIDCTokenResponseParser.parse(new TokenRequest(md.tokenEndpoint(), auth, grant).toHTTPRequest().send(sender));
if (!resp.indicatesSuccess()) {
  var err = resp.toErrorResponse().getErrorObject();
  if (OAuth2Error.INVALID_GRANT.getCode().equals(err.getCode())) {
    throw new InvalidRefreshTokenException("refresh token rejected by authorization server");
  }
  throw new IllegalStateException("refresh failed: " + err);
}
```

### Slice 6 — Switch `AuthController` off `ClientRegistration`; drop Spring Security OAuth
- `AuthController.java`: replace `ClientRegistration registration` field with `OidcProviderMetadata md`. Update `redirectUri`, `logoutRedirect`, `beginLogin` to read off `md.authorizationEndpoint()`, `md.endSessionEndpoint()`, `md.scopes()`, `md.clientId()`.
- Logout URL: use Nimbus `LogoutRequest` builder.
- `HttpClients.java`: delete (Nimbus uses its own `HTTPRequest.send()`). Or shrink to provide a shared `JdkHttpClientSender` adapter.
- `bff/pom.xml`: drop `spring-boot-starter-oauth2-client`. Keep `spring-boot-starter-security` for the `SecurityFilterChain` no-op + headers.
- `bff/src/main/resources/application.yml`: drop the `spring.security.oauth2.client.*` block.
- `bff/src/test/java/com/example/oidcreference/bff/BffFlowTest.java`: drop the `spring.security.oauth2.client.*` properties from `@SpringBootTest`. The test still works because `TokenExchangeClient` / `IdTokenValidator` / `ResourceServerProxy` are still stubbed with `@Primary`. The `ClientRegistrationRepository` `@Primary` bean in `TestBeans` becomes unused — drop it.

Verify: `./mvnw test`. Must stay 20 / 20.

### Slice 7 — Live full-stack gate on the branch
```
pkill -9 -f 'spring-boot:run' 2>/dev/null
RESET_KEYCLOAK_REALM=1 ./scripts/verify-full-stack-auth.sh
```
Expected: realm + discovery + cross-service + 4/4 Playwright.

If green: branch is done. Don't merge.

If red: most likely failure modes (and where to look):
- `OIDC_ISSUER_URI` env var not picked up by `BffProperties` → wire mapping in `application.yml`.
- `JWKSourceBuilder` failing on Keycloak's certs URL → check the discovery doc points to `/protocol/openid-connect/certs`.
- `OAuth2Error.INVALID_GRANT.getCode()` vs `ErrorObject.getCode()` — verify the comparison string.
- Keycloak `client_secret_basic` vs `_post` — `ClientSecretBasic` defaults to Basic; the realm accepts both, so no change needed.

---

## What "done" looks like

- `./mvnw -q test` on BFF: 20 / 20 ✅
- `./mvnw -q test` on RS: 12 / 12 ✅ (untouched by this swap)
- `npm run verify` on frontend: ✅ (untouched)
- `RESET_KEYCLOAK_REALM=1 ./scripts/verify-full-stack-auth.sh`: realm + discovery + cross-service + 4/4 Playwright ✅
- `spring-boot-starter-oauth2-client` no longer in `bff/pom.xml`
- No `org.springframework.security.oauth2.*` imports in `bff/src/main/java/com/example/oidcreference/bff/`
- Branch HEAD has a `SESSION-CHANGELOG-NIMBUS-*.md` summarizing the swap

The branch lives until a real `bff-quarkus/` (or equivalent) variant is added, at which point it becomes the portable reference.

---

## Out of scope on this branch

- Replacing `spring-boot-starter-security` itself (the no-op `SecurityFilterChain` is fine; replacement would be a 20-line `DefaultHeadersFilter` — separate slice).
- Replacing Spring `RestClient` in `RestClientResourceServerProxy` (the `/api/**` proxy). It's Spring-Framework, not Spring-Security, and is straightforward to swap to `java.net.http.HttpClient` later if total framework neutrality is desired.
- `BadCredentialsException` → custom exception type. Soft dep; can stay until a real lift to Quarkus where `spring-security-core` would also be dropped.
- Resource server. Untouched.
