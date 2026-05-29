# TASK-0009b: Resource Server JWT decoder negative-path tests

## Objective

Close the HIGH audit gap on the Resource Server: prove the production
`JwtDecoder` rejects HS256, `alg=none`, wrong-iss, wrong-aud,
missing-aud, expired, nbf-in-future, kid-not-in-JWKS, and
wrong-key-but-claimed-kid tokens. `ApiSecurityTest` `@MockitoBean`s the
decoder, so today the JWS-level guarantees from `SecurityConfig` have
zero proof.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `backend-resource-server/src/main/java/com/example/oidcreference/SecurityConfig.java`
- `backend-resource-server/src/main/resources/application.yml`
- `backend-resource-server/src/test/java/com/example/oidcreference/ApiSecurityTest.java`

## Owned Paths

- `backend-resource-server/src/main/java/com/example/oidcreference/SecurityConfig.java`
  (minimal refactor: extract validator chain into a package-private
  static helper so prod and tests share the same chain)
- `backend-resource-server/src/test/java/com/example/oidcreference/JwtDecoderNegativeTest.java`
  (new — 10 negative-path tests against a real `NimbusJwtDecoder`)

## Avoid Paths

- `backend-resource-server/src/test/java/com/example/oidcreference/ApiSecurityTest.java`
- `backend-resource-server/src/test/java/com/example/oidcreference/JwtAuthenticationConverterTest.java`
- `backend-resource-server/pom.xml`
- `backend-resource-server/src/main/java/com/example/oidcreference/ApiController.java`
- All other modules, scripts, and docs.

## Required Workflow

Before coding, record:

- Assumptions:
  - Nimbus + Spring Security 7.x are already on the classpath via
    `spring-boot-starter-oauth2-resource-server`. No `pom.xml` edits
    needed (audit specifically forbade them).
  - The extracted helper must produce a byte-for-byte equivalent
    validator chain to the inline construction it replaces
    (`createDefaultWithIssuer` + `JwtClaimValidator` on `aud`).
  - Building one `NimbusJwtDecoder.withJwkSource(...)` against an
    in-memory `JWKSet` preserves the kid-resolution path, so both
    kid-not-in-JWKS and wrong-key-but-claimed-kid are testable from a
    single decoder.
  - `alg=none` is delivered as a `PlainJWT`; `NimbusJwtDecoder` refuses
    to treat that as a signed JWT and surfaces `JwtException`.
  - HS256 alg-confusion is rejected by the RS256 allowlist
    (`.jwsAlgorithm(SignatureAlgorithm.RS256)`), not by validators.
- Ambiguities:
  - None material. The Boot 4 / Spring Security 7.1.0-RC1 `NimbusJwtDecoder`
    API supports both `withJwkSource(JWKSource<SecurityContext>)` and
    `withPublicKey(...)`. We chose `withJwkSource` to keep the kid
    path live.
- Owned paths: see above.
- Success criteria: see Done Criteria.

Plan:

```text
1. Read SecurityConfig + application.yml + ApiSecurityTest to confirm
   issuer/audience config and current decoder construction
   -> verify: extracted helper produces same chain as before.
2. Refactor SecurityConfig: add static jwtValidator(issuerUri,
   audience); call it from jwtDecoder(); keep Jwt import explicit
   -> verify: file compiles in isolation (no behavioral change).
3. Create JwtDecoderNegativeTest with the 10 required tests; share one
   NimbusJwtDecoder via @BeforeAll; sign with RSAKeyGenerator
   -> verify: each test asserts JwtException via assertThatThrownBy.
4. Do not run tests in this session (out of scope per the request).
```

## Done Criteria

- `SecurityConfig.jwtValidator(String, String)` exists, is
  package-private, and is the single source of the prod validator
  chain.
- `JwtDecoderNegativeTest` exists with all 10 named tests:
  `validTokenDecodes`, `algNoneIsRejected`, `algConfusionHs256IsRejected`,
  `wrongIssuerIsRejected`, `wrongAudienceIsRejected`,
  `missingAudienceIsRejected`, `expiredIsRejected`, `nbfInFutureIsRejected`,
  `kidNotInJwkSetIsRejected`, `signatureFromUnknownKeyIsRejected`.
- Each negative test asserts `JwtException` via AssertJ
  `assertThatThrownBy`.
- No edits outside the two owned paths.

## Final Report

_Status_: ✅ Done.

### Tests run

- `cd backend-resource-server && ./mvnw test -Dtest=JwtDecoderNegativeTest` →
  10 / 10 ✅
- `cd backend-resource-server && ./mvnw test` (full suite) → 24 / 24 ✅
  (was 14; +10).

### Result

All ten cases passed: happy path, alg=none, HS256 confusion,
wrong-iss, wrong-aud, missing-aud, expired, nbf in future, kid not
in JWKS, signature from unknown key. The RS's algorithm allowlist,
audience validator, issuer validator, and default timestamp
validator (with its 60s clock-skew tolerance for nbf — see below)
are all proven live.

One follow-up adjustment: the initial nbf test set `nbf = now + 60s`
which sits at the edge of Spring's default `JwtTimestampValidator`
clock-skew tolerance and passed validation. Bumped to `nbf = now + 600s`
(token also exp at +1200s) so the test exercises the not-before
rejection path itself, not the tolerance boundary. The clock-skew
note is now in the test comment so future maintainers don't
re-trip it.

### Risks / follow-ups

- The validator helper `SecurityConfig.jwtValidator(issuer, audience)`
  is package-private. If a future change adds (e.g.) a `typ` header
  validator or an `azp` claim validator to the chain, BOTH the
  production decoder and this test must consume it via the same
  helper. The test directly references this helper to guarantee that
  drift.
