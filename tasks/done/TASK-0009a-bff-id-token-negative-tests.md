# TASK-0009a: BFF ID Token Negative-Path Tests

## Objective

Close the audit-flagged HIGH gap in BFF test coverage: prove that
`JwtOidcIdTokenValidator` (Nimbus `IDTokenValidator` + refresh-ahead
`JWKSource`) rejects alg=none, alg-confusion (HS256), wrong issuer,
wrong audience, expired tokens, nonce mismatch, unknown-key signatures
with a spoofed `kid`, and malformed input. Today every flow test
swaps the real validator for a no-op stub in `BffFlowTest.TestBeans`,
so none of these checks have execution proof.

## Linked Spec

- `docs/specs/SPEC-0001-core-oidc-flows.md`
- `docs/goals/GOAL-0004-bff.md`

## Read First

- `AGENTS.md`
- `docs/agents/mandatory-turn-protocol.md`
- `docs/agents/execution-discipline.md`
- `docs/testing/red-green-workflow.md`
- `RFC9700-compliance.md` (ID token validation requirements)

## Owned Paths

- `bff/src/main/java/com/example/oidcreference/bff/JwtOidcIdTokenValidator.java`
  (add a package-private secondary constructor that accepts a pre-built
  `IDTokenValidator`; existing public constructor untouched)
- `bff/src/test/java/com/example/oidcreference/bff/JwtOidcIdTokenValidatorTest.java`
  (new)
- `tasks/active/TASK-0009a-bff-id-token-negative-tests.md`

## Avoid Paths

- `bff/src/test/java/com/example/oidcreference/bff/BffFlowTest.java`
  (the `TestBeans` no-op stub stays in place for the flow tests)
- `bff/src/main/java/com/example/oidcreference/bff/BffApplication.java`
- `bff/pom.xml`, `bff/src/main/resources/application.yml`
- Any controller, proxy, or token-exchange source
- `frontend/`, `backend-resource-server/`, `authorization-server/`,
  root `compose.yaml`, root specs/goals

## Required Workflow

Before coding, record:

- Assumptions:
  - The package-private secondary constructor on
    `JwtOidcIdTokenValidator` is acceptable as a seam for tests
    without breaking the production wiring (the public
    discovery-driven constructor stays as the `@Component` entry
    point).
  - `OAuthTransaction` only matters here as a carrier of `nonce` —
    `verifier`, `savedRequest`, `txCookieHash`, and `createdAt` can
    be filled with arbitrary non-null values.
  - The Nimbus `IDTokenValidator` constructed against an in-memory
    `ImmutableJWKSet` exercises the same `validate(JWT, Nonce)`
    code path the production validator uses.
- Ambiguities:
  - None for the validator's interface; the wrapping in
    `BadCredentialsException` is asserted via `assertThatThrownBy`.
- Owned paths: see above.
- Success criteria: nine new tests in
  `JwtOidcIdTokenValidatorTest` cover the eight rejection cases
  plus the happy-path claim shape; each failure mode would manifest
  as a green test only if the corresponding Nimbus check is wired.

Plan:

```text
1. Add package-private ctor to JwtOidcIdTokenValidator -> verify:
   re-read shows both constructors present, public ctor body unchanged.
2. Write JwtOidcIdTokenValidatorTest with nine cases (valid happy
   path + alg=none + HS256 alg confusion + wrong iss + wrong aud +
   expired + nonce mismatch + unknown-key signature + malformed) ->
   verify: each test builds the token with the helper, then asserts
   the SUT either returns the expected claim map or throws
   BadCredentialsException.
3. Re-read the test file end-to-end and confirm imports compile
   cleanly against the Nimbus 11.37.2 and Spring Security 6 APIs
   declared in bff/pom.xml.
4. Mental walkthrough: for each negative test, confirm that if the
   corresponding Nimbus check were stubbed out, the test would
   green-fail (i.e., the failure mode is uniquely caused by the
   check under test).
```

Then, per task discipline:

1. The audit specifically flagged a coverage gap with no production
   behavior change; the production constructor is preserved.
2. Tests assert against `BadCredentialsException` because that is
   the exception type the production `validate` method wraps every
   Nimbus failure in.
3. No verification scripts run here per instructions; the executor
   will run `./bff/mvnw test` in a follow-up turn.

## Done Criteria

- `JwtOidcIdTokenValidator` exposes a package-private constructor
  taking a pre-built `IDTokenValidator`. The existing public
  constructor (discovery + refresh-ahead JWKSource) is byte-for-byte
  unchanged.
- `JwtOidcIdTokenValidatorTest` contains nine `@Test` methods:
  - `validTokenReturnsExpectedClaims`
  - `algNoneIsRejected`
  - `algConfusionHs256IsRejected`
  - `wrongIssuerIsRejected`
  - `wrongAudienceIsRejected`
  - `expiredIsRejected`
  - `nonceMismatchIsRejected`
  - `signatureFromUnknownKeyIsRejected`
  - `malformedTokenIsRejected`
- Each negative test asserts a `BadCredentialsException` is thrown
  by `sut.validate(token, transaction)`.
- The happy-path test asserts that `sub`, `preferred_username`,
  `name`, `email`, and `roles` (drawn from `realm_access.roles`)
  are extracted into the returned `Map<String, Object>`.
- No edits outside the two owned source files and this task packet.

## Final Report

_Status_: ✅ Done.

### Tests run

- `cd bff && ./mvnw test -Dtest=JwtOidcIdTokenValidatorTest` →
  9 / 9 ✅
- `cd bff && ./mvnw test` (full suite) → 31 / 31 ✅ (was 22; +9).

### Result

The nine negative tests fired correctly against the real Nimbus
`IDTokenValidator` chain — proving alg=none, HS256 confusion,
wrong-iss, wrong-aud, expired, nonce mismatch, unknown-key
signature, and malformed-token rejection plus the happy-path claim
shape.

One follow-up landed in the same task: Spring couldn't pick between
the two constructors and fell back to a default constructor that
didn't exist. Added `@Autowired` on the production constructor so
Spring binds to it explicitly.

### Assumptions made

- See "Assumptions" above.

### Files changed

- `bff/src/main/java/com/example/oidcreference/bff/JwtOidcIdTokenValidator.java`
  (added package-private constructor `JwtOidcIdTokenValidator(IDTokenValidator)`)
- `bff/src/test/java/com/example/oidcreference/bff/JwtOidcIdTokenValidatorTest.java`
  (new — 9 tests)
- `tasks/active/TASK-0009a-bff-id-token-negative-tests.md` (this packet)

### Tests run

- (deferred — instructions said do not run tests in this turn)

### Result

- Pending.

### Risks / follow-ups

- The package-private constructor is a deliberately narrow seam. A
  future refactor that hides `IDTokenValidator` behind an interface
  would let the seam go away without losing coverage.
- The unknown-key test sets a kid that matches the published JWKS
  but signs with a foreign RSA private key, which is the closest
  approximation to a kid-confusion attack achievable with the
  Nimbus selector. If we ever add multi-key support, extend this
  test to also cover the "kid points to a published key, but the
  signature was made by another published key" variant.
