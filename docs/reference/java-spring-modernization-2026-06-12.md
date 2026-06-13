# Java 25 / Spring Boot 4 modernization backlog — 2026-06-12

Internal backlog from a Java 25 (LTS) + Spring Boot 4 (Spring Framework 7) idiom
review. Not a public-facing doc.

**Verdict:** the codebase is strongly idiomatic. The findings are consistency
drift in the `backend-resource-server` module, not modernization debt. None is a
bug. Each item below cites the code it refers to.

**Standing rule:** every code change here triggers the full live e2e battery
before commit.

## High-leverage

### H1 — Resource server hand-builds problem+json; auth-service uses `ProblemDetail`

- `backend-resource-server/.../ApiController.java:169-176` (`handleStepUpRequired`)
  returns `ResponseEntity<String>` with a hand-built JSON body that hardcodes
  `"title":"Unauthorized"` and `"status":401` as string literals.
- `backend-resource-server/.../SecurityConfig.java:218-233` (`writeProblem`)
  writes raw JSON with a hand-rolled `escapeJson()`.
- The auth-service already uses `ProblemDetail` (`AuthController.callbackError`,
  `InternalResolveController.problem`) — the idiomatic pattern is proven next door.
- Change: build `ProblemDetail` and serialize via the injected `ObjectMapper`;
  drop `escapeJson`. `ProblemDetail.forStatus(401)` also removes the hardcoded
  status literal that can drift.
- Trade-off: the `WWW-Authenticate` challenge string (RFC 6750 / RFC 9470) is the
  load-bearing security control and must stay byte-controlled — change only the
  body, keep the header set explicitly.

### H2 — Resource server uses scattered `@Value`; auth-service has the record model

- `backend-resource-server/.../ApiController.java:47-67` injects four `@Value`s
  (`app.service-client-ids`, `app.jobs-client-id`, `app.step-up.max-age`,
  `app.step-up.required-acr`) plus a constructor cross-field invariant check.
- `backend-resource-server/.../SecurityConfig.java:88-91,138-140` injects more
  `app.*` `@Value`s. The RS module has no `@ConfigurationProperties` type.
- The auth-service has an exemplary `@Validated` record `AuthProperties`.
- Change: add a `@Validated` record `AppProperties` mirroring `AuthProperties`
  (nested typed `step-up` block; cross-field check in the compact constructor).
  Gives fail-fast validation at boot instead of a bean-construction exception.
- Note: the blank-strip normalization now in `ApiController` moves into the record.
- Leave `spring.security.oauth2.*` `@Value`s in `SecurityConfig` as-is — they are
  framework keys, not `app.*`.

## Worth doing

### W2 — No JSpecify null-safety, despite pervasive deliberate nullability

- Repo-wide: zero `jspecify` / `@Nullable` usage.
- Nullability is currently carried in prose comments (`SessionRecord.refreshExpiresAt`,
  `OAuthTransaction.stepUp`, `subjectClaim()` returning null, null-checked claim maps).
- Change: add `org.jspecify:jspecify`, mark packages `@NullMarked` (via
  `package-info.java`), annotate genuinely-nullable record components / returns
  `@Nullable`.
- Trade-off: for a security reference, encoding nullability in the type system
  strengthens auditability. Cost: annotation noise + one dependency. The one
  substantive missing idiom.

### W3 — `RefreshLockConfig` uses an `app.refresh-lock*` `@Value` cluster

- `auth-service/.../RefreshLockConfig.java:35-38`: four `@Value`s (`app.refresh-lock`,
  `-ttl`, `-max-wait`, `-poll`) that conceptually belong in a properties record.
- Lower leverage than H2 — three Durations + a mode string, sane defaults, no
  cross-field invariant.
- Trade-off: the `@Value` defaults are self-documenting at the injection point;
  folding into a record is consistency, not a correctness win.

## Already idiomatic (confirmed, no change)

- Records for all DTOs/value carriers; `@Validated` record `@ConfigurationProperties`
  (`AuthProperties`).
- Pattern-matching `instanceof` throughout (incl. a pattern variable in a `for`
  condition, `JwtOidcIdTokenValidator.java:179`).
- Switch *expressions* with `case … when` / `case null, default`
  (`AuthorizationCodeTokenExchangeClient.java:99`).
- `Stream.toList()`, `Collectors.toUnmodifiableSet()`. No `Collectors.toList()` misuse.
- Virtual threads enabled in both modules (`spring.threads.virtual.enabled=true`),
  justified for blocking Nimbus IdP calls.
- `@MockitoBean` (3 sites), not the deprecated `@MockBean`.
- Boot 4 structured/ECS logging; banned-deps enforcer (no Lombok, no Jackson 2).
- Constructor injection throughout; no `RestTemplate` / `new Date` / `new Integer`.

## Correctly NOT modernized (do not change)

- `RefreshLock` / `StateStore` / `IdTokenValidator` / `TokenExchangeClient` are
  **not sealed** — they are runtime-swappable SPI seams selected by config/profile;
  sealing would fight the "swap not rewrite" design. No exhaustive-switch site benefits.
- The Testcontainers parity test (`RedisStateStoreParityTest`) uses raw
  `GenericContainer`, not `@ServiceConnection` — deliberate: it wires
  `RedisStateStore` directly with no Spring context and stays Docker-optional.
- `Date` at `JwtOidcIdTokenValidator.java:152` is the Nimbus
  `claims.getAuthenticationTime()` return type, converted immediately via
  `.toInstant()`. Unavoidable boundary type.

## Highest-value next step

Close the RS ↔ auth-service gap (H1 + H2): give the resource server the same
`ProblemDetail` bodies and a validated record `AppProperties` the auth-service
already models — keeping the `WWW-Authenticate` challenge hand-controlled.
