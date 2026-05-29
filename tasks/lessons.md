# Lessons Learned

Agent-portable corrections log. Every time a user (or another agent's
review) corrects an approach in this repo, distill the correction here
as a rule a future agent can read at session start.

This file is intentionally small — entries that have become permanent
project conventions belong in `CLAUDE.md` / `AGENTS.md` / the spec, not
here. Lessons graduate or get pruned.

## Format

```
### YYYY-MM-DD — Short headline
- **Mistake**: what went wrong
- **Root cause**: why it happened
- **Rule**: what to do differently next time
```

---

### 2026-05-25 — `@ConditionalOnMissingBean` on `@Component` is unreliable
- **Mistake**: BFF startup failed with "No qualifying bean of type StateStore" because `RedisStateStore` had `@ConditionalOnMissingBean(StateStore.class)` on its `@Component` annotation.
- **Root cause**: That conditional is documented for `@Bean` methods in `@Configuration` classes. On `@Component`, it evaluates in scan order and is unreliable; tests had been masking the runtime regression.
- **Rule**: For test overrides of `@Component` beans, use `@TestConfiguration` + `@Primary` in tests. Never `@ConditionalOnMissingBean` on application `@Component` beans.

### 2026-05-25 — `UriComponentsBuilder.toUriString()` does NOT URL-encode
- **Mistake**: BFF emitted `Location: ...?scope=openid profile email...` with literal spaces. Chromium refused to follow it; e2e gate hung at `page.waitForURL(Keycloak)`.
- **Root cause**: `UriComponentsBuilder.queryParam(...).build().toUriString()` returns the URI with placeholders unexpanded and query values unencoded.
- **Rule**: Always call `.encode()` before `.toUriString()` when building an OAuth/OIDC redirect URI.

### 2026-05-25 — Keycloak realm imports REPLACE built-in client scopes
- **Mistake**: BFF got `error=invalid_scope` from Keycloak. The realm JSON declared custom scopes (`api.audience`, `api.read`, etc.) but omitted the built-in `profile`, `email`, `roles` — which Spring Security still requested.
- **Root cause**: When a realm JSON includes a `clientScopes` array, Keycloak does NOT also add its defaults. The import is authoritative.
- **Rule**: Any realm JSON that customizes `clientScopes` must explicitly re-declare every built-in scope it still needs, with their standard protocol mappers (`preferred_username`, `email`, `realm_access.roles`, etc.).

### 2026-05-25 — Replacing Spring Security's response-client RestClient loses the OAuth converters
- **Mistake**: After swapping Spring's auto-wired RestClient for our timeout-configured one via `setRestClient(...)`, the live flow died with `IllegalArgumentException: additionalParameters cannot be null`.
- **Root cause**: `RestClientAuthorizationCodeTokenResponseClient`'s default internal `RestClient` ships with `FormHttpMessageConverter` + `OAuth2AccessTokenResponseHttpMessageConverter`. Overriding the RestClient without re-registering them caused Jackson to deserialize `OAuth2AccessTokenResponse` via the no-arg constructor, leaving `additionalParameters` null and the assertion-on-read throwing.
- **Rule**: When customizing the RestClient for any Spring Security response client, also `.messageConverters(c -> { c.add(0, new FormHttpMessageConverter()); c.add(0, new OAuth2AccessTokenResponseHttpMessageConverter()); })`.

### 2026-05-25 — Strict dev CSP breaks Vite HMR
- **Mistake**: Added `script-src 'self'` as a Vite dev server header. The SPA stopped rendering at all.
- **Root cause**: Vite's HMR runtime uses runtime code generation and injects inline scripts. A strict dev CSP either breaks HMR (broken inner loop) or is permissive enough to be toothless.
- **Rule**: Production CSP is owned by the BFF response headers (where it can be nonce-based). The Vite dev server gets only `Referrer-Policy` + `X-Content-Type-Options` — no CSP at all.

### 2026-05-25 — `document.cookie` never sees HttpOnly cookies (tautology trap)
- **Mistake**: e2e test asserted `expect(browserState.cookieHeader).not.toMatch(/sid=/)` as proof the session cookie was HttpOnly. The test passed regardless of whether `sid` was HttpOnly.
- **Root cause**: `document.cookie` only exposes non-HttpOnly cookies. So the assertion is trivially true even when HttpOnly is OFF — the wrong contract was being tested.
- **Rule**: To prove HttpOnly, use Playwright's `context.cookies()` and assert `c.httpOnly === true`. Never use `document.cookie` for HttpOnly proofs.
