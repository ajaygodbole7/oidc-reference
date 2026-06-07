# Review Checklist

## Spec Alignment

- Change maps to a spec or task packet.
- Acceptance criteria are satisfied or explicitly deferred.
- Non-goals were respected.
- Assumptions and ambiguities were stated before or during implementation.
- `docs/agents/mandatory-turn-protocol.md` fields are present.

## Simplicity

- Implementation is the minimum complete secure slice.
- No speculative features or configurability were added.
- No single-use abstraction was introduced without clear payoff.

## Security

- No secrets, tokens, cookies, or private keys committed.
- Issuer, audience, signature, expiration, algorithm, scopes, and roles are
  validated where relevant.
- Redirect URI and CORS behavior remain strict.
- Browser token storage is documented and intentionally chosen.

## Tests

- Red failure was observed for new behavior when applicable.
- Positive and negative tests exist for protected behavior.
- Focused tests were run.
- Broader verification gate was run or skipped with a reason.
- For any change to login/callback/session/logout, claims/roles, the realm,
  the gateway, or the SPA auth path: `just e2e-auth` was run (authenticated
  full-stack E2E — real Keycloak login, asserts `/auth/me` roles resolve and
  no token reaches the browser). Mock-only suites do not exercise this path.

## Cross-Artifact & Invariant Sweep

Run a bug-hunter pass over the seams single-file review and mock-heavy tests
miss (each found a real bug on 2026-05-31):

- **Config matches code across artifacts.** Realm protocol mappers (which claim
  lands in id_token vs access_token vs userinfo, audiences, client IDs, redirect
  URIs, flow flags) agree with what the auth-service / RS / gateway / SPA
  actually read. A static check asserting one side (e.g. `access.token.claim`)
  must also assert the side the code depends on (`id.token.claim`).
- **No token reaches the browser.** No access/refresh/id token or token-derived
  PII appears in browser JS, a SPA-readable body, or a URL the SPA reads.
- **No test locks in a bug.** No assertion pins wrong behavior; no fixture builds
  a token the realm cannot emit; no smoke covers only half a mapper config.

## Agent Hygiene

- Changes are limited to owned paths.
- No unrelated refactors.
- Every changed line traces to the task.
- Docs updated when behavior or commands changed.
- Follow-up risks are recorded.
