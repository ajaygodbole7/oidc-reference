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

## Agent Hygiene

- Changes are limited to owned paths.
- No unrelated refactors.
- Every changed line traces to the task.
- Docs updated when behavior or commands changed.
- Follow-up risks are recorded.
