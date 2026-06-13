# Documentation

What's here: the deeper reference behind the Backend-for-Frontend (BFF) OAuth 2.1 / OpenID Connect (OIDC) pattern.
Start with the root [`README.md`](../README.md) for the end-to-end flows, then
follow "Read in order" below. The other sections are reference, operations, and
testing material you can reach for as needed.

## Read in order

1. [`../README.md`](../README.md) — what the reference implements and how the
   browser flow works.
2. [`architecture/overview.md`](architecture/overview.md) — topology and the
   two flows.
3. [`architecture/architecture-decisions.md`](architecture/architecture-decisions.md)
   — why this shape, and what was rejected.
4. [`specs/SPEC-0001-core-oidc-flows.md`](specs/SPEC-0001-core-oidc-flows.md)
   — the contract: wire formats, threat model, acceptance criteria, tests.
5. [`operations/provider-adapters.md`](operations/provider-adapters.md) — how
   to swap Keycloak for another OIDC provider.

## Architecture

- [`architecture/overview.md`](architecture/overview.md) — topology and the two
  flows.
- [`architecture/architecture-decisions.md`](architecture/architecture-decisions.md)
  — why this shape, and what was rejected.
- [`architecture/phantom-token-session-resolution.md`](architecture/phantom-token-session-resolution.md)
  — why the gateway resolves sessions via `/internal/resolve` instead of holding
  a store handle.

## Reference

- [`../SECURITY.md`](../SECURITY.md) — threat model, controls, token
  invariant, key handling.
- [`../OIDC-compliance.md`](../OIDC-compliance.md) — OpenID Connect
  Core / Discovery / Relying Party (RP)-Initiated Logout conformance matrix.
- [`../RFC9700-compliance.md`](../RFC9700-compliance.md) — RFC 9700
  (OAuth 2.0 Security Best Current Practice (BCP)) conformance matrix.
- [`../RFC9470-compliance.md`](../RFC9470-compliance.md) — RFC 9470
  (OAuth 2.0 Step Up Authentication Challenge) conformance matrix.
- [`reference/refresh-rotation.md`](reference/refresh-rotation.md) — refresh
  and rotation behavior.

## Operations

- [`operations/provider-adapters.md`](operations/provider-adapters.md) —
  provider-swap surface and checklist.
- [`operations/provider-overlays/okta.md`](operations/provider-overlays/okta.md)
  — Okta runbook and evidence template.
- [`operations/production-hardening.md`](operations/production-hardening.md) —
  what must change before non-local use.

## Testing

- [`testing/red-green-workflow.md`](testing/red-green-workflow.md) — the
  implementation loop.
- [`testing/verification-gates.md`](testing/verification-gates.md) — focused
  and full gates.
- [`harnesses/local-verification.md`](harnesses/local-verification.md) —
  local verification steps.
