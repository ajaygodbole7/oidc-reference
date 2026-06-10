# Documentation

The end-to-end flows are in the root [`README.md`](../README.md). These docs
go deeper.

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

## Reference

- [`../SECURITY.md`](../SECURITY.md) — threat model, controls, token
  invariant, key handling.
- [`../OIDC-compliance.md`](../OIDC-compliance.md) — OpenID Connect
  Core / Discovery / RP-Initiated Logout conformance matrix.
- [`../RFC9700-compliance.md`](../RFC9700-compliance.md) — RFC 9700
  (OAuth 2.0 Security BCP) conformance matrix.
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
