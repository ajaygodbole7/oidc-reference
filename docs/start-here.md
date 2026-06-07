# Start Here

Read these in order.

1. `README.md` — what the reference implements and how the browser flow works.
2. `docs/specs/SPEC-0001-core-oidc-flows.md` — the contract the code must satisfy.
3. `docs/architecture/architecture-decisions.md` — why the shape was chosen.
4. `docs/operations/provider-adapters.md` — how to swap Keycloak for another OIDC provider.
5. `docs/testing/verification-gates.md` — what proves the reference still works.

For local execution:

```sh
just up
cd frontend && npm install && npm run dev
```

For the canonical proof:

```sh
just e2e-auth
```

For hardening before adapting this to a non-local environment, read
`docs/operations/production-hardening.md`.
