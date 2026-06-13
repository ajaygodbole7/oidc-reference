# Contributing

- **What this is:** a local reference implementation of the BFF session
  pattern for OAuth 2.1 / OpenID Connect.
- **Who it's for:** anyone fixing a bug, tightening a control, or improving
  the docs.
- **Where to start:** the three reads below, then the workflow.

Contributions are welcome via pull request.

## Before you open a PR

1. Read [`AGENTS.md`](AGENTS.md) — the operating contract for this repo.
   It defines ownership boundaries, the required workflow, and the
   security rules that gate every change.
2. Read [`docs/specs/SPEC-0001-core-oidc-flows.md`](docs/specs/SPEC-0001-core-oidc-flows.md)
   for the protocol contract your change must preserve.
3. Read [`SECURITY.md`](SECURITY.md) for the threat model and the
   non-goals (so you don't accidentally widen the scope).

## Workflow

- Write a failing test first when changing behavior (red/green).
- Run the relevant per-component verify script:
  `scripts/verify-{auth-service,backend,frontend,api-gateway,auth-server}.sh`.
- For full-stack changes, run `RUN_FULL_STACK_AUTH=1 ./scripts/verify-all.sh`.
- Keep changes surgical. The repo avoids speculative
  abstraction (see [README "What's deliberately not here"](README.md#whats-deliberately-not-here)).

## Reporting security issues

See [`SECURITY.md`](SECURITY.md). Use GitHub private security advisories
for anything sensitive; public issues for general bugs.

## License

Contributions are accepted under the project's [Apache 2.0
license](LICENSE).
