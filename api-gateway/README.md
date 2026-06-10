# API Gateway (APISIX)

APISIX in **standalone mode** plus the custom `bff-session` Lua plugin.
The gateway is the single browser-facing ingress in the full Compose
stack: it owns `/api/**` (bearer injection against the Resource Server)
and forwards `/auth/*` to the Auth Service unchanged.

## Where this fits in the spec

- `../docs/specs/SPEC-0001-core-oidc-flows.md`
  - §"API Gateway Architecture (APISIX)" — plugin pipeline.
  - §7.1 `/internal/refresh` contract — Gateway-side response table.
  - §7.2 `sess:{sid}` schema — tolerant reader rules.
  - §7.3 signed CSRF contract — HMAC-SHA256, constant-time compare.
  - §"Login Entry Conditions" — Fetch-Metadata 401 vs. 302 branching.
  - §"Trust Boundaries" — Gateway is the sole non-Auth-Service reader
    of `sess:*` and never writes to it.

## Files

- `config.yaml` — APISIX node config (standalone data-plane, port 9080,
  admin API disabled, `extra_lua_path` for the custom plugin, shared
  dicts for the Client-Credentials token cache and worker-local lock).
- `apisix.yaml` — declarative routes + upstreams. One route per
  allowlisted `/api/**` path attaching `bff-session`; a passthrough
  route for `/auth/*` to the Auth Service.
- `plugins/bff-session.lua` — the plugin. Implements steps 1–7 of the
  pipeline in the `access` phase; `Cache-Control: no-store` is enforced
  in `header_filter`.
- `tests/` — black-box integration tests.
- `*.example` files — frozen templates kept for new contributors.

## Run locally

Compose mounts `config.yaml` and the rendered `apisix.yaml` into
`/usr/local/apisix/conf/`, and `plugins/bff-session.lua` into the APISIX
plugin directory `/usr/local/apisix/apisix/plugins/` (see `compose.yaml`
for the exact mount targets):

```
docker compose up apisix
```

## Secrets you must populate

`apisix.yaml` contains `REPLACE_ME_*` placeholders for:

- `gateway_client_secret` — Keycloak client secret for
  `oidc-reference-api-gateway`. Realm-import procedure regenerates this.
- `cookie_signing_key` — base64-encoded 256-bit HMAC key shared with the
  Auth Service (see SPEC §7.3 for rotation discipline).

Both are env-supplied in production and gitignored locally.

## Extending the allowlist

To add a route, copy one of the `/api/*` blocks in `apisix.yaml` and
adjust `uri` + `methods`. Off-allowlist `/api/*` paths intentionally
return `404` before the plugin runs — the set of declared routes IS the
allowlist.
