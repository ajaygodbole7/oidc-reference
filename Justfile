# oidc-reference developer tasks.  Run `just --list` to see everything.
#
# This runner is a thin layer: all logic lives in scripts/*.sh, so every recipe
# also works without `just` installed (e.g. `sh scripts/test.sh`). Install the
# runner with `brew install just`.

_default:
    @just --list

# First-time setup: check the toolchain and install frontend deps.
bootstrap:
    sh scripts/bootstrap.sh

# Bring up the full local stack: Keycloak, Valkey, Auth Service, Resource
# Server, and APISIX in Compose.
up:
    sh scripts/up.sh

# Tear the whole stack down.
down:
    sh scripts/down.sh

# Run the SPA dev server (Vite) in the foreground -> http://127.0.0.1:5173
dev:
    cd frontend && npm run dev

# Fast tests: auth-service + resource-server + frontend suites, in parallel. No Docker.
test:
    sh scripts/test.sh

# Live-infra E2E: compose up -> IdP smoke + gateway behaviour -> teardown.
test-e2e:
    sh scripts/test-e2e.sh

# Live conformance checks for C8 trust identities and C9 session windows.
# Expects a running stack; `test-e2e` runs this automatically.
e2e-conformance:
    RUN_LIVE_CONFORMANCE=1 sh scripts/e2e-conformance.sh

# Authenticated full-stack E2E: real Keycloak login -> /auth/me roles ->
# /api/** -> refresh delegation -> logout, asserting no token reaches browser
# JS/storage.
e2e-auth:
    sh scripts/e2e-auth.sh

# Hermetic IdP-portability proof: same stack, alternate Keycloak realm with
# top-level groups and a different API audience. No third-party credentials.
e2e-portability:
    sh scripts/e2e-portability.sh

# Non-default internal trust-id proof for /internal/resolve.
e2e-c8-altids:
    sh scripts/e2e-c8-altids.sh

# Render api-gateway/apisix.yaml.local from the template (dev secrets).
render:
    GATEWAY_CLIENT_SECRET=LOCAL_DEV_GATEWAY_CLIENT_SECRET__CHANGE_BEFORE_DEPLOY CSRF_SIGNING_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= APISIX_IDP_TOKEN_URL=http://keycloak:8080/realms/oidc-reference/protocol/openid-connect/token sh scripts/render-apisix-config.sh

# Static gates: spec/contract strings + committed-secret scan.
check:
    sh scripts/verify-contract-strings.sh
    sh scripts/verify-secret-scan.sh

# Lint every shell script (needs shellcheck).
lint:
    shellcheck scripts/*.sh scripts/lib/*.sh

# Everything CI runs: static gates + full per-module verifies.
cibuild:
    sh scripts/verify-all.sh
