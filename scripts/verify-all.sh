#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
. "$script_dir/lib/common.sh"

# Full verification: per-module verifies + spec/contract gates + secret scan.
# This is what `just cibuild` runs. The fast inner loop is `scripts/test.sh`
# (`just test`); the live-infra E2E is `scripts/test-e2e.sh` (`just test-e2e`),
# also reachable here via RUN_FULL_STACK_AUTH=1.

info "verifying IdP (Keycloak realm static + smoke)"
sh "$script_dir/verify-idp.sh"

info "verifying auth-service"
sh "$script_dir/verify-auth-service.sh"

info "verifying api-gateway"
sh "$script_dir/verify-api-gateway.sh"

info "verifying backend-resource-server"
sh "$script_dir/verify-backend.sh"

info "verifying frontend"
sh "$script_dir/verify-frontend.sh"

info "verifying spec and flow contracts"
sh "$script_dir/verify-contract-strings.sh"
sh "$script_dir/verify-cross-service.sh"
sh "$script_dir/verify-rs-negatives.sh"

info "scanning tracked files for committed secrets"
sh "$script_dir/verify-secret-scan.sh"

info "canary-testing secret scanner patterns"
sh "$script_dir/test-verify-secret-scan.sh"

if [ "${RUN_FULL_STACK_AUTH:-0}" = "1" ]; then
  info "running live-infra E2E"
  sh "$script_dir/test-e2e.sh"
fi

success "all verifications passed"
