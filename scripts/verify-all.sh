#!/usr/bin/env sh
set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

echo "==> verifying authorization-server (static + smoke)"
sh "$script_dir/verify-auth-server.sh"

echo "==> verifying bff"
sh "$script_dir/verify-bff.sh"

echo "==> verifying auth-service (placeholder until Commit 7 / TASK-0008)"
sh "$script_dir/verify-auth-service.sh"

echo "==> verifying api-gateway (placeholder until APISIX config lands)"
sh "$script_dir/verify-api-gateway.sh"

echo "==> verifying backend-resource-server"
sh "$script_dir/verify-backend.sh"

echo "==> verifying frontend"
sh "$script_dir/verify-frontend.sh"

echo "==> verifying spec and flow contracts"
sh "$script_dir/verify-contract-strings.sh"
sh "$script_dir/verify-cross-service.sh"
sh "$script_dir/verify-rs-negatives.sh"

echo "==> scanning tracked files for committed secrets"
sh "$script_dir/verify-secret-scan.sh"

echo "==> canary-testing secret scanner patterns"
sh "$script_dir/test-verify-secret-scan.sh"

if [ "${RUN_FULL_STACK_AUTH:-0}" = "1" ]; then
  echo "==> verifying full-stack auth flow"
  sh "$script_dir/verify-full-stack-auth.sh"
fi

echo "==> all verifications passed"
