#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
api_port="${METRUNE_SSO_E2E_API_PORT:-18081}"
web_port="${METRUNE_SSO_E2E_WEB_PORT:-13002}"
oidc_port="${METRUNE_SSO_E2E_OIDC_PORT:-19090}"
api_url="http://localhost:${api_port}"
web_url="http://localhost:${web_port}"
oidc_url="http://localhost:${oidc_port}"
tmp_dir="$(mktemp -d)"
provider_pid=""
api_pid=""
web_pid=""

cleanup() {
  for pid in "$web_pid" "$api_pid" "$provider_pid"; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" >/dev/null 2>&1 || true
    fi
  done
  make -C "$repo_root" integration-down >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

make -C "$repo_root" integration-up
for migration in "$repo_root"/migrations/clickhouse/*.sql; do
  echo "Applying $(basename "$migration")"
  docker exec -i metrune-test-clickhouse \
    clickhouse-client --multiquery <"$migration"
done
cargo build --manifest-path "$repo_root/Cargo.toml" -p metrune-api
(
  cd "$repo_root/web"
  npm run build
)

METRUNE_TEST_OIDC_PORT="$oidc_port" \
  node "$repo_root/web/e2e/mock-oidc-provider.mjs" \
  >"$tmp_dir/oidc.log" 2>&1 &
provider_pid="$!"
for attempt in $(seq 1 60); do
  if curl -fsS "${oidc_url}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$provider_pid" >/dev/null 2>&1 || [[ "$attempt" -eq 60 ]]; then
    cat "$tmp_dir/oidc.log" >&2
    echo "mock OIDC provider did not become ready" >&2
    exit 1
  fi
  sleep 0.2
done

env \
  -u METRUNE_BOOTSTRAP_PASSWORD \
  -u METRUNE_OIDC_CLIENT_SECRET_FILE \
  DATABASE_URL="postgres://metrune:metrune-test@localhost:55432/metrune_test" \
  CLICKHOUSE_URL="http://localhost:58123" \
  CLICKHOUSE_DATABASE="metrune" \
  CLICKHOUSE_USER="default" \
  CLICKHOUSE_PASSWORD="" \
  METRUNE_ENV="development" \
  METRUNE_API_ADDRESS="127.0.0.1:${api_port}" \
  METRUNE_PUBLIC_API_URL="$api_url" \
  METRUNE_PUBLIC_WEB_URL="$web_url" \
  METRUNE_BOOTSTRAP_EMAIL="admin@test.com" \
  METRUNE_BOOTSTRAP_ORGANIZATION="SSO Browser E2E" \
  METRUNE_DEFAULT_PRICE_CATALOG="$repo_root/pricing/openrouter.catalog.json" \
  METRUNE_SECRETS_KEY_FILE="$tmp_dir/master.key" \
  METRUNE_OIDC_ISSUER_URL="$oidc_url" \
  METRUNE_OIDC_CLIENT_ID="metrune-browser-e2e" \
  METRUNE_OIDC_CLIENT_SECRET="metrune-browser-e2e-secret" \
  METRUNE_OIDC_PROVIDER_NAME="Test Enterprise SSO" \
  METRUNE_OIDC_PROVISIONING="none" \
  "$repo_root/target/debug/metrune-api" \
  >"$tmp_dir/api.log" 2>&1 &
api_pid="$!"
for attempt in $(seq 1 120); do
  if curl -fsS "${api_url}/v1/readyz" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$api_pid" >/dev/null 2>&1 || [[ "$attempt" -eq 120 ]]; then
    cat "$tmp_dir/api.log" >&2
    echo "OIDC E2E API did not become ready" >&2
    exit 1
  fi
  sleep 0.25
done

(
  cd "$repo_root/web"
  env \
    METRUNE_ENV="development" \
    METRUNE_API_URL="$api_url" \
    METRUNE_PUBLIC_API_URL="$api_url" \
    npm run start -- --hostname 127.0.0.1 --port "$web_port"
) >"$tmp_dir/web.log" 2>&1 &
web_pid="$!"
for attempt in $(seq 1 120); do
  if curl -fsS "${web_url}/login" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$web_pid" >/dev/null 2>&1 || [[ "$attempt" -eq 120 ]]; then
    cat "$tmp_dir/web.log" >&2
    echo "OIDC E2E web app did not become ready" >&2
    exit 1
  fi
  sleep 0.25
done

if [[ -z "${PLAYWRIGHT_EXECUTABLE_PATH:-}" ]]; then
  if [[ -x /opt/google/chrome/chrome ]]; then
    export PLAYWRIGHT_EXECUTABLE_PATH=/opt/google/chrome/chrome
  elif command -v google-chrome >/dev/null 2>&1; then
    export PLAYWRIGHT_EXECUTABLE_PATH="$(command -v google-chrome)"
  fi
fi

(
  cd "$repo_root/web"
  PLAYWRIGHT_BASE_URL="$web_url" \
    METRUNE_PUBLIC_API_URL="$api_url" \
    METRUNE_E2E_SSO=1 \
    npm run test:e2e -- e2e/sso.spec.ts
)
