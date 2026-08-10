#!/usr/bin/env bash
set -euo pipefail

export POSTGRES_PASSWORD="compose-check-postgres"
export CLICKHOUSE_PASSWORD="compose-check-clickhouse"
export DATABASE_URL="postgres://metrune:compose-check-postgres@postgres:5432/metrune"
export METRUNE_API_IMAGE="ghcr.io/example/metrune-api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
export METRUNE_WEB_IMAGE="ghcr.io/example/metrune-web@sha256:0000000000000000000000000000000000000000000000000000000000000000"
export METRUNE_PUBLIC_API_URL="https://metrune.example"
export METRUNE_PUBLIC_WEB_URL="https://metrune.example"
export METRUNE_RELEASE_PUBKEY="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
export METRUNE_CLIENT_RELEASE_DIR="/tmp/metrune-client-release"
export METRUNE_SMTP_HOST="smtp.example"
export METRUNE_SMTP_PORT="587"
export METRUNE_SMTP_USERNAME="compose-check"
export METRUNE_SMTP_PASSWORD="compose-check"
export METRUNE_SMTP_FROM="Metrune <metrune@example.com>"

rendered="$(mktemp)"
trap 'rm -f "$rendered"' EXIT

docker compose -f compose.production.yaml config > "$rendered"

expected_services=$'api\nclickhouse\npostgres\nweb'
actual_services="$(docker compose -f compose.production.yaml config --services | sort)"
if [[ "$actual_services" != "$expected_services" ]]; then
  echo "unexpected production services:" >&2
  echo "$actual_services" >&2
  exit 1
fi

if grep -Eiq 'grafana|prometheus|otel|opentelemetry' "$rendered"; then
  echo "unsupported observability services leaked into production Compose" >&2
  exit 1
fi

published_count="$(grep -c 'published:' "$rendered" || true)"
localhost_count="$(grep -c 'host_ip: 127.0.0.1' "$rendered" || true)"
if [[ "$published_count" != "2" || "$localhost_count" != "2" ]]; then
  echo "production Compose must publish only API and web on 127.0.0.1" >&2
  exit 1
fi

if grep -q 'host_ip: 0.0.0.0' "$rendered"; then
  echo "production Compose exposes a service on all interfaces" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]+METRUNE_OIDC_CLIENT_SECRET:' "$rendered"; then
  echo "production Compose must not expose the OIDC client secret in the environment" >&2
  exit 1
fi

if ! grep -q 'target: /run/secrets/metrune-oidc-client-secret' "$rendered"; then
  echo "production Compose is missing the OIDC client-secret file mount" >&2
  exit 1
fi

postgres_config="$(awk '
  /^  postgres:$/ { in_postgres = 1; next }
  in_postgres && /^  [[:alnum:]_-]+:$/ { exit }
  in_postgres { print }
' "$rendered")"
if grep -q '/docker-entrypoint-initdb.d' <<<"$postgres_config"; then
  echo "PostgreSQL migrations must be owned by the API, not run a second time by the image entrypoint" >&2
  exit 1
fi

# The dashboard forwards the browser session and nothing else; a shared token
# in the web environment would restore anonymous organization access.
if grep -Eq '^[[:space:]]+METRUNE_DASHBOARD_TOKEN:' "$rendered"; then
  echo "production Compose must not give the web service a dashboard token" >&2
  exit 1
fi

docker compose -f compose.yaml config > "$rendered"

# The development stack seeds an admin organization and a weak bootstrap
# password, so it must never be reachable from outside the host.
dev_published="$(grep -c 'published:' "$rendered" || true)"
dev_localhost="$(grep -c 'host_ip: 127.0.0.1' "$rendered" || true)"
if [[ "$dev_published" != "2" || "$dev_localhost" != "2" ]]; then
  echo "development Compose must publish only API and web on 127.0.0.1" >&2
  exit 1
fi

if grep -q 'host_ip: 0.0.0.0' "$rendered"; then
  echo "development Compose exposes a service on all interfaces" >&2
  exit 1
fi

if grep -Eq '^[[:space:]]+METRUNE_DASHBOARD_TOKEN:' "$rendered"; then
  echo "development Compose must not give the web service a dashboard token" >&2
  exit 1
fi

echo "Compose contracts are valid"
