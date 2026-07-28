#!/usr/bin/env bash
set -euo pipefail

export POSTGRES_PASSWORD="compose-check-postgres"
export CLICKHOUSE_PASSWORD="compose-check-clickhouse"
export DATABASE_URL="postgres://metrune:compose-check-postgres@postgres:5432/metrune"
export METRUNE_API_IMAGE="ghcr.io/example/metrune-api@sha256:0000000000000000000000000000000000000000000000000000000000000000"
export METRUNE_WEB_IMAGE="ghcr.io/example/metrune-web@sha256:0000000000000000000000000000000000000000000000000000000000000000"
export METRUNE_PUBLIC_API_URL="https://metrune.example"
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

echo "production Compose contract is valid"
