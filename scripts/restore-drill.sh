#!/usr/bin/env bash
#
# Metrune restore drill.
#
# Seeds a Compose deployment with the state that a real backup has to protect
# (an organization, an encrypted classifier credential, an installation, and an
# ingested usage snapshot), takes a PostgreSQL, ClickHouse, and vault-key
# backup, destroys the deployment, restores it from those backups alone, and
# then proves that the restored deployment still decrypts the classifier
# credential and still serves the ingested usage.
#
# Usage:
#   scripts/restore-drill.sh            # run the full drill and clean up
#   METRUNE_DRILL_KEEP=1 scripts/restore-drill.sh   # keep the restored stack
#
# The drill uses its own Compose project name and its own volumes. It never
# touches a running development or production deployment.

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPOSITORY_ROOT"

PROJECT="${METRUNE_DRILL_PROJECT:-metrune-restore-drill}"
# The drill publishes the API on its own host port so that it can run beside a
# development deployment.
export METRUNE_DRILL_API_PORT="${METRUNE_DRILL_API_PORT:-18080}"
API_URL="${METRUNE_DRILL_API_URL:-http://localhost:$METRUNE_DRILL_API_PORT}"
if [[ -n "${METRUNE_DRILL_BACKUP_DIR:-}" ]]; then
  BACKUP_DIR="$METRUNE_DRILL_BACKUP_DIR"
  BACKUP_DIR_IS_TEMP=0
else
  BACKUP_DIR="$(mktemp -d)"
  BACKUP_DIR_IS_TEMP=1
fi
ADMIN_EMAIL="admin@test.com"
ADMIN_PASSWORD="admin"
CREDENTIAL_ID="drill-classifier"
CREDENTIAL_SECRET="drill-secret-$(date +%s)"

compose() {
  docker compose -p "$PROJECT" \
    -f compose.yaml -f deploy/compose/restore-drill.yml "$@"
}
step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

cleanup() {
  local status=$?
  if [[ "${METRUNE_DRILL_KEEP:-0}" == "1" && $status -eq 0 ]]; then
    printf '\nRestored stack left running as project %s.\n' "$PROJECT"
    printf 'Backups kept in %s\n' "$BACKUP_DIR"
    return
  fi
  step "Tearing down the drill deployment"
  compose down -v --rmi local --remove-orphans >/dev/null 2>&1 || true
  if [[ "$BACKUP_DIR_IS_TEMP" == "1" ]]; then
    rm -rf "$BACKUP_DIR"
  fi
}
trap cleanup EXIT

wait_for_ready() {
  local attempt
  for attempt in $(seq 1 120); do
    if curl -fsS "$API_URL/v1/readyz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  compose logs --tail 50 api >&2 || true
  fail "the API did not become ready"
}

# jq is used for every response field the drill asserts on.
command -v jq >/dev/null || fail "jq is required"
command -v curl >/dev/null || fail "curl is required"

step "Starting a clean source deployment"
compose down -v --remove-orphans >/dev/null 2>&1 || true
compose up -d --build postgres clickhouse api
wait_for_ready

step "Seeding state that the backup must protect"
SESSION_TOKEN="$(curl -fsS -X POST "$API_URL/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .sessionToken)"
[[ -n "$SESSION_TOKEN" && "$SESSION_TOKEN" != "null" ]] || fail "could not log in to the source deployment"

curl -fsS -X POST "$API_URL/v1/org/credentials" \
  -H "authorization: Bearer $SESSION_TOKEN" -H 'content-type: application/json' \
  -d "{\"credentialId\":\"$CREDENTIAL_ID\",\"providerId\":\"openrouter\",\"secret\":\"$CREDENTIAL_SECRET\",\"graceHours\":0}" >/dev/null

curl -fsS -X PATCH "$API_URL/v1/org/classifier" \
  -H "authorization: Bearer $SESSION_TOKEN" -H 'content-type: application/json' \
  -d "{\"enabled\":true,\"providerId\":\"openrouter\",\"endpoint\":\"\",\"model\":\"qwen/qwen3-4b\",\"credentialId\":\"$CREDENTIAL_ID\"}" >/dev/null

ENROLLMENT_CODE="$(curl -fsS -X POST "$API_URL/v1/me/enrollment-codes" \
  -H "authorization: Bearer $SESSION_TOKEN" -H 'content-type: application/json' \
  -d '{"installationName":"restore-drill","platform":"linux"}' | jq -r .code)"
[[ -n "$ENROLLMENT_CODE" && "$ENROLLMENT_CODE" != "null" ]] || fail "could not create an enrollment code"

INSTALLATION_TOKEN="$(curl -fsS -X POST "$API_URL/v1/enroll" \
  -H 'content-type: application/json' \
  -d "{\"enrollmentToken\":\"$ENROLLMENT_CODE\",\"installationName\":\"restore-drill\",\"platform\":\"linux\"}" \
  | jq -r .installationToken)"
[[ -n "$INSTALLATION_TOKEN" && "$INSTALLATION_TOKEN" != "null" ]] || fail "could not enroll an installation"

SESSION_KEY="drill-session-key-0000000000000000000000"
USER_KEY="drill-user-key-0000000000000000000000000"
STARTED_AT="$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)"
ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
INGEST_ACK="$(curl -fsS -X POST "$API_URL/v1/ingest/sessions" \
  -H "authorization: Bearer $INSTALLATION_TOKEN" -H 'content-type: application/json' \
  -d "$(cat <<JSON
{
  "schemaVersion": "1",
  "batchId": "restore-drill-batch",
  "sentAt": "$ENDED_AT",
  "snapshots": [
    {
      "schemaVersion": "1",
      "sessionKey": "$SESSION_KEY",
      "revision": 1,
      "userKey": "$USER_KEY",
      "projectAlias": "Restore Drill",
      "clientId": "claude-code",
      "startedAt": "$STARTED_AT",
      "endedAt": "$ENDED_AT",
      "usageByModel": [
        {
          "providerId": "anthropic",
          "modelId": "claude-sonnet-4",
          "tokens": {"input": 1000, "output": 500, "cacheRead": 0, "cacheWrite": 0, "reasoning": 0},
          "cost": {"amount": 0.25, "currency": "USD", "kind": "reported", "pricebookVersion": null}
        }
      ],
      "category": {
        "categoryId": "implementation",
        "confidence": 0.9,
        "taxonomyVersion": "2026-01",
        "classifierId": "restore-drill",
        "classificationStatus": "classified"
      }
    }
  ]
}
JSON
)")"
[[ "$(jq -r .accepted <<<"$INGEST_ACK")" == "1" ]] || fail "the source deployment did not accept the snapshot: $INGEST_ACK"

EXPECTED_ROWS="$(compose exec -T clickhouse clickhouse-client --user metrune --password metrune-dev \
  --query 'SELECT count() FROM metrune.session_snapshots_dedup' | tr -d '[:space:]')"
[[ "$EXPECTED_ROWS" == "1" ]] || fail "expected exactly one seeded snapshot, found $EXPECTED_ROWS"

step "Taking PostgreSQL, ClickHouse, and vault-key backups"
mkdir -p "$BACKUP_DIR"
compose exec -T postgres pg_dump -U metrune -d metrune --format=custom > "$BACKUP_DIR/postgres.dump"
compose exec -T clickhouse clickhouse-client --user metrune --password metrune-dev \
  --query 'SELECT * FROM metrune.session_snapshots_dedup FORMAT Native' > "$BACKUP_DIR/session_snapshots_dedup.native"
compose exec -T api cat /var/lib/metrune/secrets/master.key > "$BACKUP_DIR/master.key"
[[ -s "$BACKUP_DIR/postgres.dump" ]] || fail "the PostgreSQL dump is empty"
[[ -s "$BACKUP_DIR/session_snapshots_dedup.native" ]] || fail "the ClickHouse export is empty"
[[ -s "$BACKUP_DIR/master.key" ]] || fail "the vault key backup is empty"
printf 'Backups written to %s\n' "$BACKUP_DIR"

step "Destroying the source deployment, including every volume"
compose down -v --remove-orphans >/dev/null

step "Restoring PostgreSQL into an empty instance"
compose up -d postgres clickhouse
for attempt in $(seq 1 60); do
  compose exec -T postgres pg_isready -U metrune >/dev/null 2>&1 && break
  sleep 2
done
compose exec -T postgres dropdb -U metrune --if-exists --force metrune
compose exec -T postgres createdb -U metrune metrune
compose exec -T postgres pg_restore -U metrune -d metrune --no-owner < "$BACKUP_DIR/postgres.dump"

step "Restoring the vault master key before the API starts"
compose run --rm --no-deps -T --user 0:0 --entrypoint sh \
  -v "$BACKUP_DIR:/restore:ro" api -c \
  'install -o 65532 -g 65532 -m 600 /restore/master.key /var/lib/metrune/secrets/master.key'

step "Starting the restored API"
compose up -d api
wait_for_ready

step "Restoring ClickHouse usage history"
compose exec -T clickhouse clickhouse-client --user metrune --password metrune-dev \
  --query 'INSERT INTO metrune.session_snapshots_dedup FORMAT Native' < "$BACKUP_DIR/session_snapshots_dedup.native"

step "Verifying the restored deployment"
RESTORED_TOKEN="$(curl -fsS -X POST "$API_URL/v1/auth/login" \
  -H 'content-type: application/json' \
  -d "{\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .sessionToken)"
[[ -n "$RESTORED_TOKEN" && "$RESTORED_TOKEN" != "null" ]] || fail "login failed after restore"
printf '  identity ........... restored\n'

RESTORED_ROWS="$(curl -fsS -H "authorization: Bearer $RESTORED_TOKEN" \
  "$API_URL/v1/analytics/overview" | jq -r .sessions)"
[[ "$RESTORED_ROWS" == "$EXPECTED_ROWS" ]] || fail "expected $EXPECTED_ROWS restored sessions, analytics reported $RESTORED_ROWS"
printf '  usage history ...... restored (%s session)\n' "$RESTORED_ROWS"

# The installation token is a client-held secret that survives a server
# restore; re-provisioning proves the vault key still decrypts the stored
# classifier credential.
PROVISIONED="$(curl -fsS -X POST "$API_URL/v1/installation/classifier/provision" \
  -H "authorization: Bearer $INSTALLATION_TOKEN")"
[[ "$(jq -r .credentialId <<<"$PROVISIONED")" == "$CREDENTIAL_ID" ]] \
  || fail "the restored deployment did not return the classifier credential: $PROVISIONED"
[[ "$(jq -r .credential <<<"$PROVISIONED")" == "$CREDENTIAL_SECRET" ]] \
  || fail "the restored vault key did not decrypt the classifier credential"
printf '  installation auth .. restored\n'
printf '  vault credential ... decrypted with the restored master key\n'

printf '\n\033[32mRestore drill passed.\033[0m\n'
