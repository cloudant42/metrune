#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
project="${METRUNE_E2E_PROJECT:-metrune-e2e-$$}"
api_port="${METRUNE_E2E_API_PORT:-18080}"
web_port="${METRUNE_E2E_WEB_PORT:-13001}"
api_url="http://localhost:${api_port}"
web_url="http://localhost:${web_port}"
tmp_dir="$(mktemp -d)"

cleanup() {
  docker compose -p "$project" -f "$repo_root/compose.yaml" down -v --rmi local --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

export METRUNE_API_PORT="$api_port"
export METRUNE_WEB_PORT="$web_port"
export METRUNE_PUBLIC_API_URL="$api_url"
export METRUNE_PUBLIC_WEB_URL="$web_url"
export METRUNE_CLIENT_RELEASE_BASE_URL="${api_url}/v1/downloads"

docker compose -p "$project" -f "$repo_root/compose.yaml" up -d --build

for attempt in $(seq 1 90); do
  if curl -fsS "${api_url}/v1/readyz" >/dev/null 2>&1 \
    && curl -fsS "${web_url}/login" >/dev/null 2>&1; then
    break
  fi
  if [[ "$attempt" -eq 90 ]]; then
    docker compose -p "$project" -f "$repo_root/compose.yaml" ps
    docker compose -p "$project" -f "$repo_root/compose.yaml" logs --tail=200
    echo "Metrune E2E stack did not become ready" >&2
    exit 1
  fi
  sleep 1
done

manifest_json="$(curl -fsS "${api_url}/v1/client/manifest")"
artifact_url="$(python3 -c 'import json,sys; manifest=json.load(sys.stdin); print(next(item["url"] for item in manifest["artifacts"] if item["target"] == "linux-x86_64"))' <<<"$manifest_json")"
artifact_sha256="$(python3 -c 'import json,sys; manifest=json.load(sys.stdin); print(next(item["sha256"] for item in manifest["artifacts"] if item["target"] == "linux-x86_64"))' <<<"$manifest_json")"
client="$tmp_dir/metrune"
curl -fsSL "$artifact_url" -o "$client"
[[ "$(sha256sum "$client" | cut -d' ' -f1)" == "$artifact_sha256" ]]
chmod 700 "$client"
"$client" --version
"$client" --help >/dev/null

login_json="$(curl -fsS \
  -H 'content-type: application/json' \
  -d '{"email":"admin@test.com","password":"admin"}' \
  "${api_url}/v1/auth/login")"
session_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["sessionToken"])' <<<"$login_json")"

config_path="${tmp_dir}/config.json"
state_path="${tmp_dir}/state.db"
client_home="${tmp_dir}/client-home"
mkdir -p "$client_home"
client_command=(
  env
  "HOME=$client_home"
  "XDG_CONFIG_HOME=$client_home/.config"
  "$client"
  --config "$config_path"
  --state-db "$state_path"
)
enrollment_log="${tmp_dir}/device-enrollment.log"
"${client_command[@]}" enroll \
  --server "$api_url" \
  --name "CLI E2E" \
  --platform linux \
  --classifier none >"$enrollment_log" 2>&1 &
enrollment_pid="$!"
device_user_code=""
for _ in $(seq 1 100); do
  device_user_code="$(sed -n 's/^Code: //p' "$enrollment_log" | tail -n 1)"
  if [[ -n "$device_user_code" ]]; then
    break
  fi
  if ! kill -0 "$enrollment_pid" >/dev/null 2>&1; then
    cat "$enrollment_log" >&2
    echo "client exited before presenting a device code" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ -z "$device_user_code" ]]; then
  cat "$enrollment_log" >&2
  echo "client did not present a device code" >&2
  exit 1
fi
approval_json="$(curl -fsS \
  -H 'content-type: application/json' \
  -H "authorization: Bearer ${session_token}" \
  -d "{\"userCode\":\"${device_user_code}\",\"decision\":\"approve\"}" \
  "${api_url}/v1/oauth/device/approval")"
[[ "$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$approval_json")" == "approved" ]]
if ! wait "$enrollment_pid"; then
  cat "$enrollment_log" >&2
  echo "browser-approved client enrollment failed" >&2
  exit 1
fi
grep -q "Enrollment saved to" "$enrollment_log"
[[ "$(stat -c '%a' "$config_path")" == "600" ]]

installation_id="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["installationId"])' <"$config_path")"
installation_credential_id="$(python3 -c '
import json,sys
config=json.load(sys.stdin)
assert "installationToken" not in config
credential_id=config["installationCredentialId"]
assert credential_id
print(credential_id)
' <"$config_path")"
if grep -q "0600 fallback file" "$enrollment_log"; then
  credentials_path="${client_home}/.config/metrune/credentials.json"
  [[ "$(stat -c '%a' "$credentials_path")" == "600" ]]
  python3 -c '
import json,sys
credentials=json.load(open(sys.argv[1], encoding="utf-8"))
value=credentials["values"]["installation:" + sys.argv[2]]
assert value.startswith("mti_")
' "$credentials_path" "$installation_credential_id"
else
  grep -q "system keyring" "$enrollment_log"
fi
status_output="$("${client_command[@]}" status)"
[[ "$status_output" != *"mti_"* ]]
"${client_command[@]}" classifier status
"${client_command[@]}" classifier provision
update_output="$("${client_command[@]}" update --check)"
[[ "$update_output" == *"Installed version:"* ]]
[[ "$update_output" == *"Published version:"* ]]

"${client_command[@]}" scan --clients does-not-exist --no-classify
"${client_command[@]}" export --limit 1 \
  | python3 -c 'import json,sys; payload=json.load(sys.stdin); assert payload["snapshots"] == []'

session_dir="${client_home}/.codex/sessions/$(date -u +%Y/%m/%d)"
session_file="${session_dir}/client-upload.jsonl"
session_timestamp="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
raw_session_id="raw-e2e-session-${project}"
private_project_path="/private/e2e-project-${project}"
private_prompt="E2E_PRIVATE_PROMPT_MUST_NOT_UPLOAD_${project}"
mkdir -p "$session_dir"
printf '%s\n' \
  "{\"type\":\"session_meta\",\"timestamp\":\"${session_timestamp}\",\"payload\":{\"session_id\":\"${raw_session_id}\",\"cwd\":\"${private_project_path}\",\"cli_version\":\"0.999.0-test\",\"model_provider\":\"openai\"}}" \
  '{"type":"turn_context","payload":{"model":"gpt-5-codex"}}' \
  "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"${private_prompt}\"}]}}" \
  "{\"type\":\"event_msg\",\"timestamp\":\"${session_timestamp}\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":123,\"cached_input_tokens\":20,\"output_tokens\":45,\"reasoning_output_tokens\":7,\"total_tokens\":175}}}}" \
  >"$session_file"

scan_output="$("${client_command[@]}" scan --clients codex --no-classify)"
[[ "$scan_output" == *"Queued 1 sanitized session snapshots."* ]]
first_export="$("${client_command[@]}" export --limit 10)"
retry_export="$("${client_command[@]}" export --limit 10)"
python3 -c '
import json,sys
first=json.loads(sys.argv[1])
retry=json.loads(sys.argv[2])
assert first["batchId"] == retry["batchId"]
assert len(first["snapshots"]) == 1
encoded=json.dumps(first)
for secret in sys.argv[3:]:
    assert secret not in encoded
snapshot=first["snapshots"][0]
assert snapshot["clientId"] == "codex"
tokens=snapshot["usageByModel"][0]["tokens"]
assert sum(tokens.values()) == 195
' "$first_export" "$retry_export" "$raw_session_id" "$private_project_path" "$private_prompt"

bad_config="${tmp_dir}/bad-config.json"
python3 -c 'import json,sys; data=json.load(open(sys.argv[1])); data["serverUrl"]="http://127.0.0.1:1"; json.dump(data,open(sys.argv[2],"w"))' "$config_path" "$bad_config"
chmod 600 "$bad_config"
if env "HOME=$client_home" "$client" --config "$bad_config" --state-db "$state_path" upload --limit 10 \
  >"${tmp_dir}/failed-upload.log" 2>&1; then
  echo "client upload unexpectedly succeeded against an unavailable server" >&2
  exit 1
fi
"${client_command[@]}" export --limit 10 \
  | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["snapshots"]) == 1'

upload_output="$("${client_command[@]}" upload --limit 10)"
[[ "$upload_output" == *"Uploaded 1 session snapshots."* ]]
"${client_command[@]}" export --limit 10 \
  | python3 -c 'import json,sys; assert json.load(sys.stdin)["snapshots"] == []'

assert_uploaded_session() {
  local expected_tokens="$1"
  local sessions_json
  for _ in $(seq 1 30); do
    sessions_json="$(curl -fsS \
      -H "authorization: Bearer ${session_token}" \
      "${api_url}/v1/me/sessions")"
    if python3 -c '
import json,sys
rows=json.load(sys.stdin)
matches=[row for row in rows if row["clientId"] == "codex"]
assert len(matches) == 1
assert matches[0]["totalTokens"] == int(sys.argv[1])
encoded=json.dumps(matches)
for secret in sys.argv[2:]:
    assert secret not in encoded
' "$expected_tokens" "$raw_session_id" "$private_project_path" "$private_prompt" <<<"$sessions_json" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  echo "uploaded client session did not become queryable with ${expected_tokens} tokens" >&2
  return 1
}
assert_uploaded_session 195

second_prompt="SECOND_PRIVATE_PROMPT_MUST_NOT_UPLOAD_${project}"
printf '%s\n' \
  "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"${second_prompt}\"}]}}" \
  "{\"type\":\"event_msg\",\"timestamp\":\"${session_timestamp}\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":200,\"cached_input_tokens\":30,\"output_tokens\":70,\"reasoning_output_tokens\":10,\"total_tokens\":270}}}}" \
  >>"$session_file"
scan_output="$("${client_command[@]}" scan --clients codex --no-classify)"
[[ "$scan_output" == *"Queued 1 sanitized session snapshots."* ]]
upload_output="$("${client_command[@]}" upload --limit 10)"
[[ "$upload_output" == *"Uploaded 1 session snapshots."* ]]
assert_uploaded_session 310
scan_output="$("${client_command[@]}" scan --clients codex --no-classify)"
[[ "$scan_output" == *"Queued 0 sanitized session snapshots."* ]]

if [[ -z "${PLAYWRIGHT_EXECUTABLE_PATH:-}" ]]; then
  if [[ -x /opt/google/chrome/chrome ]]; then
    export PLAYWRIGHT_EXECUTABLE_PATH=/opt/google/chrome/chrome
  elif command -v google-chrome >/dev/null 2>&1; then
    export PLAYWRIGHT_EXECUTABLE_PATH="$(command -v google-chrome)"
  fi
fi

(
  cd "$repo_root/web"
  PLAYWRIGHT_BASE_URL="$web_url" METRUNE_PUBLIC_API_URL="$api_url" npm run test:e2e
)

printf '%s\n' \
  "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":\"THIRD_PRIVATE_PROMPT_MUST_NOT_UPLOAD_${project}\"}]}}" \
  "{\"type\":\"event_msg\",\"timestamp\":\"${session_timestamp}\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":210,\"cached_input_tokens\":30,\"output_tokens\":75,\"reasoning_output_tokens\":10,\"total_tokens\":285}}}}" \
  >>"$session_file"
scan_output="$("${client_command[@]}" scan --clients codex --no-classify)"
[[ "$scan_output" == *"Queued 1 sanitized session snapshots."* ]]
revoke_status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -X DELETE \
  -H "authorization: Bearer ${session_token}" \
  "${api_url}/v1/me/installations/${installation_id}")"
[[ "$revoke_status" == "204" ]]
if "${client_command[@]}" upload --limit 10 >"${tmp_dir}/revoked-upload.log" 2>&1; then
  echo "revoked installation token unexpectedly uploaded usage" >&2
  exit 1
fi
"${client_command[@]}" export --limit 10 \
  | python3 -c 'import json,sys; assert len(json.load(sys.stdin)["snapshots"]) == 1'
