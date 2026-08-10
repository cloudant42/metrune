#!/usr/bin/env bash
# Validate, verify, and publish a resumable GitHub release draft.

set -euo pipefail

action="${1:?usage: release-draft.sh validate|verify|publish [ASSET ...]}"
shift
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_SHA:?GITHUB_SHA is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"

release_row() {
  gh api --paginate "repos/${GITHUB_REPOSITORY}/releases?per_page=100" \
    --jq ".[] | select(.tag_name == \"${RELEASE_TAG}\") | [.id, .draft, .target_commitish] | @tsv"
}

validated_release_id() {
  local rows count release_id draft target
  if ! rows="$(release_row)"; then
    echo "could not query GitHub releases for $RELEASE_TAG" >&2
    return 1
  fi
  [[ -n "$rows" ]] || return 2
  count="$(printf '%s\n' "$rows" | wc -l | tr -d '[:space:]')"
  [[ "$count" == "1" ]] || {
    echo "expected one GitHub release for $RELEASE_TAG, found $count" >&2
    return 1
  }
  IFS=$'\t' read -r release_id draft target <<<"$rows"
  [[ "$draft" == "true" ]] || {
    echo "$RELEASE_TAG is already published" >&2
    return 1
  }
  [[ "$target" == "$GITHUB_SHA" ]] || {
    echo "$RELEASE_TAG draft targets $target, not $GITHUB_SHA" >&2
    return 1
  }
  printf '%s\n' "$release_id"
}

case "$action" in
  validate)
    if release_id="$(validated_release_id)"; then
      echo "resuming release draft $release_id for $RELEASE_TAG"
    else
      status=$?
      [[ "$status" == "2" ]] || exit "$status"
      echo "no existing release draft for $RELEASE_TAG"
    fi
    ;;
  verify)
    [[ "$#" -gt 0 ]] || {
      echo "verify requires at least one expected asset" >&2
      exit 2
    }
    release_id="$(validated_release_id)" || {
      status=$?
      [[ "$status" != "2" ]] || echo "release draft $RELEASE_TAG was not created" >&2
      exit "$status"
    }
    expected="$(mktemp)"
    actual="$(mktemp)"
    trap 'rm -f "$expected" "$actual"' EXIT
    printf '%s\n' "$@" | sort > "$expected"
    gh api --paginate "repos/${GITHUB_REPOSITORY}/releases/${release_id}/assets?per_page=100" \
      --jq '.[].name' | sort > "$actual"
    if ! diff -u "$expected" "$actual"; then
      echo "release draft assets are incomplete or unexpected" >&2
      exit 1
    fi
    echo "verified $# release assets for $RELEASE_TAG"
    ;;
  publish)
    release_id="$(validated_release_id)" || {
      status=$?
      [[ "$status" != "2" ]] || echo "release draft $RELEASE_TAG was not created" >&2
      exit "$status"
    }
    # The Git tag is created only when the complete draft is published. This
    # final remote check closes the normal operator-race window.
    bash scripts/assert-release-tag-available.sh "$RELEASE_TAG"
    gh api --method PATCH "repos/${GITHUB_REPOSITORY}/releases/${release_id}" \
      -F draft=false >/dev/null
    echo "published $RELEASE_TAG from verified draft $release_id"
    ;;
  *)
    echo "unknown release-draft action: $action" >&2
    exit 2
    ;;
esac
