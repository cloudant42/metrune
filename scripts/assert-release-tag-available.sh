#!/usr/bin/env bash
# Fail closed unless a release tag is proven absent from the remote.

set -euo pipefail

tag="${1:?usage: assert-release-tag-available.sh TAG [REMOTE]}"
remote="${2:-origin}"

if git ls-remote --exit-code --refs "$remote" "refs/tags/$tag" >/dev/null 2>&1; then
  echo "$tag already exists; bump the committed package version" >&2
  exit 1
else
  status=$?
  # `git ls-remote --exit-code` reserves status 2 for a successful query with
  # no matching ref. Authentication, transport, and server failures use other
  # statuses and must never be mistaken for an available release tag.
  if [[ "$status" -ne 2 ]]; then
    echo "could not prove that $tag is absent from $remote" >&2
    exit 1
  fi
fi
