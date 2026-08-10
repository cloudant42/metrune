#!/usr/bin/env bash
# Print the committed release version for one release line.
#
# The version in the repository is the only place a release number is
# written. Releases are triggered by hand from a merged commit, and the
# workflow derives its tag from this value rather than asking an operator to
# retype it. The server and client move independently, so they read from
# different manifests: the client keeps its own package version because a
# client release must not be forced by a server bump.
set -euo pipefail

component="${1:-}"

case "$component" in
  server) manifest='Cargo.toml' ;;
  client) manifest='crates/metrune-cli/Cargo.toml' ;;
  *) echo "component must be server or client" >&2; exit 2 ;;
esac

version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$manifest" | head -1)"

if [ -z "$version" ]; then
  echo "no version found in $manifest" >&2
  exit 1
fi

printf '%s\n' "$version"
