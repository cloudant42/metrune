#!/usr/bin/env bash
# Validate the independent server/client release tag contract.
#
# Tags are deliberately namespaced so a server release and a client release
# can move independently. All platform artifacts for one client release use
# the same client-vX.Y.Z tag.
set -euo pipefail

component="${1:-}"
tag="${2:-}"
package_version="${3:-}"

case "$component" in
  server) prefix='server-v' ;;
  client) prefix='client-v' ;;
  *) echo "component must be server or client" >&2; exit 2 ;;
esac

case "$tag" in
  "${prefix}"*) version="${tag#"$prefix"}" ;;
  *) echo "$component releases must use ${prefix}X.Y.Z tags (got $tag)" >&2; exit 1 ;;
esac

semver_re='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
if ! [[ "$version" =~ $semver_re ]]; then
  echo "release tag $tag does not contain a complete semantic version" >&2
  exit 1
fi
if [[ "$package_version" != "$version" ]]; then
  echo "$component tag $tag does not match package version $package_version" >&2
  exit 1
fi

printf '%s\n' "$version"
