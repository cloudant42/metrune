#!/usr/bin/env bash
# Verifies that every commit in a range carries a Developer Certificate of
# Origin sign-off matching its own author. See DCO.txt and CONTRIBUTING.md.
#
#   scripts/check-dco.sh origin/main..HEAD
#
# Run it locally before opening a pull request; CI runs the same script over
# the commits the pull request adds.

set -euo pipefail

RANGE="${1:-}"
if [[ -z "$RANGE" ]]; then
  cat >&2 <<'USAGE'
usage: scripts/check-dco.sh <commit-range>

  scripts/check-dco.sh origin/main..HEAD
USAGE
  exit 2
fi

# Automation cannot affirm the certificate on a person's behalf, so commits
# authored by bots are not required to carry a sign-off.
BOT_PATTERN='(\[bot\]|^dependabot|^github-actions)'

failed=0
checked=0
skipped=0

while read -r sha; do
  [[ -z "$sha" ]] && continue

  # A merge commit introduces no authored content of its own; its parents are
  # checked on their own merits.
  if [[ $(git rev-list --parents -n 1 "$sha" | wc -w) -gt 2 ]]; then
    skipped=$((skipped + 1))
    continue
  fi

  author_name=$(git show -s --format='%an' "$sha")
  author_email=$(git show -s --format='%ae' "$sha")

  if [[ "$author_name" =~ $BOT_PATTERN ]] || [[ "$author_email" =~ $BOT_PATTERN ]]; then
    skipped=$((skipped + 1))
    continue
  fi

  checked=$((checked + 1))
  expected="Signed-off-by: ${author_name} <${author_email}>"

  # Normalise line endings and trailing whitespace so a stray CR or space does
  # not fail an otherwise valid trailer. A commit may carry several sign-offs
  # (co-authored work); one matching the author is enough.
  if git show -s --format='%B' "$sha" \
    | sed -e 's/\r$//' -e 's/[[:space:]]*$//' \
    | grep -qiFx "$expected"; then
    continue
  fi

  failed=$((failed + 1))
  subject=$(git show -s --format='%s' "$sha")
  {
    echo "Missing or mismatched sign-off:"
    echo "  commit:   ${sha:0:12}  ${subject}"
    echo "  author:   ${author_name} <${author_email}>"
    echo "  expected: ${expected}"
    echo
  } >&2
done < <(git rev-list "$RANGE")

if [[ "$failed" -gt 0 ]]; then
  cat >&2 <<'REMEDY'
Every commit needs a Developer Certificate of Origin sign-off (see DCO.txt).
The sign-off must match the commit author exactly.

Add one to the most recent commit:

    git commit --amend -s --no-edit

Add one to every commit on your branch:

    git rebase --signoff origin/main

Then force-push the branch. Use `git commit -s` from now on.
REMEDY
  echo "DCO check failed: ${failed} of ${checked} commit(s) are missing a sign-off." >&2
  exit 1
fi

echo "DCO check passed: ${checked} commit(s) signed off, ${skipped} skipped (merges and bots)."
