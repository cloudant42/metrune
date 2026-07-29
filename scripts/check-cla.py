#!/usr/bin/env python3
"""Verify that a pull request's author has signed the Contributor License
Agreement recorded in signatures/cla.json.

Contributors sign by adding themselves to that file in their first pull
request, so the signature is a commit attributed to them in git history rather
than a record held by a third-party service. That keeps the whole mechanism
inside the repository: no external app holds write access, and nothing here
needs `pull_request_target`.

Usage:
    scripts/check-cla.py <github-username>
    scripts/check-cla.py --list
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SIGNATURES = REPO_ROOT / "signatures" / "cla.json"
CLA = REPO_ROOT / "CLA.md"

# The maintainer is the party the agreement grants rights *to* and cannot sign
# an agreement with themselves. Bots author no copyrightable work.
ALLOWLIST = {
    "cloudant42",
    "dependabot[bot]",
    "github-actions[bot]",
    "renovate[bot]",
}

SIGN_INSTRUCTIONS = """
To sign, add yourself to signatures/cla.json in this pull request:

    {
      "githubUsername": "your-github-username",
      "name": "Your Full Name",
      "signedAt": "YYYY-MM-DD",
      "claVersion": "1.0"
    }

Adding that entry, in a commit authored by you, is your signature on CLA.md.
Read CLA.md first — section 7 is the commitment made to you in return.
"""


def load_signatures() -> dict:
    if not SIGNATURES.is_file():
        raise SystemExit(f"missing {SIGNATURES.relative_to(REPO_ROOT)}")
    try:
        return json.loads(SIGNATURES.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise SystemExit(
            f"{SIGNATURES.relative_to(REPO_ROOT)} is not valid JSON: {error}"
        ) from error


def validate_entry(entry: object, index: int) -> list[str]:
    problems = []
    if not isinstance(entry, dict):
        return [f"entry {index} is not an object"]
    for field in ("githubUsername", "name", "signedAt", "claVersion"):
        value = entry.get(field)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"entry {index} is missing a non-empty {field!r}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", nargs="?", help="the pull request author's GitHub login")
    parser.add_argument("--list", action="store_true", help="print everyone who has signed")
    arguments = parser.parse_args()

    document = load_signatures()
    signatories = document.get("signedContributors")
    if not isinstance(signatories, list):
        raise SystemExit("signedContributors must be a list")

    problems = []
    for index, entry in enumerate(signatories):
        problems.extend(validate_entry(entry, index))
    if problems:
        for problem in problems:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    signed = {
        entry["githubUsername"].strip().lower()
        for entry in signatories
        if entry["githubUsername"].strip()
    }

    duplicates = len(signatories) - len(signed)
    if duplicates:
        print(f"error: signatures/cla.json contains {duplicates} duplicate signatory", file=sys.stderr)
        return 1

    if arguments.list:
        for entry in sorted(signatories, key=lambda e: e["githubUsername"].lower()):
            print(f"{entry['githubUsername']:24} {entry['signedAt']}  CLA v{entry['claVersion']}")
        print(f"\n{len(signatories)} signatory/signatories.")
        return 0

    if not arguments.username:
        parser.error("a username is required unless --list is given")

    username = arguments.username.strip()
    if username.lower() in {name.lower() for name in ALLOWLIST}:
        print(f"{username} does not need to sign the CLA (maintainer or bot).")
        return 0

    if username.lower() in signed:
        print(f"{username} has signed the CLA.")
        return 0

    print(f"{username} has not signed the Contributor License Agreement.", file=sys.stderr)
    print(SIGN_INSTRUCTIONS, file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
