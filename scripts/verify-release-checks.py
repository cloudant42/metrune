#!/usr/bin/env python3
"""Wait for the required CI/security checks for the release commit.

Tag workflows are independent of the push workflow that produced their
artifacts. This gate prevents a tag from publishing while a required check is
still running (or after one has failed). It intentionally uses the GitHub CLI
provided by hosted runners rather than a third-party action.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime

REQUIRED = (
    "rust",
    "web",
    "e2e",
    "deployment",
    "rust-audit",
    "rust-licenses",
    "npm-licenses",
    "npm-audit",
    "github-actions-scan",
    "filesystem-scan",
    "container-images",
)


def stamp(value: str | None) -> datetime:
    if not value:
        return datetime.min
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def check_runs() -> list[dict]:
    repository = os.environ["GITHUB_REPOSITORY"]
    sha = os.environ["GITHUB_SHA"]
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repository}/commits/{sha}/check-runs",
            "--paginate",
            "--slurp",
            "--header",
            "Accept: application/vnd.github+json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    pages = json.loads(result.stdout or "[]")
    return [run for page in pages for run in page.get("check_runs", [])]


def main() -> int:
    attempts = int(os.environ.get("METRUNE_RELEASE_GATE_ATTEMPTS", "60"))
    interval = int(os.environ.get("METRUNE_RELEASE_GATE_INTERVAL", "30"))
    for attempt in range(1, attempts + 1):
        runs = check_runs()
        latest: dict[str, dict] = {}
        for run in runs:
            name = str(run.get("name", "")).split(" / ")[-1]
            if name in REQUIRED and stamp(run.get("started_at")) >= stamp(
                latest.get(name, {}).get("started_at")
            ):
                latest[name] = run

        pending: list[str] = []
        failed: list[str] = []
        for name in REQUIRED:
            run = latest.get(name)
            if run is None or run.get("status") != "completed":
                pending.append(name)
            elif run.get("conclusion") != "success":
                failed.append(f"{name}={run.get('conclusion')}")

        if failed:
            print("required release checks failed: " + ", ".join(failed), file=sys.stderr)
            return 1
        if not pending:
            print("all required CI and security checks passed")
            return 0
        print(f"release gate attempt {attempt}/{attempts}; pending: {', '.join(pending)}")
        if attempt < attempts:
            time.sleep(interval)

    print("timed out waiting for required CI/security checks", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
