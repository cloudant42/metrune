#!/usr/bin/env python3
"""Generate the third-party notice file for a release.

THIRD_PARTY_NOTICES.md states that release maintainers must review the
dependency inventories and attach generated notices to release artifacts. This
produces that artifact from the two authoritative inventories: `cargo metadata`
for Rust and `web/node_modules` for the dashboard.

Licenses that carry an attribution or source-availability obligation get their
full license text inlined, because a list of SPDX identifiers alone does not
satisfy them. Permissive dependencies are listed in a table.

Usage:
    python3 scripts/generate-notices.py [--output NOTICE] [--check]

`--check` regenerates into memory and exits non-zero if the file on disk
differs, so CI can catch a stale NOTICE.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_MODULES = REPO_ROOT / "web" / "node_modules"

# Licenses whose terms are not satisfied by a bare SPDX identifier: they require
# the license text to travel with the distribution, and in the copyleft cases
# also a statement of what is used and whether it was modified.
TEXT_REQUIRED = ("GPL", "MPL", "CC-BY", "EPL", "CDDL", "OSL", "CPL")

LICENSE_FILENAMES = (
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENCE",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "COPYING",
    "COPYING.LESSER",
    "NOTICE",
)


def needs_license_text(spdx: str) -> bool:
    """True when every way of satisfying the expression carries an obligation.

    `MIT OR Apache-2.0 OR LGPL-2.1-or-later` is satisfiable by choosing MIT, so
    it needs nothing extra. `Apache-2.0 AND LGPL-3.0-or-later AND MIT` does,
    because the LGPL term is not optional.
    """
    alternatives = [part.strip() for part in spdx.upper().split(" OR ")]
    return all(
        any(marker in alternative for marker in TEXT_REQUIRED)
        for alternative in alternatives
    )


def read_license_texts(directory: Path) -> list[tuple[str, str]]:
    """Every license file in the package directory, as (filename, text).

    Multi-licensed packages ship one file per license, so taking only the first
    would drop exactly the term that created the obligation.
    """
    found = []
    for name in LICENSE_FILENAMES:
        candidate = directory / name
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            continue
        if text:
            found.append((name, text))
    return found


def rust_dependencies() -> list[dict]:
    """Every crate in the resolved graph except the workspace's own members."""
    metadata = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--all-features"],
            cwd=REPO_ROOT,
            capture_output=True,
            check=True,
            text=True,
        ).stdout
    )
    workspace = {member.split()[0] for member in metadata.get("workspace_members", [])}
    packages = []
    for package in metadata["packages"]:
        if package["name"] in workspace and package.get("source") is None:
            continue
        directory = Path(package["manifest_path"]).parent
        packages.append(
            {
                "name": package["name"],
                "version": package["version"],
                "license": package.get("license") or "UNKNOWN",
                "directory": directory,
            }
        )
    return sorted(packages, key=lambda p: (p["name"].lower(), p["version"]))


def npm_dependencies() -> list[dict]:
    """Packages present in the installed dashboard tree.

    Read from node_modules rather than the lockfile because npm lockfiles do
    not record license metadata.
    """
    if not WEB_MODULES.is_dir():
        return []
    packages: dict[tuple[str, str], dict] = {}
    for manifest in WEB_MODULES.glob("**/package.json"):
        try:
            data = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        name, version = data.get("name"), data.get("version")
        if not name or not version:
            continue
        licence = data.get("license") or data.get("licenses") or "UNKNOWN"
        if isinstance(licence, list):
            licence = " OR ".join(
                item.get("type", str(item)) if isinstance(item, dict) else str(item)
                for item in licence
            )
        elif isinstance(licence, dict):
            licence = licence.get("type", "UNKNOWN")
        packages[(name, str(version))] = {
            "name": name,
            "version": str(version),
            "license": str(licence),
            "directory": manifest.parent,
        }
    return sorted(packages.values(), key=lambda p: (p["name"].lower(), p["version"]))


def render_section(title: str, packages: list[dict], note: str) -> list[str]:
    lines = [f"## {title}", "", note, ""]
    if not packages:
        lines += ["_No dependencies were found; the inventory was not available._", ""]
        return lines

    obligated = [p for p in packages if needs_license_text(p["license"])]

    lines += [f"{len(packages)} packages.", "", "| Package | Version | License |", "| --- | --- | --- |"]
    for package in packages:
        lines.append(f"| {package['name']} | {package['version']} | {package['license']} |")
    lines.append("")

    if obligated:
        lines += [
            f"### {title}: licenses requiring their full text",
            "",
            "These are used as published and are not modified by Metrune. Their",
            "complete license texts follow.",
            "",
        ]
        for package in obligated:
            lines += [
                f"#### {package['name']} {package['version']} — {package['license']}",
                "",
            ]
            texts = read_license_texts(package["directory"])
            if texts:
                for filename, text in texts:
                    lines += [f"<!-- {filename} -->", "```text", text, "```", ""]
            else:
                lines += [
                    "> **Action required.** The published package ships no license "
                    f"file, so the {package['license']} text must be obtained from "
                    "the project and pasted here before this artifact is released.",
                    "",
                ]
    return lines


def missing_license_text(packages: list[dict]) -> list[dict]:
    return [
        package
        for package in packages
        if needs_license_text(package["license"]) and not read_license_texts(package["directory"])
    ]


def build() -> str:
    rust = rust_dependencies()
    npm = npm_dependencies()
    lines = [
        "# Third-party notices",
        "",
        "Generated by `scripts/generate-notices.py`. Do not edit by hand.",
        "",
        "Metrune is licensed under Apache-2.0. Each dependency below remains",
        "subject to its own license and copyright; Metrune's license does not",
        "replace those terms. See THIRD_PARTY_NOTICES.md for the policy this",
        "file implements.",
        "",
        "The npm section reflects the packages installed on the machine that",
        "generated it. Generate with `make notices`, which installs with",
        "--omit=dev --omit=optional so the section matches what the runner image",
        "actually ships: dev tooling is not distributed, and the optional sharp",
        "image optimizer is excluded because the dashboard uses no next/image.",
        "",
    ]

    outstanding = missing_license_text(rust) + missing_license_text(npm)
    if outstanding:
        lines += [
            "## Action required before release",
            "",
            "These dependencies carry a license whose text must travel with the",
            "distribution, but the published package contains no license file.",
            "Obtain each text from the upstream project and paste it into the",
            "matching section below.",
            "",
        ]
        for package in outstanding:
            lines.append(
                f"- `{package['name']}` {package['version']} — {package['license']}"
            )
        lines.append("")
    lines += render_section(
        "Rust dependencies",
        rust,
        "Resolved from `cargo metadata --all-features`, excluding Metrune's own crates.",
    )
    lines += render_section(
        "Dashboard (npm) dependencies",
        npm,
        "Read from `web/node_modules`. Run `npm ci` in `web/` before generating, "
        "or this section will be empty.",
    )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="NOTICE")
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if the file on disk differs from freshly generated output",
    )
    arguments = parser.parse_args()
    target = REPO_ROOT / arguments.output
    generated = build()

    if arguments.check:
        if not target.exists():
            print(f"{arguments.output} does not exist; run scripts/generate-notices.py", file=sys.stderr)
            return 1
        if target.read_text(encoding="utf-8") != generated:
            print(f"{arguments.output} is out of date; regenerate it", file=sys.stderr)
            return 1
        print(f"{arguments.output} is up to date")
        return 0

    target.write_text(generated, encoding="utf-8")
    print(f"wrote {arguments.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
