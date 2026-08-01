# Security policy

Metrune is under active development. Do not report suspected vulnerabilities,
credentials, or private usage data in a public issue.

## Reporting a vulnerability

Report suspected vulnerabilities through a private GitHub Security Advisory
for this repository: open the repository's **Security** tab, choose
**Advisories**, and select **Report a vulnerability**. This URL-independent
flow stays valid even if the repository is renamed or moved.

Do not open a public issue as a substitute.

If the advisory flow is unavailable to you, email <cloudant42@gmail.com> with
"metrune security" in the subject and no sensitive detail in the body; a
maintainer will move the report into a private advisory. The advisory flow is
preferred, because it keeps the report, the fix, and any CVE together.

Include the affected version or commit, deployment mode, reproduction steps,
impact, and a minimal proof of concept. Redact tokens, provider keys, prompts,
source code, and organization data from reports and logs.

Maintainers aim to acknowledge reports within five business days and will
coordinate disclosure, fixes, and release notes with the reporter. Timelines
can vary while the project is pre-release.

## Supported versions

During the production beta, only the latest production-beta release is
security-supported. Linux x86_64 is the supported client/server platform;
Windows and macOS client artifacts are experimental. See the README support
matrix and release notes for version-specific exceptions.
