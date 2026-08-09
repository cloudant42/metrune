# Roadmap

The production beta deliberately keeps one narrow support contract. Items
below are candidates, not current promises.

## Before stable 1.0

- Validate OIDC federation and recovery runbooks against the supported
  enterprise providers, and add a host-controlled break-glass process for
  SSO-only administrators.
- Exercise installation, upgrade, backup, and restore on a clean Linux host.
- Add full SMTP invitation/reset delivery integration tests with a disposable
  mail server, while retaining coverage for manual invitation and
  administrator-issued reset links when no mailer is configured.
- Publish compatibility and migration guarantees.
- Attach the reviewed, generated third-party notice artifact to every release
  and keep it in sync with the production dashboard dependency tree.
- Perform an external security and privacy review.
- Define measurable availability and data-recovery objectives.
- Exercise the signed-release provenance gate end to end on GitHub, including
  canonical client self-install and promotion of the scanned image digest.
- Extend the adversarial ingestion fixtures to cover sustained retry,
  concurrent uploads, and a full operator-run quarantine/replay procedure.
- Add an explicit ClickHouse migration ledger and operator-facing compatibility
  check for independent database upgrades; the beta currently relies on
  idempotent startup changes and migration directories from the same server
  release tag.
- Complete an external authorization/privacy review, including the already
  implemented export, reverse-proxy, credential, and browser fail-closed
  controls.

## Later deployment options

- Kubernetes packaging only after persistence, disruption, upgrade, and
  rollback behavior has automated tests.
- An optional observability bundle only after its metrics, cardinality,
  retention, authentication, and privacy contracts are documented.
- High-availability PostgreSQL, ClickHouse, API, and web guidance.

## Identity and platform

- Multiple identity providers per deployment, per-organization connections,
  email-domain routing, and group-to-role mapping.
- SCIM provisioning and organization audit-log UI.
- Promote Windows and macOS clients after platform-specific installer,
  credential-store, and watch-mode tests.
