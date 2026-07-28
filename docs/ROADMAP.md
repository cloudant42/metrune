# Roadmap

The production beta deliberately keeps one narrow support contract. Items
below are candidates, not current promises.

## Before stable 1.0

- Exercise installation, upgrade, backup, and restore on a clean Linux host.
- Add full SMTP invitation/reset integration tests with a disposable mail
  server.
- Publish compatibility and migration guarantees.
- Complete dependency-license notice generation in the release workflow.
- Perform an external security and privacy review.
- Define measurable availability and data-recovery objectives.

## Later deployment options

- Kubernetes packaging only after persistence, disruption, upgrade, and
  rollback behavior has automated tests.
- An optional observability bundle only after its metrics, cardinality,
  retention, authentication, and privacy contracts are documented.
- High-availability PostgreSQL, ClickHouse, API, and web guidance.

## Identity and platform

- OIDC authorization-code + PKCE and just-in-time provisioning.
- SCIM provisioning and organization audit-log UI.
- Promote Windows and macOS clients after platform-specific installer,
  credential-store, and watch-mode tests.
