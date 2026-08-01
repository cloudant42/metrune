# Changelog

All notable changes are documented here. Release tags and the server/client
compatibility policy are defined in [VERSIONING.md](docs/VERSIONING.md).

## Unreleased

_No unreleased changes yet._

## 0.1.0

First open-source production-beta release for the server and client lines.

### Added

- Expiring, hashed email invitations with resend and revoke controls.
- Password reset with generic request responses, expiring hashed tokens, and
  revocation of existing sessions after completion.
- A standalone four-service production Compose topology and external Caddy
  proxy example.
- Explicit server and client support tiers.
- ESLint with the Next.js flat config, enforced by `make check` and CI. The
  `lint` script previously invoked `next lint`, which Next 16 removed.
- Dependabot for Cargo, npm, and GitHub Actions, and a CODEOWNERS file.
- Deployment-wide OIDC sign-in with discovery, authorization-code plus PKCE,
  verified ID tokens, identity binding, configurable just-in-time
  provisioning, SSO-only password policy, and recent-SSO vault recovery.
- Browser-approved OAuth device enrollment for the native CLI, with hashed
  short-lived codes, explicit approve/deny, workspace/team binding, paced
  polling, and transactional one-time installation credential exchange.
- Protected installation-credential storage in the operating-system keyring or
  a mode-`0600` fallback file, including transparent migration from legacy
  client config.
- An unauthenticated `/v1/server/info` compatibility endpoint, explicit CLI
  version headers, persisted installation version telemetry, and version
  visibility in organization and personal client views.
- An operator-controlled `METRUNE_MINIMUM_CLIENT_VERSION` upload floor with a
  structured HTTP 426 `client_unsupported` response.
- A once-per-24-hours update notice on upload/watch with a
  `METRUNE_NO_UPDATE_CHECK=1` opt-out. Updates remain entirely user initiated.

### Fixed

- The identity panel reports the deployment's enforced OIDC/password mode.
- Browser sessions from a previous authentication mode are rejected on every
  request and revoked at startup, preventing pre-SSO password sessions from
  bypassing enforcement.
- Unsupported clients and schemas no longer leave `watch` silently retrying a
  permanently rejected batch; the client exits with update instructions while
  preserving the queued snapshots.
- ClickHouse workflow and category analytics now use stable nested expansion
  queries, so production ClickHouse 24.8 does not reject dependent aliases.
- Release publishing now fails closed on stale third-party notices, missing
  signing/floor configuration, or a tag/version mismatch; test OIDC keys are
  generated ephemerally rather than stored in the repository.

### Changed

- Production SMTP is required and uses authenticated STARTTLS or implicit TLS.
- The API and CLI entrypoints have been split into focused modules.
- Production bootstrap credentials are rejected after the first user exists.
- The first open-source deployment target is a single Linux Compose host.

### Removed

- The optional `sharp` image optimizer from the dashboard image. The dashboard
  uses no `next/image`, so excluding it keeps the LGPL-3.0 libvips binaries out
  of the published image and clears the outstanding license-text obligation in
  NOTICE.
- Untested Helm charts.
- Bundled Grafana, Prometheus, and OpenTelemetry Collector configurations.
- The unsafe development/production Compose overlay.
