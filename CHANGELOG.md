# Changelog

All notable changes are documented here. The project follows Semantic
Versioning after the first beta tag.

## Unreleased

### Added

- Expiring, hashed email invitations with resend and revoke controls.
- Password reset with generic request responses, expiring hashed tokens, and
  revocation of existing sessions after completion.
- A standalone four-service production Compose topology and external Caddy
  proxy example.
- Explicit server and client support tiers.

### Changed

- Production SMTP is required and uses authenticated STARTTLS or implicit TLS.
- The API and CLI entrypoints have been split into focused modules.
- Production bootstrap credentials are rejected after the first user exists.
- The first open-source deployment target is a single Linux Compose host.

### Removed

- Untested Helm charts.
- Bundled Grafana, Prometheus, and OpenTelemetry Collector configurations.
- The unsafe development/production Compose overlay.

## 0.1.0-beta.1

First planned open-source production-beta release.
