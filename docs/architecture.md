# Architecture

## Client pipeline

Each source adapter reads a known local coding-agent store and converts records
into shared usage values. Raw prompts, responses, code, paths, and
provider-owned objects do not cross that boundary. Classification text is
local-only in the Rust type system and cannot be serialized.

Messages become revisioned session snapshots. Raw user, project, and session
identifiers are HMAC-pseudonymized before entering the SQLite outbox. The
outbox retains failed uploads and removes a revision only after server
acknowledgement.

## Classification

An organization explicitly chooses local or managed execution. Local mode
calls the configured model from the client. Managed mode sends at most 64 KiB
of classification text to the authenticated API, which resolves an encrypted
provider credential and returns only a category result. Neither path puts
classification text in the normal upload schema or analytics databases.

Classification failure never blocks usage accounting. A snapshot records
whether classification succeeded, was not configured, was unavailable,
failed, or had no input.

## Server

PostgreSQL owns transactional control-plane data: accounts, memberships,
sessions, invitations, reset tokens, teams, installations, settings, pricing,
and encrypted provider credentials. ClickHouse owns revisioned usage snapshots
and analytical queries. The browser communicates through the Next.js
server-side proxy and never connects directly to either database.

The API authenticates a web session, service token, installation token, or
one-time enrollment credential. Organization scope is derived from that
credential rather than accepted from the request.

## Deployment

The supported beta topology is one Linux host with four Compose services:
PostgreSQL, ClickHouse, API, and web. An external same-host reverse proxy owns
HTTPS. The repository does not bundle a telemetry collector or monitoring
suite; operators use container logs and the `/v1/healthz` and `/v1/readyz`
endpoints until an observability contract is defined.

## Source layout

- `crates/metrune-core`: upload schema, adapters, classification, and pricing.
- `crates/metrune-cli`: small entrypoint plus CLI application and credential
  storage modules.
- `crates/metrune-api`: small entrypoint plus application routing, identity,
  mail, limits, and error modules.
- `web`: dashboard pages, components, and server-side API proxy.

## Compatibility

- `schemaVersion` versions the upload envelope and snapshots.
- Session revisions increase monotonically; ClickHouse replacement semantics
  keep the latest accepted revision.
- Additive unknown fields are compatible; breaking payload changes require a
  new schema version.
- Forward-only database migrations are tied to a tagged release and documented
  in its rollback notes.
