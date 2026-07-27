# Architecture

## Client pipeline

Each `SourceAdapter` discovers known local storage, parses provider-specific records into `UsageMessage`, and returns no provider-owned object beyond that boundary. OpenCode uses read-only SQLite or legacy JSON; Claude Code and Codex use JSONL session stores. Session snapshots use a deterministic, domain-separated hash of `(client, source session ID)`, so rescanning the same session with another enrollment produces the same server identity across all supported CLIs.

`UsageMessage.classification_text` is deliberately local-only and cannot be serialized. Messages are grouped into a complete `SessionSnapshot`, with token/cost slices by provider and model. Raw user, project, and session identifiers are HMAC-pseudonymized before the snapshot enters SQLite.

The outbox keeps the newest revision of each session. An upload is acknowledged only after the server accepts the batch. Offline and failed uploads remain queued. The server’s authoritative ClickHouse table keys by organization, owner, and deterministic session key; installation ID remains payload metadata for a user’s per-client filter and is not part of the deduplication key.

## Classification

The classifier contract accepts local session text and returns one category, confidence, taxonomy version, and classifier identifier. Supported categories are implementation, debugging, research, documentation, review/refactoring, testing, planning, operations, content, and unknown. Snapshots also record a semantic classification status: a valid classifier result is `classified` (including a valid `unknown` category), while disabled, unavailable, malformed, and no-input cases are tracked separately.

The initial backend targets Ollama and other OpenAI-compatible local or company-approved endpoints. The server can provision the endpoint, model, taxonomy configuration, and a provider credential once per installation; the client stores the credential locally and sends classification requests directly to the configured engine. The server never receives classification text. Invalid output, timeouts, or unavailable models never block usage accounting and are retained as non-classified semantic status on the pseudonymous session.

## Server

Postgres owns transactional control-plane data: organizations, enrollment and dashboard tokens, installations, roles, and completed ingest batches. Tokens are stored as SHA-256 digests. Classifier provisioning reads the server-side provider configuration from deployment secrets and returns it only over an authenticated, no-store installation request. ClickHouse owns revisioned session snapshots and analytical queries. The analytics API exposes overview, time-series, one-dimensional breakdowns, and a category/model matrix so the dashboard can show which models are used for each semantic category.

Every analytics query receives its organization ID from the authenticated dashboard token; the browser never connects to ClickHouse directly. Viewer tokens can read aggregates, while analyst and admin tokens can access pseudonymous session drilldown.

OpenTelemetry is reserved for operational metrics, logs, and traces. Product usage records use the versioned domain schema so high-cardinality sessions never become metric labels.

## Compatibility

- `schemaVersion` versions the upload envelope and individual snapshots.
- Session updates use a monotonically increasing revision and ClickHouse `ReplacingMergeTree` semantics.
- Unknown fields can be added compatibly; breaking field changes require a new schema version.
- Source adapters are independent and can be added without changing the upload contract.

## Teams and retention

Teams are first-class control-plane entities. Administrators group
installations into teams in the dashboard; the server stamps each ingested
snapshot with the installation's current team name, so re-grouping affects
new uploads without client changes. Analytics filter and break down by the
stamped team.

Every snapshot row also carries the organization's `retention_days` at ingest
time, and a ClickHouse TTL deletes rows past their stamped retention. Changing
retention in the admin area updates Postgres and issues a background mutation
that restamps existing rows, so the new window applies to historical data too.

## Identity

The control plane provisions the enterprise identity schema (users, OIDC
provider connections, web sessions, group mappings, audit events) ahead of
the sign-in flows. Local passwords are the default and are disabled when SSO
is enforced. See [docs/identity.md](identity.md) for the model and rollout.
