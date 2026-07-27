# Metrune

Metrune is a local-first AI usage intelligence platform for engineering organizations. It tracks token usage and cost across coding agents, classifies sessions by purpose on the developer machine, and sends only sanitized session metadata to a self-hosted analytics service.

The first release supports OpenCode, Claude Code, and Codex CLI on Linux,
Windows, and macOS. Its scanner/parser/normalization boundaries are informed
by [Tokscale](https://github.com/junhoyeo/tokscale), but this repository is an
independent implementation.

## Privacy boundary

Metrune never includes prompts, source code, outputs, raw session IDs, or filesystem paths in its upload schema. The local model sees session text only on the configured local or company-approved endpoint. The central service receives HMAC-pseudonymous identities, token/cost totals, source/model dimensions, timestamps, and a category assignment.

The upload also records a semantic status so valid `unknown` classifications
are distinct from `not_configured`, `unavailable`, `failed`, and `no_input`.
The automated contract tests assert this boundary. See
[docs/privacy.md](docs/privacy.md) for the threat model.

## Architecture

```text
OpenCode / Claude Code / Codex session stores
                    │ read-only adapters
                    ▼
       Rust client + local SQLite outbox
                    │ local classification
                    ▼
       sanitized, revisioned session snapshots
                    │ HTTPS JSON
                    ▼
     Axum API ── Postgres control plane
          │
          └──── ClickHouse analytics ── Next.js dashboard
```

- `crates/metrune-core`: adapters, normalized contracts, pseudonymization, classifier interface, and outbox.
- `crates/metrune-cli`: enrollment, scanning, export, upload, status, and watch commands.
- `crates/metrune-api`: organization-scoped ingestion, analytics, and administration API.
- `web`: responsive dashboard with overview, usage explorer, session drilldown, model matrix, and an admin area for teams, retention, and identity.
- `migrations`: Postgres control-plane and ClickHouse analytics schemas.
- `deploy`: OpenTelemetry and optional operator observability configuration.

## Administration

The dashboard admin area (`/admin`) covers:

- **Teams**: create, rename, and delete teams, and assign enrolled installations. New uploads are stamped with the installation's current team, so re-grouping applies without touching clients.
- **Pricing**: the server imports the default model catalog and lets signed-in members create versioned organization, official-provider, custom-provider, and self-hosted rates. Reported provider cost remains authoritative.
- **Retention**: per-organization retention in days, enforced by a ClickHouse TTL on the per-row stamped retention. Changing the value restamps stored snapshots in the background.
- **Identity and profiles**: local password sign-in uses hashed, revocable web sessions. Every personal enrollment is bound to its owner, and `/profile` filters usage using the owner stamped by the server rather than a client-provided alias. OIDC remains the next identity milestone.

## Development status

Metrune is still in active development. The current checkout is suitable for
development and self-hosted evaluation, but it is not yet a finished
enterprise or public-production release. The [open-source readiness checklist](docs/OPEN_SOURCE_READINESS.md)
tracks the remaining security, operations, community, and enterprise work.

## Local development

Requirements: Rust stable, Node.js 20+, Docker Compose.

```bash
cargo test --workspace
cd web && npm ci && npm run build
docker compose up --build
```

The development stack exposes:

- Dashboard: `http://localhost:3001`
- API: `http://localhost:8080`
- API health: `http://localhost:8080/v1/healthz`
- Postgres and ClickHouse inside the Compose network
- Optional operator stack: `docker compose --profile observability up`

Development-only credentials are seeded by the migrations:

- Enrollment token: `met_enroll_dev`
- Dashboard token: `met_dashboard_dev`
- Profile login: `admin@test.com` / `admin`

Never reuse these values outside local development.

The bootstrap profile is created from `METRUNE_BOOTSTRAP_EMAIL` and
`METRUNE_BOOTSTRAP_PASSWORD`. Set deployment-specific values before first
startup and remove the password from the environment after the account exists.

## Client workflow

```bash
cargo build --release -p metrune

./target/release/metrune enroll \
  --server http://localhost:8080 \
  --token met_enroll_dev \
  --name "Flo workstation" \
  --platform wsl \
  --user-alias employee-17

./target/release/metrune scan
./target/release/metrune export
./target/release/metrune upload
./target/release/metrune watch --interval-seconds 60
```

`watch` is a foreground process intended to be managed by the operating
system's user service manager. It scans changed source files, uploads queued
snapshots, and sleeps between cycles; unchanged files are skipped. The old
`daemon` command remains an alias. No separate install flag is required: the
binary is installed once, while `watch` is simply the long-running process.
Use `watch --quiet` for background operation; routine status output is
suppressed while errors remain available on stderr for service logs.
Organization-managed classifier credentials are refreshed at most every 15
minutes rather than on every polling cycle.

Each local state database stores a checkpoint per discovered source file. A
scan skips a file when its adapter version, classifier configuration, file size,
and modification time are unchanged. Changed files are parsed, but the outbox
keeps only the newest revision for each stable session key and removes it from
the pending queue only after a successful upload. Changing the parser or
classifier configuration intentionally invalidates those checkpoints once.

Enrollment credentials are stored at `~/.config/metrune/config.json` with mode `0600` on Unix. The local SQLite outbox is stored at `~/.local/share/metrune/state.db`.

For a personal installation, sign in at `/profile`, choose Linux, Windows, or
macOS, install the matching artifact, and create a ten-minute one-time
enrollment code. The code can be redeemed once and the server binds the
resulting installation to the signed-in owner. Tag pushes build Linux,
Windows, Intel macOS, and Apple Silicon macOS artifacts through
`.github/workflows/release-client.yml`.

In an interactive terminal, enrollment offers the organization classifier,
a local OpenAI-compatible model, another provider, or classification disabled.
For scripts, select explicitly with `--classifier organization`, `local`,
`custom`, or `none`. Local configuration also accepts
`--classifier-endpoint` and `--classifier-model`; authenticated custom
providers read `METRUNE_CLASSIFIER_API_KEY` into the protected credential
store.

For local Compose development, the Linux client is built into the API image and
served from `http://localhost:8080/v1/downloads/metrune-linux-x86_64`; other
platform artifacts can be served by configuring their corresponding
`METRUNE_*_CLIENT_PATH` values or by pointing the web app at a release asset
base URL.

The server can provision the semantic classifier configuration and credential
once the client is enrolled. The admin UI offers presets for OpenRouter,
OpenAI, and Ollama/local plus a custom OpenAI-compatible endpoint. Provider
presets own their endpoint and protocol defaults, so an administrator normally
chooses only a provider, model, and encrypted credential.

Environment configuration remains available for unattended deployments:

```bash
METRUNE_CLASSIFIER_PROVIDER_ID=openrouter \
METRUNE_CLASSIFIER_CREDENTIAL_ID=openrouter \
METRUNE_CLASSIFIER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions \
METRUNE_CLASSIFIER_MODEL=<openrouter-model-slug> \
METRUNE_CLASSIFIER_API_KEY=<server-side-openrouter-key> \
docker compose up --build
```

Provider credentials can also be managed from `/admin`. Metrune generates an
AES-256-GCM vault key automatically on first startup and stores it with mode
`0600` in the persistent `metrune-secrets` Docker volume. PostgreSQL contains
only authenticated ciphertext and credential version metadata. Replacing a
credential creates a new version and a client receives it on its next
classifier provisioning refresh. The admin can export the vault recovery key
once after confirming their password.

Classifier response handling is automatic. Known hosted providers first use a
strict JSON schema and fall back when a model rejects structured output.
Ollama and custom OpenAI-compatible endpoints use prompt-based JSON by default.
Metrune tolerates fenced or wrapped JSON, retries one malformed response, and
degrades to `unknown` without blocking usage collection. The admin
**Test configuration** action sends fixed synthetic text and never session
content.

Enrollment will attempt provisioning automatically. To provision again or refresh the profile later, run:

```bash
./target/release/metrune classifier provision
./target/release/metrune classifier status
```

The server sends the URL, model, and credential only through this authenticated provisioning call. The client stores the credential in the native system keyring when available, with a `0600` fallback file for WSL/Linux environments without a keyring. The credential is never written to the regular Metrune config or upload queue. Classification continues to run directly from the client to the configured endpoint.

To use a temporary client-side override instead, configure an OpenAI-compatible endpoint:

```bash
export METRUNE_CLASSIFIER_ENDPOINT=http://localhost:11434/v1/chat/completions
export METRUNE_CLASSIFIER_MODEL=qwen3:4b
```

OpenRouter is also supported. The classifier is OpenAI-compatible; only the local classification text is sent to the endpoint you explicitly configure:

```bash
export METRUNE_CLASSIFIER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions
export METRUNE_CLASSIFIER_MODEL=<openrouter-model-slug>
export METRUNE_CLASSIFIER_API_KEY=<your-openrouter-key>
```

Environment variables override the provisioned profile and are useful for CI or one-off testing. They are not required after provisioning.

Without a configured classifier, sessions are safely uploaded as `unknown`.

By default, the client keeps the full project path local, pseudonymizes the full path into `projectKey`, and sends only the final folder name as `projectAlias`. Set `METRUNE_PROJECT_MODE=anonymous` to suppress the readable folder label while retaining the anonymous project key. Explicit entries in `project_aliases` take precedence over the derived folder label.

Reported provider costs are preserved. The server imports
`pricing/openrouter.catalog.json` as its default catalog and applies active
organization overrides at ingest time. Signed-in members manage those entries
under **Teams & settings → Pricing**; edits affect new ingestion and do not
silently rewrite historical totals.

The client-side pricebook remains available for offline/local estimates. Point
`METRUNE_PRICEBOOK` at either the legacy `fixtures/pricebook.example.json`
format or a versioned catalog. A catalog can be refreshed manually from
OpenRouter's public model catalog:

```bash
./target/release/metrune pricing sync-openrouter \
  --output pricing/openrouter.catalog.json

export METRUNE_PRICEBOOK="$PWD/pricing/openrouter.catalog.json"
./target/release/metrune scan
```

The command fetches the current model list and converts OpenRouter's dollar-per-token rates into per-million-token rates. It is intentionally manual, so teams can review and commit each catalog revision. If a catalog contains organization or self-hosted rates, preserve them while refreshing OpenRouter with `--merge-from pricing/company.catalog.json`. See `fixtures/price-catalog.example.json` for the authority-aware format.

For a company-maintained catalog, first generate the file and add any `organization_override` or `self_hosted` entries from `fixtures/price-catalog.example.json`. On later refreshes, keep those entries and replace only the OpenRouter entries:

```bash
./target/release/metrune pricing sync-openrouter \
  --output pricing/company.catalog.json \
  --merge-from pricing/company.catalog.json
```

`--merge-from` replaces old OpenRouter entries and retains non-OpenRouter entries, so self-hosted and negotiated rates survive a refresh.

Price authority is resolved per provider/model: organization overrides win first, then self-hosted, official-provider, OpenRouter, and manual entries. Provider-reported costs always remain authoritative and are never overwritten by a catalog estimate. Each estimate records both the catalog version and its price authority.

## Validation

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cd web && npm run typecheck && npm run build
docker compose config --quiet
```

Metrune is licensed under Apache-2.0.
