<p align="center">
  <img src="docs/media/metrune-logo.png" alt="Metrune" width="320">
</p>

<p align="center">
  Privacy-first, self-hosted analytics for AI coding agents.
</p>

<p align="center">
  <a href="#client">Client</a> ·
  <a href="#server">Server</a> ·
  <a href="#development">Development</a> ·
  <a href="#privacy">Privacy</a> ·
  <a href="#documentation">Documentation</a>
</p>

---

A local client reads the session stores your coding agents already write,
calculates usage and cost, optionally classifies sessions, and uploads a
deliberately limited metadata schema to a server you run. The web dashboard
shows organizations, teams, members, installations, pricing, and usage.

> **Current version:** a single Linux host deployed with Docker Compose. Good
> for evaluation and internal rollouts; not yet a high-availability platform.
> Kubernetes, Helm and bundled observability are not included.

## Client

### Install

From a Metrune server (the installer is rendered from the signed release
manifest, so it needs no dependencies on the workstation):

```bash
curl -fsSL https://metrune.example.com/v1/client/install.sh | sh
```

Then enroll and start uploading:

```bash
metrune enroll --server https://metrune.example.com --token <enrollment-token>
metrune scan       # read local agent sessions
metrune export     # review exactly what would be uploaded
metrune upload
```

Create the one-time enrollment code on your profile page in the dashboard.
`enroll` also
takes `--name`, `--user-alias` and `--classifier`; run `metrune enroll --help`
for the full set.

`metrune update` verifies and replaces the binary in place. Details and the
air-gapped path are in the [client distribution guide](docs/CLIENT_DISTRIBUTION.md).

<!-- TODO: client screenshot / demo video -->
<!-- <p align="center"><img src="docs/media/client-demo.gif" alt="Metrune client" width="720"></p> -->

### Supported coding CLIs

| Agent | Session store it reads | Setup |
| --- | --- | --- |
| Claude Code | `~/.claude/projects`, `~/.claude/transcripts` | none |
| Codex CLI | `~/.codex/sessions` | none |
| OpenCode | `~/.local/share/opencode` | none |
| GitHub Copilot CLI | `~/.copilot/otel/*.jsonl` | [telemetry export](#github-copilot-cli) |

Restrict a run to one of them with
`metrune scan --clients claude,codex,opencode,copilot`.

#### GitHub Copilot CLI

Copilot only writes token counts when OpenTelemetry file export is switched on,
so enable it in your shell profile **before** starting a session:

```bash
export COPILOT_OTEL_ENABLED=true
export COPILOT_OTEL_EXPORTER_TYPE=file
mkdir -p "$HOME/.copilot/otel"
export COPILOT_OTEL_FILE_EXPORTER_PATH="$HOME/.copilot/otel/copilot-otel-$(date +%Y%m%d-%H%M%S).jsonl"
```

Two consequences worth knowing. Sessions that ran before you enabled this leave
no usage data behind, so there is nothing to backfill. And Copilot's telemetry
carries no workspace attribute, so its sessions group under **Unassigned**
rather than a project.

Metrune reads only the telemetry export, never Copilot's `session-state`
directory — that one holds prompts and responses. Copilot inside VS Code uses a
separate exporter and is not read yet.

### Supported systems

| Platform | Status |
| --- | --- |
| Linux x86_64 (including WSL2) | Supported |
| macOS Intel and Apple Silicon | Experimental |
| Windows x86_64 | Experimental |

Experimental means CI builds and smoke-tests the binary, but installation,
credential storage and long-running watch mode are not yet guaranteed there.

## Server

### Install

The server is a Rust API, PostgreSQL control plane, ClickHouse usage store and
Next.js dashboard, run as one Docker Compose stack.

Local, for trying it out:

```bash
docker compose up --build
```

Open <http://localhost:3001> and sign in as `admin@test.com` / `admin`. These
credentials and port bindings are development-only — never expose this stack.

Production, as a separate standalone stack:

```bash
cp deploy/compose/production.env.example /private/path/metrune.env
# fill in every placeholder, then:
docker compose --env-file /private/path/metrune.env -f compose.production.yaml up -d
```

You also need authenticated TLS SMTP (invitations and password resets depend on
it) and an external HTTPS reverse proxy — a minimal Caddy example is in
[`deploy/compose/Caddyfile.example`](deploy/compose/Caddyfile.example). Every
configurable variable, the bootstrap-admin flow and the backup requirements are
in the [deployment guide](docs/DEPLOYMENT.md) and
[operations runbook](docs/OPERATIONS.md).

### Supported systems

| Platform | Status |
| --- | --- |
| Linux x86_64 with Docker Compose v2 | Supported |
| Kubernetes / Helm / multi-host HA | Not supported |

<!-- TODO: dashboard screenshot / demo video -->
<!-- <p align="center"><img src="docs/media/server-demo.gif" alt="Metrune dashboard" width="720"></p> -->

## Privacy

Uploads carry usage metadata only: pseudonymous installation, user, project and
session identifiers; the project-folder label; provider, model and client
identifiers; tokens, cost, timestamps and classification results.

There are no fields for prompts, responses, source code, patches, tool
arguments, command output, raw session IDs, full paths, classifier summaries or
provider credentials. The folder label can still reveal a project name — set
`METRUNE_PROJECT_MODE=anonymous` where that matters. The exact contract is in
[the privacy model](docs/privacy.md).

## Development

Prerequisites: Rust stable, Node.js 20+, Docker with Compose v2.

```bash
docker compose up --build    # run the full stack locally
make check                   # fmt, clippy, Rust tests, web build, compose contracts
```

Build and inspect the client on its own:

```bash
cargo build --release -p metrune
./target/release/metrune --help
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment](docs/DEPLOYMENT.md) · [Operations](docs/OPERATIONS.md)
- [Client distribution](docs/CLIENT_DISTRIBUTION.md)
- [Privacy](docs/privacy.md) · [Security and logging](docs/SECURITY_AND_LOGGING.md)
- [Authorization](docs/AUTHORIZATION.md) · [Multi-tenancy](docs/MULTI_TENANCY.md) · [Identity](docs/identity.md)
- [Pricing](docs/pricing.md) · [Classifier provisioning](docs/classifier-provisioning.md)
- [Releasing](docs/RELEASING.md) · [Roadmap](docs/ROADMAP.md) · [Changelog](CHANGELOG.md)

## Project

[Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md) ·
[Code of conduct](CODE_OF_CONDUCT.md) ·
[License](LICENSE)
