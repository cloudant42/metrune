<table align="center" border="0" cellpadding="14" cellspacing="0" bgcolor="#f8fafc">
  <tr>
    <td>
      <img src="docs/media/metrune-logo.png" alt="Metrune" width="320">
    </td>
  </tr>
</table>

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

For a visual map of the client/server boundary, start with the
[architecture overview](docs/architecture.md#at-a-glance); the linked guides
then provide the operational detail for deployment, privacy, and releases.

> **First release:** `server-v0.1.0` and `client-v0.1.0`. All client operating
> system artifacts share the one `client-v0.1.0` tag; see the
> [versioning policy](docs/VERSIONING.md). The current support target is a
> single Linux host deployed with Docker Compose for evaluation and internal
> rollouts, not a high-availability platform. Kubernetes, Helm, and bundled
> observability are not included.

## Client

### Install

From a Metrune server (the installer is rendered from the signed release
manifest, so it needs no dependencies on the workstation):

```bash
curl -fsSL https://metrune.example.com/v1/client/install.sh | sh
```

Then enroll and start uploading:

```bash
metrune enroll --server https://metrune.example.com
metrune scan       # read local agent sessions
metrune export     # review exactly what would be uploaded
metrune upload
```

`enroll` shows a 10-minute device code and browser link. Sign in to Metrune,
confirm that the browser and terminal codes match, review the client name and
platform, and approve it. The CLI receives a revocable installation credential;
it never stores your browser session or an identity-provider token. The
credential is kept in the operating-system keyring, with a private mode-`0600`
fallback file when no keyring service is available; ordinary config contains
only its reference. `enroll` also takes `--name`, `--user-alias` and
`--classifier`; run `metrune enroll --help` for the full set. The legacy
`--token` path remains available for controlled automation.

`metrune classifier configure` changes the classifier without re-enrolling.
Use `metrune scan --force` when every source must be re-read instead of using
the existing checkpoints.

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

Open <http://localhost:3001>. The dashboard requires a session, so every page
redirects to the sign-in form until you sign in as `admin@test.com` / `admin`.
These credentials are development-only, and both ports bind to `127.0.0.1`, so
the stack is reachable only from this machine.

Production, as a separate standalone stack:

```bash
cp deploy/compose/production.env.example /private/path/metrune.env
# fill in every placeholder, then:
docker compose --env-file /private/path/metrune.env -f compose.production.yaml up -d
```

SMTP is optional. Configure authenticated TLS SMTP and invitations and password
resets are emailed. Without it the server still starts, logging a warning:
invitations and administrator-issued member resets return a manual link to
deliver yourself, and only self-service password reset is unavailable. You do
need an external HTTPS reverse proxy — a minimal Caddy
example is in
[`deploy/compose/Caddyfile.example`](deploy/compose/Caddyfile.example). Every
configurable variable, the bootstrap-admin flow and the backup requirements are
in the [deployment guide](docs/DEPLOYMENT.md) and
[operations runbook](docs/OPERATIONS.md).

Enterprise deployments can configure one OpenID Connect provider. OIDC then
becomes the only web authentication method; local passwords are used only when
no provider is configured. CLI enrollment remains a public OAuth device flow:
the user approves the machine with their SSO-backed browser session, while the
CLI receives only a Metrune installation credential.

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

Prerequisites: Rust stable, Node.js 24+, Docker with Compose v2.

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
- [Versioning](docs/VERSIONING.md)
- [Privacy](docs/privacy.md) · [Security and logging](docs/SECURITY_AND_LOGGING.md)
- [Authorization](docs/AUTHORIZATION.md) · [Multi-tenancy](docs/MULTI_TENANCY.md) · [Identity](docs/identity.md) · [SSO and client auth](docs/sso-design.md)
- [Pricing](docs/pricing.md) · [Classifier provisioning](docs/classifier-provisioning.md)
- [Releasing](docs/RELEASING.md) · [Roadmap](docs/ROADMAP.md) · [Changelog](CHANGELOG.md)

## Project

[Contributing](CONTRIBUTING.md) ·
[Security policy](SECURITY.md) ·
[Code of conduct](CODE_OF_CONDUCT.md) ·
[License](LICENSE)

Contributions are accepted under an [Individual Contributor License
Agreement](CLA.md). You keep the copyright in your work, and section 7 of that
agreement is a binding commitment that your contribution stays available under
an OSI-approved licence for as long as it is distributed at all. See
[CONTRIBUTING.md](CONTRIBUTING.md#sign-the-cla) for the one-time signing step.

## License

Copyright 2026 Florian Allgöwer

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the
full text and [NOTICE](NOTICE) for third-party dependency notices.
