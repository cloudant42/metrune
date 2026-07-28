# Metrune

Metrune is a privacy-first, self-hosted analytics platform for AI coding
agents. A local Rust client reads supported agent stores, calculates usage and
cost data, optionally classifies sessions, and uploads a deliberately limited
metadata schema. The web app provides organization, team, member, installation,
pricing, and usage views.

> **Release status:** production beta. The first open-source release supports a
> single Linux host deployed with Docker Compose. It is suitable for evaluation
> and controlled internal rollouts, but it is not yet a high-availability
> platform.

## What is in the beta

- A Rust client for scanning, exporting, uploading, watching, local
  classification, and price-catalog management.
- A Rust API, PostgreSQL control plane, and ClickHouse usage store.
- A Next.js dashboard with organization-scoped roles and personal analytics.
- Installation enrollment, email invitations, password resets, and revocable
  browser sessions.
- Local or operator-managed semantic classification with explicit privacy
  boundaries.
- One supported production deployment: the standalone
  [`compose.production.yaml`](compose.production.yaml) stack behind an external
  HTTPS reverse proxy.

The beta intentionally does **not** include Helm, Kubernetes, an embedded
reverse proxy, Grafana, Prometheus, or an OpenTelemetry collector. Those can be
added later when their contracts and operating procedures are tested.

## Support matrix

| Surface | Beta status |
| --- | --- |
| Server on Linux x86_64 with Docker Compose v2 | Supported |
| External HTTPS reverse proxy on the same host | Supported |
| Linux x86_64 client, including WSL2 | Supported |
| Windows x86_64 client | Experimental artifact |
| macOS Intel and Apple Silicon clients | Experimental artifacts |
| Kubernetes / Helm / multi-host HA | Not supported |
| Bundled Grafana, Prometheus, or OTEL collector | Not included |

“Experimental” means the release workflow builds and smoke-tests the binary,
but the project does not yet promise full installation, credential-store, and
long-running watch-mode support on that platform.

## Privacy boundary

The normal upload contains usage metadata: pseudonymous installation, user,
project, and session identifiers; the final project-folder label by default;
provider/model/client identifiers; token and cost figures; timestamps; and
classification results.

It does not have fields for prompts, model responses, source code, patches,
tool arguments, command output, raw message/session IDs, full filesystem paths,
classifier summaries, or provider credentials. The default folder label can
still reveal a project name; set `METRUNE_PROJECT_MODE=anonymous` where that is
not appropriate. See [the privacy model](docs/privacy.md) for the exact
contract.

## Local development

Prerequisites:

- Rust stable
- Node.js 20+
- Docker with Compose v2

Start the development stack:

```bash
docker compose up --build
```

Open <http://localhost:3001> and sign in with the development-only account
`admin@test.com` / `admin`. The known credentials and broad application port
bindings in the development stack are not suitable for a shared or production
host.

Run the repository checks:

```bash
make check
```

The check covers formatting, Clippy, Rust tests, web type-check/build, and both
the development and production Compose contracts.

## Production deployment

Production is a separate, standalone stack; do not merge it with
`compose.yaml`.

1. Publish or obtain the released API and web image digests.
2. Copy [`deploy/compose/production.env.example`](deploy/compose/production.env.example)
   to a private environment file and replace every placeholder.
3. Configure authenticated TLS SMTP. Invitation and password-reset flows
   require it.
4. Configure an external HTTPS reverse proxy. A minimal Caddy example is in
   [`deploy/compose/Caddyfile.example`](deploy/compose/Caddyfile.example).
5. Validate and start the stack:

```bash
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml config
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml up -d
```

The first administrator is created from the one-time bootstrap values. After
the first successful sign-in, clear both bootstrap variables and recreate the
API container. Startup deliberately fails if bootstrap credentials remain
configured once a user already exists.

Follow the complete [deployment guide](docs/DEPLOYMENT.md) and
[operations runbook](docs/OPERATIONS.md), especially the backup requirement
for PostgreSQL, ClickHouse, and the credential-vault key.

## Client

Build and inspect the CLI:

```bash
cargo build --release -p metrune
./target/release/metrune --help
```

A typical installation enrolls once, scans locally, verifies the sanitized
envelope, and uploads:

```bash
metrune enroll --help
metrune scan
metrune export
metrune upload
```

`metrune export` is the easiest way to review exactly what is queued before
connecting a client to a server.

## Repository map

```text
crates/                 Rust client, API, and shared domain types
web/                    Next.js dashboard and server-side API proxy
migrations/             PostgreSQL and ClickHouse schema
deploy/compose/         Production environment and reverse-proxy examples
docs/                   Architecture, privacy, security, and operations
scripts/                Validation and restore-drill automation
compose.yaml            Development stack
compose.production.yaml Supported production-beta stack
```

## Project policy

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release process](docs/RELEASING.md)
- [Roadmap](docs/ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [License](LICENSE)
