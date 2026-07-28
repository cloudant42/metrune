# Privacy and security model

## Data that may leave the client

- HMAC-pseudonymous installation-scoped user and project keys, plus a
  deterministic opaque session key shared across enrollments for the same
  coding-CLI source session
- A final project-folder label by default, or an explicit project alias configured by the organization
- Client, provider, model, and client version
- Input, output, cache-read, cache-write, and reasoning tokens
- Reported or estimated cost metadata
- Price catalog version and authority for estimated costs
- Session start/end timestamps
- Category, confidence, taxonomy version, and classifier identifier
- Semantic classification status (`classified`, `not_configured`, `unavailable`,
  `failed`, or `no_input`)

## Data that must never enter an upload

- Prompts or model responses
- Source code, patches, command output, or tool arguments
- Raw session/message IDs
- Full filesystem paths, repository remotes, or unapproved project names
- Local classifier rationale or summaries
- Prompt/message content used for classification
- Classifier credentials are never included in uploads
- OpenRouter or price-catalog API keys

The Rust upload types contain no fields capable of carrying this content. `UsageMessage.classification_text` does not implement serialization, and the privacy contract test searches serialized snapshots for representative secrets.

## Semantic model boundaries

Classification is an explicit organization setting:

- **Local mode:** classification text is sent directly from the client only to
  the configured `METRUNE_CLASSIFIER_ENDPOINT`. A provisioned credential is
  stored in the native system credential store or protected WSL/Linux fallback
  file. A localhost model can keep text local without a provider key.
- **Managed mode:** the client sends bounded classification text to Metrune's
  installation-authenticated classify endpoint. Metrune loads the provider
  credential from its encrypted vault, calls the provider, and returns only the
  category assignment. The provider credential is never returned to the
  client.

Managed classification text is limited to 64 KiB, marked no-store, omitted
from traces and error logs, and never inserted into PostgreSQL, ClickHouse, the
local outbox, or the normal upload envelope. It may still be processed by the
Metrune API and configured model provider, so operators must disclose and
govern that transfer. Metrune never switches from local to managed mode
automatically.

See [MULTI_TENANCY.md](MULTI_TENANCY.md) for the execution trade-off and SaaS
deployment guidance.

## Central controls

- Installation, enrollment, and dashboard bearer tokens are hashed at rest.
- Browser analytics access is scoped by the web session's active organization
  membership; service and installation tokens remain bound to one
  organization.
- Session drilldown requires analyst or admin role.
- ClickHouse retention defaults to 365 days.
- Operational telemetry processors remove prompt, source-code, and raw-session attributes defensively.
- TLS is required for non-local production deployments.

## Known v1 limitations

- Pseudonymous usage can still be sensitive behavioral metadata and requires normal employee monitoring governance.
- Folder labels and explicit project aliases can reveal project names; set `METRUNE_PROJECT_MODE=anonymous` when that is not appropriate.
- SHA-256 token storage assumes high-entropy generated tokens. Human-chosen tokens are unsupported.
