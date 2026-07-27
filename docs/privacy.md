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

## Local model boundary

Classification text is sent directly from the client only to the configured `METRUNE_CLASSIFIER_ENDPOINT`. The Metrune server may provision the endpoint, model, and provider credential during installation, but it does not proxy or receive classification text. Provisioned credentials are stored locally in the native system credential store or a protected WSL/Linux fallback file. Metrune never falls back to a public model service automatically.

## Central controls

- Installation, enrollment, and dashboard bearer tokens are hashed at rest.
- Analytics access is organization-scoped.
- Session drilldown requires analyst or admin role.
- ClickHouse retention defaults to 365 days.
- Operational telemetry processors remove prompt, source-code, and raw-session attributes defensively.
- TLS is required for non-local production deployments.

## Known v1 limitations

- Pseudonymous usage can still be sensitive behavioral metadata and requires normal employee monitoring governance.
- Folder labels and explicit project aliases can reveal project names; set `METRUNE_PROJECT_MODE=anonymous` when that is not appropriate.
- SHA-256 token storage assumes high-entropy generated tokens. Human-chosen tokens are unsupported.
