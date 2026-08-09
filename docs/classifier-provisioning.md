# Classifier provisioning

Metrune supports two explicit semantic-classification modes. The server is the
configuration and provisioning control plane for both modes, and is also the
inference router in managed mode.

## Server configuration

The admin classifier panel selects an execution mode and one of four provider
types:

- OpenRouter
- OpenAI
- Ollama/local
- Custom OpenAI-compatible

In **managed** mode, the client sends bounded classification text to Metrune
using its installation credential. Metrune loads the provider credential from
the encrypted organization vault, calls the provider, and returns only the
category assignment. Neither the provider endpoint nor its credential is
returned to the client.

In **local/private** mode, the client calls the provider directly. An
organization may provision the approved endpoint, model, and provider
credential, or a developer may configure an independent OpenAI-compatible
endpoint and their own `METRUNE_CLASSIFIER_API_KEY`. Ollama on localhost does
not normally need a key.

Known providers supply their endpoint and protocol automatically. Custom
providers require an HTTPS endpoint, or HTTP on localhost. The admin chooses a
model and an encrypted vault credential, then can test the configuration with
fixed synthetic text.

Environment variables remain available for unattended deployments:

```text
METRUNE_CLASSIFIER_EXECUTION_MODE=managed
METRUNE_CLASSIFIER_PROVIDER_ID=openrouter
METRUNE_CLASSIFIER_CREDENTIAL_ID=openrouter
METRUNE_CLASSIFIER_ENDPOINT=https://openrouter.ai/api/v1/chat/completions
METRUNE_CLASSIFIER_MODEL=<approved-model>
METRUNE_CLASSIFIER_API_KEY=<deployment-secret>
METRUNE_CLASSIFIER_CONFIG_VERSION=company-1
METRUNE_CLASSIFIER_RESPONSE_MODE=auto
```

Credentials entered in `/admin` are encrypted with AES-256-GCM in PostgreSQL;
the automatically generated master key remains in the protected persistent
server volume. Environment secrets can still come from Docker Secrets, Vault,
or the platform secret manager.

The current database, development Compose, and environment fallback default is
`local`. Managed execution must be selected explicitly. Non-interactive
enrollment uses the organization classifier when one is enabled, otherwise it
disables classification. Making managed execution the ordinary deployment
default is therefore a product/configuration change that has not yet been
made; it must be paired with disclosure that selected semantic text is sent to
Metrune and the configured model provider.

## Choosing a semantic model

A semantic classifier provider must expose an OpenAI-compatible
`POST /v1/chat/completions` endpoint and return reliable JSON in the
`{category, confidence}` shape. In `auto` response mode, the client first tries
strict `json_schema` output and, when the provider rejects that request with
HTTP 400 or 422, retries with prompt-based JSON. It makes one bounded repair
attempt for malformed output. These are compatibility requirements, not a
quality benchmark.

The built-in default for a local classifier is
`http://localhost:11434/v1/chat/completions` with model `qwen2.5-coder:7b`.
Choose another model only after confirming that it supports the endpoint and
reliably returns the required JSON contract.

## Client installation

Enrollment provisions the selected organization classifier automatically. To
refresh it manually, run:

```bash
metrune classifier provision
```

The response is marked `no-store`. In managed mode it contains only the
non-secret profile; classification calls use the existing installation token.
In local/private mode it may also contain the approved endpoint and provider
credential. The client stores that credential in the native system keyring. If
the keyring is unavailable, it uses
`~/.config/metrune/credentials.json` with Unix mode `0600`.

The watch process refreshes every server-provisioned profile every 15 minutes
before scanning, including custom providers in either execution mode. Normal
uploads do not retrieve or transmit provider credentials. `metrune classifier
logout` removes the local profile and any local credential; rerunning
`provision` obtains the current server configuration.

`metrune classifier configure` changes the classifier configuration without
requiring enrollment again. Use it when switching the local/custom endpoint,
model, or classifier mode independently of server provisioning.

## Response handling

The classifier contract is always `{category, confidence}`. In `auto` response
mode, Metrune uses strict structured JSON when supported and automatically
falls back to prompt-based JSON when a provider rejects that parameter;
`prompt_json` profiles use the prompt path directly. It accepts fenced or
wrapped JSON and retries one malformed response. Persistent failures remain
visible as a
`failed` semantic status on the session, with category `unknown` only when a
valid classifier response itself cannot map the session to a supported
category. These outcomes never block usage accounting.

## Privacy boundary

The normal usage upload remains metadata-only in both modes: it cannot contain
prompts, model responses, source code, paths, or classification text. Managed
classification is a separate request containing only the selected, bounded
text assembled for semantic classification; model outputs are not sent. That
text is not stored in the outbox, PostgreSQL, ClickHouse, or analytics payloads.
Local/private mode sends it only to the client-selected provider.

Native enrollment now uses Metrune's browser-assisted OAuth device grant. A
signed-in person confirms the terminal code, client identity, workspace, and
team before the server mints the existing revocable installation credential.
The long-running `watch` process authenticates uploads with that installation
credential and never stores a person's web access or refresh tokens. Browser
OIDC sign-in is supported: when configured, it is the only way to authenticate
the approval page, without changing the CLI grant. Provider credentials remain
a separate concern in local/private mode.
