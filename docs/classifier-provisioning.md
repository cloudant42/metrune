# Classifier provisioning

Metrune uses the server as a configuration and provisioning control plane. It
does not proxy client classification requests.

## Server configuration

The admin classifier panel provides four intentionally small choices:

- OpenRouter
- OpenAI
- Ollama/local
- Custom OpenAI-compatible

Known providers supply their endpoint and protocol automatically. Custom
providers require an HTTPS endpoint, or HTTP on localhost. The admin chooses a
model and an encrypted vault credential, then can test the configuration with
fixed synthetic text.

Environment variables remain available for unattended deployments:

```text
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
server volume. Environment secrets can still come from Docker Secrets,
Kubernetes Secrets, Vault, or the platform secret manager.

## Client installation

Enrollment provisions the selected organization classifier automatically. To
refresh it manually, run:

```bash
metrune classifier provision
```

The authenticated client request returns the classifier URL, model, credential ID, and credential. The response is marked `no-store`. The client writes only the non-secret profile to its Metrune config and stores the credential in the native system keyring. If the keyring is unavailable, it uses `~/.config/metrune/credentials.json` with Unix mode `0600`.

The watch process refreshes organization-managed profiles before scanning. Normal
uploads do not retrieve or transmit the credential. `metrune classifier
logout` removes the local profile and credential; rerunning `provision`
obtains the current server configuration.

## Response handling

The classifier contract is always `{category, confidence}`. Metrune uses strict
structured JSON when supported, automatically falls back to prompt-based JSON
when a provider rejects that parameter, accepts fenced or wrapped JSON, and
retries one malformed response. Persistent failures remain visible as a
`failed` semantic status on the session, with category `unknown` only when a
valid classifier response itself cannot map the session to a supported
category. These outcomes never block usage accounting.

## Privacy boundary

The classifier request is sent directly from the client to the configured
endpoint. The Metrune API receives neither the classifier text nor the
provider response. The admin test uses only a fixed synthetic sentence. The
server controls the approved endpoint and model, while the client retains the
execution and session-content boundary.

OAuth for Metrune can replace the development enrollment token later. It should authenticate the user and installation to Metrune; it should remain separate from the locally stored provider credential.
