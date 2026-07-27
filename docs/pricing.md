# Price catalog

Metrune accepts either the legacy `pricebook.example.json` shape or a versioned catalog with `schemaVersion`, `catalogVersion`, and `entries`.

The client can manually import the current OpenRouter model catalog:

```bash
metrune pricing sync-openrouter --output pricing/company.catalog.json
```

OpenRouter rates are returned in USD per token/request/unit and token rates are stored as USD per million tokens. The catalog also retains request and image-unit rates for future usage dimensions; the current client applies input, output, cache, and reasoning token rates. Models whose input or output price is unavailable (`-1` in the OpenRouter response) are skipped instead of being treated as free. The generated catalog includes the retrieval timestamp and source URL.

Each entry has a provider/model scope and an authority:

| Authority | Intended use | Priority |
| --- | --- | ---: |
| `organization_override` | negotiated enterprise rate or internal chargeback | 50 |
| `self_hosted` | GPU/infrastructure rate for a self-hosted endpoint | 40 |
| `official_provider` | provider-published rate from a non-OpenRouter source | 30 |
| `openrouter` | imported OpenRouter catalog rate | 20 |
| `manual` | legacy/manual fallback entry | 10 |

An entry with a specific `providerId` wins over a provider-agnostic entry at the same authority. Provider-reported costs remain untouched. Estimated costs record both `pricebookVersion` and `priceSource`, making later audits possible.

For self-hosted deployments, use the provider ID emitted by the adapter or gateway. For example, a `vllm/qwen3-coder` entry with `self_hosted` authority can carry an internal cost-allocation rate, while an `openrouter/moonshotai/kimi-k3` entry can retain the public reference rate. The central server does not need raw prompts or credentials to use these estimates; the client resolves the catalog locally before upload.
