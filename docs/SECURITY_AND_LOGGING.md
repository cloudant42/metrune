# Security and logging boundary

Metrune is designed for self-hosted deployment. Operators are responsible for
placing the API and dashboard behind HTTPS and for restricting access to the
PostgreSQL, ClickHouse, and vault-key storage volumes.

## Request correlation

The API creates an `x-request-id` UUID when the caller does not provide one and
returns it on the response. A trusted reverse proxy may provide an existing
request ID for end-to-end correlation. The API cannot distinguish a
proxy-provided request ID from a client-forged one, so the reverse proxy must
overwrite or strip any inbound `x-request-id` header from untrusted clients.
Include the request ID when reporting an error or investigating a failed
client upload.

## Login throttling

Failed sign-ins are throttled per email address after repeated failures within
a one-minute window. A correct password always succeeds and clears the window,
so the throttle cannot be used to lock out a legitimate account holder. The
throttle state is per API instance and resets on restart. Additional
per-source-IP throttling belongs at the reverse proxy, which is the only layer
that sees the real client address.

## What the API logs

The default HTTP trace includes the method, URI, status, latency, and request
ID. It does not include request or response headers, cookies, authorization
values, request bodies, prompts, source code, classifier text, provider API
keys, passwords, or installation tokens. Keep this header-free trace behavior
when changing the middleware configuration. The trace span includes the full
request URI, so endpoints must never accept tokens or other secrets in query
parameters.

Application errors returned to clients should be actionable without exposing
database connection strings, vault material, provider responses, or other
internal secrets. Treat logs as sensitive operational data: restrict access,
apply the organization's retention policy, and avoid enabling debug logging in
production unless the additional data has been reviewed.

## Deployment boundary

Terminate TLS at the ingress or reverse proxy, forward only the required
headers, and do not expose PostgreSQL, ClickHouse, or the vault-key volume to
the public network. Set `METRUNE_ENV=production` and use an HTTPS
`METRUNE_PUBLIC_API_URL` before exposing the API to users. The production
Compose override binds the API and dashboard to localhost by default; replace
that boundary only when an equivalent network policy and TLS termination are
in place.
