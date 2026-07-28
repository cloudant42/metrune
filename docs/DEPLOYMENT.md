# Production deployment

## Supported topology

The production beta supports one Linux x86_64 host running Docker Engine and
Compose v2. `compose.production.yaml` is standalone and runs exactly four
services: PostgreSQL, ClickHouse, the Metrune API, and the web app.

PostgreSQL and ClickHouse are reachable only on internal Compose networks. The
API and web ports bind to `127.0.0.1` for a same-host HTTPS reverse proxy. The
API also has outbound access for SMTP and an optional managed classifier.

Kubernetes, Helm, multi-host failover, and a bundled observability stack are
outside the beta support contract.

## Prepare

1. Copy `deploy/compose/production.env.example` outside the checkout.
2. Set mode `0600` and replace every placeholder.
3. Use immutable API and web image references from the release manifest.
4. Choose independent, randomly generated PostgreSQL, ClickHouse, bootstrap,
   SMTP, and infrastructure credentials.
5. Keep the Compose file and migration directories from the same release tag.

Production startup requires:

- an HTTPS `METRUNE_PUBLIC_API_URL`;
- authenticated SMTP using certificate-verified STARTTLS or implicit TLS;
- an initial organization name, administrator email, and password of at least
  12 characters;
- a writable named volume for the encrypted credential-vault key.

## Validate and start

```bash
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml config
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml up -d
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml ps
```

Do not add `compose.yaml` to these commands. It is a development stack with
known credentials and broad local bindings.

## HTTPS edge

Terminate TLS in a reverse proxy on the same host. Route `/v1/*` to
`127.0.0.1:8080` and all other paths to `127.0.0.1:3001`. The included
`deploy/compose/Caddyfile.example` is a minimal starting point, not an
automatically managed service.

Leave `METRUNE_TRUST_PROXY_HEADERS=true` only when the proxy overwrites, rather
than appends untrusted values to, `X-Forwarded-For`.

## Bootstrap and invitations

The bootstrap email/password creates the first administrator. Sign in once,
clear `METRUNE_BOOTSTRAP_EMAIL` and `METRUNE_BOOTSTRAP_PASSWORD` from the
private environment file, then recreate the API:

```bash
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml up -d --force-recreate api
```

The API refuses production startup when bootstrap values remain after a user
exists. Administrators add later users by sending expiring invitations from
the Members page. Password-reset requests use the same SMTP transport and
return a generic response to avoid revealing registered addresses.

## Upgrade

Back up all three state assets before an upgrade:

- PostgreSQL;
- ClickHouse;
- the `metrune-secrets` volume containing the vault key.

Read the changelog and release notes, update both application image digests,
validate Compose, then recreate the services. Database migrations run forward
at API startup. Rollback is safe only when the release notes explicitly say
that its migrations are backward compatible.

See [OPERATIONS.md](OPERATIONS.md) for backup, restore, health, and incident
procedures.
