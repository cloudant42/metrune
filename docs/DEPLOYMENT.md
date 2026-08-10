# Production deployment

## Supported topology

The production beta supports one Linux x86_64 host running Docker Engine and
Compose v2. `compose.production.yaml` is standalone and runs exactly four
services: PostgreSQL, ClickHouse, the Metrune API, and the web app.

PostgreSQL and ClickHouse are reachable only on internal Compose networks. The
API and web ports bind to `127.0.0.1` for a same-host HTTPS reverse proxy. The
API also has outbound access for SMTP, an optional OIDC provider, and an
optional managed classifier.

Kubernetes, Helm, multi-host failover, and a bundled observability stack are
outside the beta support contract.

## Prepare

1. Copy `deploy/compose/production.env.example` outside the checkout.
2. Set mode `0600` and replace every placeholder.
3. Use immutable API and web image references from the release manifest.
4. Choose independent, randomly generated PostgreSQL, ClickHouse, local
   bootstrap (when used), SMTP, OIDC, and infrastructure credentials. SMTP is
   needed for email delivery and is also validated by the current production
   startup checks.
5. Use the `server-vX.Y.Z` release for the API/web images, Compose file, and
   migration directories. Select the separately released `client-vX.Y.Z`
   manifest and artifacts for the client mirror.

Production startup requires:

- HTTPS `METRUNE_PUBLIC_API_URL` and `METRUNE_PUBLIC_WEB_URL` values on the
  same hostname (the latter is used in CLI device-approval links);
- optionally, authenticated SMTP using certificate-verified STARTTLS or
  implicit TLS for invitation and password-reset email; without it, invitation
  links can be delivered manually and password reset is unavailable;
- an initial organization name and administrator email, plus either a local
  password of at least 12 characters or complete OIDC configuration;
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

## Enterprise SSO

Register this redirect URI with one OpenID Connect provider:

```text
https://metrune.example.com/v1/auth/sso/callback
```

Set the issuer, client ID, provider label, provisioning mode, and both secret
file paths shown in `deploy/compose/production.env.example`. The host secret
file is bind-mounted at `/run/secrets/metrune-oidc-client-secret`. Because the
API image runs as UID/GID `65532`, prepare it for that identity:

```bash
sudo install -o 65532 -g 65532 -m 0400 \
  /source/oidc-client-secret \
  /private/path/metrune-oidc-client-secret
```

OIDC configuration is fail-closed. Partial values, an HTTP issuer in
production, a client secret in an environment variable, a group/world-readable
secret file, failed discovery, or split API/web hostnames stop startup. The
discovery client does not follow redirects and bounds provider HTTP requests to
ten seconds. Token exchange supports the standard `client_secret_basic` and
`client_secret_post` methods advertised by the provider; startup fails if
neither is available.

When OIDC is configured, password sign-in and reset are unavailable and
sessions previously created with a password are revoked. Removing the OIDC
settings and restarting restores local mode, but SSO-only users have no local
password. There is no automated break-glass password setter in this beta, so
validate IdP administrator recovery before production rollout.

Choose provisioning deliberately:

- `none`: only invited/bootstrap or previously linked users may sign in;
- `default-org`: new verified identities join one configured organization with
  `METRUNE_OIDC_DEFAULT_ROLE`;
- `personal-org`: each new identity receives an administrator-owned workspace.

## Bootstrap and invitations

Without OIDC, the bootstrap email/password creates the first administrator.
With OIDC, set the bootstrap email but leave the password empty; the account is
linked when that verified email first signs in through the provider. After the
first successful sign-in, clear both bootstrap variables from the private
environment file and recreate the API:

```bash
docker compose --env-file /private/path/metrune.env \
  -f compose.production.yaml up -d --force-recreate api
```

The API refuses production startup when bootstrap values remain after a user
exists. Administrators add later users with expiring invitations from the
Members page. With SMTP configured, the invitation is emailed; without a
mailer, the API returns an `acceptUrl` for the administrator to deliver
manually. In local mode, password-reset requests use the same SMTP transport
and return a generic response to avoid revealing registered addresses. An
administrator can trigger a reset for a known member only when SMTP is
configured; the token is always delivered to the account owner and is never
returned to a workspace administrator. Under OIDC, invited users do not set a
password and reset endpoints are disabled.

## Upgrade

Use a compatibility release before removing support for a client or upload
schema. The safe sequence is:

1. Read `CHANGELOG.md` and the release notes for the server, client, schema,
   migration, and rollback requirements.
2. Keep `METRUNE_MINIMUM_CLIENT_VERSION` empty or at the existing floor. Deploy
   the new server while it still accepts the current and previous upload schema.
3. Confirm `GET /v1/server/info` reports the expected server version, schema
   window, and floor. Run `metrune update --check` from a staging client.
4. Roll out the client manually. The CLI prints an update notice at most once
   per 24 hours; it never installs automatically. Watch the Client version
   column on both the organization and personal installation views.
5. After every active installation needed for the rollout meets the new floor,
   set `METRUNE_MINIMUM_CLIENT_VERSION` to that complete semantic version and
   recreate the API service. Keep the signed manifest's `minimumVersion` equal
   to the enforced value.
6. Verify that a supported client uploads and an older staging client receives
   HTTP 426 with `code: client_unsupported`. The old client must exit with
   `metrune update` instructions and retain its queued snapshots.

An emergency compatibility rollback normally means restoring the previous
`METRUNE_MINIMUM_CLIENT_VERSION` and recreating only the API. That reopens
ingest without changing stored data. Do not remove the previous schema in the
same release that first raises the client floor; preserve one full release
window so the configuration rollback remains useful.

Before changing images or starting database migrations, back up all three state
assets:

- PostgreSQL;
- ClickHouse;
- the `metrune-secrets` volume containing the vault key.

Update both application image digests, validate Compose, then recreate the API
first. Database migrations run forward at API startup. Verify `/v1/readyz` and
`/v1/server/info`, then recreate the web service. Image rollback is safe only
when the release notes explicitly say that the migrations are backward
compatible; otherwise restore the backup as a coordinated recovery.

See [VERSIONING.md](VERSIONING.md) for the server/client compatibility rule and
[OPERATIONS.md](OPERATIONS.md) for backup, restore, health, and incident
procedures.
