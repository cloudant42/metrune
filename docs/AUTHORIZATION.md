# Authorization model

This document records the reviewed authorization rule for every Metrune API
operation, the principals that can hold each credential, and the limits that
apply on top of authorization. It is the reference for the readiness item
"Review authorization for every organization, team, installation, pricing,
credential, vault, and export operation".

## Principals

| Principal | Credential | Obtained by | Scope |
| --- | --- | --- | --- |
| Web session | `mts_…` bearer, hashed at rest in `web_sessions` | Local `POST /v1/auth/login` or OIDC callback | One account with a nullable active organization; authentication method must match the deployment and role comes from its active membership |
| Dashboard service token | opaque bearer, hashed at rest in `dashboard_tokens` | Provisioned by an operator | One organization, carries a stored role, has no user identity |
| Installation | `mti_…` bearer, hashed at rest in `installations` | OAuth device exchange or legacy `POST /v1/enroll` | One installation in one organization |
| Device authorization | 256-bit `mdc_…` device code plus 40-bit human code, both hashed at rest | `POST /v1/oauth/device/authorization` | One pending native client request; expires in 10 minutes and can mint one installation |
| Personal enrollment code | `mec_…` code | `POST /v1/me/enrollment-codes` | Creates exactly one owner-bound installation; expires in 10 minutes |
| Organization enrollment token | opaque token | Operator/bootstrap provisioning | Legacy unattended path; reusable until its expiry or revocation |

Roles are `admin`, `analyst`, and `viewer`. Only `admin` passes
`DashboardAuth::require_admin`.

## Browser and export boundary

The Next.js dashboard is a server-side proxy. It forwards the signed-in
`metrune_session` cookie as a bearer token and never sends database or service
credentials to the browser. There is no other credential and no fallback: a
request without that cookie has no bearer token to forward, in every
environment.

Middleware returns `307` to `/login` before rendering when the cookie is absent,
so an anonymous response never contains organization data. This is a presence
check only — the API stays authoritative, and pages additionally resolve the
signed-in user before reading data.

Dashboard pages fail closed when the API is unavailable: a failed read renders
an explicit "unavailable" panel and never substitutes placeholder data.
Missing or non-admin roles cannot open administration or pricing controls. The
session drilldown is organization-wide for an analyst or admin and scoped to the
caller's own sessions for every other role; a viewer's service token has no user
identity to scope by and is refused. The API remains the authoritative role and
organization check for every proxy mutation.

`GET /api/export` requires a signed-in web session. An admin or analyst exports
the whole organization; every other role exports only the sessions it owns, and
the filename is `metrune-sessions.csv` for the organization view or
`metrune-my-sessions.csv` for the personal view. It accepts
the same bounded date/team/project/category/client/status/workflow filters as
the dashboard, returns `401`/`403`/`503` instead of an empty success file when
the live API is unavailable, marks the response `no-store`, and prefixes cells
that begin with spreadsheet formula characters (`=`, `+`, `-`, `@`, or control
characters) before CSV quoting.

## Invariants

1. **Every query is scoped by the authenticated principal's organization.** The
   organization is never read from the request path, body, or query string, so
   a caller cannot address another organization's rows by guessing an ID.
2. **Object lookups are scoped, not just filtered.** Mutations that take an ID
   include `organization_id` in the `WHERE` clause and return `404` when no row
   matches, so a cross-organization ID is indistinguishable from a missing one.
3. **Owner-scoped endpoints require a user session.** A dashboard service token
   has no `user_id` and is rejected from every `/v1/me/*` operation, rather than
   silently matching nothing.
4. **Personal analytics authorize on the server-stamped owner.** `owner_user_id`
   is written from installation authentication at ingest time; the
   client-supplied `user_key` is pseudonymous metadata and is never used to
   authorize a query.
5. **Membership selects browser scope.** A web session is organization-scoped
   only when `active_organization_id` joins to an active membership for the
   same user. Roles come from that membership, not the legacy user columns.
6. **Classifier secrets follow execution mode.** Local mode may return the
   organization's provider secret only to its installation. Managed mode never
   returns that secret and uses it only inside the API.
7. **Browser authentication is single-mode.** When OIDC is configured, only
   `oidc` web sessions authorize; local password login/reset are disabled.
   Without OIDC, only `local` web sessions authorize. Startup revokes sessions
   from the previous mode. Dashboard service tokens are independent.

## Operation matrix

### Public

| Operation | Rule |
| --- | --- |
| `GET /v1/healthz`, `GET /v1/readyz` | Unauthenticated liveness and readiness |
| `GET /v1/client/manifest` | Unauthenticated client release manifest; signed by the release pipeline, never by the deployment |
| `GET /v1/client/install.sh` | Unauthenticated installer rendered from the manifest; it verifies the artifact digest but is not an independent signature-verification boundary |
| `GET /v1/downloads/{artifact}` | Unauthenticated client binary download; served only when it matches the manifest digest |
| `GET /v1/auth/methods` | Unauthenticated, non-secret discovery of whether OIDC or local password sign-in is active and the configured provider label |
| `GET /v1/auth/sso/start` | OIDC only; address-limited authorization-code start with server-held state, nonce, and PKCE verifier; same-origin relative continuation only |
| `GET /v1/auth/sso/callback` | OIDC only; atomically consumes state, exchanges the code, verifies signature/issuer/audience/expiry/nonce and verified email, then issues an `oidc` web session |
| `POST /v1/auth/login` | Local mode only; per-address rate limit plus a per-email failure throttle |
| `POST /v1/auth/invitations/inspect` | Unauthenticated; returns masked invitation metadata only |
| `POST /v1/auth/invitations/accept` | Unauthenticated for a new account; creates a password only in local mode. An existing account requires its matching current-mode user session |
| `POST /v1/auth/password-reset/request` | Local mode only; unauthenticated and address-limited; always returns the same accepted response |
| `POST /v1/auth/password-reset/complete` | Local mode only; unauthenticated possession flow; consumes the expiring token and revokes existing sessions |
| `POST /v1/oauth/device/authorization` | Public native client `metrune-cli`; bounded client name/platform; per-address rate limit; returns short-lived device and user codes with `Cache-Control: no-store` |
| `POST /v1/oauth/token` | Public device-code possession flow; persists polling interval, returns `authorization_pending`, `slow_down`, `access_denied`, or `expired_token`, and atomically consumes an approved grant |

### Account session

| Operation | Rule |
| --- | --- |
| `GET /v1/auth/me` | Valid user session; returns active organization plus all active memberships |
| `POST /v1/auth/organization` | Valid user session; requested organization must have an active membership for that session's user |
| `POST /v1/organizations` | Valid user session; creates the organization and its initial admin membership atomically |
| `POST /v1/auth/logout` | Revokes the presented user session |
| `POST /v1/oauth/device/verification` | Valid user session with an active membership; possession of the human code; returns only the requested client name, platform, code, and expiry |
| `POST /v1/oauth/device/approval` | Valid user session with an active membership; explicit approve or deny. Approval binds the client to that user and active organization; `teamId` must belong to the same organization |

### Installation credentials

| Operation | Rule |
| --- | --- |
| `POST /v1/enroll` | Valid unredeemed enrollment token or personal code; per-address rate limit. A personal code is single-use, expires in 10 minutes, and binds the new installation to the issuing user and organization |
| `POST /v1/ingest/sessions` | Installation token; organization and owner are taken from the token, never from the payload; per-installation rate limit |
| `POST /v1/installation/classifier/provision` | Installation token; local mode can return the organization's classifier credential, while managed mode returns no credential; per-installation rate limit; `Cache-Control: no-store` |
| `POST /v1/installation/classifier/classify` | Installation token; managed mode only; resolves the provider credential server-side, accepts at most 64 KiB of semantic text, and returns only a category assignment; per-installation rate limit; `Cache-Control: no-store` |

The native client uses Metrune's OAuth device grant by default. It has no
embedded client secret and never receives the person's web session or an
identity-provider refresh token. A successful, one-time exchange returns the
long-lived, revocable installation credential used by upload, classifier, and
provisioning requests. `POST /v1/enroll` remains the legacy personal-code and
organization-token path for controlled automation.

### Organization administration

Every operation below resolves the organization from the caller's credential.

| Operation | Rule |
| --- | --- |
| `GET /v1/org/teams` | Any member. Team names are needed by the browser device-approval flow |
| `GET /v1/org/members`, `POST /v1/org/members` | Admin. Adding requires an existing account and creates only an organization membership |
| `GET`/`POST /v1/org/invitations` | Admin user session. Lists metadata or creates an expiring invitation; SMTP sends it when configured, otherwise `201` returns `delivery: "manual"` and an `acceptUrl` whose token is in the URL fragment. Service tokens cannot invite |
| `POST /v1/org/invitations/{id}/resend`, `DELETE /v1/org/invitations/{id}` | Admin user session. Resend rotates the token and returns the same manual link when no mailer is configured; revoke invalidates it |
| `PATCH`/`DELETE /v1/org/members/{user_id}` | Admin. The final active admin cannot be demoted or removed; removal clears affected active sessions |
| `POST /v1/org/members/{user_id}/password-reset` | Admin user session in local-password mode; organization-scoped. SMTP sends the reset when configured, otherwise `200` returns `delivery: "manual"` and a fragment `resetUrl`; unavailable under OIDC |
| `POST /v1/org/teams`, `PATCH`/`DELETE /v1/org/teams/{id}` | Admin |
| `GET /v1/org/installations` | Admin. The fleet inventory is an administrative view |
| `PATCH /v1/org/installations/{id}` | Admin |
| `GET /v1/org/settings` | Any member. Returns retention only, which the dashboard shows on every page |
| `PATCH /v1/org/settings` | Admin |
| `GET`/`PATCH /v1/org/classifier`, `POST /v1/org/classifier/test` | Admin |
| `GET`/`POST /v1/org/credentials`, `DELETE /v1/org/credentials/{id}` | Admin. Responses carry credential metadata only, never the secret |
| `POST /v1/org/vault/recovery` | Admin, **plus** re-verification: the caller's password in local mode or an OIDC session less than ten minutes old, **plus** a one-time database constraint so the recovery key can never be exported twice. Returns the key derived for the caller's **active** organization, so an admin of one tenant cannot obtain a co-tenant's key |
| `GET /v1/org/prices` | Any member. Prices explain the costs already shown in analytics |
| `POST /v1/org/prices`, `PATCH`/`DELETE /v1/org/prices/{id}` | Admin, and a user session, so the pricing change has a durable actor |

### Analytics

| Operation | Rule |
| --- | --- |
| `GET /v1/analytics/*` | Any member of the organization; every generated query is organization-scoped; per-caller rate limit |
| `GET /v1/me/usage`, `GET /v1/me/sessions` | User session; filtered by `organization_id` **and** the server-stamped `owner_user_id`; an `installationId` filter is accepted only after an ownership check; per-caller rate limit |
| `GET /v1/me/installations` | User session; filtered by organization and owner |
| `DELETE /v1/me/installations/{id}` | User session; the update itself is constrained to the caller's own active installation |
| `POST /v1/me/enrollment-codes` | User session; a `teamId` is validated against the caller's organization; per-user rate limit |

## Known limits of the current model

These are accepted for the beta and tracked in [ROADMAP.md](ROADMAP.md):

- **Organization-wide analytics.** Any signed-in member sees organization-wide
  aggregates. There is no team-level restriction yet. Personal
  session-level detail remains owner-scoped.
- **Audit actors are labels.** `audit_events.actor_label` stores a display name
  rather than a durable user ID, so a renamed user weakens attribution.
- **No delegated administration.** `admin` is a single, organization-wide role;
  there is no separate pricing, credential, or billing administrator.
- **No email ownership verification beyond possession flows.** Invitations and
  resets prove access to the delivered link; signup without an invitation is
  not supported.
- **Dashboard service tokens cannot be attributed to a person.** They are
  rejected from owner-scoped and pricing-write operations for that reason.

## Rate limits

Authorization decides *whether* a caller may perform an operation; these limits
decide *how often*. All are fixed-window, in-process, and keyed by the
authenticated identity where one exists.

| Scope | Key | Default | Override |
| --- | --- | --- | --- |
| Enrollment | Client address | 10/minute | `METRUNE_RATE_LIMIT_ENROLL_PER_MINUTE` |
| Login | Client address | 30/minute | `METRUNE_RATE_LIMIT_LOGIN_PER_MINUTE` |
| Classifier provisioning | Installation | 20/minute | `METRUNE_RATE_LIMIT_PROVISION_PER_MINUTE` |
| Managed classification | Installation | 60/minute | `METRUNE_RATE_LIMIT_CLASSIFY_PER_MINUTE` |
| Ingestion | Installation | 60/minute | `METRUNE_RATE_LIMIT_INGEST_PER_MINUTE` |
| Analytics | User or dashboard token | 120/minute | `METRUNE_RATE_LIMIT_ANALYTICS_PER_MINUTE` |
| Enrollment codes | User | 20/hour | `METRUNE_RATE_LIMIT_ENROLLMENT_CODES_PER_HOUR` |
| Device authorization requests | Client address | 10/minute | `METRUNE_RATE_LIMIT_DEVICE_AUTHORIZATIONS_PER_MINUTE` |
| Device inspection/approval | User | 60/hour | `METRUNE_RATE_LIMIT_DEVICE_VERIFICATIONS_PER_HOUR` |
| Device token polls | Client address, plus persistent per-device pacing | 300/minute | `METRUNE_RATE_LIMIT_DEVICE_TOKEN_POLLS_PER_MINUTE` |
| Invitations | Admin user | 30/hour | `METRUNE_RATE_LIMIT_INVITATIONS_PER_HOUR` |
| Password-reset requests | Client address | 10/hour | `METRUNE_RATE_LIMIT_PASSWORD_RESETS_PER_HOUR` |

Setting an override to `0` disables that limit.

Address-keyed limits use the peer address by default. Set
`METRUNE_TRUST_PROXY_HEADERS=true` only when every request reaches the API
through a reverse proxy that overwrites `X-Forwarded-For`; otherwise a client
can forge the header and evade the limit. See
[SECURITY_AND_LOGGING.md](SECURITY_AND_LOGGING.md) for the TLS and proxy
boundary.

Limiter state is per process and is not shared across API replicas: a
deployment running *n* replicas allows up to *n* times each budget. Treat these
limits as abuse and runaway-client protection, not as a quota system, and place
an edge rate limit at the reverse proxy for internet-facing deployments.
