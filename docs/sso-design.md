# Single sign-on and native client authentication

Status: implemented. Browser sign-in uses deployment-wide OpenID Connect.
Native clients use Metrune's OAuth device grant and inherit the browser's
authentication method at approval time.

## Scope

One OpenID Connect provider per deployment, configured by the operator.
Authorization-code flow with PKCE. Sign-in only: the identity provider proves
who somebody is, and Metrune decides what they may do.

Deliberately out of scope for this milestone:

- Multiple identity providers in one deployment, and provider federation.
- Per-organization provider connections and email-domain routing.
- Group-to-role and group-to-team mapping.
- SCIM provisioning.
- Native SAML. An OIDC bridge remains the preferred path.

The `idp_connections`, `group_mappings`, and `scim_tokens` tables already exist
in `migrations/postgres/004_identity.sql` and stay unused. They are the seam for
the deferred work: adding per-organization providers later is additive and does
not rework what this milestone builds.

## Why one provider per deployment

A single provider removes the routing decision. With per-organization
connections, a sign-in has to be matched to a provider before the user is
authenticated, and the only available signal is the email domain. That makes
domain ownership a security boundary: any account able to create an
organization could claim a domain it does not own and influence where those
users authenticate. One provider per deployment means there is nothing to
route and nothing to claim.

It also keeps the provider registration simple. Each `redirect_uri` must be
registered with the provider in advance, so one deployment domain means one
URI registered once. Per-tenant subdomains would require a separate
registration per tenant inside every customer's provider.

## Configuration

Deployment-level, alongside the existing settings in `.env.example`. The client
secret is deployment configuration rather than tenant data, so it is referenced
the way `004_identity.sql` always described it — from the environment or a
file — and not stored in the per-organization credential vault.

| Variable | Purpose |
| --- | --- |
| `METRUNE_OIDC_ISSUER_URL` | Provider issuer. Discovery document is read from it. |
| `METRUNE_OIDC_CLIENT_ID` | Registered client. |
| `METRUNE_OIDC_CLIENT_SECRET_FILE` | Path to the secret. `METRUNE_OIDC_CLIENT_SECRET` is accepted for local development only. |
| `METRUNE_OIDC_PROVIDER_NAME` | Human-readable provider label shown on the sign-in page. |
| `METRUNE_OIDC_DEFAULT_ROLE` | Role granted on provisioning. Defaults to `viewer`. |
| `METRUNE_OIDC_PROVISIONING` | `personal-org`, `default-org`, or `none`. |
| `METRUNE_OIDC_DEFAULT_ORGANIZATION` | Required when provisioning is `default-org`. |
| `METRUNE_OIDC_SESSION_TTL_HOURS` | Browser-session lifetime, from 1 to 168 hours. Defaults to 12. |

The redirect URI is
`METRUNE_PUBLIC_API_URL/v1/auth/sso/callback`. The public API and web URLs must
share a hostname because the callback issues the host-only dashboard cookie.
This is the topology in the included Caddy example: `/v1/*` reaches the API and
all other paths reach the web app. SSO is inactive only when all three core
settings are absent. Partial configuration, conflicting secret sources,
insecure production URLs, an unreadable/non-private production secret file,
failed discovery, or a missing token endpoint stops API startup.
The server negotiates `client_secret_basic` or `client_secret_post` from the
provider metadata. A provider that advertises neither standard method is
rejected at startup rather than guessed at runtime.

`METRUNE_OIDC_PROVISIONING` exists because the two deployment models want
opposite behaviour. A hosted multi-tenant instance wants `personal-org`, where
each new person gets a workspace and invites colleagues into it. An
organization self-hosting for its own staff wants `default-org`, where everyone
the provider authenticates joins the one existing workspace. `none` refuses
sign-in for anybody not already a member, for deployments that want admission
to stay manual.

## Flow

`GET /v1/auth/sso/start` generates a PKCE verifier, `state`, and `nonce`,
persists them server-side with a short expiry, and redirects to the provider's
authorization endpoint.

`GET /v1/auth/sso/callback` consumes that record once, exchanges the code, and
validates the ID token: signature against the provider's published keys, then
`iss`, `aud`, `exp`, and `nonce`. A record that is missing, expired, or already
used fails the sign-in.

The PKCE verifier, `state`, and `nonce` are held server-side rather than
round-tripped through the browser, so the callback validates against values the
client could not have chosen. This needs one new table, the only schema change
in the milestone.

Validation uses the `openidconnect` crate rather than assembling discovery and
token checks by hand. Hand-written ID-token validation is a recurring source of
authentication bypasses — accepting `alg: none`, skipping `aud`, or ignoring
`nonce` — and none of those mistakes are visible in a passing test.

## Identity resolution

On a validated token, in order:

1. Match `users.issuer` and `users.subject`. This is the durable binding;
   `UNIQUE (issuer, subject)` already enforces it.
2. Otherwise match the verified email claim to an existing user and bind
   `issuer` and `subject` to that account. An unverified email claim does not
   match, because otherwise a provider account asserting somebody else's
   address would take over their user.
3. Otherwise provision according to `METRUNE_OIDC_PROVISIONING`.

Subject is the identity, email is only a convenience for the first link.
Providers reassign email addresses; they do not reassign subjects.

Sessions are issued through the existing `web_sessions` path and record
whether authentication was `oidc` or `local`. Every request requires the
currently configured method; startup revokes sessions from the previous mode.
Multiple memberships still leave the session unselected and route to
`/organizations`.

## Native client enrollment

The native CLI is a public client named `metrune-cli`; no client secret is
embedded in its binaries. It requests a short-lived device authorization from
`POST /v1/oauth/device/authorization`, displays the verification link and
human code, and polls `POST /v1/oauth/token` using the OAuth device grant.

The browser uses its existing Metrune session to inspect and explicitly approve
or deny the named client. Approval binds the installation to the session's
active organization, user, and optional team. The device and user codes are
stored only as SHA-256 digests, expire after 10 minutes, and are consumed
transactionally. Pending, slow polling, denial, expiry, and reuse return the
device-grant error codes defined for those states.

A successful exchange returns a revocable `mti_…` installation credential, not
the person's `mts_…` web session or an identity-provider token. The CLI stores
that credential in the operating-system keyring, with a mode-`0600` fallback
file when no keyring service is available; ordinary client config contains
only a credential reference. Existing configs containing the token migrate
transparently on their next read.

## Local sign-in and lockout

Password sign-in and password reset exist only when OIDC is absent. Configuring
OIDC automatically disables both; there is no network-reachable password
bypass or mixed mode. New invitations create passwordless accounts, and the
verified IdP email binds them on first sign-in. Vault recovery requires an OIDC
session created within the previous ten minutes instead of asking for a
password.

Removing OIDC configuration and restarting restores local-password mode, but
only accounts that already have a password hash can use it. There is currently
no automated break-glass password setter for an SSO-only account; operators
must treat IdP availability and access recovery as part of the deployment
runbook.

## Audit

`audit_events` records successful OIDC provisioning and first identity binding.
It does not record tokens, codes, PKCE material, or the `nonce`.

## Testing

Integration tests run a real HTTP discovery, authorization, JWKS, and token
server that validates PKCE and signs RSA ID tokens. Coverage includes the happy
path, concurrent replay, expired `state`, wrong PKCE verifier, nonce and
audience mismatch, expiry, unverified email, provider denial/failure/timeout,
JWKS rotation, every provisioning mode, identity conflict, invitations,
password/reset policy, recent-SSO recovery, device approval, and a resulting
client upload. A separate Playwright stack follows the complete browser
redirect/cookie flow and approves a native client. Vendor-specific federation
and policy configuration still require validation against the operator's IdP.
