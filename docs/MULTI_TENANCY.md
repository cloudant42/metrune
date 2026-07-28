# Multi-tenancy and managed classification

Metrune calls a tenant a **workspace** in the web interface and an
**organization** in the API and database. One account can belong to multiple
organizations with a different role in each.

## Isolation model

- `users` identifies the account.
- `organization_memberships` grants `viewer`, `analyst`, or `admin` access to
  one organization.
- `web_sessions.active_organization_id` is the selected workspace for that
  browser session.
- Organization APIs derive their scope and role by joining the session's
  active organization to an active membership. They never accept an
  organization override from a path, query, or request body.
- Dashboard service tokens and installation tokens remain bound to exactly one
  organization.
- Teams, installations, enrollment codes, provider credentials, classifier
  settings, prices, audit events, and analytics rows retain organization
  foreign keys or server-stamped organization identifiers.

Migration `010_multi_tenant_managed_classifier.sql` backfills one membership
from every existing user's legacy organization and role. Existing web sessions
retain that organization as active, so single-organization deployments keep
working after upgrade. The legacy columns remain as migration compatibility
data; authorization no longer reads them.

## Sign-in and workspace selection

Login returns all active memberships:

- One membership is selected automatically.
- Multiple memberships leave the session unselected and route the user to
  `/organizations`.
- `POST /v1/auth/organization` changes the active organization only after
  validating the membership.
- `POST /v1/organizations` creates an organization and an admin membership in
  one transaction.

Workspace admins invite an email address with a role, resend or revoke a
pending invitation, change a member's role, or remove a membership. New users
set their password after following the expiring email link. Existing users
must sign in as the invited address before acceptance. The API prevents
removal or demotion of the final active admin. Removing a membership clears
that workspace from the affected user's active sessions.

## Semantic classifier execution modes

Each organization chooses one mode:

### Local

Classification text stays on the client. The client calls the configured
provider directly. If that provider needs a credential, organization
provisioning stores it in the native keyring or the protected local fallback.
A localhost OpenAI-compatible model such as Ollama keeps text local and needs
no provider key.

This is the strongest privacy option, but a hosted-provider credential must be
available to the client that calls that provider.

### Managed

The client sends only the bounded classification text assembled by its local
adapters to:

`POST /v1/installation/classifier/classify`

The request uses the installation token. The API resolves the organization,
loads its provider credential from the encrypted vault, calls the provider,
and returns only the category assignment. Managed provisioning returns no
provider endpoint credential and removes a previously provisioned local copy.

Managed classification text is:

- limited to 64 KiB per request;
- protected by the installation rate limit;
- marked `Cache-Control: no-store`;
- omitted from HTTP traces and application logs;
- not inserted into PostgreSQL, ClickHouse, the outbox, or normal upload
  payloads.

Provider error bodies are not returned to clients or written to the managed
classifier warning log.

## Privacy trade-off

A remote hosted model cannot simultaneously:

1. keep its provider key secret from the client;
2. receive no inference text on a remote server; and
3. perform the remote inference.

Metrune therefore exposes the choice explicitly. Use managed mode when the
SaaS operator should protect the provider key and bounded semantic text may
leave the device. Use a local model when neither text nor a provider key may
leave the device. Confidential-computing inference could reduce trust in the
server later, but it does not eliminate sending encrypted input to remote
compute and is not part of this implementation.

## SaaS deployment notes

- Set the global classifier execution mode to `managed` only when the privacy
  notice and data-processing terms cover semantic text transfer.
- Keep the vault key outside the container image and back it up separately.
- Terminate TLS before the API and use an edge rate limiter in addition to the
  per-process installation limit.
- Treat organization creation policy, verified domains, SSO, billing, quotas,
  and abuse controls as deployment policy layers. They
  do not change the organization isolation contract.
