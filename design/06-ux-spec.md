# UX Spec: Metrune identity, pricing, and client enrollment

## Overview

Metrune keeps organization analytics aggregated while giving each signed-in
person a private profile for their own client usage. The server becomes the
authoritative pricing registry and enrollment binds every client installation
to its owner.

## Information architecture

```text
Metrune
├── Overview
├── Usage explorer
├── Models
├── My profile
│   ├── My usage
│   ├── My clients
│   └── Enroll a client
└── Teams & settings
    ├── Teams
    ├── Pricing
    ├── Installations
    └── Identity
```

The shared overview and usage explorer expose organization/team aggregates.
They do not link to an individual person's usage. Personal usage is available
only from `/profile` after user authentication.

## User flows

### Sign in and view personal usage

1. User opens `/login` and signs in with the local account.
2. The server creates an HttpOnly web session and redirects to `/profile`.
3. The profile shows only usage belonging to installations owned by the user.
4. Provider/model/client and time filters refine the personal aggregate view.

Error states: invalid credentials, expired session, disabled account, and no
owned installations must be explicit and must not fall back to organization
data.

### Enroll a client

1. User selects **Enroll a client** from the profile.
2. The server creates a one-time, short-lived enrollment code bound to the
   authenticated user and optionally to a team.
3. The UI shows platform tabs for Linux/WSL and Windows, with copyable commands
   and a download link for the matching client artifact.
4. The CLI redeems the code once, creates an installation owned by that user,
   stores the installation credential locally, and confirms success.
5. The profile lists the client as pending until its first heartbeat/upload.

Existing reusable enrollment tokens remain service/bootstrap credentials and
do not grant personal profile access unless explicitly bound to a user.

### Maintain pricing

1. Authenticated user opens **Teams & settings → Pricing**.
2. The page lists effective prices by provider/model, source, authority,
   effective date, and last editor.
3. User creates or edits an organization price for a built-in or custom
   provider/model.
4. The server validates the rate, records an audit event, versions the rule,
   and applies it to new ingests from its effective time.
5. The UI clearly distinguishes reported provider cost from server-estimated
   cost and identifies the price source.

For the initial release, all authenticated organization members may create or
edit organization price entries. Changes are shared, versioned, and audited;
the permission can be tightened to admins later without changing the data
model.

## Screens

### Login

**Route:** `/login`

Purpose: establish a user session. Fields are email and password, with clear
errors and a link to the organization's future SSO entry point when enabled.

States: loading, invalid credentials, disabled account, SSO-required, and
success redirect. Do not render dashboard data on this screen.

### My profile

**Route:** `/profile`

Purpose: private self-service usage and client ownership.

Components:

- Identity header: display name/email and sign-out action.
- Personal usage summary: tokens, estimated/reported cost, sessions, and a
  recent trend.
- Usage breakdown: provider, model, client, and time range; no other users,
  raw prompts, or session drilldown.
- My clients table: client name, platform, team, last seen, and revoke action.
- Enroll a client panel with platform-specific commands.

Empty state: explain that a client must be enrolled and upload once before
usage appears. Loading and API error states must preserve the privacy boundary
and never substitute organization demo data for a signed-in profile.

### Organization overview

**Routes:** `/`, `/usage`, `/models`

Keep the existing aggregate surfaces, but scope them to the user's permitted
organization/team groups. Remove individual-session links from the default
navigation. Show team/provider/model/category totals only. Apply a minimum
cohort threshold (default three owners) before showing a group's metrics to
avoid a one-person team becoming an indirect profile view.

### Pricing

**Route:** `/admin/pricing`

Components:

- Filter/search by provider and model.
- Source badges: default catalog, official provider, organization override,
  self-hosted, or manual.
- Rate editor for input/output/cache/reasoning/request/image units and
  currency.
- Effective-from and optional effective-until fields.
- Custom provider/model creation.
- Version history and audit trail.
- Explicit note that existing historical totals are unchanged unless a
  deliberate reprice operation is run.

### Enrollment handoff

**Route:** `/profile/enroll`

Platform tabs provide:

- Linux/WSL: verified Linux binary and shell installer, then the one-time
  enrollment command.
- Windows: signed Windows binary or PowerShell installer, then the enrollment
  command.
- Manual option: copy the server URL and one-time code separately.

The code is masked after copying, expires visibly, and cannot be reused. The
screen explains that the installation credential is stored locally and is not
shown again by the server.

## Server/data contract

- Make `users` and `web_sessions` the browser identity source; retain
  `dashboard_tokens` as service/API credentials.
- Add an owner binding to installations, preferably a user foreign key for the
  v1 one-owner-per-installation case, with a join table reserved for future
  shared ownership.
- Stamp an owner access key server-side into analytics rows. Never authorize a
  personal query using the client-provided `user_key` alone.
- Add versioned price rules keyed by provider/model and organization scope,
  seeded from the committed default JSON catalog.
- Resolve cost server-side in this order: reported provider cost, active
  organization override, provider/official rule, default catalog, unknown.
- Store price rule/version/source with estimated costs. Do not silently rewrite
  historical cost when a price changes.
- Add aggregate personal endpoints such as `/v1/me/usage` and ownership-aware
  installation endpoints. Existing organization analytics must remain
  organization-scoped and must not expose a user dimension.
- Add local login/session endpoints, logout, current-user, one-time enrollment
  code creation/redeem, and pricing CRUD endpoints. Audit all ownership,
  pricing, enrollment, and revocation changes.

## Acceptance criteria

- User A cannot read User B's profile usage, even when both users share a team.
- A team overview cannot be used to infer a one-person member's usage; small
  groups are suppressed or combined.
- Every newly enrolled installation has an authoritative owner and team scope.
- Reusing or copying an enrollment code fails after its first redemption or
  expiry.
- Custom provider/model prices calculate new estimated costs and preserve
  reported provider costs.
- Price edits show source, effective time, version, and editor, and historical
  totals remain stable until an explicit reprice action.
- Linux/WSL and Windows installation paths produce a working authenticated
  client config without exposing installation or provider secrets in the web
  page, normal config, or upload payload.
- Rust tests, web typecheck/build, migration checks, and Playwright MCP checks
  cover the authenticated profile, cross-user denial, pricing edit, and
  enrollment happy path.

## Rollout order

1. Canonical browser auth, installation ownership, and server-side authorization.
2. Personal profile API/UI and aggregate-only organization views.
3. Server pricing registry, default catalog import, ingest-time price resolver,
   and pricing UI.
4. One-time enrollment codes, client artifact manifest, Linux/WSL and Windows
   installers, and profile handoff.
5. Historical reprice job, SSO/OIDC login, shared installation ownership, and
   stricter pricing permissions as follow-up work.
