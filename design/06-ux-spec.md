# UX Spec: Metrune multi-tenant identity, pricing, and classification

## Overview

Metrune keeps each organization's data isolated while allowing one signed-in
person to belong to multiple organizations. The product calls these
organizations **workspaces** in the interface. A web session has one active
workspace at a time, and every organization-scoped request derives its scope
from the authenticated membership rather than a client-supplied identifier.

The classifier supports two deployment modes. Local mode keeps semantic text
on the client and uses a client-held or keyless localhost model. Managed mode
sends bounded classification text to Metrune's server, where a vault-held
provider credential is used without ever being returned to the client.

## Information architecture

```text
Metrune
├── Workspace chooser
│   ├── Switch workspace
│   └── Create workspace
├── Overview
├── Usage explorer
├── Models
├── My profile
│   ├── My usage
│   ├── My clients
│   └── Enroll a client
└── Teams & settings
    ├── Members
    ├── Teams
    ├── Pricing
    ├── Installations
    ├── Identity
    └── Classifier & vault
```

The shared overview and usage explorer expose organization/team aggregates.
They do not link to an individual person's usage. Personal usage is available
only from `/profile` after user authentication.

Workspace context is global, not a page filter. It appears in the account menu
and changing it refreshes all organization-scoped pages. Team and date filters
remain subordinate to the active workspace.

## User flows

### Sign in and choose a workspace

1. User signs in once with their account credentials.
2. The server creates an HttpOnly web session and returns active organization
   memberships with each workspace's name and role.
3. If exactly one active membership exists, the server selects it and the UI
   opens the overview directly.
4. If multiple memberships exist, no workspace is selected implicitly. The UI
   opens `/organizations` and asks the user to choose.
5. The selected organization is stored on the server-side web session. The
   browser never sends an organization ID as analytics authorization.
6. The account menu shows the active workspace and lets the user switch later.

Error states: no active memberships, membership removed since login, disabled
account, expired session, and failed switch. A removed membership clears the
active organization and returns the user to the chooser.

### Create and administer a workspace

1. A signed-in user opens the workspace chooser and selects **Create
   workspace**.
2. The server creates the organization and an admin membership in one
   transaction, then makes it active for the current web session.
3. An admin opens **Administration → Members** to add an existing Metrune
   account, change its workspace role, or remove it.
4. The server prevents removal or demotion of the final active admin and clears
   affected active workspace selections when membership is removed.

The first implementation adds existing accounts by email. Email invitations
and domain/SSO just-in-time membership are later acquisition paths into the
same membership table.

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

### Configure semantic classification

1. An organization admin opens **Classifier & vault**.
2. The admin chooses an execution mode before choosing provider and model:
   - **Local / private:** classification text stays on each client. A provider
     credential may be stored on that client, or a localhost model such as
     Ollama can run without a key.
   - **Managed / SaaS:** bounded classification text is sent to Metrune's API.
     The provider key remains encrypted in the server vault and is never
     returned by enrollment or classifier provisioning.
3. The UI explains the selected privacy boundary next to the control and
   requires an explicit save.
4. The CLI refreshes the profile. Local mode calls the configured provider
   directly; managed mode calls Metrune's installation-authenticated classify
   endpoint.
5. Both modes upload the same metadata-only session snapshot. Managed
   classification requests are not persisted or included in normal request
   traces.

There is no architecture that simultaneously uses a remote hosted model,
hides its key from the client, and keeps inference text off every remote
server. The keyless private option is client-side local inference; the hosted
key-safe option is the managed proxy with explicit text transfer.

## Screens

### Login

**Route:** `/login`

Purpose: establish a user session. Fields are email and password, with clear
errors and a link to the organization's future SSO entry point when enabled.

States: loading, invalid credentials, disabled account, SSO-required, direct
single-workspace redirect, and multi-workspace chooser redirect. Do not render
dashboard data on this screen.

### Workspace chooser

**Route:** `/organizations`

Purpose: select the active workspace when none is selected and provide
self-service workspace creation.

Components:

- Signed-in identity and sign-out action.
- Workspace cards with workspace name, role, and **Open workspace** action.
- Create-workspace form with a required name.
- Empty state explaining that an administrator must add the account, plus the
  create-workspace action when self-service creation is enabled.

The chooser is a focused screen without organization navigation. Loading,
switch failure, create failure, and membership-removed states keep the user on
this screen.

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

### Classifier & vault

**Route:** `/admin?tab=classifier`

The execution-mode control appears before provider configuration. Managed mode
shows **Text sent to Metrune; provider key stays on this server**. Local mode
shows **Text stays on the client; a provider key may be stored on that
client**. Selecting Ollama/local compatible inference adds **No provider key
required**.

The credential selector always refers to vault credentials. In managed mode a
selected credential is used only on the server. In local mode provisioning may
deliver the credential to enrolled clients, so the UI must say so before save.

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

- Keep `users` as account identity and add `organization_memberships` with a
  role per organization. Existing `users.organization_id` and `users.role`
  values are migration inputs, not authorization sources after rollout.
- Add nullable `web_sessions.active_organization_id`. Login sets it only for a
  single membership; the switch endpoint updates it only after validating an
  active membership.
- Make `users`, `organization_memberships`, and `web_sessions` the browser
  identity source; retain organization-bound `dashboard_tokens` as service/API
  credentials.
- Every organization endpoint and analytics query must scope through the
  session's active membership. Request bodies and query strings cannot
  override that scope.
- Add organization creation and membership list/add/role/remove endpoints.
  Prevent removal or demotion of the final active admin.
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
- Add `classifier_execution_mode` with `local` and `managed` values. Managed
  provisioning returns no provider credential to the client.
- Add an installation-authenticated managed classification endpoint with
  bounded input, per-installation rate limiting, no-store responses, generic
  upstream errors, and no semantic text persistence.

## Acceptance criteria

- A user with one membership signs in directly; a user with multiple
  memberships must choose and can later switch from the account menu.
- A user cannot select an organization without an active membership, and
  switching cannot leak settings, teams, installations, analytics, prices,
  credentials, or classifier configuration from the previous workspace.
- Role checks use the role from the active membership, so the same account may
  be a viewer in one workspace and an admin in another.
- Existing single-organization users and sessions are backfilled without
  losing access.
- A workspace can be created transactionally and the final active admin cannot
  be removed or demoted.
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
- Managed mode never returns the provider credential to a client and classifies
  through the installation-authenticated server endpoint. Local mode preserves
  the existing metadata-only upload boundary.
- Managed classification rejects oversized text, disabled/local-mode
  organizations, revoked installations, and missing credentials without
  exposing provider error bodies or secrets.
- Rust tests, web typecheck/build, migration checks, and Playwright MCP checks
  cover tenant selection/switching, cross-tenant denial, role changes,
  managed-key non-disclosure, authenticated profile, pricing edit, and
  enrollment happy path.

## Rollout order

1. Organization memberships, session workspace selection, migration backfill,
   and server-side authorization.
2. Workspace chooser/switcher, creation, and membership administration.
3. Managed classifier endpoint and client execution-mode support while
   preserving local classification.
4. Personal profile API/UI, aggregate-only organization views, pricing, and
   enrollment regression verification.
5. Email invitations, SSO/OIDC just-in-time membership, organization billing,
   and shared installation ownership as follow-up work.
