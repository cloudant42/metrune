# Identity and access

Metrune supports per-user local identity alongside service dashboard tokens
for enterprise self-hosting. This document describes the schema and rollout.

## Schema (provisioned)

Migration `004_identity.sql` adds:

- `users` — per-organization identities. `password_hash` is nullable so an
  identity can be local-only, SSO-only, or both. `issuer` + `subject` hold the
  OIDC subject for external identities.
- `idp_connections` — OIDC provider configuration per organization: issuer
  URL, client ID, a `client_secret_ref` pointing at a deployment secret
  (never the secret itself), email domain routing, the group claim used for
  mappings, and a default role. Works with Entra ID, Okta, Keycloak, Google
  Workspace, and any spec-compliant provider.
- `group_mappings` — maps an IdP group to a Metrune role and/or team.
- `team_memberships` — user/team assignment.
- `web_sessions` — hashed session tokens with expiry and revocation.
- `scim_tokens` — service tokens for future SCIM provisioning calls.
- `audit_events` — organization-scoped record of administrative actions.
- `organizations.sso_enforced` / `organizations.local_login_enabled` flags.

## Defaults

Local password sign-in is the default so a fresh deployment works out of the
box. Connecting an IdP and enforcing SSO disables local passwords for that
organization (`local_login_enabled` flips to false).

`dashboard_tokens` remain valid and now serve as service tokens for
automation (CI exports, provisioning scripts). Viewer tokens read aggregates;
analyst and admin tokens can drill into sessions; admin tokens manage teams,
installations, and retention.

## Implemented

- Local email/password sign-in with Argon2 password hashes and revocable,
  expiring HttpOnly browser sessions.
- Private `/profile` analytics scoped to the authenticated owner.
- One-time enrollment codes that bind an installation to the signed-in user.
- Organization session drilldown is unavailable to user sessions; shared
  dashboard surfaces remain aggregate-only.

## Remaining rollout

1. OIDC authorization-code + PKCE sign-in with just-in-time user provisioning
   and group-claim role/team mapping.
2. Enforce-SSO toggle and domain allowlists per organization, audit log
   surfaced in the dashboard.
3. SCIM 2.0 provisioning for automated joiner/mover/leaver flows.
4. OAuth device flow as an alternative to the implemented one-time profile
   enrollment codes.
5. SAML 2.0 only if required, via a bridge (Dex/Keycloak) rather than a
   native implementation.

The API will use the `openidconnect` crate for the relying-party flow; no new
dependencies are needed before milestone 1 starts.
