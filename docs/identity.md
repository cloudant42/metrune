# Identity and access

## Beta flows

- The deployment bootstraps exactly one initial administrator.
- Administrators invite users by email with an organization role.
- A new user follows the expiring link. They create a password only on a
  deployment without SSO; under OIDC, the account is linked by verified email
  on first provider sign-in.
- An existing user signs in as the invited address before accepting.
- On a deployment without SSO, password-reset requests return a generic
  response and send an expiring link only when the account exists. Completing
  a reset revokes all existing browser sessions. Both endpoints are disabled
  while OIDC is configured.
- Browser sessions are HttpOnly, expiring, revocable, and stored as hashes.
- Native clients enroll through a 10-minute OAuth device grant. A signed-in
  person reviews the terminal code and machine, then approves it into their
  active organization and optional team. The CLI receives an installation
  credential, never the person's browser or identity-provider token.

With no OIDC provider, passwords are hashed with Argon2. Invitation and reset tokens contain 32 random
bytes; only SHA-256 token digests are stored. Resending an invitation rotates
its token. Production mail requires authenticated, certificate-verified
STARTTLS or implicit TLS.

## Roles

Organization memberships grant `viewer`, `analyst`, or `admin`. One account
can belong to multiple organizations and selects an active organization in its
browser session. Dashboard service tokens remain available for automation but
cannot perform actions, such as invitations, that require a human audit actor.

## Enterprise SSO

One deployment-wide OIDC provider is supported with discovery,
authorization-code flow, PKCE, nonce/state validation, verified-email account
linking, and configurable just-in-time provisioning. When configured, it is
the only browser authentication method. Native client enrollment remains a
public device grant; the person approves it using their OIDC-backed Metrune
session, and the client never receives an IdP token. See
[Single sign-on and native client authentication](sso-design.md).

Per-organization providers, domain policy, SCIM, and group-to-role mapping
remain roadmap work. Native SAML is not planned; an OIDC bridge is the
preferred integration.
