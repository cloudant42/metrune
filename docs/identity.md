# Identity and access

## Beta flows

- The deployment bootstraps exactly one initial administrator.
- Administrators invite users by email with an organization role.
- A new user follows the expiring link and creates a password.
- An existing user signs in as the invited address before accepting.
- Password-reset requests return a generic response and send an expiring link
  only when the account exists.
- Completing a reset revokes all existing browser sessions.
- Browser sessions are HttpOnly, expiring, revocable, and stored as hashes.

Passwords are hashed with Argon2. Invitation and reset tokens contain 32 random
bytes; only SHA-256 token digests are stored. Resending an invitation rotates
its token. Production mail requires authenticated, certificate-verified
STARTTLS or implicit TLS.

## Roles

Organization memberships grant `viewer`, `analyst`, or `admin`. One account
can belong to multiple organizations and selects an active organization in its
browser session. Dashboard service tokens remain available for automation but
cannot perform actions, such as invitations, that require a human audit actor.

## Future identity integrations

OIDC authorization-code + PKCE, domain policy, SCIM, and group-to-role mapping
remain roadmap work. Schema reserved for those features is not a claim that
the flows are supported. Native SAML is not planned; an OIDC bridge is the
preferred future integration.
