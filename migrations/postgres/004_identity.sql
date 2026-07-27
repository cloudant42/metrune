-- Enterprise identity foundation.
--
-- Local password sign-in is the default so a fresh deployment works out of
-- the box. Connecting an OIDC identity provider (Entra ID, Okta, Keycloak,
-- Google Workspace) and enforcing SSO disables local passwords for that
-- organization. OIDC login, SCIM provisioning, and device-flow enrollment
-- build on top of these tables; dashboard_tokens remain as service tokens
-- for automation until then.

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS sso_enforced BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS local_login_enabled BOOLEAN NOT NULL DEFAULT TRUE;

CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  display_name TEXT,
  -- NULL when the identity is SSO-only (no local password set).
  password_hash TEXT,
  role TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer', 'analyst', 'admin')),
  -- External identity: OIDC issuer + subject claim. NULL for local-only users.
  issuer TEXT,
  subject TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ,
  UNIQUE (organization_id, email),
  UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS idp_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  protocol TEXT NOT NULL DEFAULT 'oidc' CHECK (protocol IN ('oidc', 'saml')),
  name TEXT NOT NULL,
  issuer_url TEXT NOT NULL,
  client_id TEXT NOT NULL,
  -- Reference to a deployment secret (env:/file:), never the secret itself.
  client_secret_ref TEXT,
  -- Email domains that are routed to this provider.
  domains TEXT[] NOT NULL DEFAULT '{}',
  -- Claim that carries group memberships for role/team mapping.
  group_claim TEXT NOT NULL DEFAULT 'groups',
  default_role TEXT NOT NULL DEFAULT 'viewer' CHECK (default_role IN ('viewer', 'analyst', 'admin')),
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS group_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  idp_connection_id UUID NOT NULL REFERENCES idp_connections(id) ON DELETE CASCADE,
  idp_group TEXT NOT NULL,
  role TEXT CHECK (role IN ('viewer', 'analyst', 'admin')),
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
  UNIQUE (idp_connection_id, idp_group)
);

CREATE TABLE IF NOT EXISTS team_memberships (
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (team_id, user_id)
);

CREATE TABLE IF NOT EXISTS web_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  ip INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS web_sessions_user_idx ON web_sessions(user_id);
CREATE INDEX IF NOT EXISTS web_sessions_expiry_idx ON web_sessions(expires_at) WHERE revoked_at IS NULL;

-- Service tokens for SCIM provisioning calls from the identity provider.
CREATE TABLE IF NOT EXISTS scim_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  -- Set once dashboard sign-in is user-based; NULL for service-token actions.
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  actor_label TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_events_org_idx ON audit_events(organization_id, created_at DESC);
