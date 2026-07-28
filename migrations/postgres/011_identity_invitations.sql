-- Invitation-based local account acquisition and password recovery.
--
-- Raw invitation and reset tokens are delivered once over email. PostgreSQL
-- stores only their SHA-256 digests, matching the existing session/token
-- storage boundary.

CREATE TABLE IF NOT EXISTS workspace_invitations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('viewer', 'analyst', 'admin')),
  token_hash TEXT NOT NULL UNIQUE,
  invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  sent_at TIMESTAMPTZ,
  delivery_error_at TIMESTAMPTZ,
  accepted_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS workspace_invitations_pending_email_idx
  ON workspace_invitations(organization_id, LOWER(email))
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS workspace_invitations_expiry_idx
  ON workspace_invitations(expires_at)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  sent_at TIMESTAMPTZ,
  delivery_error_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user_idx
  ON password_reset_tokens(user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS password_reset_tokens_expiry_idx
  ON password_reset_tokens(expires_at)
  WHERE consumed_at IS NULL AND revoked_at IS NULL;
