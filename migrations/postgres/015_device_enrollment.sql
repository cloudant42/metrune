-- Browser-approved native client enrollment.
--
-- The native client is a public OAuth client: it has no embedded secret.
-- Device and user codes are returned once and only their SHA-256 digests are
-- persisted. Approval binds the eventual installation to the approving user,
-- their active organization, and (optionally) a team.

CREATE TABLE IF NOT EXISTS device_enrollment_authorizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  installation_name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('linux', 'wsl', 'windows', 'macos', 'other')),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  owner_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
  poll_interval_seconds INTEGER NOT NULL DEFAULT 5
    CHECK (poll_interval_seconds BETWEEN 5 AND 60),
  last_polled_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  approved_at TIMESTAMPTZ,
  denied_at TIMESTAMPTZ,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (
    (status = 'pending'
      AND organization_id IS NULL
      AND owner_user_id IS NULL
      AND approved_at IS NULL
      AND denied_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'approved'
      AND organization_id IS NOT NULL
      AND owner_user_id IS NOT NULL
      AND approved_at IS NOT NULL
      AND denied_at IS NULL
      AND consumed_at IS NULL)
    OR
    (status = 'denied'
      AND organization_id IS NOT NULL
      AND owner_user_id IS NOT NULL
      AND approved_at IS NULL
      AND denied_at IS NOT NULL
      AND consumed_at IS NULL)
    OR
    (status = 'consumed'
      AND organization_id IS NOT NULL
      AND owner_user_id IS NOT NULL
      AND approved_at IS NOT NULL
      AND denied_at IS NULL
      AND consumed_at IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS device_enrollment_authorizations_expiry_idx
  ON device_enrollment_authorizations(expires_at)
  WHERE status IN ('pending', 'approved');

CREATE INDEX IF NOT EXISTS device_enrollment_authorizations_owner_idx
  ON device_enrollment_authorizations(owner_user_id, created_at DESC)
  WHERE owner_user_id IS NOT NULL;
