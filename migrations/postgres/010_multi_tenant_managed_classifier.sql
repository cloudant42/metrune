-- Multi-tenant browser identity and managed semantic classification.
--
-- `users.organization_id` and `users.role` are retained as compatibility
-- columns for existing deployments, but authorization moves to the
-- organization_memberships row selected by each web session.

CREATE TABLE IF NOT EXISTS organization_memberships (
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL DEFAULT 'viewer'
    CHECK (role IN ('viewer', 'analyst', 'admin')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  disabled_at TIMESTAMPTZ,
  PRIMARY KEY (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS organization_memberships_user_idx
  ON organization_memberships(user_id, organization_id)
  WHERE disabled_at IS NULL;

INSERT INTO organization_memberships(organization_id, user_id, role)
SELECT organization_id, id, role
FROM users
ON CONFLICT (organization_id, user_id) DO NOTHING;

ALTER TABLE web_sessions
  ADD COLUMN IF NOT EXISTS active_organization_id UUID
    REFERENCES organizations(id) ON DELETE SET NULL;

UPDATE web_sessions s
SET active_organization_id = u.organization_id
FROM users u
WHERE u.id = s.user_id
  AND s.active_organization_id IS NULL
  AND EXISTS (
    SELECT 1
    FROM organization_memberships m
    WHERE m.user_id = s.user_id
      AND m.organization_id = u.organization_id
      AND m.disabled_at IS NULL
  );

CREATE INDEX IF NOT EXISTS web_sessions_active_organization_idx
  ON web_sessions(active_organization_id)
  WHERE revoked_at IS NULL;

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS classifier_execution_mode TEXT NOT NULL DEFAULT 'local'
    CHECK (classifier_execution_mode IN ('local', 'managed'));
