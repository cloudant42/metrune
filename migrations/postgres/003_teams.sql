CREATE TABLE IF NOT EXISTS teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (organization_id, name)
);

ALTER TABLE installations ADD COLUMN IF NOT EXISTS team_id UUID REFERENCES teams(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS installations_team_idx ON installations(team_id);

-- Backfill teams from the legacy free-text team_key on installations and
-- enrollment tokens so existing deployments keep their grouping.
INSERT INTO teams(organization_id, name)
SELECT DISTINCT organization_id, team_key FROM installations
WHERE team_key IS NOT NULL AND team_key <> ''
ON CONFLICT (organization_id, name) DO NOTHING;

INSERT INTO teams(organization_id, name)
SELECT DISTINCT organization_id, team_key FROM enrollment_tokens
WHERE team_key IS NOT NULL AND team_key <> ''
ON CONFLICT (organization_id, name) DO NOTHING;

UPDATE installations i
SET team_id = t.id
FROM teams t
WHERE i.organization_id = t.organization_id
  AND i.team_key = t.name
  AND i.team_id IS NULL;

ALTER TABLE enrollment_tokens ADD COLUMN IF NOT EXISTS team_id UUID REFERENCES teams(id) ON DELETE SET NULL;

UPDATE enrollment_tokens e
SET team_id = t.id
FROM teams t
WHERE e.organization_id = t.organization_id
  AND e.team_key = t.name
  AND e.team_id IS NULL;
