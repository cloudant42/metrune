-- Authenticated personal analytics, installation ownership, and server-side
-- pricing. Existing installations remain unowned until they are re-enrolled
-- or assigned by a later administrative workflow.

ALTER TABLE installations
  ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS platform TEXT;

CREATE INDEX IF NOT EXISTS installations_owner_idx
  ON installations(owner_user_id) WHERE owner_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS enrollment_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  owner_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
  token_hash TEXT NOT NULL UNIQUE,
  installation_name TEXT NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('linux', 'wsl', 'windows', 'macos', 'other')),
  expires_at TIMESTAMPTZ NOT NULL,
  redeemed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS enrollment_codes_owner_idx
  ON enrollment_codes(owner_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS model_prices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'USD',
  input_per_million DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (input_per_million >= 0),
  output_per_million DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (output_per_million >= 0),
  cache_read_per_million DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (cache_read_per_million >= 0),
  cache_write_per_million DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (cache_write_per_million >= 0),
  reasoning_per_million DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (reasoning_per_million >= 0),
  request_per_request DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (request_per_request >= 0),
  image_per_image DOUBLE PRECISION NOT NULL DEFAULT 0 CHECK (image_per_image >= 0),
  authority TEXT NOT NULL CHECK (authority IN (
    'default_catalog', 'openrouter', 'official_provider',
    'organization_override', 'self_hosted', 'manual'
  )),
  source_url TEXT,
  catalog_version TEXT NOT NULL,
  effective_from TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  effective_until TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CHECK (effective_until IS NULL OR effective_until > effective_from)
);

CREATE INDEX IF NOT EXISTS model_prices_lookup_idx
  ON model_prices(organization_id, provider_id, model_id, effective_from DESC);

CREATE UNIQUE INDEX IF NOT EXISTS model_prices_current_unique
  ON model_prices(COALESCE(organization_id, '00000000-0000-0000-0000-000000000000'::uuid), provider_id, model_id, authority)
  WHERE effective_until IS NULL;
