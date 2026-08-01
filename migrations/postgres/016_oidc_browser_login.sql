-- Deployment-wide OpenID Connect browser sign-in.
--
-- Authorization state is short-lived and single-use. The browser receives the
-- raw state value; PostgreSQL stores only its SHA-256 digest. The PKCE verifier
-- and nonce stay server-side and never round-trip through the browser.

CREATE TABLE IF NOT EXISTS oidc_authorization_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  state_hash TEXT NOT NULL UNIQUE,
  pkce_verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  next_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  CHECK (char_length(pkce_verifier) BETWEEN 43 AND 128),
  CHECK (next_path IS NULL OR (
    char_length(next_path) BETWEEN 1 AND 2048
    AND left(next_path, 1) = '/'
    AND left(next_path, 2) <> '//'
  ))
);

CREATE INDEX IF NOT EXISTS oidc_authorization_attempts_expiry_idx
  ON oidc_authorization_attempts(expires_at)
  WHERE consumed_at IS NULL;

ALTER TABLE web_sessions
  ADD COLUMN IF NOT EXISTS authentication_method TEXT NOT NULL DEFAULT 'local'
  CHECK (authentication_method IN ('local', 'oidc'));

-- Migration 014 made unenforced per-organization SSO flags impossible. Browser
-- OIDC is now enforced at deployment level; startup synchronizes these
-- compatibility columns so older dashboards and database tooling remain
-- truthful.
ALTER TABLE organizations
  DROP CONSTRAINT IF EXISTS organizations_sso_flags_unenforced;
