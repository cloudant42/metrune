-- Authoritative owner stamped by the server from installation authentication.
-- The client-provided user_key remains pseudonymous metadata and is never used
-- to authorize a personal analytics query.
ALTER TABLE metrune.session_snapshots
  ADD COLUMN IF NOT EXISTS owner_user_id String DEFAULT '';
