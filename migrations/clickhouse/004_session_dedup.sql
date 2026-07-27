-- Cross-installation session identity.
--
-- session_snapshots is retained as the legacy source table. The API writes and
-- queries this table as the authoritative deduplicated history for snapshots
-- emitted by the deterministic session-identity client. Installation ID
-- remains a payload column so personal client filters continue to work, but
-- it is intentionally not part of the ReplacingMergeTree key.
--
-- Existing rows are intentionally not copied automatically: their keys were
-- derived from enrollment-specific HMAC keys and cannot be safely mapped back
-- to source sessions. They remain available for a reviewed reconciliation.
CREATE TABLE IF NOT EXISTS metrune.session_snapshots_dedup (
  organization_id String,
  installation_id String,
  owner_user_id String,
  session_key String,
  revision UInt64,
  user_key String,
  project_key String,
  project_alias String,
  team_key String,
  client_id LowCardinality(String),
  started_at_ms Int64,
  ended_at_ms Int64,
  category_id LowCardinality(String),
  category_confidence Float32,
  taxonomy_version LowCardinality(String),
  classifier_id String,
  total_tokens UInt64,
  total_cost Float64,
  snapshot_json String,
  ingested_at_ms Int64,
  retention_days UInt32 DEFAULT 365
)
ENGINE = ReplacingMergeTree(revision)
PARTITION BY toYYYYMM(toDateTime(ended_at_ms / 1000))
ORDER BY (organization_id, owner_user_id, session_key)
TTL toDateTime(ended_at_ms / 1000) + INTERVAL retention_days DAY DELETE;
