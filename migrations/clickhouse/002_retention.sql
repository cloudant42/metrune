-- Per-organization retention enforcement. The API stamps each snapshot with
-- the organization's current retention_days at ingest time; ClickHouse then
-- deletes rows once they age past their own stamped retention.
ALTER TABLE metrune.session_snapshots
  ADD COLUMN IF NOT EXISTS retention_days UInt32 DEFAULT 365;

ALTER TABLE metrune.session_snapshots
  MODIFY TTL toDateTime(ended_at_ms / 1000) + INTERVAL retention_days DAY DELETE;
