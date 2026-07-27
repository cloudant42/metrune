-- Distinguish a valid semantic `unknown` result from a classifier that was
-- disabled, unavailable, or returned an invalid response.
ALTER TABLE metrune.session_snapshots_dedup
  ADD COLUMN IF NOT EXISTS classification_status LowCardinality(String) DEFAULT 'unavailable';
