use crate::{
    BatchEnvelope, CategoryAssignment, SessionSnapshot, LEGACY_SCHEMA_VERSION, SCHEMA_VERSION,
};
use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
};

const STATE_RETENTION_DAYS: i64 = 30;
const SQLITE_BUSY_TIMEOUT_MS: u64 = 5_000;

pub struct LocalState {
    connection: Connection,
}

impl LocalState {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // SQLite creates WAL/SHM sidecars lazily. Open the database with a
        // private mode from the start, then re-assert it after enabling WAL so
        // an existing 0644 database cannot leak source paths or cache data.
        let connection = {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(path)?;
            drop(file);
            Connection::open(path)?
        };
        connection.busy_timeout(std::time::Duration::from_millis(SQLITE_BUSY_TIMEOUT_MS))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS source_checkpoints (
               source_path TEXT PRIMARY KEY,
               fingerprint TEXT NOT NULL,
               scanned_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS session_outbox (
               session_key TEXT PRIMARY KEY,
               revision INTEGER NOT NULL,
               snapshot_json TEXT NOT NULL,
               acknowledged_at TEXT,
               updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS local_metadata (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS session_schema (
               session_key TEXT PRIMARY KEY,
               schema_version TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS classification_cache (
               cache_key TEXT PRIMARY KEY,
               assignment_json TEXT NOT NULL,
               updated_at TEXT NOT NULL
             );",
        )?;
        let state = Self { connection };
        state.set_private_permissions(path)?;
        state.set_private_permissions(&sidecar_path(path, "-wal"))?;
        state.set_private_permissions(&sidecar_path(path, "-shm"))?;
        state.prune_expired_rows()?;
        state.ensure_v2_activation_marker()?;
        Ok(state)
    }

    pub fn fingerprint(&self, path: &Path) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT fingerprint FROM source_checkpoints WHERE source_path = ?1",
                [path.to_string_lossy().as_ref()],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn checkpoint(&self, path: &Path, fingerprint: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO source_checkpoints(source_path, fingerprint, scanned_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(source_path) DO UPDATE SET fingerprint = excluded.fingerprint, scanned_at = excluded.scanned_at",
            params![path.to_string_lossy(), fingerprint, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn queue_snapshot(&self, snapshot: &SessionSnapshot) -> Result<()> {
        self.connection.execute(
            "INSERT INTO session_outbox(session_key, revision, snapshot_json, acknowledged_at, updated_at)
             VALUES (?1, ?2, ?3, NULL, ?4)
             ON CONFLICT(session_key) DO UPDATE SET revision = excluded.revision, snapshot_json = excluded.snapshot_json,
             acknowledged_at = NULL, updated_at = excluded.updated_at WHERE excluded.revision >= session_outbox.revision",
            params![snapshot.session_key, snapshot.revision, serde_json::to_string(snapshot)?, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn pending_batch(&self, limit: usize) -> Result<BatchEnvelope> {
        let mut statement = self.connection.prepare(
            "SELECT session_key, snapshot_json FROM session_outbox WHERE acknowledged_at IS NULL ORDER BY updated_at, session_key LIMIT ?1"
        )?;
        let rows = statement.query_map([limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut snapshots = Vec::new();
        for row in rows {
            let (session_key, json) = row?;
            let snapshot = serde_json::from_str::<SessionSnapshot>(&json).with_context(|| {
                format!("decode queued session snapshot {session_key}; local state may be corrupt")
            })?;
            snapshots.push(snapshot);
        }
        // The server's idempotency record is useful only if a retry after a
        // timeout or lost acknowledgement carries the same batch ID. Hash the
        // exact ordered payload rather than minting a new random ID per
        // attempt. Any revised snapshot changes the digest and therefore gets
        // a new idempotency scope.
        let mut digest = Sha256::new();
        digest.update(SCHEMA_VERSION.as_bytes());
        for snapshot in &snapshots {
            let encoded = serde_json::to_vec(snapshot)?;
            digest.update((encoded.len() as u64).to_le_bytes());
            digest.update(encoded);
        }
        Ok(BatchEnvelope {
            schema_version: SCHEMA_VERSION.into(),
            batch_id: format!("mb_{}", hex::encode(digest.finalize())),
            sent_at: Utc::now(),
            snapshots,
        })
    }

    pub fn acknowledge(&self, snapshots: &[SessionSnapshot]) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        for snapshot in snapshots {
            self.connection.execute(
                "UPDATE session_outbox SET acknowledged_at = ?1 WHERE session_key = ?2 AND revision <= ?3",
                params![now, snapshot.session_key, snapshot.revision],
            )?;
        }
        Ok(())
    }

    /// Acknowledge only the rows named by a partial ingest response. Invalid
    /// snapshots are derived locally and cannot become valid through retry;
    /// marking them complete prevents one bad row from starving the outbox.
    pub fn acknowledge_session_keys(
        &self,
        snapshots: &[SessionSnapshot],
        session_keys: &[String],
    ) -> Result<()> {
        let keys = session_keys
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        if keys.is_empty() {
            return Ok(());
        }
        let now = Utc::now().to_rfc3339();
        for snapshot in snapshots {
            if keys.contains(snapshot.session_key.as_str()) {
                self.connection.execute(
                    "UPDATE session_outbox SET acknowledged_at = ?1 WHERE session_key = ?2 AND revision <= ?3",
                    params![now, snapshot.session_key, snapshot.revision],
                )?;
            }
        }
        Ok(())
    }

    fn ensure_v2_activation_marker(&self) -> Result<()> {
        self.connection.execute(
            "INSERT INTO local_metadata(key, value) VALUES ('schema_v2_activated_at', ?1)
             ON CONFLICT(key) DO NOTHING",
            [Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn session_schema_version(
        &self,
        session_key: &str,
        started_at: DateTime<Utc>,
    ) -> Result<String> {
        if let Some(version) = self
            .connection
            .query_row(
                "SELECT schema_version FROM session_schema WHERE session_key = ?1",
                [session_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
        {
            return Ok(version);
        }
        let activated_at = self.connection.query_row(
            "SELECT value FROM local_metadata WHERE key = 'schema_v2_activated_at'",
            [],
            |row| row.get::<_, String>(0),
        )?;
        let activated_at = DateTime::parse_from_rfc3339(&activated_at)?.with_timezone(&Utc);
        let version = if started_at >= activated_at {
            SCHEMA_VERSION
        } else {
            LEGACY_SCHEMA_VERSION
        };
        self.connection.execute(
            "INSERT INTO session_schema(session_key, schema_version) VALUES (?1, ?2)
             ON CONFLICT(session_key) DO NOTHING",
            params![session_key, version],
        )?;
        Ok(version.into())
    }

    pub fn cached_classification(&self, cache_key: &str) -> Result<Option<CategoryAssignment>> {
        let json = self
            .connection
            .query_row(
                "SELECT assignment_json FROM classification_cache WHERE cache_key = ?1",
                [cache_key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(json.and_then(|json| serde_json::from_str(&json).ok()))
    }

    pub fn cache_classification(
        &self,
        cache_key: &str,
        assignment: &CategoryAssignment,
    ) -> Result<()> {
        self.connection.execute(
            "INSERT INTO classification_cache(cache_key, assignment_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(cache_key) DO UPDATE SET assignment_json = excluded.assignment_json,
             updated_at = excluded.updated_at",
            params![
                cache_key,
                serde_json::to_string(assignment)?,
                Utc::now().to_rfc3339()
            ],
        )?;
        Ok(())
    }

    /// Update prompts may perform network I/O only once per interval. A
    /// malformed or missing timestamp is treated as due so a corrupt cache
    /// cannot suppress notices forever.
    pub fn update_check_due(&self, now: DateTime<Utc>, minimum_interval: Duration) -> Result<bool> {
        let last_checked = self
            .connection
            .query_row(
                "SELECT value FROM local_metadata WHERE key = 'last_update_check_at'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(last_checked) = last_checked
            .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
            .map(|value| value.with_timezone(&Utc))
        else {
            return Ok(true);
        };
        Ok(now < last_checked || now.signed_duration_since(last_checked) >= minimum_interval)
    }

    pub fn record_update_check(&self, checked_at: DateTime<Utc>) -> Result<()> {
        self.connection.execute(
            "INSERT INTO local_metadata(key, value) VALUES ('last_update_check_at', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [checked_at.to_rfc3339()],
        )?;
        Ok(())
    }

    /// Atomically claim the update-check slot. Multiple watch processes can
    /// run at once, so a separate check-then-record pair otherwise causes a
    /// burst of requests at the 24-hour boundary.
    pub fn claim_update_check(
        &self,
        now: DateTime<Utc>,
        minimum_interval: Duration,
    ) -> Result<bool> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let last_checked = self
                .connection
                .query_row(
                    "SELECT value FROM local_metadata WHERE key = 'last_update_check_at'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            let due = last_checked
                .and_then(|value| DateTime::parse_from_rfc3339(&value).ok())
                .map(|value| {
                    let checked_at = value.with_timezone(&Utc);
                    now < checked_at || now.signed_duration_since(checked_at) >= minimum_interval
                })
                .unwrap_or(true);
            if due {
                self.connection.execute(
                    "INSERT INTO local_metadata(key, value) VALUES ('last_update_check_at', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [now.to_rfc3339()],
                )?;
            }
            Ok::<bool, anyhow::Error>(due)
        })();
        match result {
            Ok(due) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(due)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    /// Allocate a strictly increasing revision across scans and processes.
    /// Timestamp-derived revisions can collide when two updates share a
    /// timestamp, and a classifier/config change can otherwise move a snapshot
    /// backwards and be discarded by the outbox/server replacement policy.
    pub fn next_revision(&self, observed: u64) -> Result<u64> {
        self.connection.execute_batch("BEGIN IMMEDIATE")?;
        let result = (|| {
            let current = self
                .connection
                .query_row(
                    "SELECT value FROM local_metadata WHERE key = 'last_session_revision'",
                    [],
                    |row| row.get::<_, String>(0),
                )
                .optional()?
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            let revision = observed.max(current.saturating_add(1));
            self.connection.execute(
                "INSERT INTO local_metadata(key, value) VALUES ('last_session_revision', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [revision.to_string()],
            )?;
            Ok::<u64, anyhow::Error>(revision)
        })();
        match result {
            Ok(revision) => {
                self.connection.execute_batch("COMMIT")?;
                Ok(revision)
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }

    fn prune_expired_rows(&self) -> Result<()> {
        let cutoff = (Utc::now() - Duration::days(STATE_RETENTION_DAYS)).to_rfc3339();
        self.connection.execute(
            "DELETE FROM session_outbox WHERE acknowledged_at IS NOT NULL AND acknowledged_at < ?1",
            [&cutoff],
        )?;
        self.connection.execute(
            "DELETE FROM classification_cache WHERE updated_at < ?1",
            [&cutoff],
        )?;
        Ok(())
    }

    fn set_private_permissions(&self, path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path.exists() {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
        Ok(())
    }
}

pub fn file_fingerprint(path: &Path) -> Result<String> {
    let mut components = Vec::new();
    for candidate in [
        path.to_path_buf(),
        sidecar_path(path, "-wal"),
        sidecar_path(path, "-shm"),
    ] {
        if let Some(component) = metadata_fingerprint(&candidate)? {
            components.push(component);
        }
    }
    Ok(components.join("|"))
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{}", path.display(), suffix))
}

fn metadata_fingerprint(path: &Path) -> Result<Option<String>> {
    let Ok(metadata) = path.metadata() else {
        return Ok(None);
    };
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(Some(format!("{}:{}", metadata.len(), modified)))
}
