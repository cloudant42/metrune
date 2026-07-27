use crate::{BatchEnvelope, SessionSnapshot, SCHEMA_VERSION};
use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use uuid::Uuid;

pub struct LocalState {
    connection: Connection,
}

impl LocalState {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
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
             );",
        )?;
        Ok(Self { connection })
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
            "SELECT snapshot_json FROM session_outbox WHERE acknowledged_at IS NULL ORDER BY updated_at LIMIT ?1"
        )?;
        let snapshots = statement
            .query_map([limit as i64], |row| row.get::<_, String>(0))?
            .filter_map(Result::ok)
            .filter_map(|json| serde_json::from_str::<SessionSnapshot>(&json).ok())
            .collect();
        Ok(BatchEnvelope {
            schema_version: SCHEMA_VERSION.into(),
            batch_id: Uuid::new_v4().to_string(),
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
}

pub fn file_fingerprint(path: &Path) -> Result<String> {
    let metadata = path.metadata()?;
    let modified = metadata
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{}:{modified}", metadata.len()))
}
