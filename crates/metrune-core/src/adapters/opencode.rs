use super::{
    common::{parse_usage_value, text_hint, timestamp_at, workflow_signals},
    SourceAdapter,
};
use crate::{UsageMessage, WorkflowSignal};
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub struct OpenCodeAdapter;

impl OpenCodeAdapter {
    fn is_db(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                (name == "opencode.db" || (name.starts_with("opencode-") && name.ends_with(".db")))
                    && !name.ends_with("-wal")
                    && !name.ends_with("-shm")
            })
    }
}

impl SourceAdapter for OpenCodeAdapter {
    fn id(&self) -> &'static str {
        "opencode"
    }

    fn discover(&self, home: &Path, extra_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let data_root = home.join(".local/share/opencode");
        let mut sources: Vec<PathBuf> = fs::read_dir(&data_root)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| Self::is_db(path))
            .collect();
        sources.extend(
            WalkDir::new(data_root.join("storage/message"))
                .into_iter()
                .filter_map(Result::ok)
                .map(|entry| entry.into_path())
                .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "json")),
        );
        sources.extend(extra_roots.iter().filter(|path| path.exists()).cloned());
        sources.sort();
        sources.dedup();
        Ok(sources)
    }

    fn parse(&self, source: &Path) -> Result<Vec<UsageMessage>> {
        if Self::is_db(source) {
            let connection = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| format!("open OpenCode database {}", source.display()))?;
            let mut statement = connection.prepare(
                "SELECT m.id, m.session_id, m.data, NULLIF(s.directory, '')
                 FROM message m
                 LEFT JOIN session s ON s.id = m.session_id
                 ORDER BY
                   COALESCE(
                     json_extract(m.data, '$.timestamp'),
                     json_extract(m.data, '$.created_at'),
                     json_extract(m.data, '$.createdAt'),
                     ''
                   ),
                   m.id",
            )?;
            let rows = statement.query_map([], |row| {
                let id: String = row.get(0)?;
                let session_id: String = row.get(1)?;
                let data: String = row.get(2)?;
                let project: Option<String> = row.get(3)?;
                Ok((id, session_id, data, project))
            })?;
            let mut turns: HashMap<String, (u32, u32, Option<String>)> = HashMap::new();
            let mut session_starts = HashMap::new();
            let mut messages = Vec::new();
            for (id, session_id, data, project) in rows.filter_map(Result::ok) {
                let Ok(mut value) = serde_json::from_str::<Value>(&data) else {
                    continue;
                };
                let Some(object) = value.as_object_mut() else {
                    continue;
                };
                object.entry("id").or_insert(Value::String(id.clone()));
                object
                    .entry("session_id")
                    .or_insert(Value::String(session_id.clone()));
                if let Some(project) = project {
                    object.entry("workspace").or_insert(Value::String(project));
                }
                let observed = timestamp_at(&value);
                session_starts
                    .entry(session_id.clone())
                    .and_modify(|started: &mut chrono::DateTime<chrono::Utc>| {
                        *started = (*started).min(observed)
                    })
                    .or_insert(observed);
                let state = turns.entry(session_id).or_insert((0, 0, None));
                let role = value
                    .get("role")
                    .or_else(|| value.pointer("/message/role"))
                    .and_then(Value::as_str);
                if role == Some("user") {
                    state.0 = state.0.saturating_add(1);
                    state.1 = 0;
                    state.2 = text_hint(&value);
                    continue;
                }
                if let Some(mut message) =
                    parse_usage_value(&value, self.id(), id, source.display().to_string())
                {
                    state.1 = state.1.saturating_add(1);
                    message.turn_sequence = state.0.max(1);
                    message.activity_sequence = state.1;
                    message.classification_text = state.2.clone();
                    message.workflow_signals = workflow_signals(&value);
                    message.signal_capabilities = WorkflowSignal::ALL.to_vec();
                    messages.push(message);
                }
            }
            for message in &mut messages {
                message.session_started_at = session_starts.get(&message.session_id).copied();
            }
            Ok(messages)
        } else {
            let value: Value = serde_json::from_slice(&fs::read(source)?)?;
            Ok(parse_usage_value(
                &value,
                self.id(),
                source.display().to_string(),
                source.display().to_string(),
            )
            .map(|mut message| {
                message.turn_sequence = 1;
                message.activity_sequence = 1;
                message.session_started_at = Some(message.observed_at);
                message.signal_capabilities = WorkflowSignal::ALL.to_vec();
                message
            })
            .into_iter()
            .collect())
        }
    }
}
