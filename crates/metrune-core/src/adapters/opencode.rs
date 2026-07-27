use super::{common::parse_usage_value, SourceAdapter};
use crate::UsageMessage;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde_json::Value;
use std::{
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
                "SELECT m.id, m.session_id, m.data, NULLIF(s.directory, '') FROM message m LEFT JOIN session s ON s.id = m.session_id"
            )?;
            let rows = statement.query_map([], |row| {
                let id: String = row.get(0)?;
                let session_id: String = row.get(1)?;
                let data: String = row.get(2)?;
                let project: Option<String> = row.get(3)?;
                Ok((id, session_id, data, project))
            })?;
            Ok(rows
                .filter_map(Result::ok)
                .filter_map(|(id, session_id, data, project)| {
                    let mut value: Value = serde_json::from_str(&data).ok()?;
                    let object = value.as_object_mut()?;
                    object.entry("id").or_insert(Value::String(id.clone()));
                    object
                        .entry("session_id")
                        .or_insert(Value::String(session_id));
                    if let Some(project) = project {
                        object.entry("workspace").or_insert(Value::String(project));
                    }
                    parse_usage_value(&value, self.id(), id, source.display().to_string())
                })
                .collect())
        } else {
            let value: Value = serde_json::from_slice(&fs::read(source)?)?;
            Ok(parse_usage_value(
                &value,
                self.id(),
                source.display().to_string(),
                source.display().to_string(),
            )
            .into_iter()
            .collect())
        }
    }
}
