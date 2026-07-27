use super::{common::parse_usage_value, SourceAdapter};
use crate::UsageMessage;
use anyhow::{Context, Result};
use serde_json::Value;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub struct ClaudeAdapter;

impl SourceAdapter for ClaudeAdapter {
    fn id(&self) -> &'static str {
        "claude"
    }

    fn discover(&self, home: &Path, extra_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let roots = [
            home.join(".claude/projects"),
            home.join(".claude/transcripts"),
        ]
        .into_iter()
        .chain(extra_roots.iter().cloned());
        Ok(roots
            .flat_map(|root| WalkDir::new(root).into_iter().filter_map(Result::ok))
            .map(|entry| entry.into_path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect())
    }

    fn parse(&self, source: &Path) -> Result<Vec<UsageMessage>> {
        let file = File::open(source)
            .with_context(|| format!("open Claude source {}", source.display()))?;
        Ok(BufReader::new(file)
            .lines()
            .enumerate()
            .filter_map(|(index, line)| {
                let value: Value = serde_json::from_str(&line.ok()?).ok()?;
                parse_usage_value(
                    &value,
                    self.id(),
                    format!("{}:{index}", source.display()),
                    source.display().to_string(),
                )
            })
            .collect())
    }
}
