use super::{
    common::{parse_usage_value, text_hint, timestamp_at, workflow_signals},
    SourceAdapter,
};
use crate::{UsageMessage, WorkflowSignal};
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
        let records = BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
            .collect::<Vec<_>>();
        let session_started_at = records.iter().map(timestamp_at).min();
        let mut turn_sequence = 0_u32;
        let mut activity_sequence = 0_u32;
        let mut intent = None;
        let mut pending_signals = Vec::new();
        let mut messages = Vec::new();
        for (index, value) in records.iter().enumerate() {
            let role = value
                .get("type")
                .or_else(|| value.get("role"))
                .or_else(|| value.pointer("/message/role"))
                .and_then(Value::as_str);
            let is_tool_result = value
                .pointer("/message/content")
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    parts
                        .iter()
                        .any(|part| part.get("type").and_then(Value::as_str) == Some("tool_result"))
                });
            if role == Some("user") && !is_tool_result {
                turn_sequence = turn_sequence.saturating_add(1);
                activity_sequence = 0;
                intent = text_hint(value);
                pending_signals.clear();
            }
            for signal in workflow_signals(value) {
                if !pending_signals.contains(&signal) {
                    pending_signals.push(signal);
                }
            }
            if let Some(mut message) = parse_usage_value(
                value,
                self.id(),
                format!("{}:{index}", source.display()),
                source.display().to_string(),
            ) {
                activity_sequence = activity_sequence.saturating_add(1);
                message.turn_sequence = turn_sequence.max(1);
                message.activity_sequence = activity_sequence;
                message.session_started_at = session_started_at;
                message.classification_text = intent.clone();
                message.workflow_signals = pending_signals.clone();
                message.signal_capabilities = WorkflowSignal::ALL.to_vec();
                messages.push(message);
            }
        }
        Ok(messages)
    }
}
