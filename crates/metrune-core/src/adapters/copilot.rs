use super::{common::parse_usage_value, SourceAdapter};
use crate::UsageMessage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

/// Reads the OpenTelemetry JSONL that Copilot CLI writes when file export is
/// enabled. Copilot's default session store holds prompts and responses, so it
/// is deliberately not a source here; the telemetry export carries token counts
/// without conversation content.
pub struct CopilotAdapter;

impl CopilotAdapter {
    /// The exporter writes wherever `COPILOT_OTEL_FILE_EXPORTER_PATH` points,
    /// which is a file rather than a directory and often lives outside the
    /// default folder.
    fn configured_export_path() -> Option<PathBuf> {
        env::var("COPILOT_OTEL_FILE_EXPORTER_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from)
    }

    fn is_export(path: &Path) -> bool {
        path.is_file() && path.extension().is_some_and(|ext| ext == "jsonl")
    }

    /// Merges the walked exports with an explicitly configured one. Kept
    /// separate from `discover` so the merge is testable without a test having
    /// to mutate the process environment, which would race its neighbours.
    fn merge_sources(mut discovered: Vec<PathBuf>, configured: Option<PathBuf>) -> Vec<PathBuf> {
        discovered.extend(configured);
        discovered.sort();
        discovered.dedup();
        discovered
    }
}

impl SourceAdapter for CopilotAdapter {
    fn id(&self) -> &'static str {
        "copilot"
    }

    fn discover(&self, home: &Path, extra_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let roots = std::iter::once(home.join(".copilot/otel")).chain(extra_roots.iter().cloned());
        let discovered = roots
            .flat_map(|root| WalkDir::new(root).into_iter().filter_map(Result::ok))
            .map(|entry| entry.into_path())
            .filter(|path| Self::is_export(path))
            .collect::<Vec<_>>();
        // The configured export skips the extension filter on purpose: the
        // operator named this file explicitly.
        let configured = Self::configured_export_path().filter(|path| path.is_file());
        Ok(Self::merge_sources(discovered, configured))
    }

    fn parse(&self, source: &Path) -> Result<Vec<UsageMessage>> {
        let file = File::open(source)
            .with_context(|| format!("open Copilot source {}", source.display()))?;
        Ok(BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .enumerate()
            .filter_map(|(index, line)| {
                let record: Value = serde_json::from_str(&line).ok()?;
                let value = chat_span_usage(&record)?;
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

/// Maps one `chat` span onto the shape `parse_usage_value` already understands.
/// Tool spans and cumulative metric records carry no per-call usage, so they are
/// skipped rather than double-counted.
fn chat_span_usage(record: &Value) -> Option<Value> {
    if record.get("type").and_then(Value::as_str) != Some("span") {
        return None;
    }
    let attributes = record.get("attributes")?;
    if attributes
        .get("gen_ai.operation.name")
        .and_then(Value::as_str)
        != Some("chat")
    {
        return None;
    }

    let usage = json!({
        "input_tokens": attribute_u64(attributes, "gen_ai.usage.input_tokens"),
        "output_tokens": attribute_u64(attributes, "gen_ai.usage.output_tokens"),
        "cache_read_input_tokens": attribute_u64(attributes, "gen_ai.usage.cache_read.input_tokens"),
        "cache_creation_input_tokens": attribute_u64(
            attributes,
            "gen_ai.usage.cache_creation.input_tokens",
        ),
        "reasoning_tokens": attribute_u64(attributes, "gen_ai.usage.reasoning.output_tokens"),
    });

    let mut value = json!({
        "session_id": attribute_str(attributes, "gen_ai.conversation.id"),
        "model": attribute_str(attributes, "gen_ai.response.model")
            .or_else(|| attribute_str(attributes, "gen_ai.request.model")),
        "provider": attribute_str(attributes, "gen_ai.provider.name")
            .or_else(|| attribute_str(attributes, "gen_ai.system"))
            .unwrap_or_else(|| "github-copilot".into()),
        "usage": usage,
    });

    // Copilot's OTEL payloads carry no stable workspace attribute, so sessions
    // stay unattributed rather than guessing a project from the export path.
    if let Some(timestamp) = span_timestamp(record) {
        value["timestamp"] = timestamp;
    }
    if let Some(id) = record
        .get("spanId")
        .or_else(|| record.get("span_id"))
        .and_then(Value::as_str)
    {
        value["id"] = json!(id);
    }
    Some(value)
}

fn attribute_u64(attributes: &Value, key: &str) -> u64 {
    attributes
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().map(|number| number.max(0) as u64))
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
        })
        .unwrap_or(0)
}

fn attribute_str(attributes: &Value, key: &str) -> Option<String> {
    attributes
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToOwned::to_owned)
}

/// Spans report nanosecond epochs, which the shared timestamp helper would read
/// as a far-future second count.
fn span_timestamp(record: &Value) -> Option<Value> {
    let raw = ["endTimeUnixNano", "startTimeUnixNano"]
        .iter()
        .find_map(|key| record.get(*key))?;
    let nanos = raw
        .as_u64()
        .or_else(|| raw.as_str().and_then(|value| value.parse().ok()))?;
    chrono::DateTime::from_timestamp(
        (nanos / 1_000_000_000) as i64,
        (nanos % 1_000_000_000) as u32,
    )
    .map(|timestamp| json!(timestamp.to_rfc3339()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_export_is_added_once_wherever_it_lives() {
        let walked = vec![PathBuf::from("/home/a/.copilot/otel/b.jsonl")];
        let outside = PathBuf::from("/var/log/copilot.jsonl");
        assert_eq!(
            CopilotAdapter::merge_sources(walked.clone(), Some(outside.clone())),
            vec![walked[0].clone(), outside],
            "an export outside the default folder must still be read"
        );

        // Configuring the same file the walk already found must not read it twice.
        assert_eq!(
            CopilotAdapter::merge_sources(walked.clone(), Some(walked[0].clone())),
            walked
        );
        assert_eq!(CopilotAdapter::merge_sources(walked.clone(), None), walked);
    }

    #[test]
    fn duplicate_walked_exports_collapse() {
        // extra_roots may overlap the default folder.
        let export = PathBuf::from("/home/a/.copilot/otel/b.jsonl");
        assert_eq!(
            CopilotAdapter::merge_sources(vec![export.clone(), export.clone()], None),
            vec![export]
        );
    }
}
