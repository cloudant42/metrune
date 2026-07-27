use super::{
    common::{parse_usage_value, text_hint},
    SourceAdapter,
};
use crate::UsageMessage;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

pub struct CodexAdapter;

impl SourceAdapter for CodexAdapter {
    fn id(&self) -> &'static str {
        "codex"
    }

    fn discover(&self, home: &Path, extra_roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
        let roots =
            std::iter::once(home.join(".codex/sessions")).chain(extra_roots.iter().cloned());
        Ok(roots
            .flat_map(|root| WalkDir::new(root).into_iter().filter_map(Result::ok))
            .map(|entry| entry.into_path())
            .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "jsonl"))
            .collect())
    }

    fn parse(&self, source: &Path) -> Result<Vec<UsageMessage>> {
        let file = File::open(source)
            .with_context(|| format!("open Codex source {}", source.display()))?;
        let records = BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|line| serde_json::from_str::<Value>(&line).ok())
            .collect::<Vec<_>>();

        let session_meta = records
            .iter()
            .find(|record| record["type"] == "session_meta");
        let metadata = session_meta.and_then(|record| record.get("payload"));
        let session_id = metadata
            .and_then(|value| value.get("session_id"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| source.display().to_string());
        let project_path = metadata
            .and_then(|value| value.get("cwd"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let provider_id = metadata
            .and_then(|value| value.get("model_provider"))
            .and_then(Value::as_str)
            .unwrap_or("openai");
        let client_version = metadata
            .and_then(|value| value.get("cli_version"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let model_id = records
            .iter()
            .filter_map(|record| record.get("payload"))
            .find_map(|payload| payload.get("model").and_then(Value::as_str))
            .unwrap_or("unknown");
        let classification_text = records
            .iter()
            .filter_map(|record| record.get("payload"))
            .filter_map(text_hint)
            .take(12)
            .collect::<Vec<_>>()
            .join("\n\n");

        let mut total = TokenTotals::default();
        let mut latest_timestamp = None;
        let mut saw_token_count = false;
        for record in &records {
            let Some(payload) = record.get("payload") else {
                continue;
            };
            if payload.get("type").and_then(Value::as_str) != Some("token_count") {
                continue;
            }
            let Some(usage) = payload
                .get("info")
                .and_then(|info| info.get("total_token_usage"))
            else {
                continue;
            };
            saw_token_count = true;
            total.input = total.input.max(number_at(usage, "input_tokens"));
            total.cache_read = total
                .cache_read
                .max(number_at(usage, "cached_input_tokens"));
            total.output = total.output.max(number_at(usage, "output_tokens"));
            total.reasoning = total
                .reasoning
                .max(number_at(usage, "reasoning_output_tokens"));
            latest_timestamp = record.get("timestamp").cloned();
        }

        if saw_token_count && total.total() > 0 {
            let value = json!({
                "id": format!("{session_id}:token_count"),
                "session_id": session_id,
                "cwd": project_path,
                "provider": provider_id,
                "model": model_id,
                "version": client_version,
                "timestamp": latest_timestamp.unwrap_or_else(|| Value::String(chrono::Utc::now().to_rfc3339())),
                "usage": {
                    "input_tokens": total.input,
                    "output_tokens": total.output,
                    "cache_read_input_tokens": total.cache_read,
                    "reasoning_tokens": total.reasoning
                }
            });
            let Some(mut message) = parse_usage_value(
                &value,
                self.id(),
                source.display().to_string(),
                source.display().to_string(),
            ) else {
                return Ok(Vec::new());
            };
            message.classification_text =
                (!classification_text.is_empty()).then_some(classification_text);
            return Ok(vec![message]);
        }

        Ok(records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                let value = record
                    .get("payload")
                    .filter(|payload| payload.is_object())
                    .cloned()
                    .unwrap_or_else(|| record.clone());
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

#[derive(Default)]
struct TokenTotals {
    input: u64,
    output: u64,
    cache_read: u64,
    reasoning: u64,
}

impl TokenTotals {
    fn total(&self) -> u64 {
        self.input + self.output + self.cache_read + self.reasoning
    }
}

fn number_at(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().map(|number| number.max(0) as u64))
        })
        .unwrap_or(0)
}
