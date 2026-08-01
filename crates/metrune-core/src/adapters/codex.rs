use super::{
    common::{parse_usage_value, text_hint, timestamp_at, workflow_signals},
    SourceAdapter,
};
use crate::{UsageMessage, WorkflowSignal};
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
        let session_started_at = session_meta
            .map(timestamp_at)
            .or_else(|| records.first().map(timestamp_at));
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
        let mut model_id = "unknown".to_string();
        let mut previous = TokenTotals::default();
        let mut saw_token_count = false;
        let mut turn_sequence = 0_u32;
        let mut activity_sequence = 0_u32;
        let mut intent = None;
        let mut pending_signals = Vec::new();
        let mut messages = Vec::new();
        for (index, record) in records.iter().enumerate() {
            let Some(payload) = record.get("payload") else {
                continue;
            };
            if let Some(model) = payload.get("model").and_then(Value::as_str) {
                model_id = model.to_owned();
            }
            let payload_type = payload.get("type").and_then(Value::as_str);
            let role = payload.get("role").and_then(Value::as_str);
            if payload_type == Some("user_message") || role == Some("user") {
                let is_tool_result = payload
                    .get("content")
                    .and_then(Value::as_array)
                    .is_some_and(|parts| {
                        parts.iter().any(|part| {
                            part.get("type").and_then(Value::as_str) == Some("tool_result")
                        })
                    });
                if !is_tool_result {
                    turn_sequence = turn_sequence.saturating_add(1);
                    activity_sequence = 0;
                    intent = payload
                        .get("message")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                        .or_else(|| text_hint(payload));
                    pending_signals.clear();
                }
            }
            for signal in workflow_signals(payload) {
                if !pending_signals.contains(&signal) {
                    pending_signals.push(signal);
                }
            }
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
            let current = TokenTotals {
                input: number_at(usage, "input_tokens"),
                output: number_at(usage, "output_tokens"),
                cache_read: number_at(usage, "cached_input_tokens"),
                reasoning: number_at(usage, "reasoning_output_tokens"),
            };
            let delta = current.delta_from(&previous);
            previous = current;
            if delta.total() == 0 {
                continue;
            }
            let value = json!({
                "id": format!("{session_id}:token_count:{index}"),
                "session_id": session_id,
                "cwd": project_path,
                "provider": provider_id,
                "model": model_id,
                "version": client_version,
                "timestamp": record.get("timestamp").cloned().unwrap_or_else(|| Value::String(chrono::Utc::now().to_rfc3339())),
                "usage": {
                    "input_tokens": delta.input,
                    "output_tokens": delta.output,
                    "cache_read_input_tokens": delta.cache_read,
                    "reasoning_tokens": delta.reasoning
                }
            });
            if let Some(mut message) = parse_usage_value(
                &value,
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
                pending_signals.clear();
            }
        }

        if saw_token_count {
            return Ok(messages);
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
                .map(|mut message| {
                    message.turn_sequence = index.saturating_add(1) as u32;
                    message.activity_sequence = 1;
                    message.session_started_at = session_started_at;
                    message.signal_capabilities = WorkflowSignal::ALL.to_vec();
                    message
                })
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

    fn delta_from(&self, previous: &Self) -> Self {
        let reset = self.input < previous.input
            || self.output < previous.output
            || self.cache_read < previous.cache_read
            || self.reasoning < previous.reasoning;
        if reset {
            return Self {
                input: self.input,
                output: self.output,
                cache_read: self.cache_read,
                reasoning: self.reasoning,
            };
        }
        Self {
            input: self.input - previous.input,
            output: self.output - previous.output,
            cache_read: self.cache_read - previous.cache_read,
            reasoning: self.reasoning - previous.reasoning,
        }
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
