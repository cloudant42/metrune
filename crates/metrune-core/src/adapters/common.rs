use crate::{Cost, CostKind, TokenBreakdown, UsageMessage};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

pub fn value_at<'a>(value: &'a Value, paths: &[&[&str]]) -> Option<&'a Value> {
    paths.iter().find_map(|path| {
        path.iter()
            .try_fold(value, |current, key| current.get(*key))
    })
}

fn u64_at(value: &Value, paths: &[&[&str]]) -> u64 {
    value_at(value, paths)
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_i64().map(|n| n.max(0) as u64))
        })
        .unwrap_or(0)
}

fn string_at(value: &Value, paths: &[&[&str]]) -> Option<String> {
    value_at(value, paths)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn timestamp_at(value: &Value) -> DateTime<Utc> {
    let raw = value_at(
        value,
        &[
            &["timestamp"],
            &["created_at"],
            &["createdAt"],
            &["time", "created"],
        ],
    );
    match raw {
        Some(Value::String(value)) => DateTime::parse_from_rfc3339(value)
            .map(|value| value.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        Some(Value::Number(value)) => {
            let timestamp = value.as_i64().unwrap_or_default();
            let timestamp = if timestamp > 10_000_000_000 {
                timestamp / 1000
            } else {
                timestamp
            };
            Utc.timestamp_opt(timestamp, 0)
                .single()
                .unwrap_or_else(Utc::now)
        }
        _ => Utc::now(),
    }
}

pub(crate) fn text_hint(value: &Value) -> Option<String> {
    value_at(
        value,
        &[
            &["message", "content"],
            &["content"],
            &["payload", "message", "content"],
            &["text"],
        ],
    )
    .and_then(|content| match content {
        Value::String(text) => Some(text.clone()),
        Value::Array(parts) => Some(
            parts
                .iter()
                .filter_map(|part| part.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
        _ => None,
    })
    .filter(|text| !text.trim().is_empty())
}

pub fn parse_usage_value(
    value: &Value,
    client_id: &str,
    fallback_id: String,
    fallback_session_id: String,
) -> Option<UsageMessage> {
    let role = string_at(
        value,
        &[&["role"], &["message", "role"], &["payload", "role"]],
    );
    if role.as_deref().is_some_and(|role| role != "assistant") {
        return None;
    }

    let tokens = TokenBreakdown {
        input: u64_at(
            value,
            &[
                &["usage", "input_tokens"],
                &["tokens", "input"],
                &["input_tokens"],
            ],
        ),
        output: u64_at(
            value,
            &[
                &["usage", "output_tokens"],
                &["tokens", "output"],
                &["output_tokens"],
            ],
        ),
        cache_read: u64_at(
            value,
            &[
                &["usage", "cache_read_input_tokens"],
                &["tokens", "cache", "read"],
                &["cache_read"],
            ],
        ),
        cache_write: u64_at(
            value,
            &[
                &["usage", "cache_creation_input_tokens"],
                &["tokens", "cache", "write"],
                &["cache_write"],
            ],
        ),
        reasoning: u64_at(
            value,
            &[
                &["usage", "reasoning_tokens"],
                &["tokens", "reasoning"],
                &["reasoning_tokens"],
            ],
        ),
    };
    if tokens.total() == 0 {
        return None;
    }

    let cost_amount = value_at(value, &[&["cost"], &["usage", "cost"]])
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    Some(UsageMessage {
        source_message_id: string_at(value, &[&["id"], &["message", "id"], &["uuid"]])
            .unwrap_or(fallback_id),
        session_id: string_at(
            value,
            &[&["session_id"], &["sessionId"], &["session", "id"]],
        )
        .unwrap_or(fallback_session_id),
        project_path: string_at(value, &[&["cwd"], &["workspace"], &["project_path"]]),
        client_id: client_id.into(),
        client_version: string_at(value, &[&["client_version"], &["version"]]),
        provider_id: string_at(
            value,
            &[
                &["provider"],
                &["provider_id"],
                &["providerID"],
                &["model_provider"],
            ],
        )
        .unwrap_or_else(|| "unknown".into()),
        model_id: string_at(
            value,
            &[
                &["model"],
                &["model_id"],
                &["modelID"],
                &["message", "model"],
            ],
        )
        .unwrap_or_else(|| "unknown".into()),
        observed_at: timestamp_at(value),
        tokens,
        cost: Cost {
            amount: cost_amount,
            currency: "USD".into(),
            kind: if cost_amount > 0.0 {
                CostKind::Reported
            } else {
                CostKind::Unknown
            },
            pricebook_version: None,
            price_source: None,
        },
        classification_text: text_hint(value),
    })
}
