use crate::{CategoryAssignment, CategoryId, ClassificationStatus, TAXONOMY_VERSION};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt,
    sync::{OnceLock, RwLock},
};

#[async_trait]
pub trait ClassifierBackend: Send + Sync {
    async fn classify(&self, local_text: &str) -> Result<CategoryAssignment>;
    fn id(&self) -> String;
}

pub struct UnknownClassifier;

#[async_trait]
impl ClassifierBackend for UnknownClassifier {
    async fn classify(&self, _local_text: &str) -> Result<CategoryAssignment> {
        Ok(CategoryAssignment::default())
    }
    fn id(&self) -> String {
        "unavailable".into()
    }
}

#[derive(Debug, Clone)]
pub struct OpenAiCompatibleClassifier {
    pub endpoint: String,
    pub model: String,
    pub api_key: Option<String>,
    pub response_mode: ResponseMode,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    #[default]
    Auto,
    Structured,
    PromptJson,
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Structured => "structured",
            Self::PromptJson => "prompt_json",
        })
    }
}

#[derive(Debug)]
pub struct ClassifierDiagnostic {
    pub assignment: CategoryAssignment,
    pub response_mode: ResponseMode,
    pub repaired: bool,
}

impl OpenAiCompatibleClassifier {
    pub fn new(
        endpoint: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
        response_mode: ResponseMode,
    ) -> Result<Self> {
        Ok(Self {
            endpoint: endpoint.into(),
            model: model.into(),
            api_key,
            response_mode,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()?,
        })
    }

    pub async fn classify_with_diagnostics(
        &self,
        local_text: &str,
    ) -> Result<ClassifierDiagnostic> {
        let first_mode = match self.response_mode {
            ResponseMode::PromptJson => ResponseMode::PromptJson,
            ResponseMode::Structured => ResponseMode::Structured,
            ResponseMode::Auto => cached_response_mode(&self.endpoint, &self.model)
                .unwrap_or(ResponseMode::Structured),
        };
        let (content, effective_mode) = match self.request(local_text, first_mode, false).await {
            Ok(content) => {
                if self.response_mode == ResponseMode::Auto {
                    cache_response_mode(&self.endpoint, &self.model, first_mode);
                }
                (content, first_mode)
            }
            Err(error)
                if self.response_mode == ResponseMode::Auto
                    && error.status.is_some_and(|status| {
                        status == StatusCode::BAD_REQUEST
                            || status == StatusCode::UNPROCESSABLE_ENTITY
                    }) =>
            {
                cache_response_mode(&self.endpoint, &self.model, ResponseMode::PromptJson);
                (
                    self.request(local_text, ResponseMode::PromptJson, false)
                        .await
                        .map_err(anyhow::Error::from)?,
                    ResponseMode::PromptJson,
                )
            }
            Err(error) => return Err(error.into()),
        };

        match parse_assignment(&content, &self.model) {
            Ok(assignment) => Ok(ClassifierDiagnostic {
                assignment,
                response_mode: effective_mode,
                repaired: false,
            }),
            Err(first_error) => {
                let repaired = self
                    .request(local_text, ResponseMode::PromptJson, true)
                    .await
                    .map_err(anyhow::Error::from)?;
                let assignment = parse_assignment(&repaired, &self.model).with_context(|| {
                    format!("classifier repair failed after invalid response: {first_error:#}")
                })?;
                Ok(ClassifierDiagnostic {
                    assignment,
                    response_mode: ResponseMode::PromptJson,
                    repaired: true,
                })
            }
        }
    }

    async fn request(
        &self,
        local_text: &str,
        response_mode: ResponseMode,
        repair: bool,
    ) -> std::result::Result<String, ProviderRequestError> {
        let system = if repair {
            "The previous classifier response was invalid. Classify the coding-agent session into exactly one category: implementation, debugging, research, documentation, review_refactoring, testing, planning, operations, content, unknown. Return only one JSON object with category and confidence from 0 to 1. Do not use Markdown and do not quote or summarize the input."
        } else {
            "Classify this coding-agent session into exactly one category: implementation, debugging, research, documentation, review_refactoring, testing, planning, operations, content, unknown. Return only JSON with category and confidence from 0 to 1. Do not quote or summarize the input."
        };
        let request = ChatRequest {
            model: &self.model,
            temperature: 0.0,
            response_format: (response_mode == ResponseMode::Structured)
                .then(ResponseFormat::classifier),
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: system,
                },
                ChatMessage {
                    role: "user",
                    content: local_text,
                },
            ],
        };
        let mut builder = self.client.post(&self.endpoint).json(&request);
        if let Some(key) = &self.api_key {
            builder = builder.bearer_auth(key);
        }
        let response = builder
            .send()
            .await
            .map_err(ProviderRequestError::transport)?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ProviderRequestError::http(status, body));
        }
        let response: ChatResponse = response
            .json()
            .await
            .map_err(ProviderRequestError::transport)?;
        response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| ProviderRequestError::invalid("classifier returned no choices"))
    }
}

fn response_mode_cache() -> &'static RwLock<HashMap<String, ResponseMode>> {
    static CACHE: OnceLock<RwLock<HashMap<String, ResponseMode>>> = OnceLock::new();
    CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

fn response_mode_key(endpoint: &str, model: &str) -> String {
    format!("{}|{}", endpoint.trim_end_matches('/'), model)
}

fn cached_response_mode(endpoint: &str, model: &str) -> Option<ResponseMode> {
    response_mode_cache()
        .read()
        .ok()
        .and_then(|cache| cache.get(&response_mode_key(endpoint, model)).copied())
}

fn cache_response_mode(endpoint: &str, model: &str, mode: ResponseMode) {
    if let Ok(mut cache) = response_mode_cache().write() {
        cache.insert(response_mode_key(endpoint, model), mode);
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
    messages: Vec<ChatMessage<'a>>,
}

#[derive(Serialize)]
struct ResponseFormat {
    r#type: &'static str,
    json_schema: JsonSchema,
}

impl ResponseFormat {
    fn classifier() -> Self {
        Self {
            r#type: "json_schema",
            json_schema: JsonSchema {
                name: "metrune_classifier",
                strict: true,
                schema: ClassifierSchema {
                    r#type: "object",
                    properties: ClassifierProperties {
                        category: CategorySchema {
                            r#type: "string",
                            r#enum: vec![
                                "implementation",
                                "debugging",
                                "research",
                                "documentation",
                                "review_refactoring",
                                "testing",
                                "planning",
                                "operations",
                                "content",
                                "unknown",
                            ],
                        },
                        confidence: ConfidenceSchema {
                            r#type: "number",
                            minimum: 0.0,
                            maximum: 1.0,
                        },
                    },
                    required: vec!["category", "confidence"],
                    additional_properties: false,
                },
            },
        }
    }
}

#[derive(Serialize)]
struct JsonSchema {
    name: &'static str,
    strict: bool,
    schema: ClassifierSchema,
}

#[derive(Serialize)]
struct ClassifierSchema {
    r#type: &'static str,
    properties: ClassifierProperties,
    required: Vec<&'static str>,
    #[serde(rename = "additionalProperties")]
    additional_properties: bool,
}

#[derive(Serialize)]
struct ClassifierProperties {
    category: CategorySchema,
    confidence: ConfidenceSchema,
}

#[derive(Serialize)]
struct CategorySchema {
    r#type: &'static str,
    #[serde(rename = "enum")]
    r#enum: Vec<&'static str>,
}

#[derive(Serialize)]
struct ConfidenceSchema {
    r#type: &'static str,
    minimum: f32,
    maximum: f32,
}

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: String,
}

#[derive(Deserialize)]
struct ClassifierOutput {
    category: String,
    confidence: f32,
}

#[derive(Debug)]
struct ProviderRequestError {
    status: Option<StatusCode>,
    message: String,
}

impl ProviderRequestError {
    fn transport(error: reqwest::Error) -> Self {
        Self {
            status: error.status(),
            message: error.to_string(),
        }
    }

    fn http(status: StatusCode, body: String) -> Self {
        Self {
            status: Some(status),
            message: format!("classifier request failed ({status}): {body}"),
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
        }
    }
}

impl fmt::Display for ProviderRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ProviderRequestError {}

#[async_trait]
impl ClassifierBackend for OpenAiCompatibleClassifier {
    async fn classify(&self, local_text: &str) -> Result<CategoryAssignment> {
        Ok(self.classify_with_diagnostics(local_text).await?.assignment)
    }

    fn id(&self) -> String {
        format!("openai-compatible:{}", self.model)
    }
}

fn parse_assignment(content: &str, model: &str) -> Result<CategoryAssignment> {
    let output: ClassifierOutput = parse_classifier_output(content)?;
    let category_id = match output.category.as_str() {
        "implementation" => CategoryId::Implementation,
        "debugging" => CategoryId::Debugging,
        "research" => CategoryId::Research,
        "documentation" => CategoryId::Documentation,
        "review_refactoring" => CategoryId::ReviewRefactoring,
        "testing" => CategoryId::Testing,
        "planning" => CategoryId::Planning,
        "operations" => CategoryId::Operations,
        "content" => CategoryId::Content,
        "unknown" => CategoryId::Unknown,
        other => return Err(anyhow!("unsupported category {other}")),
    };
    Ok(CategoryAssignment {
        category_id,
        confidence: output.confidence.clamp(0.0, 1.0),
        taxonomy_version: TAXONOMY_VERSION.into(),
        classifier_id: format!("openai-compatible:{model}"),
        classification_status: ClassificationStatus::Classified,
    })
}

fn parse_classifier_output(content: &str) -> Result<ClassifierOutput> {
    let trimmed = content.trim();
    if let Ok(output) = serde_json::from_str(trimmed) {
        return Ok(output);
    }
    let without_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|value| value.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);
    if let Ok(output) = serde_json::from_str(without_fence) {
        return Ok(output);
    }
    let object = without_fence
        .find('{')
        .zip(without_fence.rfind('}'))
        .filter(|(start, end)| start < end)
        .map(|(start, end)| &without_fence[start..=end])
        .context("classifier returned invalid JSON")?;
    serde_json::from_str(object).context("classifier returned invalid JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_fenced_and_wrapped_classifier_json() {
        for content in [
            r#"{"category":"debugging","confidence":0.8}"#,
            "```json\n{\"category\":\"debugging\",\"confidence\":0.8}\n```",
            "Result: {\"category\":\"debugging\",\"confidence\":0.8}\nDone.",
        ] {
            let output = parse_classifier_output(content).expect("valid classifier output");
            assert_eq!(output.category, "debugging");
            assert_eq!(output.confidence, 0.8);
        }
    }

    #[test]
    fn valid_unknown_response_is_classified_not_unavailable() {
        let assignment =
            parse_assignment(r#"{"category":"unknown","confidence":0.2}"#, "test-model")
                .expect("valid classifier output");
        assert_eq!(assignment.category_id, CategoryId::Unknown);
        assert_eq!(
            assignment.classification_status,
            ClassificationStatus::Classified
        );
    }

    #[test]
    fn structured_request_uses_a_strict_classifier_schema() {
        let request = ChatRequest {
            model: "test",
            temperature: 0.0,
            response_format: Some(ResponseFormat::classifier()),
            messages: vec![],
        };
        let value = serde_json::to_value(request).expect("serialize request");
        assert_eq!(value["response_format"]["type"], "json_schema");
        assert_eq!(
            value["response_format"]["json_schema"]["schema"]["additionalProperties"],
            false
        );
    }
}
