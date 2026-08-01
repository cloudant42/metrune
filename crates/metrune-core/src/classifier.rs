use crate::{
    taxonomy::{batch_classifier_instructions, classifier_instructions, SEMANTIC_CATEGORIES},
    CategoryAssignment, CategoryId, ClassificationStatus, ClassifierUsage, Cost, TokenBreakdown,
    UsageMeasurement, TAXONOMY_VERSION,
};
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
    async fn classify_batch(&self, local_texts: &[String]) -> Result<BatchClassification> {
        let mut assignments = Vec::with_capacity(local_texts.len());
        for text in local_texts {
            assignments.push(self.classify(text).await?);
        }
        Ok(BatchClassification {
            assignments,
            usage: ClassifierUsage {
                provider_id: self.id(),
                request_count: local_texts.len() as u32,
                ..ClassifierUsage::default()
            },
        })
    }
    fn id(&self) -> String;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchClassification {
    pub assignments: Vec<CategoryAssignment>,
    pub usage: ClassifierUsage,
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
    pub usage: ClassifierUsage,
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
        let (first, effective_mode) = match self.request(local_text, first_mode, false).await {
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

        match parse_assignment(&first.content, &self.model) {
            Ok(assignment) => Ok(ClassifierDiagnostic {
                assignment,
                response_mode: effective_mode,
                repaired: false,
                usage: classifier_usage(
                    &self.model,
                    first.usage,
                    1,
                    estimated_request_tokens(local_text),
                ),
            }),
            Err(first_error) => {
                let repaired = self
                    .request(local_text, ResponseMode::PromptJson, true)
                    .await
                    .map_err(anyhow::Error::from)?;
                let assignment =
                    parse_assignment(&repaired.content, &self.model).with_context(|| {
                        format!("classifier repair failed after invalid response: {first_error:#}")
                    })?;
                let mut usage = classifier_usage(
                    &self.model,
                    first.usage,
                    1,
                    estimated_request_tokens(local_text),
                );
                if let Some(repaired_usage) = repaired.usage {
                    usage.tokens.add_assign(&repaired_usage.tokens());
                } else {
                    usage.tokens.input = usage
                        .tokens
                        .input
                        .saturating_add(estimated_request_tokens(local_text));
                    usage.tokens.output = usage.tokens.output.saturating_add(32);
                    usage.measurement = UsageMeasurement::Estimated;
                }
                usage.request_count = usage.request_count.saturating_add(1);
                Ok(ClassifierDiagnostic {
                    assignment,
                    response_mode: ResponseMode::PromptJson,
                    repaired: true,
                    usage,
                })
            }
        }
    }

    async fn request(
        &self,
        local_text: &str,
        response_mode: ResponseMode,
        repair: bool,
    ) -> std::result::Result<ProviderChat, ProviderRequestError> {
        let system = classifier_instructions(repair);
        let request = ChatRequest {
            model: &self.model,
            temperature: 0.0,
            response_format: (response_mode == ResponseMode::Structured)
                .then(ResponseFormat::classifier),
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: &system,
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
        let content = response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| ProviderRequestError::invalid("classifier returned no choices"))?;
        Ok(ProviderChat {
            content,
            usage: response.usage,
        })
    }

    async fn request_batch(
        &self,
        local_texts: &[String],
    ) -> std::result::Result<ProviderChat, ProviderRequestError> {
        let system = batch_classifier_instructions();
        let payload = serde_json::to_string(
            &local_texts
                .iter()
                .enumerate()
                .map(|(index, text)| serde_json::json!({"index": index, "text": text}))
                .collect::<Vec<_>>(),
        )
        .map_err(|error| ProviderRequestError::invalid(error.to_string()))?;
        let request = ChatRequest {
            model: &self.model,
            temperature: 0.0,
            response_format: None,
            messages: vec![
                ChatMessage {
                    role: "system",
                    content: &system,
                },
                ChatMessage {
                    role: "user",
                    content: &payload,
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
        let content = response
            .choices
            .first()
            .map(|choice| choice.message.content.clone())
            .ok_or_else(|| ProviderRequestError::invalid("classifier returned no choices"))?;
        Ok(ProviderChat {
            content,
            usage: response.usage,
        })
    }
}

fn classifier_usage(
    model: &str,
    usage: Option<ChatUsage>,
    request_count: u32,
    estimated_input: u64,
) -> ClassifierUsage {
    let measurement = if usage.is_some() {
        UsageMeasurement::Reported
    } else {
        UsageMeasurement::Estimated
    };
    ClassifierUsage {
        provider_id: "openai-compatible".into(),
        model_id: model.into(),
        tokens: usage
            .as_ref()
            .map(ChatUsage::tokens)
            .unwrap_or(TokenBreakdown {
                input: estimated_input,
                output: 32_u64.saturating_mul(request_count as u64),
                ..TokenBreakdown::default()
            }),
        cost: Cost::default(),
        request_count,
        measurement,
    }
}

fn estimated_request_tokens(text: &str) -> u64 {
    // Explicit fallback for OpenAI-compatible providers that omit usage. The
    // prompt contributes a stable allowance and UTF-8 text is approximated at
    // four characters per token.
    400_u64.saturating_add(text.chars().count().div_ceil(4) as u64)
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
                            r#enum: SEMANTIC_CATEGORIES
                                .iter()
                                .map(|category| category.id.as_str())
                                .collect(),
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
    #[serde(default)]
    usage: Option<ChatUsage>,
}

struct ProviderChat {
    content: String,
    usage: Option<ChatUsage>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatUsage {
    #[serde(default)]
    prompt_tokens: u64,
    #[serde(default)]
    completion_tokens: u64,
    #[serde(default)]
    cached_tokens: u64,
    #[serde(default)]
    reasoning_tokens: u64,
    #[serde(default)]
    prompt_tokens_details: Option<ChatPromptTokenDetails>,
    #[serde(default)]
    completion_tokens_details: Option<ChatCompletionTokenDetails>,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatPromptTokenDetails {
    #[serde(default)]
    cached_tokens: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct ChatCompletionTokenDetails {
    #[serde(default)]
    reasoning_tokens: u64,
}

impl ChatUsage {
    fn tokens(&self) -> TokenBreakdown {
        TokenBreakdown {
            input: self.prompt_tokens,
            output: self.completion_tokens,
            cache_read: self
                .prompt_tokens_details
                .as_ref()
                .map(|details| details.cached_tokens)
                .unwrap_or(self.cached_tokens),
            cache_write: 0,
            reasoning: self
                .completion_tokens_details
                .as_ref()
                .map(|details| details.reasoning_tokens)
                .unwrap_or(self.reasoning_tokens),
        }
    }
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

    async fn classify_batch(&self, local_texts: &[String]) -> Result<BatchClassification> {
        if local_texts.is_empty() {
            return Ok(BatchClassification {
                assignments: Vec::new(),
                usage: ClassifierUsage::default(),
            });
        }
        if local_texts.len() == 1 {
            let diagnostic = self.classify_with_diagnostics(&local_texts[0]).await?;
            return Ok(BatchClassification {
                assignments: vec![diagnostic.assignment],
                usage: diagnostic.usage,
            });
        }
        let first = self
            .request_batch(local_texts)
            .await
            .map_err(anyhow::Error::from)?;
        let parsed = parse_batch_assignments(&first.content, &self.model, local_texts.len());
        let estimated = local_texts
            .iter()
            .map(|text| text.chars().count())
            .sum::<usize>();
        let mut usage = classifier_usage(
            &self.model,
            first.usage,
            1,
            500_u64.saturating_add(estimated.div_ceil(4) as u64),
        );
        let mut assignments = vec![None; local_texts.len()];
        if let Ok(results) = parsed {
            for (index, assignment) in results {
                if index < assignments.len() {
                    assignments[index] = Some(assignment);
                }
            }
        }
        for (index, assignment) in assignments.iter_mut().enumerate() {
            if assignment.is_some() {
                continue;
            }
            let diagnostic = self.classify_with_diagnostics(&local_texts[index]).await?;
            usage.tokens.add_assign(&diagnostic.usage.tokens);
            usage.request_count = usage
                .request_count
                .saturating_add(diagnostic.usage.request_count);
            if diagnostic.usage.measurement == UsageMeasurement::Estimated {
                usage.measurement = UsageMeasurement::Estimated;
            }
            *assignment = Some(diagnostic.assignment);
        }
        Ok(BatchClassification {
            assignments: assignments
                .into_iter()
                .map(|assignment| assignment.unwrap_or_default())
                .collect(),
            usage,
        })
    }

    fn id(&self) -> String {
        format!("openai-compatible:{}", self.model)
    }
}

fn parse_batch_assignments(
    content: &str,
    model: &str,
    expected: usize,
) -> Result<Vec<(usize, CategoryAssignment)>> {
    #[derive(Deserialize)]
    struct BatchOutput {
        results: Vec<BatchItem>,
    }
    #[derive(Deserialize)]
    struct BatchItem {
        index: usize,
        category: String,
        confidence: f32,
    }
    let value = parse_json_value(content)?;
    let output: BatchOutput =
        serde_json::from_value(value).context("classifier returned invalid batch JSON")?;
    let mut seen = std::collections::HashSet::new();
    let mut assignments = Vec::new();
    for item in output.results {
        if item.index >= expected || !seen.insert(item.index) {
            continue;
        }
        let raw = serde_json::json!({
            "category": item.category,
            "confidence": item.confidence,
        });
        if let Ok(assignment) = parse_assignment(&raw.to_string(), model) {
            assignments.push((item.index, assignment));
        }
    }
    Ok(assignments)
}

fn parse_json_value(content: &str) -> Result<serde_json::Value> {
    let trimmed = content.trim();
    if let Ok(value) = serde_json::from_str(trimmed) {
        return Ok(value);
    }
    let without_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|value| value.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);
    let object = without_fence
        .find('{')
        .zip(without_fence.rfind('}'))
        .filter(|(start, end)| start < end)
        .map(|(start, end)| &without_fence[start..=end])
        .context("classifier returned invalid JSON")?;
    serde_json::from_str(object).context("classifier returned invalid JSON")
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
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
        time::Duration,
    };

    struct MockReply {
        status: &'static str,
        body: &'static str,
        delay: Duration,
    }

    type MockProvider = (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        thread::JoinHandle<()>,
    );

    fn mock_provider(replies: Vec<MockReply>) -> Option<MockProvider> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("skipping mock-provider test: cannot bind loopback listener: {error}");
                return None;
            }
        };
        let endpoint = format!("http://{}", listener.local_addr().expect("mock address"));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            for reply in replies {
                let (mut stream, _) = listener.accept().expect("accept classifier request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("set read timeout");
                let mut request = Vec::new();
                let mut buffer = [0_u8; 4096];
                let (body_start, content_length) = loop {
                    let read = stream.read(&mut buffer).expect("read classifier request");
                    assert!(read > 0, "classifier request ended before its body");
                    request.extend_from_slice(&buffer[..read]);
                    let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n")
                    else {
                        continue;
                    };
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .expect("request content length");
                    break (header_end + 4, content_length);
                };
                while request.len() < body_start + content_length {
                    let read = stream.read(&mut buffer).expect("read request body");
                    assert!(read > 0, "classifier request body was truncated");
                    request.extend_from_slice(&buffer[..read]);
                }
                let body =
                    serde_json::from_slice(&request[body_start..body_start + content_length])
                        .expect("classifier request JSON");
                captured.lock().expect("request capture lock").push(body);

                thread::sleep(reply.delay);
                let response = format!(
                    "HTTP/1.1 {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    reply.status,
                    reply.body.len(),
                    reply.body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Some((endpoint, requests, handle))
    }

    fn ok(content: &'static str) -> MockReply {
        MockReply {
            status: "200 OK",
            body: content,
            delay: Duration::ZERO,
        }
    }

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
        let categories = value["response_format"]["json_schema"]["schema"]["properties"]
            ["category"]["enum"]
            .as_array()
            .expect("category enum");
        assert_eq!(categories.len(), SEMANTIC_CATEGORIES.len());
        for category in SEMANTIC_CATEGORIES {
            assert!(categories.iter().any(|value| value == category.id.as_str()));
        }
    }

    #[test]
    fn batch_parser_keeps_valid_items_and_ignores_invalid_or_duplicate_entries() {
        let parsed = parse_batch_assignments(
            r#"{"results":[
                {"index":0,"category":"research","confidence":0.8},
                {"index":1,"category":"not-real","confidence":0.9},
                {"index":0,"category":"testing","confidence":0.7},
                {"index":9,"category":"testing","confidence":0.7}
            ]}"#,
            "test-model",
            2,
        )
        .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 0);
        assert_eq!(parsed[0].1.category_id, CategoryId::Research);
    }

    #[test]
    fn missing_provider_usage_is_explicitly_estimated() {
        let usage = classifier_usage("test-model", None, 1, 456);
        assert_eq!(usage.measurement, UsageMeasurement::Estimated);
        assert_eq!(usage.tokens.input, 456);
        assert_eq!(usage.tokens.output, 32);
        assert_eq!(usage.request_count, 1);
    }

    #[test]
    fn provider_usage_preserves_cache_and_reasoning_breakdown() {
        let usage = classifier_usage(
            "test-model",
            Some(ChatUsage {
                prompt_tokens: 100,
                completion_tokens: 20,
                cached_tokens: 0,
                reasoning_tokens: 0,
                prompt_tokens_details: Some(ChatPromptTokenDetails { cached_tokens: 40 }),
                completion_tokens_details: Some(ChatCompletionTokenDetails {
                    reasoning_tokens: 7,
                }),
            }),
            1,
            999,
        );
        assert_eq!(usage.measurement, UsageMeasurement::Reported);
        assert_eq!(usage.tokens.input, 100);
        assert_eq!(usage.tokens.output, 20);
        assert_eq!(usage.tokens.cache_read, 40);
        assert_eq!(usage.tokens.reasoning, 7);
    }

    #[tokio::test]
    async fn auto_mode_falls_back_when_a_provider_rejects_structured_output() {
        let Some((endpoint, requests, server)) = mock_provider(vec![
            MockReply {
                status: "400 Bad Request",
                body: r#"{"error":"response_format is unsupported"}"#,
                delay: Duration::ZERO,
            },
            ok(
                r#"{"choices":[{"message":{"content":"{\"category\":\"research\",\"confidence\":0.75}"}}],"usage":{"prompt_tokens":12,"completion_tokens":3}}"#,
            ),
        ]) else {
            return;
        };
        let classifier =
            OpenAiCompatibleClassifier::new(endpoint, "fallback-model", None, ResponseMode::Auto)
                .expect("classifier");

        let diagnostic = classifier
            .classify_with_diagnostics("compare these implementations")
            .await
            .expect("fallback classification");
        assert_eq!(diagnostic.assignment.category_id, CategoryId::Research);
        assert_eq!(diagnostic.response_mode, ResponseMode::PromptJson);
        assert!(!diagnostic.repaired);
        assert_eq!(diagnostic.usage.request_count, 1);

        server.join().expect("mock provider");
        let requests = requests.lock().expect("request capture");
        assert_eq!(requests.len(), 2);
        assert!(
            requests[0].get("response_format").is_some(),
            "the first request did not try structured output"
        );
        assert!(
            requests[1].get("response_format").is_none(),
            "the fallback still sent unsupported structured output"
        );
    }

    #[tokio::test]
    async fn invalid_provider_json_gets_one_bounded_repair_attempt() {
        let Some((endpoint, requests, server)) = mock_provider(vec![
            ok(r#"{"choices":[{"message":{"content":"not json"}}]}"#),
            ok(
                r#"{"choices":[{"message":{"content":"{\"category\":\"debugging\",\"confidence\":0.9}"}}]}"#,
            ),
        ]) else {
            return;
        };
        let classifier = OpenAiCompatibleClassifier::new(
            endpoint,
            "repair-model",
            None,
            ResponseMode::PromptJson,
        )
        .expect("classifier");

        let diagnostic = classifier
            .classify_with_diagnostics("debug the crash")
            .await
            .expect("repaired classification");
        assert_eq!(diagnostic.assignment.category_id, CategoryId::Debugging);
        assert!(diagnostic.repaired);
        assert_eq!(diagnostic.usage.request_count, 2);

        server.join().expect("mock provider");
        let requests = requests.lock().expect("request capture");
        assert_eq!(requests.len(), 2, "repair retried more than once");
        let repair_prompt = requests[1]["messages"][0]["content"]
            .as_str()
            .expect("repair system prompt");
        assert!(repair_prompt.contains("previous classifier response was invalid"));
    }

    #[tokio::test]
    async fn a_partial_batch_falls_back_only_for_missing_assignments() {
        let Some((endpoint, requests, server)) = mock_provider(vec![
            ok(
                r#"{"choices":[{"message":{"content":"{\"results\":[{\"index\":0,\"category\":\"testing\",\"confidence\":0.8}]}"}}]}"#,
            ),
            ok(
                r#"{"choices":[{"message":{"content":"{\"category\":\"documentation\",\"confidence\":0.7}"}}]}"#,
            ),
        ]) else {
            return;
        };
        let classifier = OpenAiCompatibleClassifier::new(
            endpoint,
            "batch-model",
            None,
            ResponseMode::PromptJson,
        )
        .expect("classifier");
        let result = classifier
            .classify_batch(&["add tests".into(), "write the guide".into()])
            .await
            .expect("batch classification");

        assert_eq!(result.assignments.len(), 2);
        assert_eq!(result.assignments[0].category_id, CategoryId::Testing);
        assert_eq!(result.assignments[1].category_id, CategoryId::Documentation);
        assert_eq!(result.usage.request_count, 2);
        server.join().expect("mock provider");
        assert_eq!(
            requests.lock().expect("request capture").len(),
            2,
            "a valid batch assignment was classified again"
        );
    }

    #[tokio::test]
    async fn upstream_failures_are_reported_without_an_unbounded_retry() {
        let Some((endpoint, requests, server)) = mock_provider(vec![MockReply {
            status: "503 Service Unavailable",
            body: r#"{"error":"temporarily unavailable"}"#,
            delay: Duration::ZERO,
        }]) else {
            return;
        };
        let classifier = OpenAiCompatibleClassifier::new(
            endpoint,
            "failure-model",
            Some("secret".into()),
            ResponseMode::PromptJson,
        )
        .expect("classifier");

        let error = classifier
            .classify("research this")
            .await
            .expect_err("503 must fail");
        assert!(error.to_string().contains("503 Service Unavailable"));
        server.join().expect("mock provider");
        assert_eq!(requests.lock().expect("request capture").len(), 1);
    }

    #[tokio::test]
    async fn a_stalled_provider_is_bounded_by_the_http_timeout() {
        let Some((endpoint, _, server)) = mock_provider(vec![MockReply {
            status: "200 OK",
            body: r#"{"choices":[]}"#,
            delay: Duration::from_millis(250),
        }]) else {
            return;
        };
        let classifier = OpenAiCompatibleClassifier {
            endpoint,
            model: "timeout-model".into(),
            api_key: None,
            response_mode: ResponseMode::PromptJson,
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(50))
                .build()
                .expect("short-timeout client"),
        };

        let started = std::time::Instant::now();
        classifier
            .classify("this provider will stall")
            .await
            .expect_err("the provider timeout must fail");
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_millis(200));
        server.join().expect("mock provider");
    }
}
