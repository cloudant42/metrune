pub mod adapters;
pub mod classifier;
pub mod pricing;
pub mod state;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "1";
pub const TAXONOMY_VERSION: &str = "2026-01";

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenBreakdown {
    pub input: u64,
    pub output: u64,
    pub cache_read: u64,
    pub cache_write: u64,
    pub reasoning: u64,
}

impl TokenBreakdown {
    pub fn total(&self) -> u64 {
        self.input
            .saturating_add(self.output)
            .saturating_add(self.cache_read)
            .saturating_add(self.cache_write)
            .saturating_add(self.reasoning)
    }

    pub fn add_assign(&mut self, other: &Self) {
        self.input = self.input.saturating_add(other.input);
        self.output = self.output.saturating_add(other.output);
        self.cache_read = self.cache_read.saturating_add(other.cache_read);
        self.cache_write = self.cache_write.saturating_add(other.cache_write);
        self.reasoning = self.reasoning.saturating_add(other.reasoning);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Cost {
    pub amount: f64,
    pub currency: String,
    pub kind: CostKind,
    pub pricebook_version: Option<String>,
    #[serde(default)]
    pub price_source: Option<String>,
}

impl Default for Cost {
    fn default() -> Self {
        Self {
            amount: 0.0,
            currency: "USD".into(),
            kind: CostKind::Unknown,
            pricebook_version: None,
            price_source: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CostKind {
    Reported,
    Estimated,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CategoryId {
    Implementation,
    Debugging,
    Research,
    Documentation,
    ReviewRefactoring,
    Testing,
    Planning,
    Operations,
    Content,
    Unknown,
}

impl CategoryId {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Implementation => "implementation",
            Self::Debugging => "debugging",
            Self::Research => "research",
            Self::Documentation => "documentation",
            Self::ReviewRefactoring => "review_refactoring",
            Self::Testing => "testing",
            Self::Planning => "planning",
            Self::Operations => "operations",
            Self::Content => "content",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationStatus {
    /// A classifier returned a valid category. The category may still be Unknown.
    Classified,
    /// Classification was explicitly disabled or no semantic model was selected.
    NotConfigured,
    /// A classifier could not be used, for example because credentials or the
    /// configured endpoint were unavailable.
    /// Also the conservative default for snapshots created before status was
    /// persisted.
    #[default]
    Unavailable,
    /// A classifier was invoked but its response could not be accepted.
    Failed,
    /// The local adapter did not provide any text to classify.
    NoInput,
}

impl ClassificationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Classified => "classified",
            Self::NotConfigured => "not_configured",
            Self::Unavailable => "unavailable",
            Self::Failed => "failed",
            Self::NoInput => "no_input",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CategoryAssignment {
    pub category_id: CategoryId,
    pub confidence: f32,
    pub taxonomy_version: String,
    pub classifier_id: String,
    #[serde(default)]
    pub classification_status: ClassificationStatus,
}

impl Default for CategoryAssignment {
    fn default() -> Self {
        Self {
            category_id: CategoryId::Unknown,
            confidence: 0.0,
            taxonomy_version: TAXONOMY_VERSION.into(),
            classifier_id: "unavailable".into(),
            classification_status: ClassificationStatus::Unavailable,
        }
    }
}

impl CategoryAssignment {
    pub fn not_configured() -> Self {
        Self {
            classifier_id: "not_configured".into(),
            classification_status: ClassificationStatus::NotConfigured,
            ..Self::default()
        }
    }

    pub fn no_input() -> Self {
        Self {
            classifier_id: "no_input".into(),
            classification_status: ClassificationStatus::NoInput,
            ..Self::default()
        }
    }

    pub fn failed(classifier_id: impl Into<String>) -> Self {
        Self {
            classifier_id: classifier_id.into(),
            classification_status: ClassificationStatus::Failed,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct UsageMessage {
    pub source_message_id: String,
    pub session_id: String,
    pub project_path: Option<String>,
    pub client_id: String,
    pub client_version: Option<String>,
    pub provider_id: String,
    pub model_id: String,
    pub observed_at: DateTime<Utc>,
    pub tokens: TokenBreakdown,
    pub cost: Cost,
    /// Local-only text supplied to the classifier. It must never be persisted or uploaded.
    pub classification_text: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UsageSlice {
    pub provider_id: String,
    pub model_id: String,
    pub tokens: TokenBreakdown,
    pub cost: Cost,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SessionSnapshot {
    pub schema_version: String,
    pub session_key: String,
    pub revision: u64,
    pub user_key: String,
    pub project_key: Option<String>,
    pub project_alias: Option<String>,
    pub team_key: Option<String>,
    pub client_id: String,
    pub client_version: Option<String>,
    pub started_at: DateTime<Utc>,
    pub ended_at: DateTime<Utc>,
    pub usage_by_model: Vec<UsageSlice>,
    pub category: CategoryAssignment,
    pub source_schema_version: Option<String>,
}

impl SessionSnapshot {
    pub fn total_tokens(&self) -> u64 {
        self.usage_by_model
            .iter()
            .map(|slice| slice.tokens.total())
            .sum()
    }

    pub fn total_cost(&self) -> f64 {
        self.usage_by_model
            .iter()
            .map(|slice| slice.cost.amount)
            .sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchEnvelope {
    pub schema_version: String,
    pub batch_id: String,
    pub sent_at: DateTime<Utc>,
    pub snapshots: Vec<SessionSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestAck {
    pub batch_id: String,
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProjectLabelMode {
    #[default]
    Folder,
    Anonymous,
}

#[derive(Debug, Clone, Default)]
pub struct IdentityContext {
    pub pseudonym_key: Vec<u8>,
    pub user_alias: String,
    pub team_key: Option<String>,
    pub project_aliases: BTreeMap<String, String>,
    pub project_label_mode: ProjectLabelMode,
}

impl IdentityContext {
    pub fn pseudonymize(&self, value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.pseudonym_key)
            .expect("HMAC accepts keys of any size");
        mac.update(value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn user_key(&self) -> String {
        self.pseudonymize(&format!("user:{}", self.user_alias))
    }

    pub fn project_identity(&self, path: Option<&str>) -> (Option<String>, Option<String>) {
        path.map(|path| {
            let folder = path
                .trim_end_matches(['/', '\\'])
                .rsplit(['/', '\\'])
                .next()
                .filter(|folder| !folder.is_empty())
                .map(ToOwned::to_owned);
            (
                self.pseudonymize(&format!("project:{path}")),
                self.project_aliases.get(path).cloned().or_else(|| {
                    (self.project_label_mode == ProjectLabelMode::Folder)
                        .then_some(folder)
                        .flatten()
                }),
            )
        })
        .map_or((None, None), |(key, alias)| (Some(key), alias))
    }
}

pub fn aggregate_session(
    messages: &[UsageMessage],
    identity: &IdentityContext,
    revision: u64,
    category: CategoryAssignment,
) -> Option<SessionSnapshot> {
    let first = messages.iter().min_by_key(|message| message.observed_at)?;
    let last = messages.iter().max_by_key(|message| message.observed_at)?;
    let session_id = &first.session_id;
    let mut grouped: BTreeMap<(String, String), UsageSlice> = BTreeMap::new();

    for message in messages
        .iter()
        .filter(|message| &message.session_id == session_id)
    {
        let key = (
            message.provider_id.clone(),
            canonical_model_id(&message.model_id),
        );
        let slice = grouped.entry(key.clone()).or_insert_with(|| UsageSlice {
            provider_id: key.0,
            model_id: key.1,
            tokens: TokenBreakdown::default(),
            cost: Cost {
                currency: message.cost.currency.clone(),
                kind: message.cost.kind.clone(),
                pricebook_version: message.cost.pricebook_version.clone(),
                price_source: message.cost.price_source.clone(),
                ..Cost::default()
            },
        });
        slice.tokens.add_assign(&message.tokens);
        slice.cost.amount += message.cost.amount;
    }

    let (project_key, project_alias) = identity.project_identity(first.project_path.as_deref());
    Some(SessionSnapshot {
        schema_version: SCHEMA_VERSION.into(),
        session_key: stable_session_key(&first.client_id, session_id),
        revision,
        user_key: identity.user_key(),
        project_key,
        project_alias,
        team_key: identity.team_key.clone(),
        client_id: first.client_id.clone(),
        client_version: first.client_version.clone(),
        started_at: first.observed_at,
        ended_at: last.observed_at,
        usage_by_model: grouped.into_values().collect(),
        category,
        source_schema_version: None,
    })
}

/// Derive the same opaque session identity when the same local CLI history is
/// scanned by multiple Metrune installations. The source session IDs from
/// supported CLIs are already opaque identifiers (typically UUIDs), so the
/// domain-separated digest is sufficient while keeping the raw ID out of the
/// uploaded snapshot.
pub fn stable_session_key(client_id: &str, session_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"metrune-session-v1\0");
    digest.update(client_id.trim().to_ascii_lowercase().as_bytes());
    digest.update([0]);
    digest.update(session_id.as_bytes());
    hex::encode(digest.finalize())
}

pub fn canonical_model_id(model: &str) -> String {
    let normalized = model.trim().to_ascii_lowercase().replace('.', "-");
    normalized
        .strip_prefix("anthropic/")
        .unwrap_or(&normalized)
        .to_string()
}
