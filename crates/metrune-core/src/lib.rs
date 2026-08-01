pub mod adapters;
pub mod classifier;
pub mod pricing;
pub mod release;
pub mod state;
pub mod taxonomy;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: &str = "2";
pub const LEGACY_SCHEMA_VERSION: &str = "1";
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClassificationMethod {
    Rule,
    SemanticModel,
    Inherited,
    #[default]
    None,
}

impl ClassificationMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::SemanticModel => "semantic_model",
            Self::Inherited => "inherited",
            Self::None => "none",
        }
    }
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
    /// Local-only source session start used to lock schema activation. It is
    /// never serialized into an upload.
    pub session_started_at: Option<DateTime<Utc>>,
    pub observed_at: DateTime<Utc>,
    pub tokens: TokenBreakdown,
    pub cost: Cost,
    /// Local-only stable ordering within the source session.
    pub turn_sequence: u32,
    /// Local-only ordering of model activity within a turn.
    pub activity_sequence: u32,
    /// Locally observed workflow events. Counts are metadata; raw tool
    /// arguments, commands and paths are never retained.
    pub workflow_signals: Vec<WorkflowSignal>,
    /// Signals the source can meaningfully observe. An absent capability is
    /// distinct from an observed count of zero.
    pub signal_capabilities: Vec<WorkflowSignal>,
    /// Local-only text supplied to the classifier. It must never be persisted or uploaded.
    pub classification_text: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowSignal {
    Read,
    Searched,
    Edited,
    TestsRun,
    TestsFailed,
    Planned,
    Delegated,
    GitUsed,
    Built,
    Deployed,
}

impl WorkflowSignal {
    pub const ALL: [Self; 10] = [
        Self::Read,
        Self::Searched,
        Self::Edited,
        Self::TestsRun,
        Self::TestsFailed,
        Self::Planned,
        Self::Delegated,
        Self::GitUsed,
        Self::Built,
        Self::Deployed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Searched => "searched",
            Self::Edited => "edited",
            Self::TestsRun => "tests_run",
            Self::TestsFailed => "tests_failed",
            Self::Planned => "planned",
            Self::Delegated => "delegated",
            Self::GitUsed => "git_used",
            Self::Built => "built",
            Self::Deployed => "deployed",
        }
    }
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
pub struct ModelActivityStep {
    pub sequence: u32,
    pub provider_id: String,
    pub model_id: String,
    pub tokens: TokenBreakdown,
    pub cost: Cost,
    pub call_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignalCount {
    pub signal: WorkflowSignal,
    pub count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_step_index: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TurnSnapshot {
    pub sequence: u32,
    pub category: CategoryAssignment,
    pub classification_method: ClassificationMethod,
    #[serde(default)]
    pub classification_cached: bool,
    pub model_activity: Vec<ModelActivityStep>,
    pub workflow_signals: Vec<SignalCount>,
}

impl TurnSnapshot {
    pub fn total_tokens(&self) -> u64 {
        self.model_activity
            .iter()
            .map(|step| step.tokens.total())
            .sum()
    }

    pub fn total_cost(&self) -> f64 {
        self.model_activity
            .iter()
            .map(|step| step.cost.amount)
            .sum()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SignalCapability {
    pub signal: WorkflowSignal,
    pub supported: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ClassificationMethodCount {
    pub method: ClassificationMethod,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageMeasurement {
    Reported,
    Estimated,
    #[default]
    Unavailable,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ClassifierUsage {
    pub provider_id: String,
    pub model_id: String,
    pub tokens: TokenBreakdown,
    pub cost: Cost,
    pub request_count: u32,
    pub measurement: UsageMeasurement,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub turns: Vec<TurnSnapshot>,
    #[serde(default)]
    pub classifier_usage: ClassifierUsage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signal_capabilities: Vec<SignalCapability>,
    #[serde(default)]
    pub classified_token_coverage: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub classification_method_counts: Vec<ClassificationMethodCount>,
    #[serde(default)]
    pub turn_detail_truncated: bool,
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

    pub fn calculate_classified_token_coverage(&self) -> f64 {
        let total = self.total_tokens();
        if total == 0 {
            return 0.0;
        }
        let classified = self
            .turns
            .iter()
            .filter(|turn| turn.category.classification_status == ClassificationStatus::Classified)
            .map(TurnSnapshot::total_tokens)
            .sum::<u64>();
        classified as f64 / total as f64
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
    /// Session keys accepted in this response. These are explicit so a
    /// partially valid batch can be acknowledged without retrying accepted
    /// rows forever when one malformed snapshot is present.
    #[serde(default)]
    pub accepted_session_keys: Vec<String>,
    /// Session keys rejected as permanently invalid. The CLI quarantines
    /// these derived snapshots locally and reports the validation errors,
    /// allowing later queued sessions to upload.
    #[serde(default)]
    pub rejected_session_keys: Vec<String>,
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
        turns: Vec::new(),
        classifier_usage: ClassifierUsage::default(),
        signal_capabilities: Vec::new(),
        classified_token_coverage: 0.0,
        classification_method_counts: Vec::new(),
        turn_detail_truncated: false,
        source_schema_version: None,
    })
}

pub fn aggregate_session_v2(
    messages: &[UsageMessage],
    identity: &IdentityContext,
    revision: u64,
    turns: Vec<TurnSnapshot>,
    classifier_usage: ClassifierUsage,
) -> Option<SessionSnapshot> {
    let mut snapshot = aggregate_session(messages, identity, revision, dominant_category(&turns))?;
    snapshot.schema_version = SCHEMA_VERSION.into();
    snapshot.turns = turns;
    snapshot.classifier_usage = classifier_usage;
    snapshot.classified_token_coverage = snapshot.calculate_classified_token_coverage();
    let mut methods = BTreeMap::<&'static str, (ClassificationMethod, u32)>::new();
    for turn in &snapshot.turns {
        let entry = methods
            .entry(turn.classification_method.as_str())
            .or_insert((turn.classification_method, 0));
        entry.1 = entry.1.saturating_add(1);
    }
    snapshot.classification_method_counts = methods
        .into_values()
        .map(|(method, count)| ClassificationMethodCount { method, count })
        .collect();
    let supported = messages
        .iter()
        .flat_map(|message| message.signal_capabilities.iter().copied())
        .collect::<std::collections::BTreeSet<_>>();
    snapshot.signal_capabilities = WorkflowSignal::ALL
        .into_iter()
        .map(|signal| SignalCapability {
            signal,
            supported: supported.contains(&signal),
        })
        .collect();
    if serde_json::to_vec(&snapshot.turns).is_ok_and(|encoded| encoded.len() > 512 * 1024) {
        snapshot.turns.clear();
        snapshot.turn_detail_truncated = true;
    }
    Some(snapshot)
}

fn dominant_category(turns: &[TurnSnapshot]) -> CategoryAssignment {
    let mut weighted: BTreeMap<&'static str, (u64, CategoryAssignment)> = BTreeMap::new();
    for turn in turns
        .iter()
        .filter(|turn| turn.category.classification_status == ClassificationStatus::Classified)
    {
        let entry = weighted
            .entry(turn.category.category_id.as_str())
            .or_insert((0, turn.category.clone()));
        entry.0 = entry.0.saturating_add(turn.total_tokens());
        if turn.category.confidence > entry.1.confidence {
            entry.1 = turn.category.clone();
        }
    }
    weighted
        .into_values()
        .max_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then_with(|| left.1.confidence.total_cmp(&right.1.confidence))
        })
        .map(|(_, assignment)| assignment)
        .unwrap_or_default()
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
