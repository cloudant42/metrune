use crate::credentials::{set_private_permissions, CredentialStore};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use dialoguer::{theme::ColorfulTheme, Select};
use flate2::{write::GzEncoder, Compression};
use hmac::{Hmac, Mac};
use metrune_core::{
    adapters::built_in_adapters,
    aggregate_session, aggregate_session_v2,
    classifier::{
        BatchClassification, ClassifierBackend, OpenAiCompatibleClassifier, ResponseMode,
        UnknownClassifier,
    },
    pricing::{PriceAuthority, PriceBook, PriceCatalog},
    release::{
        version_is_older, versions_share_major, ClientReleaseManifest, ClientUnsupportedResponse,
        ServerInfo, CLIENT_UNSUPPORTED_ERROR_CODE, CLIENT_VERSION_HEADER,
    },
    stable_session_key,
    state::{file_fingerprint, LocalState},
    CategoryAssignment, CategoryId, ClassificationMethod, ClassificationStatus, ClassifierUsage,
    IdentityContext, ModelActivityStep, ProjectLabelMode, SignalCount, TurnSnapshot, UsageMessage,
    WorkflowSignal, TAXONOMY_VERSION,
};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};
use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Parser)]
#[command(
    name = "metrune",
    version,
    about = "Privacy-first AI usage intelligence"
)]
struct Cli {
    #[arg(long, env = "METRUNE_STATE_DB")]
    state_db: Option<PathBuf>,
    #[arg(long, env = "METRUNE_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Enroll this installation and store its credentials locally.
    Enroll {
        #[arg(long)]
        server: String,
        /// Legacy enrollment code. Omit to approve this device in your browser.
        #[arg(long)]
        token: Option<String>,
        #[arg(long, default_value = "Developer workstation")]
        name: String,
        #[arg(long, default_value = "other")]
        platform: String,
        #[arg(long, default_value = "anonymous-user")]
        user_alias: String,
        /// Classifier selection. Omit to choose interactively in a terminal.
        #[arg(long, value_enum)]
        classifier: Option<ClassifierSelection>,
        /// OpenAI-compatible endpoint for --classifier local or custom.
        #[arg(long)]
        classifier_endpoint: Option<String>,
        /// Model for --classifier local or custom.
        #[arg(long)]
        classifier_model: Option<String>,
    },
    /// Scan local coding-agent stores and queue sanitized session snapshots.
    Scan {
        #[arg(long, value_delimiter = ',')]
        clients: Vec<String>,
        #[arg(long)]
        no_classify: bool,
    },
    /// Print the pending, sanitized upload envelope.
    Export {
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Upload pending snapshots to the configured Metrune server.
    Upload {
        #[arg(long, default_value_t = 500)]
        limit: usize,
    },
    /// Watch local coding-agent stores and upload changes continuously.
    #[command(alias = "daemon")]
    Watch {
        #[arg(long, default_value_t = 60)]
        interval_seconds: u64,
        /// Suppress normal status and provisioning output; errors still go to stderr.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show non-secret local configuration and queue state.
    Status,
    /// Provision and manage the local semantic classifier.
    Classifier {
        #[command(subcommand)]
        command: ClassifierCommand,
    },
    /// Maintain a local, versioned model price catalog.
    Pricing {
        #[command(subcommand)]
        command: PricingCommand,
    },
    /// Check for a newer client and install it.
    Update {
        /// Metrune server to read the release manifest from. Defaults to the
        /// server this installation is enrolled with.
        #[arg(long)]
        server: Option<String>,
        /// Report what is available without installing anything.
        #[arg(long)]
        check: bool,
        /// Install even though no release key is pinned in this build.
        #[arg(long)]
        allow_unsigned: bool,
    },
    /// Release tooling. Runs in CI, not on a developer machine.
    #[command(hide = true)]
    Release {
        #[command(subcommand)]
        command: ReleaseCommand,
    },
}

#[derive(Subcommand)]
enum ReleaseCommand {
    /// Build the client release manifest from a SHA256SUMS file, signing it
    /// when a release key is available.
    Manifest {
        /// Release version, e.g. 0.1.0.
        #[arg(long)]
        version: String,
        /// Oldest client version the server still accepts uploads from.
        #[arg(long)]
        minimum_version: String,
        /// `sha256sum` output covering the release artifacts.
        #[arg(long, default_value = "SHA256SUMS")]
        checksums: PathBuf,
        /// Base URL the release assets are published under.
        #[arg(long)]
        upstream_base_url: String,
        #[arg(long, default_value = "client-manifest.json")]
        output: PathBuf,
        /// Base64 ed25519 release key. Unsigned when absent.
        #[arg(long, env = "METRUNE_RELEASE_SIGNING_KEY", hide_env_values = true)]
        signing_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum ClassifierCommand {
    /// Fetch the classifier URL, model, and credential from the Metrune server.
    Provision,
    /// Show classifier configuration without revealing its credential.
    Status,
    /// Remove the locally stored classifier credential and profile.
    Logout,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ClassifierSelection {
    Organization,
    Local,
    Custom,
    None,
}

#[derive(Subcommand)]
enum PricingCommand {
    /// Fetch the current OpenRouter catalog and write it as JSON.
    SyncOpenrouter {
        #[arg(long, default_value = "pricing/openrouter.catalog.json")]
        output: PathBuf,
        #[arg(long, env = "OPENROUTER_API_KEY")]
        api_key: Option<String>,
        #[arg(long, default_value = "https://openrouter.ai/api/v1/models")]
        endpoint: String,
        /// Preserve non-OpenRouter entries from an existing catalog.
        #[arg(long)]
        merge_from: Option<PathBuf>,
    },
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClientConfig {
    server_url: String,
    installation_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    installation_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    installation_credential_id: String,
    pseudonym_key: String,
    user_alias: String,
    team_key: Option<String>,
    #[serde(default)]
    project_aliases: BTreeMap<String, String>,
    #[serde(default)]
    classifier: Option<ClassifierProfile>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierProfile {
    enabled: bool,
    #[serde(default)]
    execution_mode: ClassifierExecutionMode,
    provider_id: String,
    endpoint: String,
    model: String,
    credential_id: String,
    config_version: String,
    #[serde(default)]
    credential_version: Option<i32>,
    #[serde(default)]
    response_mode: ResponseMode,
}

// Bump this when the emitted session identity changes. This forces an updated
// client to revisit unchanged source files and replace snapshots created with
// the previous identity scheme.
const ADAPTER_PARSER_VERSION: &str = "7";
const CLASSIFIER_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
const UPDATE_CHECK_INTERVAL_HOURS: i64 = 24;
const UPDATE_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

fn metrune_default_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::HeaderName::from_static(CLIENT_VERSION_HEADER),
        reqwest::header::HeaderValue::from_static(env!("CARGO_PKG_VERSION")),
    );
    headers.insert(
        reqwest::header::USER_AGENT,
        reqwest::header::HeaderValue::from_static(concat!("metrune/", env!("CARGO_PKG_VERSION"))),
    );
    headers
}

fn metrune_http_client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .default_headers(metrune_default_headers())
        .timeout(CLIENT_HTTP_TIMEOUT)
}

fn metrune_http_client() -> Result<reqwest::Client> {
    metrune_http_client_builder()
        .build()
        .context("build Metrune HTTP client")
}

#[derive(Debug)]
struct ClientUnsupportedUpload {
    minimum_client_version: Option<String>,
}

impl fmt::Display for ClientUnsupportedUpload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.minimum_client_version.as_deref() {
            Some(minimum) => write!(
                formatter,
                "server requires Metrune client >= {minimum}; run `metrune update`"
            ),
            None => formatter
                .write_str("server no longer supports this Metrune client; run `metrune update`"),
        }
    }
}

impl std::error::Error for ClientUnsupportedUpload {}

fn client_unsupported_upload(
    status: reqwest::StatusCode,
    body: &[u8],
) -> Option<ClientUnsupportedUpload> {
    if status != reqwest::StatusCode::UPGRADE_REQUIRED {
        return None;
    }
    let response = serde_json::from_slice::<ClientUnsupportedResponse>(body).ok()?;
    (response.code == CLIENT_UNSUPPORTED_ERROR_CODE).then_some(ClientUnsupportedUpload {
        minimum_client_version: response.minimum_client_version,
    })
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollRequest<'a> {
    enrollment_token: &'a str,
    installation_name: &'a str,
    platform: &'a str,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollResponse {
    installation_id: String,
    installation_token: String,
    pseudonym_key: String,
    team_key: Option<String>,
}

const DEVICE_CLIENT_ID: &str = "metrune-cli";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const MAX_DEVICE_AUTH_SECONDS: u64 = 15 * 60;
const MAX_DEVICE_POLL_SECONDS: u64 = 60;

#[derive(serde::Serialize)]
struct DeviceAuthorizationRequest<'a> {
    client_id: &'static str,
    installation_name: &'a str,
    platform: &'a str,
}

#[derive(serde::Deserialize)]
struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: u64,
    interval: u64,
}

#[derive(serde::Serialize)]
struct DeviceTokenRequest<'a> {
    grant_type: &'static str,
    device_code: &'a str,
    client_id: &'static str,
}

#[derive(serde::Deserialize)]
struct DeviceTokenResponse {
    access_token: String,
    token_type: String,
    installation_id: String,
    pseudonym_key: String,
    team_key: Option<String>,
}

#[derive(serde::Deserialize)]
struct OAuthErrorResponse {
    error: String,
    #[serde(default)]
    error_description: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierProvisionResponse {
    enabled: bool,
    #[serde(default)]
    execution_mode: ClassifierExecutionMode,
    config_version: String,
    provider_id: String,
    endpoint: String,
    model: String,
    credential_id: String,
    credential: Option<String>,
    credential_version: Option<i32>,
    #[serde(default)]
    response_mode: ResponseMode,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClassifierExecutionMode {
    #[default]
    Local,
    Managed,
}

impl std::fmt::Display for ClassifierExecutionMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local",
            Self::Managed => "managed",
        })
    }
}

struct ResolvedClassifier {
    execution_mode: ClassifierExecutionMode,
    endpoint: String,
    model: String,
    api_key: Option<String>,
    installation_token: Option<String>,
    config_version: String,
    response_mode: ResponseMode,
}

struct ManagedClassifier {
    endpoint: String,
    installation_token: String,
    config_version: String,
    client: reqwest::Client,
}

#[derive(serde::Serialize)]
struct ManagedClassifyRequest<'a> {
    text: &'a str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ManagedClassifyBatchRequest<'a> {
    texts: &'a [String],
}

#[async_trait]
impl ClassifierBackend for ManagedClassifier {
    async fn classify(&self, local_text: &str) -> Result<CategoryAssignment> {
        let response = self
            .client
            .post(self.endpoint.replace("classify-batch", "classify"))
            .bearer_auth(&self.installation_token)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .json(&ManagedClassifyRequest { text: local_text })
            .send()
            .await
            .context("send managed classifier request")?;
        let status = response.status();
        if !status.is_success() {
            bail!("managed classifier returned HTTP {status}");
        }
        response
            .json()
            .await
            .context("read managed classifier response")
    }

    async fn classify_batch(&self, local_texts: &[String]) -> Result<BatchClassification> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.installation_token)
            .header(reqwest::header::CACHE_CONTROL, "no-store")
            .json(&ManagedClassifyBatchRequest { texts: local_texts })
            .send()
            .await
            .context("send managed classifier batch request")?;
        let status = response.status();
        if !status.is_success() {
            bail!("managed classifier batch returned HTTP {status}");
        }
        response
            .json()
            .await
            .context("read managed classifier batch response")
    }

    fn id(&self) -> String {
        format!("managed:{}", self.config_version)
    }
}

pub(crate) async fn run() -> Result<()> {
    let Cli {
        state_db,
        config,
        command,
    } = Cli::parse();
    let config_path = config.unwrap_or_else(default_config_path);
    // These commands never touch the local outbox, so they run before it is
    // opened — `update` in particular has to work on a machine whose state
    // database is missing or was written by a different client version.
    if matches!(
        &command,
        Command::Pricing { .. }
            | Command::Classifier { .. }
            | Command::Update { .. }
            | Command::Release { .. }
    ) {
        match command {
            Command::Pricing {
                command:
                    PricingCommand::SyncOpenrouter {
                        output,
                        api_key,
                        endpoint,
                        merge_from,
                    },
            } => {
                sync_openrouter(
                    &output,
                    &endpoint,
                    api_key.as_deref(),
                    merge_from.as_deref(),
                )
                .await?;
            }
            Command::Classifier { command } => {
                classifier_command(&config_path, command).await?;
            }
            Command::Update {
                server,
                check,
                allow_unsigned,
            } => {
                update_client(&config_path, server.as_deref(), check, allow_unsigned).await?;
            }
            Command::Release { command } => release_command(command)?,
            _ => unreachable!("non-pricing command handled by the normal state path"),
        }
        return Ok(());
    }
    let state_path = state_db.unwrap_or_else(default_state_path);
    if let Some(parent) = state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let state = LocalState::open(&state_path)?;
    match command {
        Command::Enroll {
            server,
            token,
            name,
            platform,
            user_alias,
            classifier,
            classifier_endpoint,
            classifier_model,
        } => {
            enroll(
                &config_path,
                &server,
                token.as_deref(),
                &name,
                &platform,
                &user_alias,
            )
            .await?;
            println!("Enrollment saved to {}.", config_path.display());
            configure_classifier_after_enrollment(
                &config_path,
                classifier,
                classifier_endpoint,
                classifier_model,
            )
            .await?;
        }
        Command::Scan {
            clients,
            no_classify,
        } => {
            let config = load_config(&config_path)?;
            let count = scan(&state, &config, &clients, no_classify).await?;
            println!("Queued {count} sanitized session snapshots.");
        }
        Command::Export { limit } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&state.pending_batch(limit)?)?
            );
        }
        Command::Upload { limit } => {
            let config = load_config(&config_path)?;
            let count = upload(&state, &config, limit).await?;
            maybe_print_update_notice(&state, &config).await;
            println!("Uploaded {count} session snapshots.");
        }
        Command::Watch {
            interval_seconds,
            quiet,
        } => watch(&state, &config_path, interval_seconds, quiet).await?,
        Command::Status => {
            let config = load_config(&config_path)?;
            println!("Server: {}", config.server_url);
            println!("Installation: {}", config.installation_id);
            println!("User alias: {}", config.user_alias);
            println!(
                "Team: {}",
                config.team_key.as_deref().unwrap_or("unassigned")
            );
            println!(
                "Pending snapshots: {}",
                state.pending_batch(10_000)?.snapshots.len()
            );
        }
        Command::Pricing { .. } => {
            unreachable!("pricing commands return before opening local state")
        }
        Command::Classifier { .. } => {
            unreachable!("classifier commands return before opening local state")
        }
        Command::Update { .. } | Command::Release { .. } => {
            unreachable!("update and release commands return before opening local state")
        }
    }
    Ok(())
}

async fn watch(
    state: &LocalState,
    config_path: &Path,
    interval_seconds: u64,
    quiet: bool,
) -> Result<()> {
    let interval = Duration::from_secs(interval_seconds.max(10));
    if !quiet {
        println!(
            "Metrune watch running; checking every {} seconds. Press Ctrl-C to stop.",
            interval.as_secs()
        );
    }
    if let Ok(config) = load_config(config_path) {
        maybe_print_update_notice(state, &config).await;
    }

    let mut last_classifier_refresh: Option<Instant> = None;
    loop {
        let refresh_classifier = last_classifier_refresh
            .is_none_or(|last| last.elapsed() >= CLASSIFIER_REFRESH_INTERVAL);
        let cycle = async {
            if let Ok(current) = load_config(config_path) {
                let server_provisioned = current
                    .classifier
                    .as_ref()
                    .is_some_and(should_refresh_classifier);
                if refresh_classifier && server_provisioned {
                    if let Err(error) = provision_classifier(config_path, quiet).await {
                        eprintln!(
                            "classifier refresh failed; keeping the current credential: {error:#}"
                        );
                    }
                }
            }
            let config = load_config(config_path)?;
            if let Err(error) = scan(state, &config, &[], false).await {
                eprintln!("scan failed: {error:#}");
            }
            match upload(state, &config, 500).await {
                Ok(_) => maybe_print_update_notice(state, &config).await,
                Err(error) if error.downcast_ref::<ClientUnsupportedUpload>().is_some() => {
                    return Err(error);
                }
                Err(error) => {
                    eprintln!("upload failed; snapshots remain queued: {error:#}");
                }
            }
            Ok::<(), anyhow::Error>(())
        };

        tokio::select! {
            result = cycle => result?,
            _ = tokio::signal::ctrl_c() => {
                if !quiet {
                    println!("Metrune watch stopped.");
                }
                return Ok(());
            }
        }

        if refresh_classifier {
            last_classifier_refresh = Some(Instant::now());
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => {
                if !quiet {
                    println!("Metrune watch stopped.");
                }
                return Ok(());
            }
        }
    }
}

async fn sync_openrouter(
    output: &Path,
    endpoint: &str,
    api_key: Option<&str>,
    merge_from: Option<&Path>,
) -> Result<()> {
    let mut request = metrune_http_client()?
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/json");
    if let Some(api_key) = api_key.filter(|key| !key.trim().is_empty()) {
        request = request.bearer_auth(api_key);
    }
    let body = request.send().await?.error_for_status()?.text().await?;
    let retrieved_at = Utc::now();
    let mut catalog = PriceCatalog::from_openrouter_json(&body, retrieved_at)?;

    if let Some(merge_from) = merge_from {
        let existing = PriceCatalog::load(merge_from).with_context(|| {
            format!(
                "load catalog to merge from {}; use a catalog generated by `pricing sync-openrouter`",
                merge_from.display()
            )
        })?;
        let custom_entries = existing
            .entries
            .into_iter()
            .filter(|entry| entry.authority != PriceAuthority::OpenRouter)
            .collect::<Vec<_>>();
        catalog.entries.extend(custom_entries);
        catalog.catalog_version.push_str("-merged");
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(output, serde_json::to_vec_pretty(&catalog)?)?;
    println!(
        "Wrote {} price entries to {} (catalog {}).",
        catalog.entries.len(),
        output.display(),
        catalog.catalog_version
    );
    Ok(())
}

async fn classifier_command(config_path: &Path, command: ClassifierCommand) -> Result<()> {
    match command {
        ClassifierCommand::Provision => provision_classifier(config_path, false).await,
        ClassifierCommand::Status => {
            let config = load_config(config_path)?;
            let Some(profile) = config.classifier else {
                println!("Classifier: not provisioned");
                return Ok(());
            };
            let credential_stored = !profile.credential_id.is_empty()
                && CredentialStore::default()
                    .get_for_server(&config.server_url, &profile.credential_id)?
                    .is_some();
            println!(
                "Classifier: {}",
                if profile.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Execution: {}", profile.execution_mode);
            println!("Provider: {}", profile.provider_id);
            println!(
                "Endpoint: {}",
                if profile.execution_mode == ClassifierExecutionMode::Managed {
                    "Metrune managed classifier"
                } else {
                    &profile.endpoint
                }
            );
            println!("Model: {}", profile.model);
            println!("Configuration: {}", profile.config_version);
            println!(
                "Credential: {}",
                if profile.execution_mode == ClassifierExecutionMode::Managed {
                    "held by the Metrune server"
                } else if credential_stored {
                    "stored locally"
                } else {
                    "not stored"
                }
            );
            Ok(())
        }
        ClassifierCommand::Logout => {
            let mut config = load_config(config_path)?;
            if let Some(profile) = config.classifier.take() {
                if !profile.credential_id.is_empty() {
                    CredentialStore::default()
                        .delete_for_server(&config.server_url, &profile.credential_id)?;
                }
                save_config(config_path, &config)?;
                println!("Removed local classifier profile and credential.");
            } else {
                println!("No local classifier profile is provisioned.");
            }
            Ok(())
        }
    }
}

fn should_refresh_classifier(profile: &ClassifierProfile) -> bool {
    // Profiles configured directly by the client are versioned with
    // `client-…`. Provider IDs cannot identify the origin: an organization can
    // legitimately provision either a custom endpoint or a local provider.
    !profile.config_version.starts_with("client-")
}

async fn provision_classifier(config_path: &Path, quiet: bool) -> Result<()> {
    let response = fetch_server_classifier(config_path).await?;
    if !response.enabled {
        let mut config = load_config(config_path)?;
        if let Some(profile) = config.classifier.take() {
            if !profile.credential_id.is_empty() {
                CredentialStore::default()
                    .delete_for_server(&config.server_url, &profile.credential_id)?;
            }
        }
        save_config(config_path, &config)?;
        if !quiet {
            println!("Classification is disabled; it can be configured later.");
        }
        return Ok(());
    }
    apply_server_classifier(config_path, response, quiet)
}

async fn fetch_server_classifier(config_path: &Path) -> Result<ClassifierProvisionResponse> {
    let config = load_config(config_path)?;
    let installation_token = resolve_installation_token(&config)?;
    metrune_http_client()?
        .post(format!(
            "{}/v1/installation/classifier/provision",
            config.server_url.trim_end_matches('/')
        ))
        .bearer_auth(installation_token)
        .header(reqwest::header::CACHE_CONTROL, "no-store")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("read server classifier profile")
}

fn apply_server_classifier(
    config_path: &Path,
    response: ClassifierProvisionResponse,
    quiet: bool,
) -> Result<()> {
    let mut config = load_config(config_path)?;
    let credential_store = CredentialStore::default();
    let server_url = config.server_url.clone();
    let previous_credential_id = config
        .classifier
        .as_ref()
        .map(|profile| profile.credential_id.clone())
        .filter(|credential_id| !credential_id.is_empty());
    let storage = if response.execution_mode == ClassifierExecutionMode::Managed {
        if response.credential.is_some() {
            bail!("managed classifier provisioning must not return a provider credential");
        }
        if let Some(credential_id) = previous_credential_id.as_deref() {
            credential_store.delete_for_server(&server_url, credential_id)?;
        }
        None
    } else if let Some(credential) = response
        .credential
        .as_deref()
        .filter(|credential| !credential.trim().is_empty())
    {
        if response.credential_id.trim().is_empty() {
            bail!("server returned a classifier credential without an id");
        }
        Some(credential_store.set_for_server(&server_url, &response.credential_id, credential)?)
    } else if !response.credential_id.is_empty()
        && credential_store
            .get_for_server(&server_url, &response.credential_id)?
            .is_some()
    {
        Some("already stored locally")
    } else {
        None
    };
    let normalized_endpoint = response.endpoint.to_ascii_lowercase();
    let endpoint_requires_credential = response.execution_mode == ClassifierExecutionMode::Local
        && (normalized_endpoint.contains("api.openai.com")
            || normalized_endpoint.contains("openrouter.ai"));
    if endpoint_requires_credential && storage.is_none() {
        bail!("server did not provide the provider credential required for local classification");
    }
    if response.execution_mode == ClassifierExecutionMode::Local {
        if let Some(previous) = previous_credential_id.as_deref() {
            if previous != response.credential_id {
                credential_store.delete_for_server(&server_url, previous)?;
            }
        }
    }

    config.classifier = Some(ClassifierProfile {
        enabled: true,
        execution_mode: response.execution_mode,
        provider_id: response.provider_id.clone(),
        endpoint: response.endpoint,
        model: response.model,
        credential_id: response.credential_id,
        config_version: response.config_version.clone(),
        credential_version: response.credential_version,
        response_mode: response.response_mode,
    });
    save_config(config_path, &config)?;
    if !quiet {
        if response.execution_mode == ClassifierExecutionMode::Managed {
            println!(
                "Managed classifier provisioned ({}); provider credential remains on the Metrune server.",
                response.config_version
            );
        } else {
            println!(
                "Local classifier provisioned ({}); credential {}.",
                response.config_version,
                storage.unwrap_or("not required")
            );
        }
    }
    Ok(())
}

async fn configure_classifier_after_enrollment(
    config_path: &Path,
    requested: Option<ClassifierSelection>,
    endpoint: Option<String>,
    model: Option<String>,
) -> Result<()> {
    let server_profile = fetch_server_classifier(config_path).await?;
    let selection = match requested {
        Some(selection) => selection,
        None if std::io::stdin().is_terminal() => choose_classifier_interactively(&server_profile)?,
        None if server_profile.enabled => ClassifierSelection::Organization,
        None => ClassifierSelection::None,
    };

    match selection {
        ClassifierSelection::Organization => {
            if !server_profile.enabled {
                bail!(
                    "the Metrune server has no organization classifier; choose local, custom, or none"
                );
            }
            apply_server_classifier(config_path, server_profile, false)
        }
        ClassifierSelection::Local => configure_local_classifier(
            config_path,
            "local",
            endpoint,
            model,
            "http://localhost:11434/v1/chat/completions",
            "qwen2.5-coder:7b",
        ),
        ClassifierSelection::Custom => {
            configure_local_classifier(config_path, "custom", endpoint, model, "", "")
        }
        ClassifierSelection::None => {
            let mut config = load_config(config_path)?;
            if let Some(profile) = config.classifier.take() {
                if !profile.credential_id.is_empty() {
                    CredentialStore::default()
                        .delete_for_server(&config.server_url, &profile.credential_id)?;
                }
            }
            save_config(config_path, &config)?;
            println!("Semantic classification disabled. Usage and cost tracking still work.");
            Ok(())
        }
    }
}

fn choose_classifier_interactively(
    server_profile: &ClassifierProvisionResponse,
) -> Result<ClassifierSelection> {
    println!();
    println!("Semantic classifier");
    if server_profile.enabled {
        println!("Your Metrune server provides:");
        println!("  Execution: {}", server_profile.execution_mode);
        println!("  Provider: {}", server_profile.provider_id);
        println!("  Model:    {}", server_profile.model);
        if server_profile.execution_mode == ClassifierExecutionMode::Managed {
            println!("  Privacy:  selected semantic text is sent to Metrune; the provider key stays on the server");
        } else {
            println!("  Privacy:  semantic text stays on this client");
        }
        let choices = [
            "Use organization classifier (recommended)",
            "Configure a local model",
            "Configure another provider",
            "Disable classification",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose classifier")
            .items(&choices)
            .default(0)
            .interact()
            .context("select classifier")?;
        Ok([
            ClassifierSelection::Organization,
            ClassifierSelection::Local,
            ClassifierSelection::Custom,
            ClassifierSelection::None,
        ][selected])
    } else {
        println!("No organization classifier is configured.");
        let choices = [
            "Continue without classification (recommended)",
            "Configure a local model",
            "Configure another provider",
        ];
        let selected = Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Choose classifier")
            .items(&choices)
            .default(0)
            .interact()
            .context("select classifier")?;
        Ok([
            ClassifierSelection::None,
            ClassifierSelection::Local,
            ClassifierSelection::Custom,
        ][selected])
    }
}

fn configure_local_classifier(
    config_path: &Path,
    provider_id: &str,
    endpoint: Option<String>,
    model: Option<String>,
    default_endpoint: &str,
    default_model: &str,
) -> Result<()> {
    let endpoint = required_setting(
        endpoint,
        "OpenAI-compatible endpoint",
        default_endpoint,
        "--classifier-endpoint",
    )?;
    let model = required_setting(model, "Model", default_model, "--classifier-model")?;
    let credential_id = format!(
        "{}-{}",
        provider_id,
        &hex::encode(Sha256::digest(endpoint.as_bytes()))[..12]
    );
    let mut config = load_config(config_path)?;
    let api_key = env::var("METRUNE_CLASSIFIER_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if let Some(api_key) = api_key {
        let storage = CredentialStore::default().set_for_server(
            &config.server_url,
            &credential_id,
            &api_key,
        )?;
        println!("Classifier credential stored in {storage}.");
    }

    config.classifier = Some(ClassifierProfile {
        enabled: true,
        execution_mode: ClassifierExecutionMode::Local,
        provider_id: provider_id.into(),
        endpoint,
        model,
        credential_id,
        config_version: format!("client-{}", Utc::now().timestamp()),
        credential_version: None,
        response_mode: ResponseMode::PromptJson,
    });
    save_config(config_path, &config)?;
    println!(
        "Semantic classifier configured. Set METRUNE_CLASSIFIER_API_KEY before scanning if the endpoint requires authentication."
    );
    Ok(())
}

fn required_setting(
    supplied: Option<String>,
    label: &str,
    default: &str,
    flag: &str,
) -> Result<String> {
    if let Some(value) = supplied.filter(|value| !value.trim().is_empty()) {
        return Ok(value);
    }
    if std::io::stdin().is_terminal() {
        let message = if default.is_empty() {
            format!("{label}: ")
        } else {
            format!("{label} [{default}]: ")
        };
        let value = prompt(&message, default)?;
        if !value.trim().is_empty() {
            return Ok(value);
        }
    }
    bail!("{label} is required; provide {flag}")
}

fn prompt(message: &str, default: &str) -> Result<String> {
    print!("{message}");
    std::io::stdout().flush()?;
    let mut value = String::new();
    std::io::stdin().read_line(&mut value)?;
    let value = value.trim();
    Ok(if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    })
}

fn save_config(path: &Path, config: &ClientConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let contents = serde_json::to_vec_pretty(config)?;
    let staged = path.with_extension(format!("json.{}.tmp", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staged)?;
        file.write_all(&contents)?;
        file.sync_all()?;
    }
    set_private_permissions(&staged)?;
    std::fs::rename(&staged, path)?;
    set_private_permissions(path)?;
    Ok(())
}

fn resolve_classifier(config: &ClientConfig) -> Result<Option<ResolvedClassifier>> {
    let profile = config.classifier.as_ref();
    let endpoint = env::var("METRUNE_CLASSIFIER_ENDPOINT").ok();
    let model = env::var("METRUNE_CLASSIFIER_MODEL").ok();
    if let (Some(endpoint), Some(model)) = (endpoint, model) {
        let env_key = env::var("METRUNE_CLASSIFIER_API_KEY")
            .ok()
            .filter(|key| !key.trim().is_empty());
        let api_key = match (env_key, profile) {
            (Some(key), _) => Some(key),
            (None, Some(profile)) => CredentialStore::default()
                .get_for_server(&config.server_url, &profile.credential_id)?,
            (None, None) => None,
        };
        return Ok(Some(ResolvedClassifier {
            execution_mode: ClassifierExecutionMode::Local,
            endpoint,
            model,
            api_key,
            installation_token: None,
            config_version: env::var("METRUNE_CLASSIFIER_CONFIG_VERSION")
                .ok()
                .or_else(|| profile.map(|profile| profile.config_version.clone()))
                .unwrap_or_else(|| "environment".into()),
            response_mode: profile
                .map(|profile| profile.response_mode)
                .unwrap_or(ResponseMode::Auto),
        }));
    }

    let Some(profile) = profile.filter(|profile| profile.enabled) else {
        return Ok(None);
    };
    if profile.execution_mode == ClassifierExecutionMode::Managed {
        let installation_token = resolve_installation_token(config)?;
        return Ok(Some(ResolvedClassifier {
            execution_mode: ClassifierExecutionMode::Managed,
            endpoint: format!(
                "{}/v1/installation/classifier/classify-batch",
                config.server_url.trim_end_matches('/')
            ),
            model: profile.model.clone(),
            api_key: None,
            installation_token: Some(installation_token),
            config_version: profile.config_version.clone(),
            response_mode: profile.response_mode,
        }));
    }
    Ok(Some(ResolvedClassifier {
        execution_mode: ClassifierExecutionMode::Local,
        endpoint: profile.endpoint.clone(),
        model: profile.model.clone(),
        api_key: CredentialStore::default()
            .get_for_server(&config.server_url, &profile.credential_id)?,
        installation_token: None,
        config_version: profile.config_version.clone(),
        response_mode: profile.response_mode,
    }))
}

async fn scan(
    state: &LocalState,
    config: &ClientConfig,
    requested_clients: &[String],
    no_classify: bool,
) -> Result<usize> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")?;
    let identity = IdentityContext {
        pseudonym_key: config.pseudonym_key.as_bytes().to_vec(),
        user_alias: config.user_alias.clone(),
        team_key: config.team_key.clone(),
        project_aliases: config.project_aliases.clone(),
        project_label_mode: match env::var("METRUNE_PROJECT_MODE").as_deref() {
            Ok("anonymous") => ProjectLabelMode::Anonymous,
            _ => ProjectLabelMode::Folder,
        },
    };
    let classifier_settings = if no_classify {
        None
    } else {
        resolve_classifier(config)?
    };
    let classifier = classifier(no_classify, classifier_settings.as_ref())?;
    let classifier_fingerprint = classifier_fingerprint(no_classify, classifier_settings.as_ref());
    let classification_mode = if no_classify {
        "disabled"
    } else if classifier_settings.is_some() {
        "enabled"
    } else {
        "unavailable"
    };
    let revision_tag = match classification_mode {
        "enabled" => 2,
        "unavailable" => 1,
        _ => 0,
    };
    let pricebook = env::var_os("METRUNE_PRICEBOOK")
        .map(PathBuf::from)
        .map(|path| PriceBook::load(&path))
        .transpose()?;
    let scan_context_fingerprint = scan_context_fingerprint(config)?;
    let mut sessions: HashMap<(String, String), Vec<UsageMessage>> = HashMap::new();

    for adapter in built_in_adapters() {
        if !requested_clients.is_empty() && !requested_clients.iter().any(|id| id == adapter.id()) {
            continue;
        }
        for source in adapter.discover(&home, &[])? {
            let fingerprint = format!(
                "{}:{}:{}:{}:{}",
                ADAPTER_PARSER_VERSION,
                adapter.id(),
                classifier_fingerprint,
                scan_context_fingerprint,
                file_fingerprint(&source)?
            );
            if state.fingerprint(&source)?.as_deref() == Some(&fingerprint) {
                continue;
            }
            match adapter.parse(&source) {
                Ok(messages) => {
                    for mut message in messages {
                        if let Some(pricebook) = &pricebook {
                            pricebook.estimate(&mut message);
                        }
                        sessions
                            .entry((message.client_id.clone(), message.session_id.clone()))
                            .or_default()
                            .push(message);
                    }
                    state.checkpoint(&source, &fingerprint)?;
                }
                Err(error) => eprintln!(
                    "{} parser skipped {}: {error:#}",
                    adapter.id(),
                    source.display()
                ),
            }
        }
    }

    let mut queued = 0;
    for mut messages in sessions.into_values() {
        messages.sort_by_key(|message| (message.turn_sequence, message.activity_sequence));
        let Some(first) = messages.iter().min_by_key(|message| message.observed_at) else {
            continue;
        };
        let session_key = stable_session_key(&first.client_id, &first.session_id);
        let schema_version = state.session_schema_version(
            &session_key,
            first.session_started_at.unwrap_or(first.observed_at),
        )?;
        let classification_text = messages
            .iter()
            .filter_map(|message| message.classification_text.as_deref())
            .take(12)
            .collect::<Vec<_>>()
            .join("\n\n");
        let category = if schema_version == metrune_core::SCHEMA_VERSION {
            CategoryAssignment::default()
        } else if no_classify {
            CategoryAssignment::not_configured()
        } else if classification_text.is_empty() {
            CategoryAssignment::no_input()
        } else {
            classifier
                .classify(&classification_text)
                .await
                .unwrap_or_else(|error| {
                    eprintln!(
                        "semantic classification failed; keeping semantic status failed: {error:#}"
                    );
                    CategoryAssignment::failed(classifier.id())
                })
        };
        let observed_revision = messages
            .iter()
            .map(|message| message.observed_at.timestamp_millis().max(0) as u64)
            .max()
            .unwrap_or(1);
        let observed_revision = observed_revision
            .saturating_mul(1_000)
            .saturating_add(ADAPTER_PARSER_VERSION.parse::<u64>().unwrap_or(1) * 10)
            .saturating_add(revision_tag);
        let revision = state.next_revision(observed_revision)?;
        let snapshot = if schema_version == metrune_core::SCHEMA_VERSION {
            let (turns, classifier_usage) = classify_turns(
                state,
                &messages,
                classifier.as_ref(),
                no_classify,
                &classifier_fingerprint,
                config.pseudonym_key.as_bytes(),
            )
            .await;
            aggregate_session_v2(&messages, &identity, revision, turns, classifier_usage)
        } else {
            aggregate_session(&messages, &identity, revision, category)
        };
        if let Some(snapshot) = snapshot {
            state.queue_snapshot(&snapshot)?;
            queued += 1;
        }
    }
    Ok(queued)
}

async fn classify_turns(
    state: &LocalState,
    messages: &[UsageMessage],
    classifier: &dyn ClassifierBackend,
    disabled: bool,
    classifier_fingerprint: &str,
    cache_secret: &[u8],
) -> (Vec<TurnSnapshot>, ClassifierUsage) {
    let mut grouped: BTreeMap<u32, Vec<&UsageMessage>> = BTreeMap::new();
    for message in messages {
        grouped
            .entry(message.turn_sequence.max(1))
            .or_default()
            .push(message);
    }
    let mut turns = grouped
        .into_iter()
        .map(|(sequence, messages)| turn_from_messages(sequence, &messages))
        .collect::<Vec<_>>();
    let intents = turns
        .iter()
        .map(|turn| {
            messages
                .iter()
                .find(|message| message.turn_sequence.max(1) == turn.sequence)
                .and_then(|message| message.classification_text.as_deref())
                .map(normalize_intent)
        })
        .collect::<Vec<_>>();
    let mut pending = Vec::new();
    let mut deferred_inheritance = Vec::new();
    let mut previous: Option<CategoryAssignment> = None;
    for (index, turn) in turns.iter_mut().enumerate() {
        if disabled {
            turn.category = CategoryAssignment::not_configured();
            continue;
        }
        let Some(intent) = intents[index].as_deref().filter(|text| !text.is_empty()) else {
            if !turn.workflow_signals.is_empty() {
                if let Some(inherited) = previous.clone() {
                    turn.category = inherited;
                    turn.category.classifier_id = "hybrid-inheritance:v1".into();
                    turn.classification_method = ClassificationMethod::Inherited;
                    previous = Some(turn.category.clone());
                    continue;
                }
            }
            turn.category = CategoryAssignment::no_input();
            continue;
        };
        let cache_key = classification_cache_key(
            cache_secret,
            classifier_fingerprint,
            intent,
            &turn.workflow_signals,
            previous.as_ref(),
        );
        if let Ok(Some(cached)) = state.cached_classification(&cache_key) {
            turn.category = cached;
            turn.classification_method = ClassificationMethod::SemanticModel;
            turn.classification_cached = true;
            previous = Some(turn.category.clone());
            continue;
        }
        if is_continuation(intent) {
            if let Some(inherited) = previous.clone() {
                turn.category = inherited;
                turn.category.classifier_id = "hybrid-inheritance:v1".into();
                turn.classification_method = ClassificationMethod::Inherited;
                previous = Some(turn.category.clone());
                continue;
            } else if index > 0 && intents[index - 1].is_some() {
                deferred_inheritance.push((index, index - 1));
                continue;
            }
        }
        if let Some(assignment) = classify_by_rule(intent, &turn.workflow_signals) {
            turn.category = assignment;
            turn.classification_method = ClassificationMethod::Rule;
            previous = Some(turn.category.clone());
            continue;
        }
        pending.push((index, intent.to_owned(), cache_key));
    }

    let mut usage = ClassifierUsage::default();
    let mut cursor = 0;
    while cursor < pending.len() {
        let mut end = cursor;
        let mut bytes = 0_usize;
        while end < pending.len() && end - cursor < 12 {
            let next = pending[end].1.len();
            if end > cursor && bytes.saturating_add(next) > 16 * 1024 {
                break;
            }
            bytes = bytes.saturating_add(next);
            end += 1;
        }
        let texts = pending[cursor..end]
            .iter()
            .map(|(_, text, _)| text.clone())
            .collect::<Vec<_>>();
        match classifier.classify_batch(&texts).await {
            Ok(batch) => {
                usage.provider_id = batch.usage.provider_id.clone();
                usage.model_id = batch.usage.model_id.clone();
                usage.tokens.add_assign(&batch.usage.tokens);
                usage.cost.amount += batch.usage.cost.amount;
                usage.request_count = usage
                    .request_count
                    .saturating_add(batch.usage.request_count);
                usage.measurement = match (usage.measurement, batch.usage.measurement) {
                    (metrune_core::UsageMeasurement::Unavailable, next) => next,
                    (metrune_core::UsageMeasurement::Estimated, _)
                    | (_, metrune_core::UsageMeasurement::Estimated) => {
                        metrune_core::UsageMeasurement::Estimated
                    }
                    (current, metrune_core::UsageMeasurement::Unavailable) => current,
                    _ => metrune_core::UsageMeasurement::Reported,
                };
                for ((turn_index, _, cache_key), assignment) in
                    pending[cursor..end].iter().zip(batch.assignments)
                {
                    let turn = &mut turns[*turn_index];
                    turn.category = assignment;
                    turn.classification_method = ClassificationMethod::SemanticModel;
                    let _ = state.cache_classification(cache_key, &turn.category);
                }
            }
            Err(error) => {
                eprintln!("semantic turn classification failed; preserving work usage: {error:#}");
                for (turn_index, _, _) in &pending[cursor..end] {
                    turns[*turn_index].category = CategoryAssignment::failed(classifier.id());
                }
            }
        }
        cursor = end;
    }
    for (turn_index, source_index) in deferred_inheritance {
        let source = turns[source_index].category.clone();
        if source.classification_status == ClassificationStatus::Classified {
            turns[turn_index].category = source;
            turns[turn_index].category.classifier_id = "hybrid-inheritance:v1".into();
            turns[turn_index].classification_method = ClassificationMethod::Inherited;
        } else {
            turns[turn_index].category = CategoryAssignment::no_input();
        }
    }
    (turns, usage)
}

fn turn_from_messages(sequence: u32, messages: &[&UsageMessage]) -> TurnSnapshot {
    let mut ordered = messages.to_vec();
    ordered.sort_by_key(|message| message.activity_sequence);
    let mut steps: Vec<ModelActivityStep> = Vec::new();
    let mut signal_counts: BTreeMap<(WorkflowSignal, u32), u32> = BTreeMap::new();
    for message in ordered {
        let provider_id = message.provider_id.clone();
        let model_id = metrune_core::canonical_model_id(&message.model_id);
        let step_index = if let Some(last) = steps
            .last_mut()
            .filter(|step| step.provider_id == provider_id && step.model_id == model_id)
        {
            last.tokens.add_assign(&message.tokens);
            last.cost.amount += message.cost.amount;
            last.call_count = last.call_count.saturating_add(1);
            last.sequence
        } else {
            let step = steps.len() as u32;
            steps.push(ModelActivityStep {
                sequence: step,
                provider_id,
                model_id,
                tokens: message.tokens.clone(),
                cost: message.cost.clone(),
                call_count: 1,
            });
            step
        };
        for signal in &message.workflow_signals {
            *signal_counts.entry((*signal, step_index)).or_default() += 1;
        }
    }
    TurnSnapshot {
        sequence,
        category: CategoryAssignment::default(),
        classification_method: ClassificationMethod::None,
        classification_cached: false,
        model_activity: steps,
        workflow_signals: signal_counts
            .into_iter()
            .map(|((signal, model_step_index), count)| SignalCount {
                signal,
                count,
                model_step_index: Some(model_step_index),
            })
            .collect(),
    }
}

fn normalize_intent(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(2_048)
        .collect::<String>()
        .to_lowercase()
}

fn classification_cache_key(
    secret: &[u8],
    classifier_fingerprint: &str,
    intent: &str,
    signals: &[SignalCount],
    previous: Option<&CategoryAssignment>,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(TAXONOMY_VERSION.as_bytes());
    mac.update(b"\0hybrid-rules-v1\0");
    mac.update(classifier_fingerprint.as_bytes());
    mac.update(b"\0");
    mac.update(intent.as_bytes());
    for signal in signals {
        mac.update(signal.signal.as_str().as_bytes());
        mac.update(signal.count.to_le_bytes().as_ref());
    }
    if let Some(previous) = previous {
        mac.update(previous.category_id.as_str().as_bytes());
    }
    hex::encode(mac.finalize().into_bytes())
}

fn is_continuation(intent: &str) -> bool {
    matches!(
        intent.trim_matches(|character: char| !character.is_alphanumeric()),
        "yes"
            | "ok"
            | "okay"
            | "continue"
            | "go ahead"
            | "do it"
            | "please do"
            | "sounds good"
            | "thanks"
            | "thank you"
    )
}

fn classify_by_rule(intent: &str, signals: &[SignalCount]) -> Option<CategoryAssignment> {
    let has = |signal| signals.iter().any(|count| count.signal == signal);
    let contains = |needles: &[&str]| needles.iter().any(|needle| intent.contains(needle));
    let category = if contains(&[
        "bug",
        "debug",
        "root cause",
        "failing",
        "failure",
        "crash",
        "regression",
        "fix the error",
    ]) {
        Some(CategoryId::Debugging)
    } else if contains(&[
        "write tests",
        "add tests",
        "run the tests",
        "test coverage",
        "integration test",
        "unit test",
    ]) {
        Some(CategoryId::Testing)
    } else if contains(&[
        "deploy",
        "release",
        "ci/cd",
        "pipeline",
        "infrastructure",
        "docker",
        "kubernetes",
    ]) && (has(WorkflowSignal::Deployed)
        || has(WorkflowSignal::Built)
        || contains(&["set up", "configure", "ship"]))
    {
        Some(CategoryId::Operations)
    } else if contains(&[
        "readme",
        "documentation",
        "document this",
        "api docs",
        "technical guide",
    ]) {
        Some(CategoryId::Documentation)
    } else if contains(&["refactor", "code review", "review this", "clean up"])
        && !contains(&["bug", "failure"])
    {
        Some(CategoryId::ReviewRefactoring)
    } else if contains(&[
        "make a plan",
        "implementation plan",
        "design the architecture",
        "write a spec",
        "define requirements",
    ]) && !has(WorkflowSignal::Edited)
    {
        Some(CategoryId::Planning)
    } else if contains(&[
        "investigate",
        "research",
        "compare",
        "explain",
        "understand",
        "analyze the codebase",
        "check how",
    ]) && !has(WorkflowSignal::Edited)
    {
        Some(CategoryId::Research)
    } else if contains(&[
        "blog post",
        "marketing copy",
        "user-facing copy",
        "write an article",
    ]) {
        Some(CategoryId::Content)
    } else if contains(&[
        "implement",
        "add a feature",
        "build a feature",
        "create an endpoint",
        "change the behavior",
    ]) {
        Some(CategoryId::Implementation)
    } else {
        None
    }?;
    Some(CategoryAssignment {
        category_id: category,
        confidence: 0.92,
        taxonomy_version: TAXONOMY_VERSION.into(),
        classifier_id: "hybrid-rule:v1".into(),
        classification_status: ClassificationStatus::Classified,
    })
}

fn classifier(
    disabled: bool,
    settings: Option<&ResolvedClassifier>,
) -> Result<Box<dyn ClassifierBackend>> {
    if disabled {
        return Ok(Box::new(UnknownClassifier));
    }
    let Some(settings) = settings else {
        return Ok(Box::new(UnknownClassifier));
    };
    if settings.execution_mode == ClassifierExecutionMode::Managed {
        let installation_token = settings
            .installation_token
            .clone()
            .context("managed classifier is missing the installation credential")?;
        return Ok(Box::new(ManagedClassifier {
            endpoint: settings.endpoint.clone(),
            installation_token,
            config_version: settings.config_version.clone(),
            client: metrune_http_client_builder()
                .timeout(Duration::from_secs(45))
                .build()?,
        }));
    }
    if settings.endpoint.contains("openrouter.ai") && settings.api_key.is_none() {
        // Keep collecting tokens and costs when the semantic credential is
        // unavailable. The snapshot records this as `unavailable`.
        return Ok(Box::new(UnknownClassifier));
    }
    Ok(Box::new(OpenAiCompatibleClassifier::new(
        settings.endpoint.clone(),
        settings.model.clone(),
        settings.api_key.clone(),
        settings.response_mode,
    )?))
}

fn classifier_fingerprint(disabled: bool, settings: Option<&ResolvedClassifier>) -> String {
    let mut digest = Sha256::new();
    let (execution_mode, endpoint, model, api_key, config_version) = settings
        .map(|settings| {
            (
                settings.execution_mode.to_string(),
                settings.endpoint.as_str(),
                settings.model.as_str(),
                settings.api_key.as_deref().unwrap_or_default(),
                settings.config_version.as_str(),
            )
        })
        .unwrap_or_else(|| (String::new(), "", "", "", ""));
    for value in [
        disabled.to_string(),
        execution_mode,
        endpoint.to_string(),
        model.to_string(),
        api_key.to_string(),
        config_version.to_string(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value.as_bytes());
    }
    format!("classifier-{}", hex::encode(digest.finalize()))
}

fn scan_context_fingerprint(config: &ClientConfig) -> Result<String> {
    let pricebook = env::var_os("METRUNE_PRICEBOOK").map(PathBuf::from);
    let pricebook_fingerprint = pricebook
        .as_deref()
        .map(file_fingerprint)
        .transpose()?
        .unwrap_or_else(|| "none".into());
    let project_mode = env::var("METRUNE_PROJECT_MODE").unwrap_or_else(|_| "folder".into());
    let config_json = serde_json::to_vec(config)?;
    let mut digest = Sha256::new();
    for value in [
        config_json,
        project_mode.into_bytes(),
        pricebook_fingerprint.into_bytes(),
    ] {
        digest.update((value.len() as u64).to_le_bytes());
        digest.update(value);
    }
    Ok(format!("context-{}", hex::encode(digest.finalize())))
}

async fn upload(state: &LocalState, config: &ClientConfig, limit: usize) -> Result<usize> {
    let batch = state.pending_batch(limit)?;
    if batch.snapshots.is_empty() {
        return Ok(0);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(&batch)?)?;
    let body = encoder.finish()?;
    let installation_token = resolve_installation_token(config)?;
    let response = metrune_http_client()?
        .post(format!(
            "{}/v1/ingest/sessions",
            config.server_url.trim_end_matches('/')
        ))
        .bearer_auth(installation_token)
        .header("Idempotency-Key", &batch.batch_id)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .body(body)
        .send()
        .await?;
    let status = response.status();
    if status == reqwest::StatusCode::UPGRADE_REQUIRED {
        let body = response.bytes().await?;
        if let Some(error) = client_unsupported_upload(status, &body) {
            return Err(error.into());
        }
        bail!("server returned HTTP 426 Upgrade Required");
    }
    let response = response.error_for_status()?;
    let ack: metrune_core::IngestAck = response.json().await?;
    if ack.rejected > 0 {
        // New servers identify each row in a partial response. Acknowledge
        // accepted rows and quarantine permanently invalid derived snapshots
        // so a single malformed row cannot starve later uploads. Older
        // servers omit these fields; in that case retain the whole batch and
        // retry conservatively.
        if !ack.accepted_session_keys.is_empty() || !ack.rejected_session_keys.is_empty() {
            state.acknowledge_session_keys(&batch.snapshots, &ack.accepted_session_keys)?;
            state.acknowledge_session_keys(&batch.snapshots, &ack.rejected_session_keys)?;
            eprintln!(
                "quarantined {} rejected snapshot(s); rescan after correcting the source if needed",
                ack.rejected_session_keys.len()
            );
        }
        bail!(
            "server rejected {} snapshots: {}",
            ack.rejected,
            ack.errors.join("; ")
        );
    }
    state.acknowledge(&batch.snapshots)?;
    Ok(ack.accepted + ack.duplicates)
}

fn truthy_env_flag(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

async fn maybe_print_update_notice(state: &LocalState, config: &ClientConfig) {
    if env::var("METRUNE_NO_UPDATE_CHECK")
        .ok()
        .as_deref()
        .is_some_and(truthy_env_flag)
    {
        return;
    }
    let checked_at = Utc::now();
    let interval = chrono::Duration::hours(UPDATE_CHECK_INTERVAL_HOURS);
    // Claim the slot before network I/O. An unavailable server should not turn
    // every watch cycle into another background request, and concurrent watch
    // processes must not both pass a check-then-record race.
    if !state
        .claim_update_check(checked_at, interval)
        .unwrap_or(false)
    {
        return;
    }
    let Ok(client) = metrune_http_client_builder()
        .timeout(UPDATE_CHECK_TIMEOUT)
        .build()
    else {
        return;
    };
    let base_url = config.server_url.trim_end_matches('/');
    let (info, manifest) = tokio::join!(
        fetch_server_info_with_client(&client, base_url),
        fetch_manifest_with_client(&client, base_url),
    );
    if let Some(notice) = update_notice(
        env!("CARGO_PKG_VERSION"),
        info.as_ref().ok(),
        manifest.as_ref().ok(),
    ) {
        eprintln!("{notice}");
    }
}

async fn fetch_server_info_with_client(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<ServerInfo> {
    let endpoint = format!("{base_url}/v1/server/info");
    client
        .get(&endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("request {endpoint}"))?
        .error_for_status()
        .with_context(|| format!("request {endpoint}"))?
        .json()
        .await
        .with_context(|| format!("parse server information from {endpoint}"))
}

fn update_notice(
    current: &str,
    info: Option<&ServerInfo>,
    manifest: Option<&ClientReleaseManifest>,
) -> Option<String> {
    if let Some(server) = info.filter(|info| !versions_share_major(current, &info.server_version)) {
        return Some(format!(
            "Metrune client {current} is incompatible with server {} (major versions must match); install a client from the server's release line.",
            server.server_version
        ));
    }
    if let Some(minimum) = info.and_then(|info| info.minimum_client_version.as_deref()) {
        if version_is_older(current, minimum) {
            return Some(format!(
                "Metrune client {current} is unsupported by this server (minimum {minimum}); run `metrune update`."
            ));
        }
    } else if let Some(manifest) = manifest.filter(|manifest| manifest.requires_upgrade(current)) {
        return Some(format!(
            "Metrune client {current} is below the published minimum {}; run `metrune update`.",
            manifest.minimum_version
        ));
    }
    manifest
        .filter(|manifest| manifest.is_newer_than(current))
        .map(|manifest| {
            format!(
                "Metrune client {} is available (installed {current}); run `metrune update`.",
                manifest.version
            )
        })
}

async fn enroll(
    config_path: &Path,
    server: &str,
    token: Option<&str>,
    name: &str,
    platform: &str,
    user_alias: &str,
) -> Result<()> {
    let server = validate_server_url(server)?;
    let client = metrune_http_client_builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build enrollment HTTP client")?;
    let response = match token {
        Some(token) => enroll_with_token(&client, &server, token, name, platform).await?,
        None => enroll_with_device_authorization(&client, &server, name, platform).await?,
    };
    let installation_credential_id = installation_credential_id(&server, &response.installation_id);
    let credential_store = CredentialStore::default();
    let storage = credential_store
        .set_installation(&installation_credential_id, &response.installation_token)?;
    let config = ClientConfig {
        server_url: server,
        installation_id: response.installation_id,
        installation_token: String::new(),
        installation_credential_id: installation_credential_id.clone(),
        pseudonym_key: response.pseudonym_key,
        user_alias: user_alias.into(),
        team_key: response.team_key,
        project_aliases: BTreeMap::new(),
        classifier: None,
    };
    if let Err(error) = save_config(config_path, &config) {
        let _ = credential_store.delete_installation(&installation_credential_id);
        return Err(error);
    }
    println!("Installation credential stored in {storage}.");
    Ok(())
}

async fn enroll_with_token(
    client: &reqwest::Client,
    server: &str,
    token: &str,
    name: &str,
    platform: &str,
) -> Result<EnrollResponse> {
    client
        .post(format!("{}/v1/enroll", server.trim_end_matches('/')))
        .json(&EnrollRequest {
            enrollment_token: token,
            installation_name: name,
            platform,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await
        .context("read enrollment response")
}

async fn enroll_with_device_authorization(
    client: &reqwest::Client,
    server: &str,
    name: &str,
    platform: &str,
) -> Result<EnrollResponse> {
    let base = server.trim_end_matches('/');
    let authorization_response = client
        .post(format!("{base}/v1/oauth/device/authorization"))
        .form(&DeviceAuthorizationRequest {
            client_id: DEVICE_CLIENT_ID,
            installation_name: name,
            platform,
        })
        .send()
        .await
        .context("request a device authorization code")?;
    let status = authorization_response.status();
    let body = authorization_response
        .bytes()
        .await
        .context("read device authorization response")?;
    if !status.is_success() {
        let oauth_error = serde_json::from_slice::<OAuthErrorResponse>(&body).ok();
        let detail = oauth_error
            .as_ref()
            .map(format_oauth_error)
            .unwrap_or_else(|| format!("HTTP {status}"));
        bail!("device authorization failed: {detail}");
    }
    let authorization: DeviceAuthorizationResponse =
        serde_json::from_slice(&body).context("parse device authorization response")?;
    if authorization.device_code.is_empty()
        || authorization.user_code.is_empty()
        || authorization.verification_uri.is_empty()
    {
        bail!("device authorization response is missing required fields");
    }

    println!("Approve this client in your browser:");
    println!("  {}", authorization.verification_uri_complete);
    println!("Code: {}", authorization.user_code);
    println!(
        "If the complete link does not open, visit {} and enter the code.",
        authorization.verification_uri
    );
    std::io::stdout()
        .flush()
        .context("flush device authorization instructions")?;

    let deadline = Instant::now()
        + Duration::from_secs(authorization.expires_in.clamp(1, MAX_DEVICE_AUTH_SECONDS));
    let mut interval = authorization.interval.clamp(1, MAX_DEVICE_POLL_SECONDS);
    loop {
        if Instant::now() >= deadline {
            bail!("device authorization expired before it was approved");
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let token_response = match client
            .post(format!("{base}/v1/oauth/token"))
            .form(&DeviceTokenRequest {
                grant_type: DEVICE_GRANT_TYPE,
                device_code: &authorization.device_code,
                client_id: DEVICE_CLIENT_ID,
            })
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) if error.is_timeout() || error.is_connect() => {
                interval = (interval + 5).min(MAX_DEVICE_POLL_SECONDS);
                eprintln!("Authorization server is temporarily unavailable; retrying.");
                continue;
            }
            Err(error) => return Err(error).context("poll device authorization"),
        };
        let status = token_response.status();
        let body = token_response
            .bytes()
            .await
            .context("read device token response")?;
        if status.is_success() {
            let token: DeviceTokenResponse =
                serde_json::from_slice(&body).context("parse device token response")?;
            if !token.token_type.eq_ignore_ascii_case("bearer") {
                bail!("device token response used an unsupported token type");
            }
            if token.access_token.is_empty()
                || token.installation_id.is_empty()
                || token.pseudonym_key.is_empty()
            {
                bail!("device token response is missing required fields");
            }
            return Ok(EnrollResponse {
                installation_id: token.installation_id,
                installation_token: token.access_token,
                pseudonym_key: token.pseudonym_key,
                team_key: token.team_key,
            });
        }
        let oauth_error = serde_json::from_slice::<OAuthErrorResponse>(&body)
            .with_context(|| format!("device token endpoint returned HTTP {status}"))?;
        match oauth_error.error.as_str() {
            "authorization_pending" => {}
            "slow_down" => {
                interval = (interval + 5).min(MAX_DEVICE_POLL_SECONDS);
            }
            "temporarily_unavailable" | "server_error"
                if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS =>
            {
                interval = (interval + 5).min(MAX_DEVICE_POLL_SECONDS);
            }
            "access_denied" => bail!("device authorization was denied"),
            "expired_token" => bail!("device authorization expired before it was approved"),
            _ => bail!(
                "device authorization failed: {}",
                format_oauth_error(&oauth_error)
            ),
        }
    }
}

fn format_oauth_error(error: &OAuthErrorResponse) -> String {
    if error.error_description.trim().is_empty() {
        error.error.clone()
    } else {
        format!("{} ({})", error.error, error.error_description)
    }
}

fn load_config(path: &Path) -> Result<ClientConfig> {
    load_config_with_store(path, &CredentialStore::default())
}

/// Installation and upload credentials must never be sent to an arbitrary
/// clear-text endpoint. Localhost HTTP remains available for development and
/// test servers; every remote server must use HTTPS and a real host.
fn validate_server_url(value: &str) -> Result<String> {
    let normalized = value.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(normalized)
        .with_context(|| format!("invalid Metrune server URL {value:?}"))?;
    if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        bail!("Metrune server URL must not contain credentials and must include a host");
    }
    let local_http = url.scheme() == "http"
        && matches!(
            url.host_str(),
            Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
        );
    if url.scheme() != "https" && !local_http {
        bail!("Metrune server URL must use HTTPS (HTTP is allowed only for localhost development)");
    }
    Ok(normalized.to_string())
}

fn load_config_with_store(path: &Path, credential_store: &CredentialStore) -> Result<ClientConfig> {
    let mut config: ClientConfig = serde_json::from_slice(
        &std::fs::read(path)
            .with_context(|| format!("read {}; run `metrune enroll` first", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    config.server_url = validate_server_url(&config.server_url)?;
    if !config.installation_token.is_empty() {
        let credential_id = installation_credential_id(&config.server_url, &config.installation_id);
        credential_store
            .set_installation(&credential_id, &config.installation_token)
            .context("migrate the installation credential to protected storage")?;
        config.installation_token.clear();
        config.installation_credential_id = credential_id;
        save_config(path, &config)
            .context("remove the migrated installation credential from the client config")?;
    }
    Ok(config)
}

fn installation_credential_id(server_url: &str, installation_id: &str) -> String {
    let server_digest = hex::encode(Sha256::digest(server_url.trim_end_matches('/').as_bytes()));
    format!("{installation_id}-{}", &server_digest[..16])
}

fn resolve_installation_token(config: &ClientConfig) -> Result<String> {
    resolve_installation_token_with_store(config, &CredentialStore::default())
}

fn resolve_installation_token_with_store(
    config: &ClientConfig,
    credential_store: &CredentialStore,
) -> Result<String> {
    if !config.installation_credential_id.is_empty() {
        return credential_store
            .get_installation(&config.installation_credential_id)?
            .context(
                "installation credential is missing from protected storage; run `metrune enroll` again",
            );
    }
    if !config.installation_token.is_empty() {
        return Ok(config.installation_token.clone());
    }
    bail!("installation credential is not configured; run `metrune enroll` again")
}

fn default_state_path() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join(".local/share/metrune/state.db")
}

/// The Metrune release key this build trusts, baked in at compile time. A build
/// without one can still report what is available, but it refuses to install
/// unless the operator accepts that with `--allow-unsigned`.
const RELEASE_PUBLIC_KEY: Option<&str> = option_env!("METRUNE_RELEASE_PUBKEY");

async fn update_client(
    config_path: &Path,
    server: Option<&str>,
    check_only: bool,
    allow_unsigned: bool,
) -> Result<()> {
    let base_url = match server {
        Some(server) => validate_server_url(server)?,
        None => {
            load_config(config_path)
                .context("no --server given and this installation is not enrolled")?
                .server_url
        }
    };
    let current = env!("CARGO_PKG_VERSION");
    let manifest = fetch_manifest(&base_url).await?;

    let signature_state = match RELEASE_PUBLIC_KEY {
        Some(key) => match manifest.verify_signature(key) {
            Ok(()) => "verified against the pinned Metrune release key",
            Err(error) => {
                // A mirror may rewrite download URLs, never versions or
                // digests, so a failure here is not a transport hiccup.
                anyhow::bail!("the release manifest from {base_url} is not trustworthy: {error}");
            }
        },
        None => "not verified: this build pins no release key",
    };

    println!("Installed version: {current}");
    println!("Published version: {}", manifest.version);
    println!("Minimum supported: {}", manifest.minimum_version);
    println!("Signature: {signature_state}");
    if manifest.requires_upgrade(current) {
        println!(
            "This client is older than the minimum this server supports; uploads may be refused."
        );
    }
    if !manifest.is_newer_than(current) {
        println!("Already up to date.");
        return Ok(());
    }

    let Some(target) = metrune_core::release::current_target() else {
        anyhow::bail!(
            "no Metrune client is published for {} {}",
            env::consts::OS,
            env::consts::ARCH
        );
    };
    let artifact = manifest.artifact_for(target).ok_or_else(|| {
        anyhow::anyhow!("release {} publishes no {target} client", manifest.version)
    })?;
    let source = match artifact.source {
        metrune_core::release::ArtifactSource::Mirror => "mirrored by this server",
        metrune_core::release::ArtifactSource::Upstream => "the canonical Metrune release",
    };
    println!("Download: {} ({source})", artifact.url);
    if check_only {
        return Ok(());
    }
    if RELEASE_PUBLIC_KEY.is_none() && !allow_unsigned {
        anyhow::bail!(
            "refusing to install an unverified client: this build pins no release key, so pass --allow-unsigned to accept that, or install from {}",
            manifest.upstream_base_url
        );
    }

    let binary = metrune_http_client()
        .context("build update HTTP client")?
        .get(&artifact.url)
        .send()
        .await
        .with_context(|| format!("download {}", artifact.url))?
        .error_for_status()
        .with_context(|| format!("download {}", artifact.url))?
        .bytes()
        .await?;
    let digest = metrune_core::release::sha256_hex(&binary);
    if !digest.eq_ignore_ascii_case(&artifact.sha256) {
        anyhow::bail!(
            "the downloaded client does not match the release manifest (expected {}, got {digest})",
            artifact.sha256
        );
    }
    replace_running_binary(&binary)?;
    println!("Updated to {}.", manifest.version);
    Ok(())
}

async fn fetch_manifest(base_url: &str) -> Result<metrune_core::release::ClientReleaseManifest> {
    let client = metrune_http_client()?;
    fetch_manifest_with_client(&client, base_url).await
}

async fn fetch_manifest_with_client(
    client: &reqwest::Client,
    base_url: &str,
) -> Result<ClientReleaseManifest> {
    let endpoint = format!("{base_url}/v1/client/manifest");
    let response = client
        .get(&endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .with_context(|| format!("request {endpoint}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "{base_url} publishes no client release manifest; install from the Metrune release page"
        );
    }
    let response = response
        .error_for_status()
        .with_context(|| format!("request {endpoint}"))?;
    let manifest: ClientReleaseManifest = response
        .json()
        .await
        .with_context(|| format!("parse the release manifest from {endpoint}"))?;
    manifest
        .validate()
        .with_context(|| format!("validate the release manifest from {endpoint}"))?;
    Ok(manifest)
}

/// Replace the running executable. The new binary is written beside the old one
/// and moved into place, so a failed download can never leave a half-written
/// `metrune` on PATH. Windows cannot unlink a running image, so the old one is
/// renamed aside first and cleaned up on the next run.
fn replace_running_binary(binary: &[u8]) -> Result<()> {
    let current = env::current_exe().context("locate the running metrune executable")?;
    replace_binary_at(&current, binary)
}

fn replace_binary_at(current: &Path, binary: &[u8]) -> Result<()> {
    let directory = current
        .parent()
        .ok_or_else(|| anyhow::anyhow!("the running executable has no parent directory"))?;
    let staged = directory.join(format!("metrune.{}.new", std::process::id()));
    std::fs::write(&staged, binary).with_context(|| {
        format!(
            "write {} (run the update with permission to write {})",
            staged.display(),
            directory.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
            .with_context(|| format!("make {} executable", staged.display()))?;
    }
    let previous = directory.join("metrune.old");
    let _ = std::fs::remove_file(&previous);
    if cfg!(windows) {
        std::fs::rename(current, &previous)
            .with_context(|| format!("move {} aside", current.display()))?;
    }
    match std::fs::rename(&staged, current) {
        Ok(()) => Ok(()),
        Err(error) => {
            // Put the old binary back rather than leaving nothing on PATH.
            if cfg!(windows) {
                let _ = std::fs::rename(&previous, current);
            }
            let _ = std::fs::remove_file(&staged);
            Err(anyhow::Error::from(error)
                .context(format!("replace {} with the new client", current.display())))
        }
    }
}

fn release_command(command: ReleaseCommand) -> Result<()> {
    let ReleaseCommand::Manifest {
        version,
        minimum_version,
        checksums,
        upstream_base_url,
        output,
        signing_key,
    } = command;
    let raw = std::fs::read_to_string(&checksums)
        .with_context(|| format!("read {}", checksums.display()))?;
    let digests = parse_checksums(&raw);
    if digests.is_empty() {
        anyhow::bail!("{} lists no artifacts", checksums.display());
    }
    let mut manifest = metrune_core::release::upstream_manifest(
        &version,
        &minimum_version,
        &Utc::now().to_rfc3339(),
        &upstream_base_url,
        &digests,
    );
    match signing_key.as_deref().map(str::trim).filter(|key| !key.is_empty()) {
        Some(key) => {
            manifest.sign(key)?;
            let public_key =
                metrune_core::release::ClientReleaseManifest::public_key_for(key)?;
            eprintln!("Signed with release public key {public_key}");
        }
        None => eprintln!(
            "No release signing key provided; publishing an unsigned manifest that clients pinning a key will reject."
        ),
    }
    manifest
        .validate()
        .context("validate generated release manifest")?;
    std::fs::write(&output, serde_json::to_vec_pretty(&manifest)?)
        .with_context(|| format!("write {}", output.display()))?;
    println!("{}", output.display());
    Ok(())
}

/// Parse `sha256sum` output, keeping only the artifact file name so the manifest
/// does not depend on where CI happened to stage the files.
fn parse_checksums(raw: &str) -> BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let (digest, path) = line.split_once(char::is_whitespace)?;
            let name = path.trim().trim_start_matches('*').rsplit('/').next()?;
            (digest.len() == 64 && !name.is_empty())
                .then(|| (name.to_string(), digest.to_ascii_lowercase()))
        })
        .collect()
}

fn default_config_path() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join(".config/metrune/config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sha256sums_into_bare_artifact_names() {
        let digests = parse_checksums(&format!(
            "{}  artifacts/metrune-linux-x86_64\n{}  *metrune-windows-x86_64.exe\n",
            "A".repeat(64),
            "b".repeat(64)
        ));
        assert_eq!(
            digests.get("metrune-linux-x86_64").map(String::as_str),
            Some("a".repeat(64).as_str())
        );
        assert!(digests.contains_key("metrune-windows-x86_64.exe"));
    }

    #[test]
    fn ignores_checksum_lines_that_are_not_sha256() {
        let digests = parse_checksums("not-a-digest  metrune-linux-x86_64\n\ngarbage\n");
        assert!(digests.is_empty());
    }

    #[test]
    fn update_defaults_to_installing_from_the_enrolled_server() {
        let cli = Cli::try_parse_from(["metrune", "update"]).expect("update should parse");
        let Command::Update {
            server,
            check,
            allow_unsigned,
        } = cli.command
        else {
            panic!("expected update command");
        };
        assert!(server.is_none());
        assert!(!check);
        assert!(!allow_unsigned);
    }

    #[test]
    fn metrune_requests_report_the_running_client_version() {
        let headers = metrune_default_headers();
        assert_eq!(
            headers
                .get(CLIENT_VERSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            headers
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(concat!("metrune/", env!("CARGO_PKG_VERSION")))
        );
    }

    #[test]
    fn typed_upgrade_required_responses_become_terminal_update_instructions() {
        let body = serde_json::to_vec(&ClientUnsupportedResponse {
            error: "unsupported".into(),
            code: CLIENT_UNSUPPORTED_ERROR_CODE.into(),
            minimum_client_version: Some("0.2.0".into()),
        })
        .expect("compatibility response");
        let error = client_unsupported_upload(reqwest::StatusCode::UPGRADE_REQUIRED, &body)
            .expect("typed compatibility error");
        assert_eq!(
            error.to_string(),
            "server requires Metrune client >= 0.2.0; run `metrune update`"
        );
        assert!(client_unsupported_upload(reqwest::StatusCode::BAD_REQUEST, &body).is_none());
    }

    #[test]
    fn update_notices_prefer_the_server_floor_then_the_published_release() {
        let manifest = ClientReleaseManifest {
            schema_version: metrune_core::release::MANIFEST_SCHEMA_VERSION,
            version: "0.3.0".into(),
            minimum_version: "0.1.0".into(),
            released_at: "2026-08-01T00:00:00Z".into(),
            upstream_base_url: "https://example.test/releases".into(),
            artifacts: vec![],
            signature: None,
        };
        let info = ServerInfo {
            server_version: "0.3.0".into(),
            supported_schema_versions: vec!["1".into(), "2".into()],
            minimum_client_version: Some("0.2.0-beta.2".into()),
        };
        assert!(update_notice("0.2.0-beta.1", Some(&info), Some(&manifest))
            .expect("required notice")
            .contains("minimum 0.2.0-beta.2"));

        let compatible = ServerInfo {
            minimum_client_version: Some("0.1.0".into()),
            ..info
        };
        assert!(update_notice("0.2.0", Some(&compatible), Some(&manifest))
            .expect("available notice")
            .contains("0.3.0 is available"));
        assert!(update_notice("0.3.0", Some(&compatible), Some(&manifest)).is_none());
    }

    #[test]
    fn update_notice_explains_a_major_compatibility_mismatch() {
        let info = ServerInfo {
            server_version: "1.0.0".into(),
            supported_schema_versions: vec!["1".into(), "2".into()],
            minimum_client_version: None,
        };
        let notice = update_notice("0.1.0", Some(&info), None).expect("major mismatch notice");
        assert!(notice.contains("major versions must match"));
    }

    #[test]
    fn update_check_opt_out_requires_an_explicit_truthy_value() {
        for value in ["1", "TRUE", "yes", " on "] {
            assert!(truthy_env_flag(value));
        }
        for value in ["", "0", "false", "off"] {
            assert!(!truthy_env_flag(value));
        }
    }

    #[test]
    fn updater_stages_and_atomically_replaces_the_existing_binary() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "metrune-update-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create updater test directory");
        let current = root.join(if cfg!(windows) {
            "metrune.exe"
        } else {
            "metrune"
        });
        std::fs::write(&current, b"old client").expect("write old client");

        replace_binary_at(&current, b"new verified client").expect("replace client");
        assert_eq!(
            std::fs::read(&current).expect("read replacement"),
            b"new verified client"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                std::fs::metadata(&current)
                    .expect("replacement metadata")
                    .permissions()
                    .mode()
                    & 0o111,
                0,
                "the replacement is not executable"
            );
        }

        std::fs::remove_dir_all(root).expect("remove updater test directory");
    }

    #[test]
    fn enroll_accepts_scriptable_classifier_selection() {
        let cli = Cli::try_parse_from([
            "metrune",
            "enroll",
            "--server",
            "https://metrune.example",
            "--token",
            "one-time-token",
            "--classifier",
            "local",
            "--classifier-endpoint",
            "http://localhost:11434/v1/chat/completions",
            "--classifier-model",
            "qwen2.5-coder:7b",
        ])
        .expect("enrollment arguments should parse");

        let Command::Enroll {
            classifier,
            classifier_endpoint,
            classifier_model,
            ..
        } = cli.command
        else {
            panic!("expected enroll command");
        };
        assert!(matches!(classifier, Some(ClassifierSelection::Local)));
        assert_eq!(
            classifier_endpoint.as_deref(),
            Some("http://localhost:11434/v1/chat/completions")
        );
        assert_eq!(classifier_model.as_deref(), Some("qwen2.5-coder:7b"));
    }

    #[test]
    fn enroll_defaults_to_browser_approved_device_authorization() {
        let cli = Cli::try_parse_from([
            "metrune",
            "enroll",
            "--server",
            "https://metrune.example",
            "--name",
            "Developer workstation",
        ])
        .expect("device enrollment arguments should parse");
        let Command::Enroll { token, .. } = cli.command else {
            panic!("expected enroll command");
        };
        assert!(token.is_none());
    }

    #[test]
    fn legacy_installation_tokens_migrate_out_of_config_without_losing_access() {
        use std::sync::atomic::{AtomicU64, Ordering};

        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "metrune-config-migration-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&root).expect("create migration test directory");
        let config_path = root.join("config.json");
        let credentials_path = root.join("credentials.json");
        let legacy_token = "mti_legacy-installation-secret";
        save_config(
            &config_path,
            &ClientConfig {
                server_url: "https://metrune.example/".into(),
                installation_id: "installation-1".into(),
                installation_token: legacy_token.into(),
                installation_credential_id: String::new(),
                pseudonym_key: "pseudonym".into(),
                user_alias: "user".into(),
                team_key: None,
                project_aliases: BTreeMap::new(),
                classifier: None,
            },
        )
        .expect("write legacy client config");
        let credential_store = CredentialStore::for_tests(credentials_path.clone());

        let migrated = load_config_with_store(&config_path, &credential_store)
            .expect("migrate legacy installation token");
        assert!(migrated.installation_token.is_empty());
        assert!(!migrated.installation_credential_id.is_empty());
        assert_eq!(
            resolve_installation_token_with_store(&migrated, &credential_store)
                .expect("resolve migrated installation token"),
            legacy_token
        );
        let serialized = std::fs::read_to_string(&config_path).expect("read migrated config");
        assert!(!serialized.contains(legacy_token));
        let config_json: serde_json::Value =
            serde_json::from_str(&serialized).expect("parse migrated config");
        assert!(config_json.get("installationToken").is_none());
        assert_eq!(
            config_json["installationCredentialId"],
            migrated.installation_credential_id
        );
        let credentials =
            std::fs::read_to_string(&credentials_path).expect("read protected credentials");
        assert!(credentials.contains(legacy_token));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&config_path)
                    .expect("config metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&credentials_path)
                    .expect("credentials metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        std::fs::remove_dir_all(root).expect("remove migration test directory");
    }

    #[test]
    fn oauth_errors_preserve_the_protocol_code_and_human_detail() {
        assert_eq!(
            format_oauth_error(&OAuthErrorResponse {
                error: "access_denied".into(),
                error_description: "the user denied this device".into(),
            }),
            "access_denied (the user denied this device)"
        );
        assert_eq!(
            format_oauth_error(&OAuthErrorResponse {
                error: "invalid_grant".into(),
                error_description: String::new(),
            }),
            "invalid_grant"
        );
    }

    #[test]
    fn watch_is_the_primary_name_with_daemon_as_a_compatibility_alias() {
        for command in ["watch", "daemon"] {
            let cli =
                Cli::try_parse_from(["metrune", command, "--interval-seconds", "120", "--quiet"])
                    .expect("watch command should parse");
            assert!(matches!(
                cli.command,
                Command::Watch {
                    interval_seconds: 120,
                    quiet: true,
                }
            ));
        }
    }

    #[test]
    fn managed_profile_uses_metrune_without_a_local_provider_key() {
        let config = ClientConfig {
            server_url: "https://metrune.example/".into(),
            installation_id: "installation".into(),
            installation_token: "mti_secret".into(),
            installation_credential_id: String::new(),
            pseudonym_key: "pseudonym".into(),
            user_alias: "user".into(),
            team_key: None,
            project_aliases: BTreeMap::new(),
            classifier: Some(ClassifierProfile {
                enabled: true,
                execution_mode: ClassifierExecutionMode::Managed,
                provider_id: "openrouter".into(),
                endpoint: String::new(),
                model: "provider/model".into(),
                credential_id: String::new(),
                config_version: "org-7".into(),
                credential_version: None,
                response_mode: ResponseMode::Auto,
            }),
        };
        let resolved = resolve_classifier(&config)
            .expect("managed profile should resolve")
            .expect("managed classifier");
        assert_eq!(resolved.execution_mode, ClassifierExecutionMode::Managed);
        assert_eq!(
            resolved.endpoint,
            "https://metrune.example/v1/installation/classifier/classify-batch"
        );
        assert_eq!(resolved.installation_token.as_deref(), Some("mti_secret"));
        assert!(resolved.api_key.is_none());
    }

    #[test]
    fn watch_refreshes_server_profiles_regardless_of_provider_or_execution_mode() {
        let profile = |provider_id: &str,
                       execution_mode: ClassifierExecutionMode,
                       config_version: &str| ClassifierProfile {
            enabled: true,
            execution_mode,
            provider_id: provider_id.into(),
            endpoint: "https://provider.example/v1/chat/completions".into(),
            model: "test-model".into(),
            credential_id: "test-credential".into(),
            config_version: config_version.into(),
            credential_version: Some(1),
            response_mode: ResponseMode::Auto,
        };

        assert!(should_refresh_classifier(&profile(
            "custom",
            ClassifierExecutionMode::Managed,
            "org-7",
        )));
        assert!(should_refresh_classifier(&profile(
            "custom",
            ClassifierExecutionMode::Local,
            "org-8",
        )));
        assert!(should_refresh_classifier(&profile(
            "openrouter",
            ClassifierExecutionMode::Local,
            "dev-1",
        )));
        assert!(!should_refresh_classifier(&profile(
            "custom",
            ClassifierExecutionMode::Local,
            "client-123",
        )));
    }

    #[test]
    fn conservative_rules_use_intent_and_never_treat_editing_alone_as_implementation() {
        let edited = vec![SignalCount {
            signal: WorkflowSignal::Edited,
            count: 1,
            model_step_index: Some(0),
        }];
        assert!(classify_by_rule("change this file", &edited).is_none());
        assert_eq!(
            classify_by_rule("find the root cause of this crash", &[])
                .map(|assignment| assignment.category_id),
            Some(CategoryId::Debugging)
        );
        assert_eq!(
            classify_by_rule("write tests for this behavior", &[])
                .map(|assignment| assignment.category_id),
            Some(CategoryId::Testing)
        );
    }

    #[test]
    fn cache_key_changes_with_taxonomy_context_signals_and_previous_category() {
        let base = classification_cache_key(b"secret", "config-a", "investigate", &[], None);
        let signaled = classification_cache_key(
            b"secret",
            "config-a",
            "investigate",
            &[SignalCount {
                signal: WorkflowSignal::Searched,
                count: 1,
                model_step_index: Some(0),
            }],
            None,
        );
        let previous = classification_cache_key(
            b"secret",
            "config-a",
            "investigate",
            &[],
            Some(&CategoryAssignment {
                category_id: CategoryId::Research,
                ..CategoryAssignment::default()
            }),
        );
        assert_ne!(base, signaled);
        assert_ne!(base, previous);
        assert_ne!(
            base,
            classification_cache_key(b"secret", "config-b", "investigate", &[], None)
        );
        assert!(!base.contains("investigate"));
    }

    #[test]
    fn turn_activity_compacts_only_consecutive_models_and_preserves_a_b_a() {
        let message = |activity_sequence: u32, model: &str, tokens: u64| UsageMessage {
            source_message_id: format!("m-{activity_sequence}"),
            session_id: "s".into(),
            project_path: None,
            client_id: "codex".into(),
            client_version: None,
            provider_id: "openai".into(),
            model_id: model.into(),
            session_started_at: None,
            observed_at: Utc::now(),
            tokens: metrune_core::TokenBreakdown {
                input: tokens,
                ..Default::default()
            },
            cost: metrune_core::Cost::default(),
            turn_sequence: 1,
            activity_sequence,
            workflow_signals: vec![],
            signal_capabilities: WorkflowSignal::ALL.to_vec(),
            classification_text: Some("investigate".into()),
        };
        let messages = [
            message(1, "model-a", 10),
            message(2, "model-a", 20),
            message(3, "model-b", 30),
            message(4, "model-a", 40),
        ];
        let references = messages.iter().collect::<Vec<_>>();
        let turn = turn_from_messages(1, &references);
        assert_eq!(turn.model_activity.len(), 3);
        assert_eq!(turn.model_activity[0].call_count, 2);
        assert_eq!(turn.model_activity[0].tokens.total(), 30);
        assert_eq!(turn.model_activity[1].model_id, "model-b");
        assert_eq!(turn.model_activity[2].model_id, "model-a");
    }
}
