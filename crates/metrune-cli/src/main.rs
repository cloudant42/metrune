mod credentials;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand, ValueEnum};
use credentials::{set_private_permissions, CredentialStore};
use dialoguer::{theme::ColorfulTheme, Select};
use flate2::{write::GzEncoder, Compression};
use metrune_core::{
    adapters::built_in_adapters,
    aggregate_session,
    classifier::{ClassifierBackend, OpenAiCompatibleClassifier, ResponseMode, UnknownClassifier},
    pricing::{PriceAuthority, PriceBook, PriceCatalog},
    state::{file_fingerprint, LocalState},
    CategoryAssignment, IdentityContext, ProjectLabelMode, UsageMessage,
};
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Write};
use std::{
    collections::{BTreeMap, HashMap},
    env,
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
        #[arg(long)]
        token: String,
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
    installation_token: String,
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
const ADAPTER_PARSER_VERSION: &str = "6";
const CLASSIFIER_REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);

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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierProvisionResponse {
    enabled: bool,
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

struct ResolvedClassifier {
    endpoint: String,
    model: String,
    api_key: Option<String>,
    config_version: String,
    response_mode: ResponseMode,
}

#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        state_db,
        config,
        command,
    } = Cli::parse();
    let config_path = config.unwrap_or_else(default_config_path);
    if matches!(
        &command,
        Command::Pricing { .. } | Command::Classifier { .. }
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
            enroll(&config_path, &server, &token, &name, &platform, &user_alias).await?;
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

    let mut last_classifier_refresh: Option<Instant> = None;
    loop {
        let refresh_classifier = last_classifier_refresh
            .is_none_or(|last| last.elapsed() >= CLASSIFIER_REFRESH_INTERVAL);
        let cycle = async {
            if let Ok(current) = load_config(config_path) {
                let organization_managed = current.classifier.as_ref().is_some_and(|profile| {
                    profile.provider_id != "local" && profile.provider_id != "custom"
                });
                if refresh_classifier && organization_managed {
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
            if let Err(error) = upload(state, &config, 500).await {
                eprintln!("upload failed; snapshots remain queued: {error:#}");
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
    let mut request = reqwest::Client::new()
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
            let credential_stored = CredentialStore::default()
                .get(&profile.credential_id)?
                .is_some();
            println!(
                "Classifier: {}",
                if profile.enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            println!("Provider: {}", profile.provider_id);
            println!("Endpoint: {}", profile.endpoint);
            println!("Model: {}", profile.model);
            println!("Configuration: {}", profile.config_version);
            println!(
                "Credential: {}",
                if credential_stored {
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
                CredentialStore::default().delete(&profile.credential_id)?;
                save_config(config_path, &config)?;
                println!("Removed local classifier profile and credential.");
            } else {
                println!("No local classifier profile is provisioned.");
            }
            Ok(())
        }
    }
}

async fn provision_classifier(config_path: &Path, quiet: bool) -> Result<()> {
    let response = fetch_server_classifier(config_path).await?;
    if !response.enabled {
        let mut config = load_config(config_path)?;
        config.classifier = None;
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
    reqwest::Client::new()
        .post(format!(
            "{}/v1/installation/classifier/provision",
            config.server_url.trim_end_matches('/')
        ))
        .bearer_auth(&config.installation_token)
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
    if response.credential_id.trim().is_empty() {
        bail!("server returned an empty classifier credential id");
    }
    let credential_store = CredentialStore::default();
    let storage = if let Some(credential) = response
        .credential
        .as_deref()
        .filter(|credential| !credential.trim().is_empty())
    {
        Some(credential_store.set(&response.credential_id, credential)?)
    } else if credential_store.get(&response.credential_id)?.is_some() {
        Some("already stored locally")
    } else {
        None
    };
    if storage.is_none()
        && response
            .endpoint
            .to_ascii_lowercase()
            .contains("openrouter.ai")
    {
        bail!(
            "server did not provide a credential for OpenRouter; configure METRUNE_CLASSIFIER_API_KEY on the server"
        );
    }

    config.classifier = Some(ClassifierProfile {
        enabled: true,
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
        println!(
            "Classifier provisioned ({}); credential {}.",
            response.config_version,
            storage.unwrap_or("not required")
        );
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
            config.classifier = None;
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
        println!("  Provider: {}", server_profile.provider_id);
        println!("  Model:    {}", server_profile.model);
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
    let api_key = env::var("METRUNE_CLASSIFIER_API_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if let Some(api_key) = api_key {
        let storage = CredentialStore::default().set(&credential_id, &api_key)?;
        println!("Classifier credential stored in {storage}.");
    }

    let mut config = load_config(config_path)?;
    config.classifier = Some(ClassifierProfile {
        enabled: true,
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
    std::fs::write(path, serde_json::to_vec_pretty(config)?)?;
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
            (None, Some(profile)) => CredentialStore::default().get(&profile.credential_id)?,
            (None, None) => None,
        };
        return Ok(Some(ResolvedClassifier {
            endpoint,
            model,
            api_key,
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
    Ok(Some(ResolvedClassifier {
        endpoint: profile.endpoint.clone(),
        model: profile.model.clone(),
        api_key: CredentialStore::default().get(&profile.credential_id)?,
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
    let mut sessions: HashMap<(String, String), Vec<UsageMessage>> = HashMap::new();

    for adapter in built_in_adapters() {
        if !requested_clients.is_empty() && !requested_clients.iter().any(|id| id == adapter.id()) {
            continue;
        }
        for source in adapter.discover(&home, &[])? {
            let fingerprint = format!(
                "{}:{}:{}:{}",
                ADAPTER_PARSER_VERSION,
                adapter.id(),
                classifier_fingerprint,
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
    for messages in sessions.into_values() {
        let classification_text = messages
            .iter()
            .filter_map(|message| message.classification_text.as_deref())
            .take(12)
            .collect::<Vec<_>>()
            .join("\n\n");
        let category = if no_classify {
            CategoryAssignment::not_configured()
        } else if classification_text.is_empty() {
            CategoryAssignment::no_input()
        } else {
            classifier
                .classify(&classification_text)
                .await
                .unwrap_or_else(|error| {
                    eprintln!(
                        "local classification failed; keeping semantic status failed: {error:#}"
                    );
                    CategoryAssignment::failed(classifier.id())
                })
        };
        let observed_revision = messages
            .iter()
            .map(|message| message.observed_at.timestamp_millis().max(0) as u64)
            .max()
            .unwrap_or(1);
        let revision = observed_revision
            .saturating_mul(1_000)
            .saturating_add(ADAPTER_PARSER_VERSION.parse::<u64>().unwrap_or(1) * 10)
            .saturating_add(revision_tag);
        if let Some(snapshot) = aggregate_session(&messages, &identity, revision, category) {
            state.queue_snapshot(&snapshot)?;
            queued += 1;
        }
    }
    Ok(queued)
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
    let (endpoint, model, api_key, config_version) = settings
        .map(|settings| {
            (
                settings.endpoint.as_str(),
                settings.model.as_str(),
                settings.api_key.as_deref().unwrap_or_default(),
                settings.config_version.as_str(),
            )
        })
        .unwrap_or_default();
    for value in [
        disabled.to_string(),
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

async fn upload(state: &LocalState, config: &ClientConfig, limit: usize) -> Result<usize> {
    let batch = state.pending_batch(limit)?;
    if batch.snapshots.is_empty() {
        return Ok(0);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&serde_json::to_vec(&batch)?)?;
    let body = encoder.finish()?;
    let response = reqwest::Client::new()
        .post(format!(
            "{}/v1/ingest/sessions",
            config.server_url.trim_end_matches('/')
        ))
        .bearer_auth(&config.installation_token)
        .header("Idempotency-Key", &batch.batch_id)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::CONTENT_ENCODING, "gzip")
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    let ack: metrune_core::IngestAck = response.json().await?;
    if ack.rejected > 0 {
        bail!(
            "server rejected {} snapshots: {}",
            ack.rejected,
            ack.errors.join("; ")
        );
    }
    state.acknowledge(&batch.snapshots)?;
    Ok(ack.accepted + ack.duplicates)
}

async fn enroll(
    config_path: &Path,
    server: &str,
    token: &str,
    name: &str,
    platform: &str,
    user_alias: &str,
) -> Result<()> {
    let response: EnrollResponse = reqwest::Client::new()
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
        .await?;
    let config = ClientConfig {
        server_url: server.trim_end_matches('/').into(),
        installation_id: response.installation_id,
        installation_token: response.installation_token,
        pseudonym_key: response.pseudonym_key,
        user_alias: user_alias.into(),
        team_key: response.team_key,
        project_aliases: BTreeMap::new(),
        classifier: None,
    };
    save_config(config_path, &config)?;
    Ok(())
}

fn load_config(path: &Path) -> Result<ClientConfig> {
    serde_json::from_slice(
        &std::fs::read(path)
            .with_context(|| format!("read {}; run `metrune enroll` first", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))
}

fn default_state_path() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf())
        .join(".local/share/metrune/state.db")
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
}
