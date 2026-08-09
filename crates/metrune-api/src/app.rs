#[cfg(test)]
use crate::limits::{RateLimit, MAX_LOGIN_FAILURES_PER_WINDOW};
use crate::{
    device_auth,
    distribution::{self, ClientDistribution},
    error::{bearer, token_hash, ApiError},
    identity,
    limits::{client_address, LoginAttemptLimiter, RateLimiter, RateLimits},
    mailer, oidc,
};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{
        rand_core::{OsRng, RngCore},
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::CACHE_CONTROL, HeaderMap, HeaderValue, Request, StatusCode},
    response::IntoResponse,
    routing::{delete, get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use clickhouse::Row;
use hkdf::Hkdf;
use metrune_core::{
    canonical_model_id,
    classifier::{
        BatchClassification, ClassifierBackend, OpenAiCompatibleClassifier, ResponseMode,
    },
    pricing::{ModelPrice, PriceCatalog},
    release::{
        is_valid_version, version_is_older, versions_share_major, ServerInfo, CLIENT_VERSION_HEADER,
    },
    BatchEnvelope, CostKind, IngestAck, SessionSnapshot, LEGACY_SCHEMA_VERSION, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{PgPool, Postgres, Transaction};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::Path as StdPath,
    sync::OnceLock,
    time::Duration as StdDuration,
};
use tower_http::{
    decompression::RequestDecompressionLayer,
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) postgres: PgPool,
    clickhouse: clickhouse::Client,
    classifier: Option<ServerClassifierConfig>,
    vault: SecretVault,
    login_limiter: LoginAttemptLimiter,
    pub(crate) rate_limiter: RateLimiter,
    pub(crate) rate_limits: RateLimits,
    pub(crate) trust_proxy_headers: bool,
    pub(crate) mailer: Option<mailer::Mailer>,
    pub(crate) distribution: ClientDistribution,
    pub(crate) public_web_url: String,
    pub(crate) oidc: Option<oidc::OidcRuntime>,
    minimum_client_version: Option<String>,
}

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_BATCH_SNAPSHOTS: usize = 1_000;
const MAX_CLASSIFICATION_TEXT_BYTES: usize = 64 * 1024;
const MAX_SESSION_PAGE_OFFSET: u32 = 100_000;
const MAX_SNAPSHOT_TEXT_BYTES: usize = 512;
const MAX_USAGE_SLICES: usize = 256;
const MAX_TURNS: usize = 4_096;
const MAX_MODEL_ACTIVITY_STEPS: usize = 128;
const MAX_WORKFLOW_SIGNALS: usize = 32;
const MAX_CLASSIFICATION_METHODS: usize = 16;
const MAX_SNAPSHOT_TOKENS: u64 = 1_000_000_000_000;
const MAX_SNAPSHOT_COST: f64 = 1_000_000_000.0;
/// HKDF context separating credential keys from any other future use of the
/// master key. Changing it invalidates every stored credential.
const CREDENTIAL_KEY_INFO: &[u8] = b"metrune/provider-credential/v1";
/// Sealed under the deployment master key directly (pre-derivation rows).
const KEY_DERIVATION_MASTER: i16 = 0;
/// Sealed under a per-organization key derived from the master key.
const KEY_DERIVATION_ORGANIZATION: i16 = 1;
const DEFAULT_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(60);
const LONG_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(300);
const DEVELOPMENT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";
const DEVELOPMENT_DASHBOARD_TOKEN_HASH: &str =
    "78e35941c163d606f0a3f1820de4eae3a43381b5603df86772bdd11168d2e434";
const DEVELOPMENT_ENROLLMENT_TOKEN_HASH: &str =
    "18daf9c40bec25b9eadfaad2a5b487d38c61716c60000ff4f61e981ba1462c26";
const DEVELOPMENT_BOOTSTRAP_EMAIL: &str = "admin@test.com";

#[derive(Clone)]
struct SecretVault {
    key: [u8; 32],
    created: bool,
}

fn ensure_private_secret_file(path: &StdPath) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            anyhow::bail!(
                "secret vault key file {} must not be readable or writable by other users (mode {:o})",
                path.display(),
                mode & 0o777
            );
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

impl SecretVault {
    fn load_or_create() -> anyhow::Result<Self> {
        let path = env::var("METRUNE_SECRETS_KEY_FILE")
            .unwrap_or_else(|_| "/var/lib/metrune/secrets/master.key".into());
        let path = StdPath::new(&path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (encoded, created) = match fs::read_to_string(path) {
            Ok(value) => {
                ensure_private_secret_file(path)?;
                (value, false)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0_u8; 32];
                OsRng.fill_bytes(&mut key);
                let encoded = URL_SAFE_NO_PAD.encode(key);
                // The mode is set at creation: writing the key first and
                // chmod-ing afterwards exposes the master key to every local
                // account for the width of that window.
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let mut file = options.open(path)?;
                file.write_all(encoded.as_bytes())?;
                file.sync_all()?;
                (encoded, true)
            }
            Err(error) => return Err(error.into()),
        };
        let decoded = URL_SAFE_NO_PAD.decode(encoded.trim())?;
        let key: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("vault key must contain exactly 32 bytes"))?;
        Ok(Self { key, created })
    }

    /// Credential key for one organization, derived from the deployment master
    /// key. Exporting or compromising one organization's key tells an attacker
    /// nothing about any other organization's credentials, and the master key
    /// cannot be recovered from a derived one.
    fn organization_key(&self, organization_id: Uuid) -> [u8; 32] {
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(organization_id.as_bytes()), &self.key)
            .expand(CREDENTIAL_KEY_INFO, &mut key)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        key
    }

    /// Rows written before per-organization derivation are sealed under the
    /// master key and carry [`KEY_DERIVATION_MASTER`] until they are re-wrapped.
    fn key_for(&self, organization_id: Uuid, derivation: i16) -> [u8; 32] {
        match derivation {
            KEY_DERIVATION_MASTER => self.key,
            _ => self.organization_key(organization_id),
        }
    }

    fn encrypt(
        &self,
        organization_id: Uuid,
        plaintext: &str,
        aad: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        Self::seal(&self.organization_key(organization_id), plaintext, aad)
    }

    fn decrypt(
        &self,
        organization_id: Uuid,
        derivation: i16,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<String> {
        Self::open(
            &self.key_for(organization_id, derivation),
            ciphertext,
            nonce,
            aad,
        )
    }

    fn seal(key: &[u8; 32], plaintext: &str, aad: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("credential encryption failed"))?;
        Ok((ciphertext, nonce.to_vec()))
    }

    fn open(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<String> {
        if nonce.len() != 12 {
            anyhow::bail!("invalid credential nonce");
        }
        let cipher = Aes256Gcm::new_from_slice(key)?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("credential decryption failed"))?;
        Ok(String::from_utf8(plaintext)?)
    }

    /// The exportable key for one organization. It unlocks that organization's
    /// credentials and nothing else, so an admin holding it cannot reach a
    /// co-tenant's secrets.
    fn recovery_key(&self, organization_id: Uuid) -> String {
        format!(
            "mvrk_{}",
            URL_SAFE_NO_PAD.encode(self.organization_key(organization_id))
        )
    }
}

#[derive(Clone)]
struct ServerClassifierConfig {
    execution_mode: ClassifierExecutionMode,
    provider_id: String,
    endpoint: String,
    model: String,
    credential_id: String,
    api_key: Option<String>,
    config_version: String,
    response_mode: ResponseMode,
}

impl ServerClassifierConfig {
    fn from_env() -> Option<Self> {
        let endpoint = env::var("METRUNE_CLASSIFIER_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let model = env::var("METRUNE_CLASSIFIER_MODEL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        Some(Self {
            execution_mode: env::var("METRUNE_CLASSIFIER_EXECUTION_MODE")
                .ok()
                .as_deref()
                .map(parse_classifier_execution_mode)
                .unwrap_or_default(),
            provider_id: env::var("METRUNE_CLASSIFIER_PROVIDER_ID")
                .unwrap_or_else(|_| "openai-compatible".into()),
            endpoint,
            model,
            credential_id: env::var("METRUNE_CLASSIFIER_CREDENTIAL_ID")
                .unwrap_or_else(|_| "classifier-default".into()),
            api_key: env::var("METRUNE_CLASSIFIER_API_KEY")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            config_version: env::var("METRUNE_CLASSIFIER_CONFIG_VERSION")
                .unwrap_or_else(|_| "dev-1".into()),
            response_mode: env::var("METRUNE_CLASSIFIER_RESPONSE_MODE")
                .ok()
                .and_then(|value| serde_json::from_value(serde_json::Value::String(value)).ok())
                .unwrap_or_default(),
        })
    }
}

impl AppState {
    /// Seals a secret the way the vault did before per-organization key
    /// derivation, so tests can plant a genuine pre-migration row.
    #[cfg(test)]
    pub(crate) fn seal_under_master_key(
        &self,
        plaintext: &str,
        aad: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        SecretVault::seal(&self.vault.key, plaintext, aad)
    }

    #[cfg(test)]
    pub(crate) fn credential_aad(
        organization_id: Uuid,
        credential_id: &str,
        version: i32,
    ) -> String {
        credential_aad(organization_id, credential_id, version)
    }

    #[cfg(test)]
    pub(crate) fn decrypt_for_tests(
        &self,
        organization_id: Uuid,
        derivation: i16,
        ciphertext: &[u8],
        nonce: &[u8],
        aad: &[u8],
    ) -> anyhow::Result<String> {
        self.vault
            .decrypt(organization_id, derivation, ciphertext, nonce, aad)
    }

    #[cfg(test)]
    pub(crate) fn clickhouse_for_tests(&self) -> &clickhouse::Client {
        &self.clickhouse
    }

    /// Builds a state around a live Postgres pool for integration tests.
    ///
    /// With no ClickHouse URL the client points at an unroutable address on
    /// purpose: routes that must never reach the analytics store fail loudly
    /// instead of passing for the wrong reason.
    #[cfg(test)]
    pub(crate) fn for_tests(postgres: PgPool, clickhouse: Option<clickhouse::Client>) -> Self {
        Self {
            postgres,
            clickhouse: clickhouse
                .unwrap_or_else(|| clickhouse::Client::default().with_url("http://127.0.0.1:1")),
            classifier: None,
            vault: SecretVault {
                key: [3_u8; 32],
                created: false,
            },
            login_limiter: LoginAttemptLimiter::default(),
            rate_limiter: RateLimiter::default(),
            rate_limits: RateLimits::from_env(),
            trust_proxy_headers: false,
            mailer: None,
            distribution: ClientDistribution::from_env(),
            public_web_url: "https://metrune.example".into(),
            oidc: None,
            minimum_client_version: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_minimum_client_version(&mut self, version: Option<&str>) {
        self.minimum_client_version = version.map(str::to_string);
    }
}

pub async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "metrune_api=info,tower_http=info".into()),
        )
        .json()
        .init();

    let environment = env::var("METRUNE_ENV").unwrap_or_else(|_| "development".into());
    let bootstrap_email = env::var("METRUNE_BOOTSTRAP_EMAIL").ok();
    let bootstrap_password = env::var("METRUNE_BOOTSTRAP_PASSWORD").ok();
    let database_url = env::var("DATABASE_URL")?;
    let clickhouse_password = env::var("CLICKHOUSE_PASSWORD").unwrap_or_default();
    let public_api_url = env::var("METRUNE_PUBLIC_API_URL").ok();
    let public_web_url =
        env::var("METRUNE_PUBLIC_WEB_URL").unwrap_or_else(|_| "http://localhost:3001".into());
    let minimum_client_version = configured_minimum_client_version()?;
    validate_production_configuration(
        &environment,
        public_api_url.as_deref(),
        Some(&public_web_url),
        &database_url,
        &clickhouse_password,
        bootstrap_email.as_deref(),
        bootstrap_password.as_deref(),
    )?;
    let oidc =
        oidc::OidcRuntime::from_env(&environment, public_api_url.as_deref(), &public_web_url)
            .await?;
    let postgres = PgPool::connect(&database_url).await?;
    sqlx::migrate!("../../migrations/postgres")
        .run(&postgres)
        .await?;
    if environment == "production" {
        ensure_production_database_is_clean(&postgres).await?;
    } else {
        ensure_development_seed_data(&postgres).await?;
    }
    let clickhouse = clickhouse::Client::default()
        .with_url(env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://clickhouse:8123".into()))
        .with_database(env::var("CLICKHOUSE_DATABASE").unwrap_or_else(|_| "metrune".into()))
        .with_user(env::var("CLICKHOUSE_USER").unwrap_or_else(|_| "default".into()))
        .with_password(clickhouse_password);
    let state = AppState {
        postgres,
        clickhouse,
        classifier: ServerClassifierConfig::from_env(),
        vault: SecretVault::load_or_create()?,
        login_limiter: LoginAttemptLimiter::default(),
        rate_limiter: RateLimiter::default(),
        rate_limits: RateLimits::from_env(),
        trust_proxy_headers: env::var("METRUNE_TRUST_PROXY_HEADERS")
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case("true")),
        mailer: mailer::Mailer::from_env(&environment)?,
        distribution: ClientDistribution::from_env(),
        public_web_url,
        oidc,
        minimum_client_version,
    };
    let credentials_exist: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM provider_credentials)")
            .fetch_one(&state.postgres)
            .await?;
    if state.vault.created && credentials_exist {
        anyhow::bail!(
            "the vault master key is missing but encrypted credentials already exist; restore the key before starting Metrune"
        );
    }
    state
        .clickhouse
        .query(
            "ALTER TABLE session_snapshots ADD COLUMN IF NOT EXISTS owner_user_id String DEFAULT ''",
        )
        .execute()
        .await?;
    state
        .clickhouse
        .query(
            "ALTER TABLE session_snapshots ADD COLUMN IF NOT EXISTS retention_days UInt32 DEFAULT 365",
        )
        .execute()
        .await?;
    ensure_deduplicated_session_table(&state.clickhouse).await?;
    bootstrap_local_user(&state).await?;
    reconcile_authentication_mode(&state.postgres, state.oidc.is_some()).await?;
    import_default_price_catalog(&state).await?;
    reprice_unknown_history(&state).await?;
    rewrap_legacy_credentials(&state).await?;

    let app = router(state.clone());

    tokio::spawn(expired_session_reaper(state.postgres.clone()));

    let address: SocketAddr = env::var("METRUNE_API_ADDRESS")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    tracing::info!(%address, "Metrune API listening");
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Builds the HTTP surface. Kept separate from [`run`] so tests can exercise
/// routing, authentication and authorization against a state they construct,
/// without binding a socket or running the boot-time migrations.
pub(crate) fn router(state: AppState) -> Router {
    let long_running_routes = Router::new()
        .route("/v1/ingest/sessions", post(ingest_sessions))
        .route("/v1/analytics/overview", get(analytics_overview))
        .route("/v1/analytics/timeseries", get(analytics_timeseries))
        .route("/v1/analytics/breakdowns", get(analytics_breakdowns))
        .route(
            "/v1/analytics/category-model",
            get(analytics_category_model),
        )
        .route(
            "/v1/analytics/workflow-model",
            get(analytics_workflow_model),
        )
        .route(
            "/v1/analytics/classification-overhead",
            get(analytics_classification_overhead),
        )
        .route("/v1/analytics/sessions", get(analytics_sessions))
        .route(
            "/v1/analytics/sessions/{session_key}",
            get(analytics_session_detail),
        )
        .route("/v1/analytics/facets", get(analytics_facets))
        .route("/v1/me/usage", get(my_usage))
        .route("/v1/me/sessions", get(my_sessions))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            LONG_REQUEST_TIMEOUT,
        ));

    Router::new()
        .route("/v1/healthz", get(health))
        .route("/v1/server/info", get(server_info))
        .route("/v1/readyz", get(ready))
        .route(
            "/v1/downloads/{artifact}",
            get(distribution::download_client),
        )
        .route("/v1/client/manifest", get(distribution::client_manifest))
        .route("/v1/client/install.sh", get(distribution::install_script))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/methods", get(oidc::auth_methods))
        .route("/v1/auth/sso/start", get(oidc::start))
        .route("/v1/auth/sso/callback", get(oidc::callback))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(current_user))
        .route("/v1/auth/organization", post(switch_organization))
        .route(
            "/v1/auth/invitations/inspect",
            post(identity::inspect_invitation),
        )
        .route(
            "/v1/auth/invitations/accept",
            post(identity::accept_invitation),
        )
        .route(
            "/v1/auth/password-reset/request",
            post(identity::request_password_reset),
        )
        .route(
            "/v1/auth/password-reset/complete",
            post(identity::complete_password_reset),
        )
        .route("/v1/organizations", post(create_organization))
        .route("/v1/enroll", post(enroll))
        .route(
            "/v1/oauth/device/authorization",
            post(device_auth::authorize_device),
        )
        .route(
            "/v1/oauth/device/verification",
            post(device_auth::inspect_device),
        )
        .route(
            "/v1/oauth/device/approval",
            post(device_auth::approve_device),
        )
        .route("/v1/oauth/token", post(device_auth::exchange_device_code))
        .route(
            "/v1/installation/classifier/provision",
            post(provision_classifier),
        )
        .route(
            "/v1/installation/classifier/classify",
            post(managed_classify),
        )
        .route(
            "/v1/installation/classifier/classify-batch",
            post(managed_classify_batch),
        )
        .route("/v1/org/members", get(list_members).post(add_member))
        .route(
            "/v1/org/members/{user_id}",
            patch(update_member).delete(remove_member),
        )
        .route(
            "/v1/org/members/{user_id}/password-reset",
            post(identity::reset_member_password),
        )
        .route(
            "/v1/org/invitations",
            get(identity::list_invitations).post(identity::create_invitation),
        )
        .route(
            "/v1/org/invitations/{id}/resend",
            post(identity::resend_invitation),
        )
        .route(
            "/v1/org/invitations/{id}",
            delete(identity::revoke_invitation),
        )
        .route("/v1/org/teams", get(list_teams).post(create_team))
        .route("/v1/org/teams/{id}", patch(update_team).delete(delete_team))
        .route("/v1/org/installations", get(list_installations))
        .route("/v1/org/installations/{id}", patch(update_installation))
        .route("/v1/org/settings", get(get_settings).patch(update_settings))
        .route(
            "/v1/org/classifier",
            get(get_classifier_settings).patch(update_classifier_settings),
        )
        .route("/v1/org/classifier/test", post(test_classifier_settings))
        .route(
            "/v1/org/credentials",
            get(list_credentials).post(upsert_credential),
        )
        .route(
            "/v1/org/credentials/{credential_id}",
            delete(revoke_credential),
        )
        .route("/v1/org/vault/recovery", post(export_recovery_key))
        .route("/v1/org/prices", get(list_prices).post(create_price))
        .route(
            "/v1/org/prices/{id}",
            patch(update_price).delete(delete_price),
        )
        .route("/v1/me/installations", get(my_installations))
        .route("/v1/me/installations/{id}", delete(revoke_my_installation))
        .route("/v1/me/enrollment-codes", post(create_enrollment_code))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            DEFAULT_REQUEST_TIMEOUT,
        ))
        .merge(long_running_routes)
        .layer(RequestBodyLimitLayer::new(MAX_REQUEST_BODY_BYTES))
        .layer(RequestDecompressionLayer::new())
        .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<_>| {
                let request_id = request
                    .extensions()
                    .get::<RequestId>()
                    .and_then(|request_id| request_id.header_value().to_str().ok())
                    .unwrap_or("missing");
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    request_id = %request_id,
                )
            }),
        )
        .layer(PropagateRequestIdLayer::x_request_id())
        .with_state(state)
}

pub(crate) async fn ensure_deduplicated_session_table(
    clickhouse: &clickhouse::Client,
) -> anyhow::Result<()> {
    clickhouse
        .query(
            "CREATE TABLE IF NOT EXISTS session_snapshots_dedup (
                organization_id String,
                installation_id String,
                owner_user_id String,
                session_key String,
                revision UInt64,
                user_key String,
                project_key String,
                project_alias String,
                team_key String,
                client_id LowCardinality(String),
                started_at_ms Int64,
                ended_at_ms Int64,
                category_id LowCardinality(String),
                category_confidence Float32,
                taxonomy_version LowCardinality(String),
                classifier_id String,
                classification_status LowCardinality(String) DEFAULT 'unavailable',
                total_tokens UInt64,
                total_cost Float64,
                snapshot_json String,
                ingested_at_ms Int64,
                retention_days UInt32 DEFAULT 365
            )
            ENGINE = ReplacingMergeTree(revision)
            PARTITION BY toYYYYMM(toDateTime(ended_at_ms / 1000))
            ORDER BY (organization_id, owner_user_id, session_key)
            TTL toDateTime(ended_at_ms / 1000) + INTERVAL retention_days DAY",
        )
        .execute()
        .await?;
    // The API also upgrades databases created before semantic status was
    // introduced. Existing rows remain conservatively `unavailable` because
    // their old payloads cannot distinguish a valid unknown result from a
    // classifier failure.
    clickhouse
        .query(
            "ALTER TABLE session_snapshots_dedup
             ADD COLUMN IF NOT EXISTS classification_status LowCardinality(String) DEFAULT 'unavailable'",
        )
        .execute()
        .await?;
    // Do not copy legacy rows automatically. Their session keys were derived
    // from enrollment-specific HMAC keys, so the server cannot prove which
    // rows are the same source session. Copying them would preserve existing
    // duplicates and then double-count sessions when clients rescan with the
    // new deterministic key. The legacy table remains intact for a reviewed,
    // operator-led historical reconciliation.
    Ok(())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok","service":"metrune-api","schemaVersion":SCHEMA_VERSION}))
}

async fn server_info(State(state): State<AppState>) -> impl IntoResponse {
    (
        [(CACHE_CONTROL, HeaderValue::from_static("no-store"))],
        Json(ServerInfo {
            server_version: env!("CARGO_PKG_VERSION").into(),
            supported_schema_versions: vec![LEGACY_SCHEMA_VERSION.into(), SCHEMA_VERSION.into()],
            minimum_client_version: state.minimum_client_version,
        }),
    )
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

fn configured_minimum_client_version() -> anyhow::Result<Option<String>> {
    let Some(version) = env::var("METRUNE_MINIMUM_CLIENT_VERSION")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    if !is_valid_version(&version) {
        anyhow::bail!(
            "METRUNE_MINIMUM_CLIENT_VERSION must be a complete semantic version such as 0.2.0"
        );
    }
    if !versions_share_major(&version, env!("CARGO_PKG_VERSION")) {
        anyhow::bail!(
            "METRUNE_MINIMUM_CLIENT_VERSION must stay on the server's major compatibility line"
        );
    }
    Ok(Some(version))
}

fn validate_production_configuration(
    environment: &str,
    public_api_url: Option<&str>,
    public_web_url: Option<&str>,
    database_url: &str,
    clickhouse_password: &str,
    bootstrap_email: Option<&str>,
    bootstrap_password: Option<&str>,
) -> anyhow::Result<()> {
    if environment != "production" {
        return Ok(());
    }
    let public_api_url = public_api_url
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("METRUNE_PUBLIC_API_URL is required in production"))?;
    if !valid_public_https_url(public_api_url) {
        anyhow::bail!("METRUNE_PUBLIC_API_URL must use HTTPS in production");
    }
    let public_web_url = public_web_url
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("METRUNE_PUBLIC_WEB_URL is required in production"))?;
    if !valid_public_https_url(public_web_url) {
        anyhow::bail!("METRUNE_PUBLIC_WEB_URL must use HTTPS in production");
    }
    if database_url.contains(":metrune-dev@") || clickhouse_password == "metrune-dev" {
        anyhow::bail!("development database credentials are not allowed in production");
    }
    if bootstrap_email.is_some_and(|email| {
        email
            .trim()
            .eq_ignore_ascii_case(DEVELOPMENT_BOOTSTRAP_EMAIL)
    }) {
        anyhow::bail!("the development bootstrap email is not allowed in production");
    }
    if bootstrap_password.is_some_and(|password| {
        matches!(
            password,
            "admin" | "password" | "metrune-dev" | "change-me" | "changeme"
        )
    }) {
        anyhow::bail!("a development bootstrap password is not allowed in production");
    }
    Ok(())
}

fn valid_public_https_url(value: &str) -> bool {
    reqwest::Url::parse(value.trim()).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

async fn ensure_development_seed_data(postgres: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO organizations(id, name)
         VALUES ($1, 'Acme Engineering')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(Uuid::parse_str(DEVELOPMENT_ORGANIZATION_ID)?)
    .execute(postgres)
    .await?;

    let team_id: Uuid = sqlx::query_scalar(
        "INSERT INTO teams(organization_id, name)
         VALUES ($1, 'engineering')
         ON CONFLICT (organization_id, name) DO UPDATE SET name = EXCLUDED.name
         RETURNING id",
    )
    .bind(Uuid::parse_str(DEVELOPMENT_ORGANIZATION_ID)?)
    .fetch_one(postgres)
    .await?;

    sqlx::query(
        "INSERT INTO dashboard_tokens(id, organization_id, token_hash, name, role)
         VALUES ('00000000-0000-0000-0000-000000000003', $1, $2, 'Local dashboard', 'admin')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(Uuid::parse_str(DEVELOPMENT_ORGANIZATION_ID)?)
    .bind(DEVELOPMENT_DASHBOARD_TOKEN_HASH)
    .execute(postgres)
    .await?;

    sqlx::query(
        "INSERT INTO enrollment_tokens(id, organization_id, token_hash, name, team_key, team_id)
         VALUES ('00000000-0000-0000-0000-000000000002', $1, $2, 'Local development', 'engineering', $3)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(Uuid::parse_str(DEVELOPMENT_ORGANIZATION_ID)?)
    .bind(DEVELOPMENT_ENROLLMENT_TOKEN_HASH)
    .bind(team_id)
    .execute(postgres)
    .await?;
    Ok(())
}

async fn ensure_production_database_is_clean(postgres: &PgPool) -> anyhow::Result<()> {
    let development_tokens: i64 = sqlx::query_scalar(
        "SELECT
             (SELECT COUNT(*) FROM dashboard_tokens WHERE token_hash = $1)
           + (SELECT COUNT(*) FROM enrollment_tokens WHERE token_hash = $2)",
    )
    .bind(DEVELOPMENT_DASHBOARD_TOKEN_HASH)
    .bind(DEVELOPMENT_ENROLLMENT_TOKEN_HASH)
    .fetch_one(postgres)
    .await?;
    if development_tokens > 0 {
        anyhow::bail!(
            "development dashboard or enrollment tokens are present in the production database"
        );
    }

    let development_users: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE LOWER(email) = $1")
            .bind(DEVELOPMENT_BOOTSTRAP_EMAIL)
            .fetch_one(postgres)
            .await?;
    if development_users > 0 {
        anyhow::bail!("the development bootstrap identity is present in the production database");
    }
    Ok(())
}

fn active_authentication_method(state: &AppState) -> &'static str {
    if state.oidc.is_some() {
        "oidc"
    } else {
        "local"
    }
}

async fn reconcile_authentication_mode(
    postgres: &PgPool,
    oidc_enabled: bool,
) -> anyhow::Result<()> {
    let active_method = if oidc_enabled { "oidc" } else { "local" };
    let mut transaction = postgres.begin().await?;
    sqlx::query(
        "UPDATE organizations
         SET sso_enforced = $1, local_login_enabled = $2
         WHERE sso_enforced IS DISTINCT FROM $1
            OR local_login_enabled IS DISTINCT FROM $2",
    )
    .bind(oidc_enabled)
    .bind(!oidc_enabled)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE web_sessions SET revoked_at = NOW()
         WHERE revoked_at IS NULL AND authentication_method <> $1",
    )
    .bind(active_method)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let postgres_ready = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.postgres)
        .await
        .is_ok();
    let clickhouse_ready = state
        .clickhouse
        .query("SELECT 1")
        .fetch_one::<u8>()
        .await
        .is_ok();
    let status = if postgres_ready && clickhouse_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(serde_json::json!({"postgres":postgres_ready,"clickhouse":clickhouse_ready})),
    )
}

async fn bootstrap_local_user(state: &AppState) -> anyhow::Result<()> {
    let email = env::var("METRUNE_BOOTSTRAP_EMAIL")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let password = env::var("METRUNE_BOOTSTRAP_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let environment = env::var("METRUNE_ENV").unwrap_or_else(|_| "development".into());
    let sso_enabled = state.oidc.is_some();
    if environment == "production" {
        let existing_users = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
            .fetch_one(&state.postgres)
            .await?;
        if existing_users > 0 && (email.is_some() || password.is_some()) {
            anyhow::bail!(
                "remove METRUNE_BOOTSTRAP_EMAIL and METRUNE_BOOTSTRAP_PASSWORD after \
                 creating the first administrator"
            );
        }
        if existing_users == 0 {
            if email.is_none() {
                anyhow::bail!(
                    "METRUNE_BOOTSTRAP_EMAIL is required to create the first production administrator"
                );
            }
            if !sso_enabled && password.is_none() {
                anyhow::bail!("METRUNE_BOOTSTRAP_PASSWORD is required when OIDC is not configured");
            }
        }
    }
    let Some(email) = email else {
        return Ok(());
    };
    if sso_enabled && password.is_some() {
        anyhow::bail!(
            "remove METRUNE_BOOTSTRAP_PASSWORD when OIDC is configured; SSO-only accounts do not use local passwords"
        );
    }
    let email = mailer::normalize_email(&email)
        .map_err(|_| anyhow::anyhow!("METRUNE_BOOTSTRAP_EMAIL must be a valid email address"))?;
    let password_hash = match password {
        Some(password) => {
            let password_chars = password.chars().count();
            if !(12..=128).contains(&password_chars) && environment == "production" {
                anyhow::bail!("METRUNE_BOOTSTRAP_PASSWORD must be between 12 and 128 characters");
            }
            Some(
                Argon2::default()
                    .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
                    .map_err(|error| anyhow::anyhow!("hash bootstrap password: {error}"))?
                    .to_string(),
            )
        }
        None => None,
    };
    let organization_id = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM organizations ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&state.postgres)
    .await?
    {
        Some(id) => id,
        None => {
            let name = env::var("METRUNE_BOOTSTRAP_ORGANIZATION")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty() && value.chars().count() <= 120)
                .unwrap_or_else(|| "Metrune Workspace".into());
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO organizations(name, sso_enforced, local_login_enabled)
                 VALUES ($1,$2,$3) RETURNING id",
            )
            .bind(name)
            .bind(sso_enabled)
            .bind(!sso_enabled)
            .fetch_one(&state.postgres)
            .await?
        }
    };
    let user_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users(organization_id, email, display_name, password_hash, role)
         VALUES ($1,$2,'Metrune Admin',$3,'admin')
         ON CONFLICT (organization_id, email)
         DO UPDATE SET email = EXCLUDED.email
         RETURNING id",
    )
    .bind(organization_id)
    .bind(email)
    .bind(password_hash)
    .fetch_one(&state.postgres)
    .await?;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id, user_id, role)
         VALUES ($1,$2,'admin')
         ON CONFLICT (organization_id, user_id) DO NOTHING",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&state.postgres)
    .await?;
    Ok(())
}

async fn import_default_price_catalog(state: &AppState) -> anyhow::Result<()> {
    let Some(path) = env::var_os("METRUNE_DEFAULT_PRICE_CATALOG") else {
        return Ok(());
    };
    let catalog = PriceCatalog::load(std::path::Path::new(&path))?;
    sqlx::query(
        "UPDATE model_prices SET effective_until = NOW(), updated_at = NOW()
         WHERE organization_id IS NULL
           AND authority IN ('openrouter', 'default_catalog')
           AND catalog_version <> $1
           AND effective_until IS NULL",
    )
    .bind(&catalog.catalog_version)
    .execute(&state.postgres)
    .await?;
    for entry in catalog.entries {
        let Some(provider_id) = entry.provider_id else {
            continue;
        };
        let model_id = canonical_model_id(&entry.model_id);
        let effective_from = entry.effective_from.unwrap_or(catalog.generated_at);
        insert_catalog_price(
            state,
            &provider_id,
            &model_id,
            &entry.currency,
            &entry.price,
            entry.authority.as_str(),
            entry.source_url.as_deref(),
            &catalog.catalog_version,
            effective_from,
            entry.effective_until,
        )
        .await?;
        if let Some((vendor, vendor_model)) = model_id.split_once('/') {
            insert_catalog_price(
                state,
                vendor,
                vendor_model,
                &entry.currency,
                &entry.price,
                "default_catalog",
                entry.source_url.as_deref(),
                &catalog.catalog_version,
                effective_from,
                entry.effective_until,
            )
            .await?;
        }
        for (alias_provider, alias_model) in default_price_aliases(&model_id) {
            insert_catalog_price(
                state,
                alias_provider,
                alias_model,
                &entry.currency,
                &entry.price,
                "default_catalog",
                entry.source_url.as_deref(),
                &catalog.catalog_version,
                effective_from,
                entry.effective_until,
            )
            .await?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn insert_catalog_price(
    state: &AppState,
    provider_id: &str,
    model_id: &str,
    currency: &str,
    price: &ModelPrice,
    authority: &str,
    source_url: Option<&str>,
    catalog_version: &str,
    effective_from: chrono::DateTime<Utc>,
    effective_until: Option<chrono::DateTime<Utc>>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO model_prices(
           organization_id, provider_id, model_id, currency,
           input_per_million, output_per_million, cache_read_per_million,
           cache_write_per_million, reasoning_per_million,
           request_per_request, image_per_image, authority, source_url,
           catalog_version, effective_from, effective_until
         ) VALUES (
           NULL,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15
         ) ON CONFLICT DO NOTHING",
    )
    .bind(provider_id.trim().to_ascii_lowercase())
    .bind(canonical_model_id(model_id))
    .bind(currency)
    .bind(price.input_per_million)
    .bind(price.output_per_million)
    .bind(price.cache_read_per_million)
    .bind(price.cache_write_per_million)
    .bind(price.reasoning_per_million)
    .bind(price.request_per_request)
    .bind(price.image_per_image)
    .bind(authority)
    .bind(source_url)
    .bind(catalog_version)
    .bind(effective_from)
    .bind(effective_until)
    .execute(&state.postgres)
    .await?;
    Ok(())
}

fn default_price_aliases(model_id: &str) -> &'static [(&'static str, &'static str)] {
    match model_id {
        "moonshotai/kimi-k3" => &[("kimi-for-coding", "k3")],
        // Codex currently reports auto-review as a routing label rather than
        // the underlying model. Use the checked-in GPT-5.5 reference rate
        // until a provider-reported cost or organization override is present.
        "openai/gpt-5-5" => &[("openai", "codex-auto-review")],
        _ => &[],
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginResponse {
    session_token: String,
    expires_at: chrono::DateTime<Utc>,
    user: CurrentUserResponse,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct OrganizationMembershipResponse {
    id: Uuid,
    name: String,
    role: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct CurrentUserResponse {
    id: Uuid,
    organization_id: Option<Uuid>,
    organization_name: Option<String>,
    email: String,
    display_name: Option<String>,
    role: Option<String>,
    organizations: Vec<OrganizationMembershipResponse>,
}

/// Charges a failed attempt against the account's budget. `login` rejects an
/// already-exhausted budget up front, so reaching here means the account still
/// had attempts left and the caller deserves the generic credential error.
fn failed_login(state: &AppState, email: &str) -> ApiError {
    state.login_limiter.record_failure(email);
    ApiError::unauthorized("invalid email or password")
}

fn dummy_login_password_hash() -> String {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| {
        // Generate one valid Argon2 hash once so unknown accounts take the
        // same password-verification path as known accounts. The random salt
        // is process-local and the value is never used as a real credential.
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(b"metrune-invalid-login", &salt)
            .expect("the dummy login password hash must be generated")
            .to_string()
    })
    .clone()
}

async fn organization_memberships(
    state: &AppState,
    user_id: Uuid,
) -> Result<Vec<OrganizationMembershipResponse>, ApiError> {
    let rows = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT o.id, o.name, m.role
         FROM organization_memberships m
         JOIN organizations o ON o.id = m.organization_id
         WHERE m.user_id = $1 AND m.disabled_at IS NULL
         ORDER BY LOWER(o.name), o.id",
    )
    .bind(user_id)
    .fetch_all(&state.postgres)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| OrganizationMembershipResponse {
            id: row.0,
            name: row.1,
            role: row.2,
        })
        .collect())
}

async fn current_user_response(
    state: &AppState,
    user_id: Uuid,
    active_organization_id: Option<Uuid>,
) -> Result<CurrentUserResponse, ApiError> {
    let identity = sqlx::query_as::<_, (String, Option<String>)>(
        "SELECT email, display_name
         FROM users
         WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::unauthorized("account is disabled or unavailable"))?;
    let organizations = organization_memberships(state, user_id).await?;
    let active = active_organization_id.and_then(|organization_id| {
        organizations
            .iter()
            .find(|organization| organization.id == organization_id)
    });
    Ok(CurrentUserResponse {
        id: user_id,
        organization_id: active.map(|organization| organization.id),
        organization_name: active.map(|organization| organization.name.clone()),
        email: identity.0,
        display_name: identity.1,
        role: active.map(|organization| organization.role.clone()),
        organizations,
    })
}

pub(crate) struct UserSessionAuth {
    session_id: Uuid,
    pub(crate) user_id: Uuid,
    pub(crate) active_organization_id: Option<Uuid>,
}

pub(crate) async fn user_session_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<UserSessionAuth, ApiError> {
    let digest = token_hash(bearer(headers)?);
    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>)>(
        "SELECT s.id, s.user_id, s.active_organization_id
         FROM web_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL
           AND s.expires_at > NOW() AND u.disabled_at IS NULL
           AND s.authentication_method = $2",
    )
    .bind(digest)
    .bind(active_authentication_method(state))
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::unauthorized("invalid or expired session"))?;
    Ok(UserSessionAuth {
        session_id: row.0,
        user_id: row.1,
        active_organization_id: row.2,
    })
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<(HeaderMap, Json<LoginResponse>), ApiError> {
    if state.oidc.is_some() {
        return Err(ApiError::forbidden(
            "password sign-in is unavailable while single sign-on is configured",
        ));
    }
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    state
        .rate_limiter
        .check("login", &address, state.rate_limits.login)?;
    let email = request.email.trim().to_ascii_lowercase();
    // Refuse the attempt before the account lookup and the Argon2 verification.
    // Checking the per-account budget only on the failure path would let a
    // guesser keep spending a password hash per request and still learn a
    // correct password while nominally "locked out".
    if state.login_limiter.is_limited(&email) {
        return Err(ApiError::too_many_requests(
            "too many login attempts; try again later",
        ));
    }
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, Option<String>)>(
        "SELECT u.id, u.email, u.display_name, u.password_hash
         FROM users u
         WHERE LOWER(u.email) = $1 AND u.disabled_at IS NULL
         ORDER BY u.created_at LIMIT 2",
    )
    .bind(&email)
    .fetch_all(&state.postgres)
    .await?;
    let password_hash = rows
        .first()
        .and_then(|row| row.3.clone())
        .unwrap_or_else(dummy_login_password_hash);
    let password = request.password.clone();
    let password_valid = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await?;
    if rows.len() != 1 || !password_valid {
        return Err(failed_login(&state, &email));
    }
    let row = &rows[0];
    state.login_limiter.reset(&email);
    let organizations = organization_memberships(&state, row.0).await?;
    if organizations.is_empty() {
        return Err(ApiError::forbidden(
            "this account does not belong to an active organization",
        ));
    }
    let active_organization_id = (organizations.len() == 1).then_some(organizations[0].id);
    let session_token = format!("mts_{}", Uuid::new_v4().simple());
    let expires_at = Utc::now() + Duration::days(30);
    sqlx::query(
        "INSERT INTO web_sessions(
             user_id, token_hash, active_organization_id, created_at, expires_at
         ) VALUES ($1,$2,$3,NOW(),$4)",
    )
    .bind(row.0)
    .bind(token_hash(&session_token))
    .bind(active_organization_id)
    .bind(expires_at)
    .execute(&state.postgres)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(row.0)
        .execute(&state.postgres)
        .await?;
    Ok((
        no_store_headers(),
        Json(LoginResponse {
            session_token,
            expires_at,
            user: CurrentUserResponse {
                id: row.0,
                organization_id: active_organization_id,
                organization_name: active_organization_id.map(|_| organizations[0].name.clone()),
                email: row.1.clone(),
                display_name: row.2.clone(),
                role: active_organization_id.map(|_| organizations[0].role.clone()),
                organizations,
            },
        }),
    ))
}

async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    let token = bearer(&headers)?;
    sqlx::query("UPDATE web_sessions SET revoked_at = NOW() WHERE token_hash = $1")
        .bind(token_hash(token))
        .execute(&state.postgres)
        .await?;
    Ok((no_store_headers(), StatusCode::NO_CONTENT))
}

async fn current_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<CurrentUserResponse>), ApiError> {
    let session = user_session_auth(&state, &headers).await?;
    Ok((
        no_store_headers(),
        Json(current_user_response(&state, session.user_id, session.active_organization_id).await?),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SwitchOrganizationRequest {
    organization_id: Uuid,
}

async fn switch_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SwitchOrganizationRequest>,
) -> Result<(HeaderMap, Json<CurrentUserResponse>), ApiError> {
    let session = user_session_auth(&state, &headers).await?;
    let updated = sqlx::query(
        "UPDATE web_sessions
         SET active_organization_id = $2
         WHERE id = $1 AND EXISTS (
           SELECT 1 FROM organization_memberships
           WHERE user_id = $3 AND organization_id = $2
             AND disabled_at IS NULL
         )",
    )
    .bind(session.session_id)
    .bind(request.organization_id)
    .bind(session.user_id)
    .execute(&state.postgres)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::forbidden(
            "you are not an active member of that organization",
        ));
    }
    Ok((
        no_store_headers(),
        Json(current_user_response(&state, session.user_id, Some(request.organization_id)).await?),
    ))
}

#[derive(Deserialize)]
struct CreateOrganizationRequest {
    name: String,
}

async fn create_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateOrganizationRequest>,
) -> Result<(StatusCode, Json<CurrentUserResponse>), ApiError> {
    let session = user_session_auth(&state, &headers).await?;
    state.rate_limiter.check(
        "organization-create",
        &format!("user:{}", session.user_id),
        state.rate_limits.organization_create,
    )?;
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::bad_request(
            "organization name must be between 1 and 120 characters",
        ));
    }
    let mut transaction = state.postgres.begin().await?;
    let organization_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO organizations(name, sso_enforced, local_login_enabled)
             VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(name)
    .bind(state.oidc.is_some())
    .bind(state.oidc.is_none())
    .fetch_one(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id, user_id, role)
         VALUES ($1,$2,'admin')",
    )
    .bind(organization_id)
    .bind(session.user_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE web_sessions SET active_organization_id = $2 WHERE id = $1")
        .bind(session.session_id)
        .bind(organization_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(current_user_response(&state, session.user_id, Some(organization_id)).await?),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollRequest {
    enrollment_token: String,
    installation_name: String,
    #[serde(default)]
    platform: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnrollResponse {
    pub(crate) installation_id: Uuid,
    pub(crate) installation_token: String,
    pub(crate) pseudonym_key: String,
    pub(crate) organization_id: Uuid,
    pub(crate) team_key: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierProvisionResponse {
    enabled: bool,
    execution_mode: ClassifierExecutionMode,
    config_version: String,
    provider_id: String,
    endpoint: String,
    model: String,
    credential_id: String,
    credential: Option<String>,
    credential_version: Option<i32>,
    response_mode: ResponseMode,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ClassifierExecutionMode {
    #[default]
    Local,
    Managed,
}

impl ClassifierExecutionMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Managed => "managed",
        }
    }
}

fn parse_classifier_execution_mode(value: &str) -> ClassifierExecutionMode {
    match value {
        "managed" => ClassifierExecutionMode::Managed,
        _ => ClassifierExecutionMode::Local,
    }
}

fn provisioned_classifier_material(
    execution_mode: ClassifierExecutionMode,
    endpoint: String,
    credential_id: String,
    credential: Option<String>,
    credential_version: Option<i32>,
) -> (String, String, Option<String>, Option<i32>) {
    match execution_mode {
        ClassifierExecutionMode::Local => (endpoint, credential_id, credential, credential_version),
        ClassifierExecutionMode::Managed => (String::new(), String::new(), None, None),
    }
}

const SUPPORTED_PLATFORMS: [&str; 5] = ["linux", "wsl", "windows", "macos", "other"];

/// Installation names are chosen by whoever holds an enrollment secret and are
/// rendered back to organization admins, so they are bounded at the edge rather
/// than trusted because the caller authenticated.
pub(crate) fn validate_installation_name(name: &str) -> Result<&str, ApiError> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return Err(ApiError::bad_request(
            "installationName must be between 1 and 120 characters",
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "installationName cannot contain control characters",
        ));
    }
    Ok(name)
}

pub(crate) fn validate_platform(platform: &str) -> Result<&str, ApiError> {
    if SUPPORTED_PLATFORMS.contains(&platform) {
        return Ok(platform);
    }
    Err(ApiError::bad_request("unsupported platform"))
}

async fn enroll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<EnrollRequest>,
) -> Result<(HeaderMap, Json<EnrollResponse>), ApiError> {
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    state
        .rate_limiter
        .check("enroll", &address, state.rate_limits.enroll)?;
    let installation_name = validate_installation_name(&request.installation_name)?.to_owned();
    let requested_platform = request
        .platform
        .as_deref()
        .map(validate_platform)
        .transpose()?
        .map(str::to_owned);
    let hash = token_hash(&request.enrollment_token);
    let mut transaction = state.postgres.begin().await?;
    let personal = sqlx::query_as::<_, (Uuid, Uuid, Option<Uuid>, Option<String>, String, Uuid)>(
        "SELECT c.organization_id, c.owner_user_id, c.team_id, t.name, c.platform, c.id
         FROM enrollment_codes c
         LEFT JOIN teams t ON t.id = c.team_id
         WHERE c.token_hash = $1 AND c.redeemed_at IS NULL AND c.expires_at > NOW()
         FOR UPDATE OF c",
    )
    .bind(&hash)
    .fetch_optional(&mut *transaction)
    .await?;
    if let Some((organization_id, owner_user_id, team_id, team_name, platform, code_id)) = personal
    {
        let installation_id = Uuid::new_v4();
        let installation_token = format!("mti_{}", Uuid::new_v4().simple());
        let pseudonym_key = format!("mpk_{}", Uuid::new_v4().simple());
        sqlx::query(
            "INSERT INTO installations(id, organization_id, name, token_hash, team_key, team_id, owner_user_id, platform, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())"
        )
        .bind(installation_id)
        .bind(organization_id)
        .bind(&installation_name)
        .bind(token_hash(&installation_token))
        .bind(&team_name)
        .bind(team_id)
        .bind(owner_user_id)
        .bind(requested_platform.as_deref().unwrap_or(&platform))
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE enrollment_codes SET redeemed_at = NOW() WHERE id = $1")
            .bind(code_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Ok((
            no_store_headers(),
            Json(EnrollResponse {
                installation_id,
                installation_token,
                pseudonym_key,
                organization_id,
                team_key: team_name,
            }),
        ));
    }
    transaction.rollback().await?;
    let row = sqlx::query_as::<_, (Uuid, Option<String>, Option<Uuid>, Option<String>)>(
        "SELECT e.organization_id, e.team_key, e.team_id, t.name FROM enrollment_tokens e LEFT JOIN teams t ON t.id = e.team_id WHERE e.token_hash = $1 AND e.revoked_at IS NULL AND (e.expires_at IS NULL OR e.expires_at > NOW())"
    ).bind(hash).fetch_optional(&state.postgres).await?.ok_or(ApiError::unauthorized("invalid enrollment token"))?;
    let installation_id = Uuid::new_v4();
    let installation_token = format!("mti_{}", Uuid::new_v4().simple());
    let pseudonym_key = format!("mpk_{}", Uuid::new_v4().simple());
    let team_key = row.3.clone().or(row.1.clone());
    sqlx::query(
        "INSERT INTO installations(id, organization_id, name, token_hash, team_key, team_id, platform, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())"
    ).bind(installation_id).bind(row.0).bind(&installation_name)
        .bind(token_hash(&installation_token)).bind(team_key.clone()).bind(row.2)
        .bind(requested_platform.as_deref().unwrap_or("other"))
        .execute(&state.postgres).await?;
    Ok((
        no_store_headers(),
        Json(EnrollResponse {
            installation_id,
            installation_token,
            pseudonym_key,
            organization_id: row.0,
            team_key,
        }),
    ))
}

async fn provision_classifier(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<(HeaderMap, Json<ClassifierProvisionResponse>), ApiError> {
    let auth = installation_auth(&state, &headers).await?;
    state.rate_limiter.check(
        "classifier-provision",
        &auth.installation_id.to_string(),
        state.rate_limits.provision,
    )?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let organization = sqlx::query_as::<_, (
        bool,
        bool,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>(
        "SELECT classifier_configured, classifier_enabled, classifier_provider_id, classifier_endpoint,
                classifier_model, classifier_credential_id, classifier_config_version,
                classifier_protocol, classifier_response_mode, classifier_execution_mode
         FROM organizations WHERE id = $1",
    )
    .bind(auth.organization_id)
    .fetch_one(&state.postgres)
    .await?;
    let configured = organization.0;
    let fallback = state.classifier.as_ref();
    if (configured && !organization.1) || (!configured && fallback.is_none()) {
        return Ok((
            response_headers,
            Json(ClassifierProvisionResponse {
                enabled: false,
                execution_mode: ClassifierExecutionMode::Local,
                config_version: "disabled".into(),
                provider_id: String::new(),
                endpoint: String::new(),
                model: String::new(),
                credential_id: String::new(),
                credential: None,
                credential_version: None,
                response_mode: ResponseMode::PromptJson,
            }),
        ));
    }
    let (
        execution_mode,
        provider_id,
        endpoint,
        model,
        credential_id,
        config_version,
        response_mode,
    ) = if configured {
        (
            parse_classifier_execution_mode(&organization.9),
            organization.2,
            organization.3,
            organization.4,
            organization.5,
            organization.6,
            parse_response_mode(&organization.8),
        )
    } else {
        let config = fallback.expect("checked above");
        (
            config.execution_mode,
            config.provider_id.clone(),
            config.endpoint.clone(),
            config.model.clone(),
            config.credential_id.clone(),
            config.config_version.clone(),
            config.response_mode,
        )
    };
    let (credential, credential_version) = if execution_mode == ClassifierExecutionMode::Managed {
        (None, None)
    } else {
        let (stored, version) =
            active_classifier_credential(&state, auth.organization_id, &credential_id).await?;
        (
            stored.or_else(|| {
                fallback
                    .filter(|config| config.credential_id == credential_id)
                    .and_then(|config| config.api_key.clone())
            }),
            version,
        )
    };
    sqlx::query(
        "UPDATE installations SET classifier_credential_id = $2,
             classifier_credential_version = $3 WHERE id = $1",
    )
    .bind(auth.installation_id)
    .bind((execution_mode == ClassifierExecutionMode::Local).then_some(credential_id.as_str()))
    .bind(credential_version)
    .execute(&state.postgres)
    .await?;
    let (endpoint, credential_id, credential, credential_version) = provisioned_classifier_material(
        execution_mode,
        endpoint,
        credential_id,
        credential,
        credential_version,
    );
    Ok((
        response_headers,
        Json(ClassifierProvisionResponse {
            enabled: true,
            execution_mode,
            config_version,
            provider_id,
            endpoint,
            model,
            credential_id,
            credential,
            credential_version,
            response_mode,
        }),
    ))
}

#[derive(Deserialize)]
struct ManagedClassifyRequest {
    text: String,
}

#[derive(Deserialize)]
struct ManagedClassifyBatchRequest {
    texts: Vec<String>,
}

fn validate_managed_classification_text(text: &str) -> Result<&str, ApiError> {
    let text = text.trim();
    if text.is_empty() {
        return Err(ApiError::bad_request("classification text is required"));
    }
    if text.len() > MAX_CLASSIFICATION_TEXT_BYTES {
        return Err(ApiError::payload_too_large(format!(
            "classification text cannot exceed {MAX_CLASSIFICATION_TEXT_BYTES} bytes"
        )));
    }
    Ok(text)
}

async fn managed_classify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManagedClassifyRequest>,
) -> Result<(HeaderMap, Json<metrune_core::CategoryAssignment>), ApiError> {
    let auth = installation_auth(&state, &headers).await?;
    state.rate_limiter.check(
        "classifier-managed",
        &auth.installation_id.to_string(),
        state.rate_limits.classify,
    )?;
    let text = validate_managed_classification_text(&request.text)?;
    let classifier = managed_classifier(&state, &auth).await?;
    let diagnostic = classifier
        .classify_with_diagnostics(text)
        .await
        .map_err(|_| {
            tracing::warn!(
                organization_id = %auth.organization_id,
                installation_id = %auth.installation_id,
                "managed classifier request failed"
            );
            ApiError::bad_gateway("managed classifier request failed")
        })?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, Json(diagnostic.assignment)))
}

async fn managed_classify_batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManagedClassifyBatchRequest>,
) -> Result<(HeaderMap, Json<BatchClassification>), ApiError> {
    let auth = installation_auth(&state, &headers).await?;
    state.rate_limiter.check(
        "classifier-managed",
        &auth.installation_id.to_string(),
        state.rate_limits.classify,
    )?;
    if request.texts.is_empty() || request.texts.len() > 12 {
        return Err(ApiError::bad_request(
            "classification batch must contain between 1 and 12 turns",
        ));
    }
    let mut bytes = 0_usize;
    let mut texts = Vec::with_capacity(request.texts.len());
    for text in &request.texts {
        let text = validate_managed_classification_text(text)?;
        bytes = bytes.saturating_add(text.len());
        texts.push(text.to_owned());
    }
    if bytes > 16 * 1024 {
        return Err(ApiError::payload_too_large(
            "classification batch cannot exceed 16384 text bytes",
        ));
    }
    let classifier = managed_classifier(&state, &auth).await?;
    let result = classifier
        .classify_batch(&texts)
        .await
        .map_err(|_| ApiError::bad_gateway("managed classifier batch request failed"))?;
    let mut response_headers = HeaderMap::new();
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok((response_headers, Json(result)))
}

async fn managed_classifier(
    state: &AppState,
    auth: &InstallationAuth,
) -> Result<OpenAiCompatibleClassifier, ApiError> {
    let organization =
        sqlx::query_as::<_, (bool, bool, String, String, String, String, String, String)>(
            "SELECT classifier_configured, classifier_enabled, classifier_execution_mode,
                classifier_provider_id, classifier_endpoint, classifier_model,
                classifier_credential_id, classifier_response_mode
         FROM organizations WHERE id = $1",
        )
        .bind(auth.organization_id)
        .fetch_one(&state.postgres)
        .await?;
    let (execution_mode, provider_id, endpoint, model, credential_id, response_mode) =
        if organization.0 {
            if !organization.1 {
                return Err(ApiError::conflict(
                    "managed classification is not enabled for this organization",
                ));
            }
            (
                parse_classifier_execution_mode(&organization.2),
                organization.3,
                organization.4,
                organization.5,
                organization.6,
                parse_response_mode(&organization.7),
            )
        } else if let Some(fallback) = &state.classifier {
            (
                fallback.execution_mode,
                fallback.provider_id.clone(),
                fallback.endpoint.clone(),
                fallback.model.clone(),
                fallback.credential_id.clone(),
                fallback.response_mode,
            )
        } else {
            return Err(ApiError::conflict(
                "managed classification is not enabled for this organization",
            ));
        };
    if execution_mode != ClassifierExecutionMode::Managed {
        return Err(ApiError::conflict(
            "this organization uses local client-side classification",
        ));
    }
    let (stored_credential, _) =
        active_classifier_credential(state, auth.organization_id, &credential_id).await?;
    let credential = stored_credential.or_else(|| {
        state
            .classifier
            .as_ref()
            .filter(|fallback| fallback.credential_id == credential_id)
            .and_then(|fallback| fallback.api_key.clone())
    });
    if matches!(provider_id.as_str(), "openrouter" | "openai") && credential.is_none() {
        return Err(ApiError::conflict(
            "the managed classifier credential is unavailable",
        ));
    }
    OpenAiCompatibleClassifier::new(endpoint, model, credential, response_mode)
        .map_err(|_| ApiError::bad_gateway("managed classifier is unavailable"))
}

async fn ingest_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<BatchEnvelope>,
) -> Result<Json<IngestAck>, ApiError> {
    let auth = installation_auth(&state, &headers).await?;
    state.rate_limiter.check(
        "ingest",
        &auth.installation_id.to_string(),
        state.rate_limits.ingest,
    )?;
    let client_version = reported_client_version(&headers);
    if let Some(version) = &client_version {
        sqlx::query("UPDATE installations SET last_client_version = $2 WHERE id = $1")
            .bind(auth.installation_id)
            .bind(version)
            .execute(&state.postgres)
            .await?;
        if !versions_share_major(version, env!("CARGO_PKG_VERSION")) {
            return Err(ApiError::client_unsupported(
                format!(
                    "client major version {version} is incompatible with server {}",
                    env!("CARGO_PKG_VERSION")
                ),
                state.minimum_client_version.clone(),
            ));
        }
    }
    if state
        .minimum_client_version
        .as_deref()
        .is_some_and(|minimum| {
            client_version
                .as_deref()
                .is_none_or(|current| version_is_older(current, minimum))
        })
    {
        return Err(ApiError::client_unsupported(
            "this server does not support the reported Metrune client version",
            state.minimum_client_version.clone(),
        ));
    }
    if batch.schema_version != SCHEMA_VERSION && batch.schema_version != LEGACY_SCHEMA_VERSION
        || batch.snapshots.iter().any(|snapshot| {
            snapshot.schema_version != SCHEMA_VERSION
                && snapshot.schema_version != LEGACY_SCHEMA_VERSION
        })
    {
        return Err(ApiError::client_unsupported(
            "this server does not support the uploaded schema",
            state.minimum_client_version.clone(),
        ));
    }
    let snapshot_count = batch.snapshots.len();
    if batch.batch_id.trim().is_empty() || batch.batch_id.len() > 128 {
        return Err(ApiError::bad_request(
            "batch_id must be between 1 and 128 bytes",
        ));
    }
    if snapshot_count > MAX_BATCH_SNAPSHOTS {
        return Err(ApiError::payload_too_large(format!(
            "a batch cannot contain more than {MAX_BATCH_SNAPSHOTS} snapshots"
        )));
    }
    let completed = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM ingest_batches WHERE installation_id = $1 AND batch_id = $2)",
    )
    .bind(auth.installation_id)
    .bind(&batch.batch_id)
    .fetch_one(&state.postgres)
    .await?;
    if completed {
        mark_installation_seen(&state.postgres, auth.installation_id).await?;
        return Ok(Json(IngestAck {
            batch_id: batch.batch_id,
            accepted: 0,
            duplicates: snapshot_count,
            rejected: 0,
            errors: vec![],
            accepted_session_keys: vec![],
            rejected_session_keys: vec![],
        }));
    }
    let mut ack = IngestAck {
        batch_id: batch.batch_id.clone(),
        accepted: 0,
        duplicates: 0,
        rejected: 0,
        errors: vec![],
        accepted_session_keys: vec![],
        rejected_session_keys: vec![],
    };
    let mut insert = state
        .clickhouse
        .insert::<SnapshotRow>("session_snapshots_dedup")?;
    for mut snapshot in batch.snapshots {
        match validate_snapshot(&snapshot) {
            Ok(()) => {
                apply_server_prices(&state, auth.organization_id, &mut snapshot).await?;
                validate_snapshot(&snapshot).map_err(ApiError::bad_request)?;
                let session_key = snapshot.session_key.clone();
                insert.write(&SnapshotRow::new(&auth, snapshot)?).await?;
                ack.accepted += 1;
                ack.accepted_session_keys.push(session_key);
            }
            Err(error) => {
                ack.rejected += 1;
                ack.errors.push(error);
                ack.rejected_session_keys.push(snapshot.session_key);
            }
        }
    }
    insert.end().await?;
    // A partial acknowledgement is not completion. The client acknowledges
    // only the explicit accepted/rejected keys and retries the remaining
    // queue; the batch id therefore stays open until every row is handled.
    if ack.rejected == 0 {
        sqlx::query(
            "INSERT INTO ingest_batches(installation_id, batch_id, snapshot_count, completed_at) VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING",
        )
        .bind(auth.installation_id)
        .bind(&batch.batch_id)
        .bind(snapshot_count as i32)
        .execute(&state.postgres)
        .await?;
    }
    mark_installation_seen(&state.postgres, auth.installation_id).await?;
    Ok(Json(ack))
}

fn reported_client_version(headers: &HeaderMap) -> Option<String> {
    headers
        .get(CLIENT_VERSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty() && value.len() <= 64 && is_valid_version(value))
        .map(str::to_string)
}

async fn mark_installation_seen(postgres: &PgPool, installation_id: Uuid) -> Result<(), ApiError> {
    sqlx::query("UPDATE installations SET last_seen_at = NOW() WHERE id = $1")
        .bind(installation_id)
        .execute(postgres)
        .await?;
    Ok(())
}

struct InstallationAuth {
    organization_id: Uuid,
    installation_id: Uuid,
    team_key: Option<String>,
    retention_days: u32,
    owner_user_id: Option<Uuid>,
}

async fn installation_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<InstallationAuth, ApiError> {
    let token = bearer(headers)?;
    let row = sqlx::query_as::<_, (Uuid, Uuid, Option<String>, i32, Option<Uuid>)>(
        "SELECT i.organization_id, i.id, COALESCE(t.name, i.team_key), o.retention_days, i.owner_user_id FROM installations i JOIN organizations o ON o.id = i.organization_id LEFT JOIN teams t ON t.id = i.team_id WHERE i.token_hash = $1 AND i.revoked_at IS NULL"
    ).bind(token_hash(token)).fetch_optional(&state.postgres).await?
        .ok_or(ApiError::unauthorized("invalid installation token"))?;
    Ok(InstallationAuth {
        organization_id: row.0,
        installation_id: row.1,
        team_key: row.2,
        retention_days: row.3.clamp(1, 3650) as u32,
        owner_user_id: row.4,
    })
}

fn validate_snapshot(snapshot: &SessionSnapshot) -> Result<(), String> {
    if snapshot.schema_version != SCHEMA_VERSION && snapshot.schema_version != LEGACY_SCHEMA_VERSION
    {
        return Err("unsupported snapshot schema".into());
    }
    if snapshot.session_key.len() < 32 || snapshot.user_key.len() < 32 {
        return Err("identifiers are not pseudonymous".into());
    }
    for (field, value) in [
        ("session_key", snapshot.session_key.as_str()),
        ("user_key", snapshot.user_key.as_str()),
        ("client_id", snapshot.client_id.as_str()),
        (
            "category classifier_id",
            snapshot.category.classifier_id.as_str(),
        ),
    ] {
        validate_snapshot_text(field, value)?;
    }
    for (field, value) in [
        ("project_key", snapshot.project_key.as_deref()),
        ("project_alias", snapshot.project_alias.as_deref()),
        ("team_key", snapshot.team_key.as_deref()),
        ("client_version", snapshot.client_version.as_deref()),
        (
            "source_schema_version",
            snapshot.source_schema_version.as_deref(),
        ),
    ] {
        if let Some(value) = value {
            validate_snapshot_text(field, value)?;
        }
    }
    if snapshot.ended_at < snapshot.started_at {
        return Err("session ended before it started".into());
    }
    if snapshot.usage_by_model.is_empty() {
        return Err("snapshot contains no usage".into());
    }
    if snapshot.usage_by_model.len() > MAX_USAGE_SLICES {
        return Err(format!(
            "snapshot contains more than {MAX_USAGE_SLICES} usage slices"
        ));
    }
    if snapshot.turns.len() > MAX_TURNS {
        return Err(format!("snapshot contains more than {MAX_TURNS} turns"));
    }
    if snapshot.classification_method_counts.len() > MAX_CLASSIFICATION_METHODS {
        return Err(format!(
            "snapshot contains more than {MAX_CLASSIFICATION_METHODS} classification methods"
        ));
    }
    if !snapshot.category.confidence.is_finite()
        || !(0.0..=1.0).contains(&snapshot.category.confidence)
    {
        return Err("category confidence must be finite and between 0 and 1".into());
    }
    if !snapshot.classified_token_coverage.is_finite()
        || !(0.0..=1.0).contains(&snapshot.classified_token_coverage)
    {
        return Err("classified token coverage must be finite and between 0 and 1".into());
    }
    if snapshot.total_tokens() > MAX_SNAPSHOT_TOKENS {
        return Err("snapshot token total exceeds the allowed bound".into());
    }
    if !snapshot.total_cost().is_finite()
        || snapshot.total_cost() < 0.0
        || snapshot.total_cost() > MAX_SNAPSHOT_COST
    {
        return Err("snapshot cost must be finite and within the allowed bound".into());
    }
    for slice in &snapshot.usage_by_model {
        validate_snapshot_text("provider_id", &slice.provider_id)?;
        validate_snapshot_text("model_id", &slice.model_id)?;
        validate_snapshot_cost(&slice.cost)?;
    }
    validate_classifier_usage(&snapshot.classifier_usage)?;
    if snapshot.turns.iter().any(|turn| {
        turn.model_activity.len() > MAX_MODEL_ACTIVITY_STEPS
            || turn.workflow_signals.len() > MAX_WORKFLOW_SIGNALS
    }) {
        return Err("turn activity or workflow signals exceed the allowed bound".into());
    }
    for turn in &snapshot.turns {
        validate_snapshot_text("turn classifier_id", &turn.category.classifier_id)?;
        if !turn.category.confidence.is_finite() || !(0.0..=1.0).contains(&turn.category.confidence)
        {
            return Err("turn category confidence must be finite and between 0 and 1".into());
        }
        for step in &turn.model_activity {
            validate_snapshot_text("activity provider_id", &step.provider_id)?;
            validate_snapshot_text("activity model_id", &step.model_id)?;
            validate_snapshot_cost(&step.cost)?;
        }
    }
    if snapshot.schema_version == SCHEMA_VERSION && !snapshot.turns.is_empty() {
        let turn_tokens = snapshot
            .turns
            .iter()
            .map(metrune_core::TurnSnapshot::total_tokens)
            .sum::<u64>();
        if turn_tokens != snapshot.total_tokens() {
            return Err("turn token totals do not reconcile with session usage".into());
        }
        let turn_cost = snapshot
            .turns
            .iter()
            .map(metrune_core::TurnSnapshot::total_cost)
            .sum::<f64>();
        if (turn_cost - snapshot.total_cost()).abs() > 0.000_001 {
            return Err("turn cost totals do not reconcile with session usage".into());
        }
        if snapshot
            .turns
            .windows(2)
            .any(|pair| pair[0].sequence >= pair[1].sequence)
        {
            return Err("turn sequences must be strictly increasing".into());
        }
        if snapshot.turns.iter().any(|turn| {
            turn.model_activity
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
        }) {
            return Err("model activity sequences must be strictly increasing".into());
        }
        let mut turn_models =
            BTreeMap::<(String, String), (metrune_core::TokenBreakdown, f64)>::new();
        for step in snapshot
            .turns
            .iter()
            .flat_map(|turn| turn.model_activity.iter())
        {
            let key = (
                step.provider_id.trim().to_ascii_lowercase(),
                canonical_model_id(&step.model_id),
            );
            let entry = turn_models.entry(key).or_default();
            entry.0.add_assign(&step.tokens);
            entry.1 += step.cost.amount;
        }
        for slice in &snapshot.usage_by_model {
            let key = (
                slice.provider_id.trim().to_ascii_lowercase(),
                canonical_model_id(&slice.model_id),
            );
            let Some((tokens, cost)) = turn_models.remove(&key) else {
                return Err("session model usage is missing from turn activity".into());
            };
            if tokens != slice.tokens || (cost - slice.cost.amount).abs() > 0.000_001 {
                return Err("turn model totals do not reconcile with session usage".into());
            }
        }
        if !turn_models.is_empty() {
            return Err("turn activity contains model usage missing from session totals".into());
        }
    }
    Ok(())
}

fn validate_snapshot_text(field: &str, value: &str) -> Result<(), String> {
    if value.len() > MAX_SNAPSHOT_TEXT_BYTES {
        return Err(format!("{field} exceeds {MAX_SNAPSHOT_TEXT_BYTES} bytes"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{field} contains control characters"));
    }
    Ok(())
}

fn validate_snapshot_cost(cost: &metrune_core::Cost) -> Result<(), String> {
    if !cost.amount.is_finite() || cost.amount < 0.0 || cost.amount > MAX_SNAPSHOT_COST {
        return Err("cost amount must be finite and within the allowed bound".into());
    }
    validate_snapshot_text("cost currency", &cost.currency)?;
    if cost.currency.chars().count() != 3 {
        return Err("cost currency must be a three-letter code".into());
    }
    if let Some(version) = cost.pricebook_version.as_deref() {
        validate_snapshot_text("pricebook_version", version)?;
    }
    if let Some(source) = cost.price_source.as_deref() {
        validate_snapshot_text("price_source", source)?;
    }
    Ok(())
}

fn validate_classifier_usage(usage: &metrune_core::ClassifierUsage) -> Result<(), String> {
    validate_snapshot_text("classifier provider_id", &usage.provider_id)?;
    validate_snapshot_text("classifier model_id", &usage.model_id)?;
    validate_snapshot_cost(&usage.cost)
}

#[derive(Row, Serialize, Deserialize)]
struct SnapshotRow {
    organization_id: String,
    installation_id: String,
    owner_user_id: String,
    session_key: String,
    revision: u64,
    user_key: String,
    project_key: String,
    project_alias: String,
    team_key: String,
    client_id: String,
    started_at_ms: i64,
    ended_at_ms: i64,
    category_id: String,
    category_confidence: f32,
    taxonomy_version: String,
    classifier_id: String,
    classification_status: String,
    total_tokens: u64,
    total_cost: f64,
    snapshot_json: String,
    ingested_at_ms: i64,
    retention_days: u32,
}

impl SnapshotRow {
    fn new(auth: &InstallationAuth, snapshot: SessionSnapshot) -> anyhow::Result<Self> {
        Ok(Self {
            organization_id: auth.organization_id.to_string(),
            installation_id: auth.installation_id.to_string(),
            owner_user_id: auth
                .owner_user_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            session_key: snapshot.session_key.clone(),
            revision: snapshot.revision,
            user_key: snapshot.user_key.clone(),
            project_key: snapshot.project_key.clone().unwrap_or_default(),
            project_alias: snapshot.project_alias.clone().unwrap_or_default(),
            team_key: auth
                .team_key
                .clone()
                .or_else(|| snapshot.team_key.clone())
                .unwrap_or_default(),
            client_id: snapshot.client_id.clone(),
            started_at_ms: snapshot.started_at.timestamp_millis(),
            ended_at_ms: snapshot.ended_at.timestamp_millis(),
            category_id: snapshot.category.category_id.as_str().into(),
            category_confidence: snapshot.category.confidence,
            taxonomy_version: snapshot.category.taxonomy_version.clone(),
            classifier_id: snapshot.category.classifier_id.clone(),
            classification_status: snapshot.category.classification_status.as_str().into(),
            total_tokens: snapshot.total_tokens(),
            total_cost: snapshot.total_cost(),
            snapshot_json: serde_json::to_string(&snapshot)?,
            ingested_at_ms: Utc::now().timestamp_millis(),
            retention_days: auth.retention_days,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AnalyticsQuery {
    from: Option<String>,
    to: Option<String>,
    team: Option<String>,
    project: Option<String>,
    category: Option<String>,
    client: Option<String>,
    status: Option<String>,
    workflow: Option<String>,
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct OverviewRow {
    total_tokens: u64,
    total_cost: f64,
    sessions: u64,
    active_users: u64,
}

async fn analytics_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<OverviewRow>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let (sql, params) = filtered_query(
        "SELECT toUInt64(sum(total_tokens)) total_tokens, sum(total_cost) total_cost, toUInt64(count()) sessions, toUInt64(uniqExact(user_key)) active_users FROM session_snapshots_dedup FINAL",
        &query, &auth.organization_id,
    );
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    let row = q.fetch_one::<OverviewRow>().await?;
    Ok(Json(row))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct TimeseriesRow {
    bucket: String,
    tokens: u64,
    cost: f64,
    sessions: u64,
}

async fn analytics_timeseries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<TimeseriesRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let base = "SELECT formatDateTime(toDateTime(ended_at_ms/1000), '%Y-%m-%d') bucket, toUInt64(sum(total_tokens)) tokens, sum(total_cost) cost, toUInt64(count()) sessions FROM session_snapshots_dedup FINAL";
    let (mut sql, params) = filtered_query(base, &query, &auth.organization_id);
    sql.push_str(" GROUP BY bucket ORDER BY bucket");
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<TimeseriesRow>().await?))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct CategoryModelRow {
    category: String,
    model: String,
    tokens: u64,
    cost: f64,
    sessions: u64,
}

async fn analytics_category_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<CategoryModelRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let v2 = "SELECT JSONExtractString(turn, 'category', 'categoryId') category, concat(JSONExtractString(step, 'providerId'), '/', JSONExtractString(step, 'modelId')) model, JSONExtractUInt(step, 'tokens', 'input') + JSONExtractUInt(step, 'tokens', 'output') + JSONExtractUInt(step, 'tokens', 'cacheRead') + JSONExtractUInt(step, 'tokens', 'cacheWrite') + JSONExtractUInt(step, 'tokens', 'reasoning') tokens, JSONExtractFloat(step, 'cost', 'amount') cost, session_key FROM (SELECT *, arrayJoin(JSONExtractArrayRaw(snapshot_json, 'turns')) AS turn FROM session_snapshots_dedup FINAL) ARRAY JOIN JSONExtractArrayRaw(turn, 'modelActivity') AS step";
    let v1 = "SELECT category_id category, concat(JSONExtractString(usage_slice, 'providerId'), '/', JSONExtractString(usage_slice, 'modelId')) model, JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning') tokens, JSONExtractFloat(usage_slice, 'cost', 'amount') cost, session_key FROM session_snapshots_dedup FINAL ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice";
    let mut v2_query = query.clone();
    let category = v2_query.category.take();
    let (mut v2_sql, mut v2_params) = filtered_query(v2, &v2_query, &auth.organization_id);
    v2_sql.push_str(" AND length(JSONExtractArrayRaw(snapshot_json, 'turns')) > 0 AND JSONExtractString(turn, 'category', 'classificationStatus') = 'classified'");
    if let Some(category) = category {
        v2_sql.push_str(" AND JSONExtractString(turn, 'category', 'categoryId') = ?");
        v2_params.push(category);
    }
    let (mut v1_sql, v1_params) = filtered_query(v1, &query, &auth.organization_id);
    v1_sql.push_str(" AND length(JSONExtractArrayRaw(snapshot_json, 'turns')) = 0 AND classification_status = 'classified'");
    let sql = format!(
        "SELECT category, model, toUInt64(sum(tokens)) tokens, sum(cost) cost, toUInt64(uniqExact(session_key)) sessions FROM ({v2_sql} UNION ALL {v1_sql}) GROUP BY category, model ORDER BY category, tokens DESC LIMIT 500"
    );
    let mut q = state.clickhouse.query(&sql);
    for param in v2_params.into_iter().chain(v1_params) {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<CategoryModelRow>().await?))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct WorkflowModelRow {
    signal: String,
    model: String,
    count: u64,
    tokens: u64,
    cost: f64,
    sessions: u64,
}

async fn analytics_workflow_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<WorkflowModelRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let base = "SELECT JSONExtractString(signal, 'signal') signal, if(JSONHas(signal, 'modelStepIndex'), concat(JSONExtractString(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'providerId'), '/', JSONExtractString(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'modelId')), 'Unattributed') model, toUInt64(sum(JSONExtractUInt(signal, 'count'))) count, toUInt64(sum(if(JSONHas(signal, 'modelStepIndex'), JSONExtractUInt(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'tokens', 'input') + JSONExtractUInt(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'tokens', 'output') + JSONExtractUInt(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'tokens', 'cacheRead') + JSONExtractUInt(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'tokens', 'cacheWrite') + JSONExtractUInt(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'tokens', 'reasoning'), 0))) tokens, sum(if(JSONHas(signal, 'modelStepIndex'), JSONExtractFloat(arrayElement(JSONExtractArrayRaw(turn, 'modelActivity'), JSONExtractUInt(signal, 'modelStepIndex') + 1), 'cost', 'amount'), 0)) cost, toUInt64(uniqExact(session_key)) sessions FROM (SELECT *, arrayJoin(JSONExtractArrayRaw(snapshot_json, 'turns')) AS turn FROM session_snapshots_dedup FINAL) ARRAY JOIN JSONExtractArrayRaw(turn, 'workflowSignals') AS signal";
    let (mut sql, mut params) = filtered_query(base, &query, &auth.organization_id);
    if let Some(workflow) = &query.workflow {
        sql.push_str(" AND JSONExtractString(signal, 'signal') = ?");
        params.push(workflow.clone());
    }
    sql.push_str(" GROUP BY signal, model ORDER BY signal, count DESC LIMIT 500");
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<WorkflowModelRow>().await?))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct ClassificationOverheadRow {
    provider: String,
    model: String,
    measurement: String,
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    reasoning_tokens: u64,
    requests: u64,
}

async fn analytics_classification_overhead(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<Vec<ClassificationOverheadRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let base = "SELECT JSONExtractString(snapshot_json, 'classifierUsage', 'providerId') provider, JSONExtractString(snapshot_json, 'classifierUsage', 'modelId') model, JSONExtractString(snapshot_json, 'classifierUsage', 'measurement') measurement, toUInt64(sum(JSONExtractUInt(snapshot_json, 'classifierUsage', 'tokens', 'input'))) input_tokens, toUInt64(sum(JSONExtractUInt(snapshot_json, 'classifierUsage', 'tokens', 'output'))) output_tokens, toUInt64(sum(JSONExtractUInt(snapshot_json, 'classifierUsage', 'tokens', 'cacheRead'))) cache_read_tokens, toUInt64(sum(JSONExtractUInt(snapshot_json, 'classifierUsage', 'tokens', 'reasoning'))) reasoning_tokens, toUInt64(sum(JSONExtractUInt(snapshot_json, 'classifierUsage', 'requestCount'))) requests FROM session_snapshots_dedup FINAL";
    let (mut sql, params) = filtered_query(base, &query, &auth.organization_id);
    sql.push_str(" AND JSONExtractUInt(snapshot_json, 'classifierUsage', 'requestCount') > 0 GROUP BY provider, model, measurement ORDER BY requests DESC");
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<ClassificationOverheadRow>().await?))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct BreakdownRow {
    dimension: String,
    tokens: u64,
    cost: f64,
    sessions: u64,
}

#[derive(Deserialize)]
struct BreakdownQuery {
    dimension: Option<String>,
    from: Option<String>,
    to: Option<String>,
    team: Option<String>,
    project: Option<String>,
    category: Option<String>,
    client: Option<String>,
    status: Option<String>,
    workflow: Option<String>,
}

async fn analytics_breakdowns(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BreakdownQuery>,
) -> Result<Json<Vec<BreakdownRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let (dimension, tokens, cost, array_join) = match query.dimension.as_deref().unwrap_or("category") {
        "category" => ("category_id", "total_tokens", "total_cost", ""),
        "client" => ("client_id", "total_tokens", "total_cost", ""),
        "team" => ("team_key", "total_tokens", "total_cost", ""),
        "project" => ("if(project_alias = '', 'Unassigned', project_alias)", "total_tokens", "total_cost", ""),
        "model" => (
            "concat(JSONExtractString(usage_slice, 'providerId'), '/', JSONExtractString(usage_slice, 'modelId'))",
            "JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning')",
            "JSONExtractFloat(usage_slice, 'cost', 'amount')",
            "ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice",
        ),
        "provider" => (
            "JSONExtractString(usage_slice, 'providerId')",
            "JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning')",
            "JSONExtractFloat(usage_slice, 'cost', 'amount')",
            "ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice",
        ),
        "status" => ("classification_status", "total_tokens", "total_cost", ""),
        "workflow" => (
            "JSONExtractString(signal, 'signal')",
            "arraySum(step -> JSONExtractUInt(step, 'tokens', 'input') + JSONExtractUInt(step, 'tokens', 'output') + JSONExtractUInt(step, 'tokens', 'cacheRead') + JSONExtractUInt(step, 'tokens', 'cacheWrite') + JSONExtractUInt(step, 'tokens', 'reasoning'), JSONExtractArrayRaw(turn, 'modelActivity'))",
            "arraySum(step -> JSONExtractFloat(step, 'cost', 'amount'), JSONExtractArrayRaw(turn, 'modelActivity'))",
            "ARRAY JOIN JSONExtractArrayRaw(turn, 'workflowSignals') AS signal",
        ),
        _ => return Err(ApiError::bad_request("unsupported breakdown dimension")),
    };
    let filters = AnalyticsQuery {
        from: query.from,
        to: query.to,
        team: query.team,
        project: query.project,
        category: query.category,
        client: query.client,
        status: query.status,
        workflow: query.workflow,
    };
    if query.dimension.as_deref().unwrap_or("category") == "category" {
        let mut v2_filters = filters.clone();
        let category = v2_filters.category.take();
        let v2 = "SELECT JSONExtractString(turn, 'category', 'categoryId') dimension, arraySum(step -> JSONExtractUInt(step, 'tokens', 'input') + JSONExtractUInt(step, 'tokens', 'output') + JSONExtractUInt(step, 'tokens', 'cacheRead') + JSONExtractUInt(step, 'tokens', 'cacheWrite') + JSONExtractUInt(step, 'tokens', 'reasoning'), JSONExtractArrayRaw(turn, 'modelActivity')) tokens, arraySum(step -> JSONExtractFloat(step, 'cost', 'amount'), JSONExtractArrayRaw(turn, 'modelActivity')) cost, session_key FROM (SELECT *, arrayJoin(JSONExtractArrayRaw(snapshot_json, 'turns')) AS turn FROM session_snapshots_dedup FINAL)";
        let (mut v2_sql, mut v2_params) = filtered_query(v2, &v2_filters, &auth.organization_id);
        v2_sql.push_str(
            " AND JSONExtractString(turn, 'category', 'classificationStatus') = 'classified'",
        );
        if let Some(category) = category {
            v2_sql.push_str(" AND JSONExtractString(turn, 'category', 'categoryId') = ?");
            v2_params.push(category);
        }
        let v1 = "SELECT category_id dimension, total_tokens tokens, total_cost cost, session_key FROM session_snapshots_dedup FINAL";
        let (mut v1_sql, v1_params) = filtered_query(v1, &filters, &auth.organization_id);
        v1_sql.push_str(" AND length(JSONExtractArrayRaw(snapshot_json, 'turns')) = 0 AND classification_status = 'classified'");
        let sql = format!(
            "SELECT dimension, toUInt64(sum(tokens)) tokens, sum(cost) cost, toUInt64(uniqExact(session_key)) sessions FROM ({v2_sql} UNION ALL {v1_sql}) GROUP BY dimension ORDER BY cost DESC LIMIT 50"
        );
        let mut q = state.clickhouse.query(&sql);
        for param in v2_params.into_iter().chain(v1_params) {
            q = q.bind(param);
        }
        return Ok(Json(q.fetch_all::<BreakdownRow>().await?));
    }
    let source = if query.dimension.as_deref() == Some("workflow") {
        "FROM (SELECT *, arrayJoin(JSONExtractArrayRaw(snapshot_json, 'turns')) AS turn FROM session_snapshots_dedup FINAL) ARRAY JOIN JSONExtractArrayRaw(turn, 'workflowSignals') AS signal".to_string()
    } else {
        format!("FROM session_snapshots_dedup FINAL {array_join}")
    };
    let base = format!("SELECT {dimension} dimension, toUInt64(sum({tokens})) tokens, sum({cost}) cost, toUInt64(uniqExact(session_key)) sessions {source}");
    let (mut sql, mut params) = filtered_query(&base, &filters, &auth.organization_id);
    if query.dimension.as_deref().unwrap_or("category") == "category" {
        sql.push_str(" AND classification_status = 'classified'");
    }
    if query.dimension.as_deref() == Some("workflow") {
        if let Some(workflow) = &filters.workflow {
            sql.push_str(" AND JSONExtractString(signal, 'signal') = ?");
            params.push(workflow.clone());
        }
    }
    sql.push_str(" GROUP BY dimension ORDER BY cost DESC LIMIT 50");
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<BreakdownRow>().await?))
}

#[derive(Deserialize, Serialize, Row)]
#[serde(rename_all = "camelCase")]
struct SessionRow {
    session_key: String,
    installation_id: String,
    client_id: String,
    project_alias: String,
    category_id: String,
    category_confidence: f32,
    classification_status: String,
    total_tokens: u64,
    total_cost: f64,
    ended_at_ms: i64,
}

#[derive(Debug, Deserialize)]
struct SessionsQuery {
    from: Option<String>,
    to: Option<String>,
    team: Option<String>,
    project: Option<String>,
    category: Option<String>,
    client: Option<String>,
    status: Option<String>,
    workflow: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
    sort: Option<String>,
}

async fn analytics_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SessionsQuery>,
) -> Result<Json<Vec<SessionRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let owner_scope = auth.session_owner_scope()?;
    let order = match query.sort.as_deref() {
        Some("cost") => "total_cost DESC",
        Some("tokens") => "total_tokens DESC",
        Some("category") => "category_id ASC, ended_at_ms DESC",
        _ => "ended_at_ms DESC",
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    // ClickHouse still scans every row it skips, so an unbounded offset is a
    // cheap way to make the server do expensive work.
    let offset = query.offset.unwrap_or(0).min(MAX_SESSION_PAGE_OFFSET);
    let filters = AnalyticsQuery {
        from: query.from,
        to: query.to,
        team: query.team,
        project: query.project,
        category: query.category,
        client: query.client,
        status: query.status,
        workflow: query.workflow,
    };
    let base = "SELECT session_key, installation_id, client_id, project_alias, category_id, category_confidence, classification_status, total_tokens, total_cost, ended_at_ms FROM session_snapshots_dedup FINAL";
    let (mut sql, mut params) = filtered_query(base, &filters, &auth.organization_id);
    if let Some(owner) = owner_scope {
        sql.push_str(" AND owner_user_id = ?");
        params.push(owner.to_string());
    }
    sql.push_str(&format!(" ORDER BY {order} LIMIT {limit} OFFSET {offset}"));
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<SessionRow>().await?))
}

#[derive(Deserialize, Row)]
struct SnapshotJsonRow {
    snapshot_json: String,
}

async fn analytics_session_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_key): Path<String>,
) -> Result<Json<SessionSnapshot>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    if session_key.len() < 32 || session_key.len() > 128 {
        return Err(ApiError::bad_request("invalid session key"));
    }
    let owner_scope = auth.session_owner_scope()?;
    let mut sql = "SELECT snapshot_json FROM session_snapshots_dedup FINAL WHERE organization_id = ? AND session_key = ?".to_string();
    if owner_scope.is_some() {
        sql.push_str(" AND owner_user_id = ?");
    }
    sql.push_str(" LIMIT 1");
    let mut query = state
        .clickhouse
        .query(&sql)
        .bind(&auth.organization_id)
        .bind(&session_key);
    if let Some(owner) = owner_scope {
        query = query.bind(owner.to_string());
    }
    let row = query
        .fetch_optional::<SnapshotJsonRow>()
        .await?
        .ok_or(ApiError::not_found("session not found"))?;
    let snapshot = serde_json::from_str(&row.snapshot_json)
        .map_err(|_| ApiError::bad_gateway("stored session detail is invalid"))?;
    Ok(Json(snapshot))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FacetsResponse {
    teams: Vec<String>,
    projects: Vec<String>,
    categories: Vec<String>,
    clients: Vec<String>,
    statuses: Vec<String>,
}

async fn analytics_facets(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AnalyticsQuery>,
) -> Result<Json<FacetsResponse>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let organization_id: Uuid = auth
        .organization_id
        .parse()
        .map_err(|_| ApiError::unauthorized("invalid dashboard token"))?;
    let mut facets = FacetsResponse {
        teams: vec![],
        projects: vec![],
        categories: vec![],
        clients: vec![],
        statuses: vec![],
    };
    for (column, target) in [
        ("team_key", &mut facets.teams),
        ("project_alias", &mut facets.projects),
        ("category_id", &mut facets.categories),
        ("client_id", &mut facets.clients),
        ("classification_status", &mut facets.statuses),
    ] {
        let base = format!("SELECT DISTINCT {column} value FROM session_snapshots_dedup FINAL");
        let (mut sql, params) = filtered_query(&base, &query, &auth.organization_id);
        sql.push_str(" AND value != '' ORDER BY value LIMIT 100");
        let mut q = state.clickhouse.query(&sql);
        for param in params {
            q = q.bind(param);
        }
        *target = q
            .fetch_all::<ValueRow>()
            .await?
            .into_iter()
            .map(|row| row.value)
            .collect();
    }
    // Teams are managed in Postgres; merge configured teams so newly created
    // ones are filterable before their first upload arrives.
    let configured: Vec<String> =
        sqlx::query_scalar("SELECT name FROM teams WHERE organization_id = $1 ORDER BY name")
            .bind(organization_id)
            .fetch_all(&state.postgres)
            .await?;
    for name in configured {
        if !facets.teams.contains(&name) {
            facets.teams.push(name);
        }
    }
    facets.teams.sort();
    Ok(Json(facets))
}

#[derive(Deserialize, Row)]
struct ValueRow {
    value: String,
}

fn filtered_query(
    base: &str,
    query: &AnalyticsQuery,
    organization_id: &str,
) -> (String, Vec<String>) {
    let from = query.from.clone().unwrap_or_else(|| {
        (Utc::now() - Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });
    let to = query
        .to
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let mut clauses = vec![
        "organization_id = ?".to_string(),
        "ended_at_ms >= toUnixTimestamp(parseDateTimeBestEffort(?)) * 1000".to_string(),
        "ended_at_ms < (toUnixTimestamp(parseDateTimeBestEffort(?)) + 86400) * 1000".to_string(),
    ];
    let mut params = vec![organization_id.to_string(), from, to];
    for (value, column) in [
        (&query.team, "team_key"),
        (&query.project, "project_alias"),
        (&query.category, "category_id"),
        (&query.client, "client_id"),
        (&query.status, "classification_status"),
    ] {
        if let Some(value) = value {
            clauses.push(format!("{column} = ?"));
            params.push(value.clone());
        }
    }
    if let Some(workflow) = &query.workflow {
        clauses.push(
            "arrayExists(turn -> arrayExists(signal -> JSONExtractString(signal, 'signal') = ?, JSONExtractArrayRaw(turn, 'workflowSignals')), JSONExtractArrayRaw(snapshot_json, 'turns'))"
                .into(),
        );
        params.push(workflow.clone());
    }
    (format!("{base} WHERE {}", clauses.join(" AND ")), params)
}

pub(crate) struct DashboardAuth {
    organization_id: String,
    role: String,
    pub(crate) name: String,
    pub(crate) user_id: Option<Uuid>,
    /// Stable rate-limiting identity: the user id for a web session, or the
    /// stored digest for a service dashboard token.
    pub(crate) subject: String,
}

impl DashboardAuth {
    pub(crate) fn require_admin(&self) -> Result<(), ApiError> {
        if self.role != "admin" {
            return Err(ApiError::forbidden("organization admin role required"));
        }
        Ok(())
    }

    /// Whether this caller may read the whole organization's session data.
    ///
    /// Analysts and admins drill into every session. Anyone else is limited to
    /// the sessions they own, which needs a user identity to scope by.
    pub(crate) fn reads_whole_organization(&self) -> bool {
        self.role == "admin" || self.role == "analyst"
    }

    /// The owner every session row must match, or `None` for an
    /// organization-wide read. A viewer's service token has no user identity to
    /// scope by, so it may read nothing.
    pub(crate) fn session_owner_scope(&self) -> Result<Option<Uuid>, ApiError> {
        if self.reads_whole_organization() {
            return Ok(None);
        }
        self.user_id.map(Some).ok_or(ApiError::forbidden(
            "session drilldown requires analyst or admin role",
        ))
    }

    pub(crate) fn organization_uuid(&self) -> Result<Uuid, ApiError> {
        self.organization_id
            .parse()
            .map_err(|_| ApiError::unauthorized("invalid dashboard token"))
    }
}

pub(crate) async fn dashboard_auth(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<DashboardAuth, ApiError> {
    let digest = token_hash(bearer(headers)?);
    if let Some(row) = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT organization_id, role, name FROM dashboard_tokens WHERE token_hash = $1 AND revoked_at IS NULL",
    )
    .bind(&digest)
    .fetch_optional(&state.postgres)
    .await?
    {
        return Ok(DashboardAuth {
            organization_id: row.0.to_string(),
            role: row.1,
            name: row.2,
            user_id: None,
            subject: format!("token:{digest}"),
        });
    }
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String)>(
        "SELECT m.organization_id, u.id, m.role, COALESCE(u.display_name, u.email)
         FROM web_sessions s
         JOIN users u ON u.id = s.user_id
         JOIN organization_memberships m
           ON m.user_id = s.user_id
          AND m.organization_id = s.active_organization_id
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
           AND u.disabled_at IS NULL AND m.disabled_at IS NULL
           AND s.authentication_method = $2",
    )
    .bind(&digest)
    .bind(active_authentication_method(state))
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::unauthorized(
        "invalid session or organization selection required",
    ))?;
    Ok(DashboardAuth {
        organization_id: row.0.to_string(),
        user_id: Some(row.1),
        role: row.2,
        name: row.3,
        subject: format!("user:{}", row.1),
    })
}

/// Authenticates a dashboard caller for an expensive analytics query and
/// charges it against the caller's analytics budget.
async fn analytics_auth(state: &AppState, headers: &HeaderMap) -> Result<DashboardAuth, ApiError> {
    let auth = dashboard_auth(state, headers).await?;
    state
        .rate_limiter
        .check("analytics", &auth.subject, state.rate_limits.analytics)?;
    Ok(auth)
}

pub(crate) async fn audit(
    state: &AppState,
    organization_id: Uuid,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: String,
    metadata: serde_json::Value,
) {
    let result = sqlx::query(
        "INSERT INTO audit_events(organization_id, actor_label, action, target_type, target_id, metadata) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(organization_id)
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(metadata)
    .execute(&state.postgres)
    .await;
    if let Err(error) = result {
        tracing::warn!(%error, action, "failed to write audit event");
    }
}

async fn expired_session_reaper(pool: PgPool) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
    loop {
        interval.tick().await;
        if let Err(error) = reap_expired_identity_records(&pool).await {
            tracing::warn!(%error, "expired session reaper failed");
        }
    }
}

/// Performs one cleanup pass for the hourly identity-record reaper.
///
/// Kept as a separate operation so the retention contract can be exercised
/// against PostgreSQL without waiting for a background timer.
pub(crate) async fn reap_expired_identity_records(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "WITH deleted_sessions AS (
           DELETE FROM web_sessions
           WHERE expires_at < NOW() OR revoked_at < NOW() - INTERVAL '7 days'
         ), deleted_invitations AS (
           DELETE FROM workspace_invitations
           WHERE expires_at < NOW() - INTERVAL '7 days'
              OR revoked_at < NOW() - INTERVAL '7 days'
              OR accepted_at < NOW() - INTERVAL '7 days'
         ), deleted_device_authorizations AS (
           DELETE FROM device_enrollment_authorizations
           WHERE expires_at < NOW() - INTERVAL '7 days'
              OR denied_at < NOW() - INTERVAL '7 days'
              OR consumed_at < NOW() - INTERVAL '7 days'
         ), deleted_oidc_authorizations AS (
           DELETE FROM oidc_authorization_attempts
           WHERE expires_at < NOW() - INTERVAL '7 days'
              OR consumed_at < NOW() - INTERVAL '7 days'
         )
         DELETE FROM password_reset_tokens
         WHERE expires_at < NOW() - INTERVAL '7 days'
            OR revoked_at < NOW() - INTERVAL '7 days'
            OR consumed_at < NOW() - INTERVAL '7 days'",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberResponse {
    user_id: Uuid,
    email: String,
    display_name: Option<String>,
    role: String,
    created_at: chrono::DateTime<Utc>,
}

pub(crate) fn validate_member_role(role: &str) -> Result<&str, ApiError> {
    match role {
        "viewer" | "analyst" | "admin" => Ok(role),
        _ => Err(ApiError::bad_request(
            "role must be viewer, analyst, or admin",
        )),
    }
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MemberResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let rows = sqlx::query_as::<_, (Uuid, String, Option<String>, String, chrono::DateTime<Utc>)>(
        "SELECT u.id, u.email, u.display_name, m.role, m.created_at
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.organization_id = $1 AND m.disabled_at IS NULL
           AND u.disabled_at IS NULL
         ORDER BY LOWER(COALESCE(u.display_name, u.email)), u.id",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| MemberResponse {
                user_id: row.0,
                email: row.1,
                display_name: row.2,
                role: row.3,
                created_at: row.4,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct AddMemberRequest {
    email: String,
    role: String,
}

async fn add_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AddMemberRequest>,
) -> Result<(StatusCode, Json<MemberResponse>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let role = validate_member_role(request.role.trim())?;
    let email = request.email.trim().to_ascii_lowercase();
    if email.is_empty() || email.len() > 320 {
        return Err(ApiError::bad_request("a valid account email is required"));
    }
    let users = sqlx::query_as::<_, (Uuid, String, Option<String>)>(
        "SELECT id, email, display_name
         FROM users
         WHERE LOWER(email) = $1 AND disabled_at IS NULL
         ORDER BY created_at LIMIT 2",
    )
    .bind(&email)
    .fetch_all(&state.postgres)
    .await?;
    if users.is_empty() {
        return Err(ApiError::not_found(
            "no Metrune account exists for that email",
        ));
    }
    if users.len() > 1 {
        return Err(ApiError::conflict(
            "multiple legacy accounts use that email; consolidate them before adding a membership",
        ));
    }
    let user = &users[0];
    let organization_id = auth.organization_uuid()?;
    let created_at = sqlx::query_scalar::<_, chrono::DateTime<Utc>>(
        "INSERT INTO organization_memberships(
             organization_id, user_id, role, disabled_at, updated_at
         ) VALUES ($1,$2,$3,NULL,NOW())
         ON CONFLICT (organization_id, user_id)
         DO UPDATE SET role = EXCLUDED.role, disabled_at = NULL, updated_at = NOW()
         RETURNING created_at",
    )
    .bind(organization_id)
    .bind(user.0)
    .bind(role)
    .fetch_one(&state.postgres)
    .await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "member.add",
        "user",
        user.0.to_string(),
        serde_json::json!({"email": user.1, "role": role}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(MemberResponse {
            user_id: user.0,
            email: user.1.clone(),
            display_name: user.2.clone(),
            role: role.into(),
            created_at,
        }),
    ))
}

#[derive(Deserialize)]
struct UpdateMemberRequest {
    role: String,
}

async fn ensure_another_admin(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    target_user_id: Uuid,
) -> Result<(), ApiError> {
    // Lock all active memberships for this organization before checking the
    // final-admin invariant. Without this, two concurrent demotions/removals
    // can both observe the same second admin and leave the organization with
    // none.
    let memberships = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT user_id, role
         FROM organization_memberships
         WHERE organization_id = $1 AND disabled_at IS NULL
         FOR UPDATE",
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;
    let target_is_admin = memberships
        .iter()
        .any(|(user_id, role)| *user_id == target_user_id && role == "admin");
    if !target_is_admin {
        return Ok(());
    }
    let other_admins = memberships
        .iter()
        .filter(|(user_id, role)| *user_id != target_user_id && role == "admin")
        .count();
    if other_admins == 0 {
        return Err(ApiError::conflict(
            "the final organization admin cannot be removed or demoted",
        ));
    }
    Ok(())
}

async fn update_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
    Json(request): Json<UpdateMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let role = validate_member_role(request.role.trim())?;
    let organization_id = auth.organization_uuid()?;
    let mut transaction = state.postgres.begin().await?;
    if role != "admin" {
        ensure_another_admin(&mut transaction, organization_id, user_id).await?;
    }
    let updated = sqlx::query(
        "UPDATE organization_memberships
         SET role = $3, updated_at = NOW()
         WHERE organization_id = $1 AND user_id = $2 AND disabled_at IS NULL",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut *transaction)
    .await?;
    if updated.rows_affected() == 0 {
        transaction.rollback().await.ok();
        return Err(ApiError::not_found("organization member not found"));
    }
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "member.update_role",
        "user",
        user_id.to_string(),
        serde_json::json!({"role": role}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let mut transaction = state.postgres.begin().await?;
    ensure_another_admin(&mut transaction, organization_id, user_id).await?;
    sqlx::query(
        "UPDATE web_sessions SET active_organization_id = NULL
         WHERE user_id = $1 AND active_organization_id = $2",
    )
    .bind(user_id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    // Dashboard access dies with the membership, but an installation token is
    // an independent credential: without this the removed member's client keeps
    // uploading into the organization indefinitely.
    let revoked_installations = sqlx::query(
        "UPDATE installations SET revoked_at = NOW()
         WHERE organization_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    sqlx::query(
        "UPDATE enrollment_codes SET redeemed_at = NOW()
         WHERE organization_id = $1 AND owner_user_id = $2 AND redeemed_at IS NULL",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    let removed = sqlx::query(
        "DELETE FROM organization_memberships
         WHERE organization_id = $1 AND user_id = $2",
    )
    .bind(organization_id)
    .bind(user_id)
    .execute(&mut *transaction)
    .await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::not_found("organization member not found"));
    }
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "member.remove",
        "user",
        user_id.to_string(),
        serde_json::json!({"revokedInstallations": revoked_installations}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamResponse {
    id: Uuid,
    name: String,
    installations: i64,
    created_at: chrono::DateTime<Utc>,
}

async fn list_teams(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<TeamResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let teams = sqlx::query_as::<_, (Uuid, String, i64, chrono::DateTime<Utc>)>(
        "SELECT t.id, t.name, COUNT(i.id) FILTER (WHERE i.revoked_at IS NULL), t.created_at FROM teams t LEFT JOIN installations i ON i.team_id = t.id WHERE t.organization_id = $1 GROUP BY t.id, t.name, t.created_at ORDER BY t.name",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        teams
            .into_iter()
            .map(|(id, name, installations, created_at)| TeamResponse {
                id,
                name,
                installations,
                created_at,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct TeamRequest {
    name: String,
}

fn validated_team_name(name: &str) -> Result<&str, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 80 {
        return Err(ApiError::bad_request(
            "team name must be between 1 and 80 characters",
        ));
    }
    Ok(trimmed)
}

async fn create_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<TeamRequest>,
) -> Result<(StatusCode, Json<TeamResponse>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let name = validated_team_name(&request.name)?;
    let created = sqlx::query_as::<_, (Uuid, chrono::DateTime<Utc>)>(
        "INSERT INTO teams(organization_id, name) VALUES ($1,$2) ON CONFLICT (organization_id, name) DO NOTHING RETURNING id, created_at",
    )
    .bind(organization_id)
    .bind(name)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::conflict("a team with this name already exists"))?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "team.create",
        "team",
        created.0.to_string(),
        serde_json::json!({"name": name}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(TeamResponse {
            id: created.0,
            name: name.to_string(),
            installations: 0,
            created_at: created.1,
        }),
    ))
}

async fn update_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<TeamRequest>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let name = validated_team_name(&request.name)?;
    let updated = sqlx::query("UPDATE teams SET name = $3 WHERE id = $1 AND organization_id = $2")
        .bind(id)
        .bind(organization_id)
        .bind(name)
        .execute(&state.postgres)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("team not found"));
    }
    // Keep the denormalized key in sync so future uploads carry the new name.
    sqlx::query("UPDATE installations SET team_key = $2 WHERE team_id = $1")
        .bind(id)
        .bind(name)
        .execute(&state.postgres)
        .await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "team.rename",
        "team",
        id.to_string(),
        serde_json::json!({"name": name}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_team(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let mut transaction = state.postgres.begin().await?;
    let owned = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM teams
         WHERE id = $1 AND organization_id = $2
         FOR UPDATE",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if owned.is_none() {
        return Err(ApiError::not_found("team not found"));
    }
    sqlx::query(
        "UPDATE installations SET team_key = NULL
         WHERE team_id = $1 AND organization_id = $2",
    )
    .bind(id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("DELETE FROM teams WHERE id = $1 AND organization_id = $2")
        .bind(id)
        .bind(organization_id)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "team.delete",
        "team",
        id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallationResponse {
    id: Uuid,
    name: String,
    team_id: Option<Uuid>,
    team_name: Option<String>,
    created_at: chrono::DateTime<Utc>,
    last_seen_at: Option<chrono::DateTime<Utc>>,
    last_client_version: Option<String>,
    revoked: bool,
}

async fn list_installations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InstallationResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<Uuid>,
            Option<String>,
            chrono::DateTime<Utc>,
            Option<chrono::DateTime<Utc>>,
            Option<String>,
            bool,
        ),
    >(
        "SELECT i.id, i.name, i.team_id, t.name, i.created_at, i.last_seen_at,
                i.last_client_version, i.revoked_at IS NOT NULL
         FROM installations i LEFT JOIN teams t ON t.id = i.team_id
         WHERE i.organization_id = $1 ORDER BY i.created_at DESC LIMIT 500",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(
                    id,
                    name,
                    team_id,
                    team_name,
                    created_at,
                    last_seen_at,
                    last_client_version,
                    revoked,
                )| {
                    InstallationResponse {
                        id,
                        name,
                        team_id,
                        team_name,
                        created_at,
                        last_seen_at,
                        last_client_version,
                        revoked,
                    }
                },
            )
            .collect(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstallationUpdateRequest {
    team_id: Option<Uuid>,
}

async fn update_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<InstallationUpdateRequest>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let team_name: Option<String> = match request.team_id {
        Some(team_id) => Some(
            sqlx::query_scalar("SELECT name FROM teams WHERE id = $1 AND organization_id = $2")
                .bind(team_id)
                .bind(organization_id)
                .fetch_optional(&state.postgres)
                .await?
                .ok_or(ApiError::bad_request(
                    "team does not exist in this organization",
                ))?,
        ),
        None => None,
    };
    let updated = sqlx::query(
        "UPDATE installations SET team_id = $3, team_key = $4 WHERE id = $1 AND organization_id = $2",
    )
    .bind(id)
    .bind(organization_id)
    .bind(request.team_id)
    .bind(&team_name)
    .execute(&state.postgres)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("installation not found"));
    }
    audit(
        &state,
        organization_id,
        &auth.name,
        "installation.assign_team",
        "installation",
        id.to_string(),
        serde_json::json!({"teamId": request.team_id, "team": team_name}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SettingsResponse {
    organization_name: String,
    retention_days: i32,
    sso_enforced: bool,
    local_login_enabled: bool,
}

async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SettingsResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let row = sqlx::query_as::<_, (String, i32)>(
        "SELECT name, retention_days FROM organizations WHERE id = $1",
    )
    .bind(auth.organization_uuid()?)
    .fetch_one(&state.postgres)
    .await?;
    Ok(Json(SettingsResponse {
        organization_name: row.0,
        retention_days: row.1,
        sso_enforced: state.oidc.is_some(),
        local_login_enabled: state.oidc.is_none(),
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SettingsUpdateRequest {
    retention_days: i32,
}

async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SettingsUpdateRequest>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    if !(1..=3650).contains(&request.retention_days) {
        return Err(ApiError::bad_request(
            "retention_days must be between 1 and 3650",
        ));
    }
    sqlx::query("UPDATE organizations SET retention_days = $2 WHERE id = $1")
        .bind(organization_id)
        .bind(request.retention_days)
        .execute(&state.postgres)
        .await?;
    // Restamp stored snapshots so the new retention applies to existing data
    // too. Values are validated primitives, safe to inline in the mutation.
    let days = request.retention_days as u32;
    state
        .clickhouse
        .query(&format!(
            "ALTER TABLE session_snapshots_dedup UPDATE retention_days = {days} WHERE organization_id = '{organization_id}'"
        ))
        .execute()
        .await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "org.update_retention",
        "organization",
        organization_id.to_string(),
        serde_json::json!({"retentionDays": request.retention_days}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierSettingsResponse {
    enabled: bool,
    execution_mode: ClassifierExecutionMode,
    provider_id: String,
    protocol: String,
    endpoint: String,
    model: String,
    credential_id: String,
    config_version: String,
    credential_available: bool,
    response_mode: ResponseMode,
}

async fn get_classifier_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ClassifierSettingsResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let row = sqlx::query_as::<_, (
        bool,
        bool,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    )>(
        "SELECT classifier_configured, classifier_enabled, classifier_provider_id, classifier_endpoint,
                classifier_model, classifier_credential_id, classifier_config_version,
                classifier_protocol, classifier_response_mode, classifier_execution_mode
         FROM organizations WHERE id = $1",
    )
    .bind(auth.organization_uuid()?)
    .fetch_one(&state.postgres)
    .await?;
    if !row.0 {
        if let Some(config) = &state.classifier {
            return Ok(Json(ClassifierSettingsResponse {
                enabled: true,
                execution_mode: config.execution_mode,
                provider_id: config.provider_id.clone(),
                protocol: "openai_chat".into(),
                endpoint: config.endpoint.clone(),
                model: config.model.clone(),
                credential_id: config.credential_id.clone(),
                config_version: config.config_version.clone(),
                credential_available: config.api_key.is_some(),
                response_mode: config.response_mode,
            }));
        }
    }
    let stored_credential = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM provider_credentials
            WHERE organization_id = $1 AND credential_id = $2
              AND revoked_at IS NULL AND grace_until IS NULL
         )",
    )
    .bind(auth.organization_uuid()?)
    .bind(&row.5)
    .fetch_one(&state.postgres)
    .await?;
    let credential_available = stored_credential
        || state
            .classifier
            .as_ref()
            .is_some_and(|config| config.api_key.is_some() && config.credential_id == row.5);
    Ok(Json(ClassifierSettingsResponse {
        enabled: row.1,
        execution_mode: parse_classifier_execution_mode(&row.9),
        provider_id: row.2,
        protocol: row.7,
        endpoint: row.3,
        model: row.4,
        credential_id: row.5,
        config_version: row.6,
        credential_available,
        response_mode: parse_response_mode(&row.8),
    }))
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierSettingsUpdateRequest {
    enabled: bool,
    #[serde(default)]
    execution_mode: ClassifierExecutionMode,
    provider_id: String,
    endpoint: String,
    model: String,
    credential_id: String,
    #[serde(default)]
    response_mode: Option<ResponseMode>,
}

struct ResolvedProviderConfig {
    provider_id: String,
    protocol: String,
    endpoint: String,
    model: String,
    credential_id: String,
    response_mode: ResponseMode,
}

/// Returns the `host[:port]` authority of an absolute URL.
fn url_authority(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn is_loopback_authority(authority: &str) -> bool {
    // Userinfo can disguise the real host (`localhost@evil.example`), so an
    // authority carrying any is refused rather than parsed.
    if authority.contains('@') {
        return false;
    }
    let host = match authority.rsplit_once(':') {
        // Only a trailing `:<digits>` is a port; IPv6 literals keep brackets.
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => authority,
    };
    matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "[::1]"
    )
}

/// In managed mode the server itself calls this endpoint, so cleartext is
/// confined to the loopback interface. The host must be compared exactly: a
/// `starts_with("http://localhost")` prefix test also accepts
/// `http://localhost.attacker.example`, which is neither local nor encrypted.
fn endpoint_transport_is_allowed(endpoint: &str) -> bool {
    if endpoint.starts_with("https://") {
        return url_authority(endpoint).is_some_and(|authority| !authority.is_empty());
    }
    endpoint.starts_with("http://") && url_authority(endpoint).is_some_and(is_loopback_authority)
}

fn resolve_provider_config(
    request: &ClassifierSettingsUpdateRequest,
) -> Result<ResolvedProviderConfig, ApiError> {
    let provider_id = request.provider_id.trim().to_ascii_lowercase();
    let model = request.model.trim().to_string();
    let credential_id = request.credential_id.trim().to_string();
    let (endpoint, response_mode): (String, ResponseMode) = match provider_id.as_str() {
        "openrouter" => (
            "https://openrouter.ai/api/v1/chat/completions".into(),
            request.response_mode.unwrap_or(ResponseMode::Auto),
        ),
        "openai" => (
            "https://api.openai.com/v1/chat/completions".into(),
            request.response_mode.unwrap_or(ResponseMode::Auto),
        ),
        "ollama" => (
            "http://localhost:11434/v1/chat/completions".into(),
            ResponseMode::PromptJson,
        ),
        "custom" | "openai-compatible" => {
            let endpoint = request.endpoint.trim();
            if endpoint.is_empty() {
                return Err(ApiError::bad_request(
                    "an endpoint is required for a custom provider",
                ));
            }
            (endpoint.into(), ResponseMode::PromptJson)
        }
        _ => {
            return Err(ApiError::bad_request(
                "provider must be openrouter, openai, ollama, or custom",
            ));
        }
    };
    if model.is_empty() {
        return Err(ApiError::bad_request("model is required"));
    }
    if !endpoint_transport_is_allowed(&endpoint) {
        return Err(ApiError::bad_request(
            "endpoint must use HTTPS, or HTTP on localhost",
        ));
    }
    Ok(ResolvedProviderConfig {
        provider_id: if provider_id == "openai-compatible" {
            "custom".into()
        } else {
            provider_id
        },
        protocol: "openai_chat".into(),
        endpoint,
        model,
        credential_id,
        response_mode,
    })
}

fn parse_response_mode(value: &str) -> ResponseMode {
    serde_json::from_value(serde_json::Value::String(value.to_string())).unwrap_or_default()
}

async fn update_classifier_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClassifierSettingsUpdateRequest>,
) -> Result<Json<ClassifierSettingsResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let resolved = if request.enabled {
        Some(resolve_provider_config(&request)?)
    } else {
        None
    };
    let config_version = format!("org-{}", Utc::now().timestamp_millis());
    let organization_id = auth.organization_uuid()?;
    let provider_id = resolved
        .as_ref()
        .map(|config| config.provider_id.as_str())
        .unwrap_or("");
    let protocol = resolved
        .as_ref()
        .map(|config| config.protocol.as_str())
        .unwrap_or("openai_chat");
    let endpoint = resolved
        .as_ref()
        .map(|config| config.endpoint.as_str())
        .unwrap_or("");
    let model = resolved
        .as_ref()
        .map(|config| config.model.as_str())
        .unwrap_or("");
    let credential_id = resolved
        .as_ref()
        .map(|config| config.credential_id.as_str())
        .unwrap_or("");
    let response_mode = resolved
        .as_ref()
        .map(|config| config.response_mode)
        .unwrap_or(ResponseMode::PromptJson);
    sqlx::query(
        "UPDATE organizations
         SET classifier_configured = TRUE, classifier_enabled = $2, classifier_provider_id = $3,
             classifier_endpoint = $4, classifier_model = $5,
             classifier_credential_id = $6, classifier_config_version = $7,
             classifier_protocol = $8, classifier_response_mode = $9,
             classifier_execution_mode = $10
         WHERE id = $1",
    )
    .bind(organization_id)
    .bind(request.enabled)
    .bind(provider_id)
    .bind(endpoint)
    .bind(model)
    .bind(credential_id)
    .bind(&config_version)
    .bind(protocol)
    .bind(response_mode.to_string())
    .bind(request.execution_mode.as_str())
    .execute(&state.postgres)
    .await?;
    let stored_credential = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM provider_credentials
            WHERE organization_id = $1 AND credential_id = $2
              AND revoked_at IS NULL AND grace_until IS NULL
         )",
    )
    .bind(organization_id)
    .bind(credential_id)
    .fetch_one(&state.postgres)
    .await?;
    let credential_available = stored_credential
        || state.classifier.as_ref().is_some_and(|config| {
            config.api_key.is_some() && config.credential_id == credential_id
        });
    audit(
        &state,
        organization_id,
        &auth.name,
        "org.update_classifier",
        "organization",
        organization_id.to_string(),
        serde_json::json!({
            "enabled": request.enabled,
            "executionMode": request.execution_mode.as_str(),
            "providerId": provider_id,
            "endpoint": endpoint,
            "model": model,
            "credentialId": credential_id,
        }),
    )
    .await;
    Ok(Json(ClassifierSettingsResponse {
        enabled: request.enabled,
        execution_mode: request.execution_mode,
        provider_id: provider_id.into(),
        protocol: protocol.into(),
        endpoint: endpoint.into(),
        model: model.into(),
        credential_id: credential_id.into(),
        config_version,
        credential_available,
        response_mode,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ClassifierTestResponse {
    category: String,
    confidence: f32,
    response_mode: ResponseMode,
    repaired: bool,
}

async fn test_classifier_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ClassifierSettingsUpdateRequest>,
) -> Result<Json<ClassifierTestResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let config = resolve_provider_config(&request)?;
    let organization_id = auth.organization_uuid()?;
    let (stored_credential, _) =
        active_classifier_credential(&state, organization_id, &config.credential_id).await?;
    let credential = stored_credential.or_else(|| {
        state
            .classifier
            .as_ref()
            .filter(|fallback| fallback.credential_id == config.credential_id)
            .and_then(|fallback| fallback.api_key.clone())
    });
    if matches!(config.provider_id.as_str(), "openrouter" | "openai") && credential.is_none() {
        return Err(ApiError::bad_request(
            "select or create a provider credential before testing",
        ));
    }
    let classifier = OpenAiCompatibleClassifier::new(
        config.endpoint,
        config.model,
        credential,
        config.response_mode,
    )?;
    let diagnostic = classifier
        .classify_with_diagnostics(
            "A coding agent investigated a failing test, identified the defect, and corrected the implementation.",
        )
        .await
        .map_err(|_| ApiError::bad_gateway("classifier request failed"))?;
    Ok(Json(ClassifierTestResponse {
        category: diagnostic.assignment.category_id.as_str().into(),
        confidence: diagnostic.assignment.confidence,
        response_mode: diagnostic.response_mode,
        repaired: diagnostic.repaired,
    }))
}

fn credential_aad(organization_id: Uuid, credential_id: &str, version: i32) -> String {
    format!("{organization_id}:{credential_id}:{version}")
}

/// Re-seals credentials written before per-organization key derivation under
/// their organization's key. Runs once per deployment: after it completes no
/// stored ciphertext is readable with the master key alone.
///
/// A row that fails to decrypt is left alone and reported rather than dropped,
/// because the master key file may legitimately have been replaced.
pub(crate) async fn rewrap_legacy_credentials(state: &AppState) -> anyhow::Result<()> {
    let legacy = sqlx::query_as::<_, (Uuid, Uuid, String, i32, Vec<u8>, Vec<u8>)>(
        "SELECT id, organization_id, credential_id, version, ciphertext, nonce
         FROM provider_credentials
         WHERE key_derivation = $1
         ORDER BY created_at",
    )
    .bind(KEY_DERIVATION_MASTER)
    .fetch_all(&state.postgres)
    .await?;
    if legacy.is_empty() {
        return Ok(());
    }
    let total = legacy.len();
    let mut rewrapped = 0_usize;
    let mut failed = 0_usize;
    for (id, organization_id, credential_id, version, ciphertext, nonce) in legacy {
        let aad = credential_aad(organization_id, &credential_id, version);
        let secret = match state.vault.decrypt(
            organization_id,
            KEY_DERIVATION_MASTER,
            &ciphertext,
            &nonce,
            aad.as_bytes(),
        ) {
            Ok(secret) => secret,
            Err(error) => {
                failed += 1;
                tracing::warn!(
                    credential_id,
                    %organization_id,
                    %error,
                    "leaving a provider credential sealed under the master key; it did not decrypt"
                );
                continue;
            }
        };
        let (ciphertext, nonce) = state
            .vault
            .encrypt(organization_id, &secret, aad.as_bytes())?;
        sqlx::query(
            "UPDATE provider_credentials
             SET ciphertext = $2, nonce = $3, key_derivation = $4
             WHERE id = $1 AND key_derivation = $5",
        )
        .bind(id)
        .bind(ciphertext)
        .bind(nonce)
        .bind(KEY_DERIVATION_ORGANIZATION)
        .bind(KEY_DERIVATION_MASTER)
        .execute(&state.postgres)
        .await?;
        rewrapped += 1;
    }
    tracing::info!(
        total,
        rewrapped,
        failed,
        "re-sealed provider credentials under per-organization keys"
    );
    Ok(())
}

async fn active_classifier_credential(
    state: &AppState,
    organization_id: Uuid,
    credential_id: &str,
) -> Result<(Option<String>, Option<i32>), ApiError> {
    if credential_id.is_empty() {
        return Ok((None, None));
    }
    let stored = sqlx::query_as::<_, (i32, Vec<u8>, Vec<u8>, i16)>(
        "SELECT version, ciphertext, nonce, key_derivation FROM provider_credentials
         WHERE organization_id = $1 AND credential_id = $2
           AND revoked_at IS NULL AND grace_until IS NULL
         ORDER BY version DESC LIMIT 1",
    )
    .bind(organization_id)
    .bind(credential_id)
    .fetch_optional(&state.postgres)
    .await?;
    let Some((version, ciphertext, nonce, derivation)) = stored else {
        return Ok((None, None));
    };
    let aad = credential_aad(organization_id, credential_id, version);
    Ok((
        Some(state.vault.decrypt(
            organization_id,
            derivation,
            &ciphertext,
            &nonce,
            aad.as_bytes(),
        )?),
        Some(version),
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CredentialResponse {
    credential_id: String,
    provider_id: String,
    version: i32,
    created_at: chrono::DateTime<Utc>,
    clients_on_version: i64,
}

async fn list_credentials(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<CredentialResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let rows = sqlx::query_as::<_, (String, String, i32, chrono::DateTime<Utc>, i64)>(
        "SELECT c.credential_id, c.provider_id, c.version, c.created_at,
                COUNT(i.id)::BIGINT
         FROM provider_credentials c
         LEFT JOIN installations i ON i.organization_id = c.organization_id
           AND i.classifier_credential_id = c.credential_id
           AND i.classifier_credential_version = c.version
         WHERE c.organization_id = $1 AND c.revoked_at IS NULL
           AND c.grace_until IS NULL
         GROUP BY c.credential_id, c.provider_id, c.version, c.created_at
         ORDER BY c.credential_id",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| CredentialResponse {
                credential_id: row.0,
                provider_id: row.1,
                version: row.2,
                created_at: row.3,
                clients_on_version: row.4,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CredentialUpsertRequest {
    credential_id: String,
    provider_id: String,
    secret: String,
    #[serde(default = "default_grace_hours")]
    grace_hours: i64,
}

fn default_grace_hours() -> i64 {
    24
}

async fn upsert_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CredentialUpsertRequest>,
) -> Result<Json<CredentialResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let credential_id = request.credential_id.trim();
    let provider_id = request.provider_id.trim();
    if credential_id.is_empty() || provider_id.is_empty() || request.secret.trim().is_empty() {
        return Err(ApiError::bad_request(
            "credential ID, provider, and secret are required",
        ));
    }
    if !(0..=168).contains(&request.grace_hours) {
        return Err(ApiError::bad_request(
            "grace_hours must be between 0 and 168",
        ));
    }
    let organization_id = auth.organization_uuid()?;
    let mut transaction = state.postgres.begin().await?;
    let version = sqlx::query_scalar::<_, i32>(
        "SELECT version FROM provider_credentials
         WHERE organization_id = $1 AND credential_id = $2
         ORDER BY version DESC LIMIT 1 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(credential_id)
    .fetch_optional(&mut *transaction)
    .await?
    .unwrap_or(0)
        + 1;
    let aad = credential_aad(organization_id, credential_id, version);
    let (ciphertext, nonce) =
        state
            .vault
            .encrypt(organization_id, &request.secret, aad.as_bytes())?;
    sqlx::query(
        "UPDATE provider_credentials
         SET grace_until = NOW() + ($3 * INTERVAL '1 hour')
         WHERE organization_id = $1 AND credential_id = $2
           AND revoked_at IS NULL AND grace_until IS NULL",
    )
    .bind(organization_id)
    .bind(credential_id)
    .bind(request.grace_hours)
    .execute(&mut *transaction)
    .await?;
    let id = Uuid::new_v4();
    let created_at = Utc::now();
    sqlx::query(
        "INSERT INTO provider_credentials(
            id, organization_id, credential_id, provider_id, version,
            ciphertext, nonce, created_by, created_at, key_derivation
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(id)
    .bind(organization_id)
    .bind(credential_id)
    .bind(provider_id)
    .bind(version)
    .bind(ciphertext)
    .bind(nonce)
    .bind(user_id)
    .bind(created_at)
    .bind(KEY_DERIVATION_ORGANIZATION)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "credential.rotate",
        "provider_credential",
        credential_id.to_string(),
        serde_json::json!({"providerId": provider_id, "version": version}),
    )
    .await;
    Ok(Json(CredentialResponse {
        credential_id: credential_id.into(),
        provider_id: provider_id.into(),
        version,
        created_at,
        clients_on_version: 0,
    }))
}

async fn revoke_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(credential_id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    sqlx::query(
        "UPDATE provider_credentials SET revoked_at = NOW()
         WHERE organization_id = $1 AND credential_id = $2 AND revoked_at IS NULL",
    )
    .bind(organization_id)
    .bind(&credential_id)
    .execute(&state.postgres)
    .await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "credential.revoke",
        "provider_credential",
        credential_id,
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct RecoveryRequest {
    password: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryResponse {
    recovery_key: String,
}

async fn export_recovery_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RecoveryRequest>,
) -> Result<(HeaderMap, Json<RecoveryResponse>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    state.rate_limiter.check(
        "vault-recovery",
        &auth.subject,
        state.rate_limits.vault_recovery,
    )?;
    let organization_id = auth.organization_uuid()?;
    if state.oidc.is_some() {
        if request.password.is_some() {
            return Err(ApiError::bad_request(
                "password reauthentication is unavailable while single sign-on is configured",
            ));
        }
        let session = user_session_auth(&state, &headers).await?;
        let recently_authenticated = sqlx::query_scalar::<_, bool>(
            "SELECT authentication_method = 'oidc'
                    AND created_at > NOW() - INTERVAL '10 minutes'
             FROM web_sessions
             WHERE id = $1 AND user_id = $2",
        )
        .bind(session.session_id)
        .bind(user_id)
        .fetch_one(&state.postgres)
        .await?;
        if !recently_authenticated {
            return Err(ApiError::unauthorized(
                "a recent single sign-on is required to export the recovery key",
            ));
        }
    } else {
        let password_hash = sqlx::query_scalar::<_, Option<String>>(
            "SELECT password_hash FROM users WHERE id = $1 AND disabled_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(&state.postgres)
        .await?
        .ok_or(ApiError::unauthorized(
            "local password verification is unavailable",
        ))?;
        let password = request.password.clone().ok_or(ApiError::bad_request(
            "password is required for local reauthentication",
        ))?;
        let password_valid = tokio::task::spawn_blocking(move || {
            PasswordHash::new(&password_hash).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
            })
        })
        .await?;
        if !password_valid {
            return Err(ApiError::unauthorized("password verification failed"));
        }
    }
    let inserted = sqlx::query(
        "INSERT INTO vault_recovery_exports(organization_id, exported_by, key_derivation)
         VALUES ($1,$2,$3) ON CONFLICT (organization_id) DO NOTHING",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(KEY_DERIVATION_ORGANIZATION)
    .execute(&state.postgres)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::bad_request(
            "the recovery key has already been exported",
        ));
    }
    audit(
        &state,
        organization_id,
        &auth.name,
        "vault.export_recovery_key",
        "organization",
        organization_id.to_string(),
        serde_json::json!({"scope": "organization"}),
    )
    .await;
    Ok((
        no_store_headers(),
        Json(RecoveryResponse {
            recovery_key: state.vault.recovery_key(organization_id),
        }),
    ))
}

async fn apply_server_prices(
    state: &AppState,
    organization_id: Uuid,
    snapshot: &mut SessionSnapshot,
) -> anyhow::Result<()> {
    for slice in &mut snapshot.usage_by_model {
        if slice.cost.kind == CostKind::Reported {
            continue;
        }
        let provider_id = slice.provider_id.trim().to_ascii_lowercase();
        let model_id = canonical_model_id(&slice.model_id);
        let price = sqlx::query_as::<_, (String, f64, f64, f64, f64, f64, String, String)>(
            "SELECT currency, input_per_million, output_per_million,
                    cache_read_per_million, cache_write_per_million,
                    reasoning_per_million, authority, catalog_version
             FROM model_prices
             WHERE (organization_id = $1 OR organization_id IS NULL)
               AND LOWER(provider_id) = $2 AND LOWER(model_id) = $3
               AND effective_from <= NOW()
               AND (effective_until IS NULL OR effective_until > NOW())
             ORDER BY
               (organization_id IS NOT NULL) DESC,
               CASE authority
                 WHEN 'organization_override' THEN 60
                 WHEN 'self_hosted' THEN 50
                 WHEN 'official_provider' THEN 40
                 WHEN 'openrouter' THEN 30
                 WHEN 'default_catalog' THEN 20
                 ELSE 10
               END DESC,
               effective_from DESC
             LIMIT 1",
        )
        .bind(organization_id)
        .bind(provider_id)
        .bind(model_id)
        .fetch_optional(&state.postgres)
        .await?;
        let Some(price) = price else {
            continue;
        };
        let million = 1_000_000.0;
        slice.cost.amount = (slice.tokens.input as f64 * price.1
            + slice.tokens.output as f64 * price.2
            + slice.tokens.cache_read as f64 * price.3
            + slice.tokens.cache_write as f64 * price.4
            + slice.tokens.reasoning as f64 * price.5)
            / million;
        slice.cost.currency = price.0;
        slice.cost.kind = CostKind::Estimated;
        slice.cost.price_source = Some(price.6);
        slice.cost.pricebook_version = Some(price.7);
    }
    for slice in &snapshot.usage_by_model {
        let mut matching = snapshot
            .turns
            .iter_mut()
            .flat_map(|turn| turn.model_activity.iter_mut())
            .filter(|step| {
                step.provider_id.eq_ignore_ascii_case(&slice.provider_id)
                    && canonical_model_id(&step.model_id) == canonical_model_id(&slice.model_id)
            })
            .collect::<Vec<_>>();
        if matching.is_empty() || slice.cost.kind == CostKind::Reported {
            continue;
        }
        let total_tokens = matching.iter().map(|step| step.tokens.total()).sum::<u64>();
        let mut assigned = 0.0;
        let last = matching.len().saturating_sub(1);
        for (index, step) in matching.iter_mut().enumerate() {
            let amount = if index == last {
                (slice.cost.amount - assigned).max(0.0)
            } else if total_tokens == 0 {
                0.0
            } else {
                slice.cost.amount * step.tokens.total() as f64 / total_tokens as f64
            };
            assigned += amount;
            step.cost = slice.cost.clone();
            step.cost.amount = amount;
        }
    }
    Ok(())
}

async fn reprice_unknown_history(state: &AppState) -> anyhow::Result<()> {
    let rows = state
        .clickhouse
        .query(
            "SELECT organization_id, installation_id, owner_user_id, session_key, revision,
                    user_key, project_key, project_alias, team_key, client_id,
                    started_at_ms, ended_at_ms, category_id, category_confidence,
                    taxonomy_version, classifier_id, classification_status, total_tokens, total_cost,
                    snapshot_json, ingested_at_ms, retention_days
             FROM session_snapshots_dedup FINAL
             WHERE position(snapshot_json, '\"kind\":\"unknown\"') > 0",
        )
        .fetch_all::<SnapshotRow>()
        .await?;
    if rows.is_empty() {
        return Ok(());
    }

    let mut insert = state
        .clickhouse
        .insert::<SnapshotRow>("session_snapshots_dedup")?;
    let mut updated = 0_u64;
    for mut row in rows {
        let organization_id = Uuid::parse_str(&row.organization_id)?;
        let mut snapshot: SessionSnapshot = serde_json::from_str(&row.snapshot_json)?;
        apply_server_prices(state, organization_id, &mut snapshot).await?;
        if !snapshot
            .usage_by_model
            .iter()
            .any(|slice| slice.cost.kind == CostKind::Estimated)
        {
            continue;
        }

        snapshot.revision = row.revision.saturating_add(1);
        row.revision = snapshot.revision;
        row.total_cost = snapshot.total_cost();
        row.snapshot_json = serde_json::to_string(&snapshot)?;
        row.ingested_at_ms = Utc::now().timestamp_millis();
        insert.write(&row).await?;
        updated += 1;
    }
    insert.end().await?;
    if updated > 0 {
        tracing::info!(snapshots = updated, "repriced historical snapshots");
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PriceResponse {
    id: Uuid,
    scope: String,
    provider_id: String,
    model_id: String,
    currency: String,
    price: ModelPrice,
    authority: String,
    catalog_version: String,
    effective_from: chrono::DateTime<Utc>,
    updated_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PriceRequest {
    provider_id: String,
    model_id: String,
    #[serde(default = "default_currency")]
    currency: String,
    #[serde(default)]
    input_per_million: f64,
    #[serde(default)]
    output_per_million: f64,
    #[serde(default)]
    cache_read_per_million: f64,
    #[serde(default)]
    cache_write_per_million: f64,
    #[serde(default)]
    reasoning_per_million: f64,
    #[serde(default)]
    request_per_request: f64,
    #[serde(default)]
    image_per_image: f64,
    #[serde(default = "default_price_authority")]
    authority: String,
}

fn default_currency() -> String {
    "USD".into()
}

fn default_price_authority() -> String {
    "organization_override".into()
}

fn validate_price_request(request: &PriceRequest) -> Result<(), ApiError> {
    if request.provider_id.trim().is_empty()
        || request.model_id.trim().is_empty()
        || request.provider_id.chars().count() > 120
        || request.model_id.chars().count() > 240
    {
        return Err(ApiError::bad_request(
            "providerId and modelId are required and must fit within their limits",
        ));
    }
    if request.currency.trim().len() != 3 {
        return Err(ApiError::bad_request(
            "currency must be a three-letter code",
        ));
    }
    if ![
        request.input_per_million,
        request.output_per_million,
        request.cache_read_per_million,
        request.cache_write_per_million,
        request.reasoning_per_million,
        request.request_per_request,
        request.image_per_image,
    ]
    .into_iter()
    .all(|value| value.is_finite() && value >= 0.0)
    {
        return Err(ApiError::bad_request(
            "all prices must be finite non-negative numbers",
        ));
    }
    if !matches!(
        request.authority.as_str(),
        "organization_override" | "self_hosted" | "official_provider" | "manual"
    ) {
        return Err(ApiError::bad_request("unsupported price authority"));
    }
    Ok(())
}

async fn list_prices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<PriceResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            Option<Uuid>,
            String,
            String,
            String,
            f64,
            f64,
            f64,
            f64,
            f64,
            f64,
            f64,
            String,
            String,
            chrono::DateTime<Utc>,
            chrono::DateTime<Utc>,
        ),
    >(
        "SELECT id, organization_id, provider_id, model_id, currency,
                input_per_million, output_per_million, cache_read_per_million,
                cache_write_per_million, reasoning_per_million,
                request_per_request, image_per_image, authority, catalog_version,
                effective_from, updated_at
         FROM model_prices
         WHERE (organization_id = $1 OR organization_id IS NULL)
           AND effective_from <= NOW()
           AND (effective_until IS NULL OR effective_until > NOW())
         ORDER BY provider_id, model_id, (organization_id IS NOT NULL) DESC, effective_from DESC
         LIMIT 2000",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| PriceResponse {
                id: row.0,
                scope: if row.1.is_some() {
                    "organization".into()
                } else {
                    "default".into()
                },
                provider_id: row.2,
                model_id: row.3,
                currency: row.4,
                price: ModelPrice {
                    input_per_million: row.5,
                    output_per_million: row.6,
                    cache_read_per_million: row.7,
                    cache_write_per_million: row.8,
                    reasoning_per_million: row.9,
                    request_per_request: row.10,
                    image_per_image: row.11,
                },
                authority: row.12,
                catalog_version: row.13,
                effective_from: row.14,
                updated_at: row.15,
            })
            .collect(),
    ))
}

async fn insert_org_price(
    state: &AppState,
    auth: &DashboardAuth,
    request: &PriceRequest,
) -> Result<PriceResponse, ApiError> {
    validate_price_request(request)?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::forbidden("user session required to edit pricing"))?;
    let organization_id = auth.organization_uuid()?;
    let now = Utc::now();
    let catalog_version = format!("org-{}", Uuid::new_v4().simple());
    let mut transaction = state.postgres.begin().await?;
    let response = insert_org_price_in_transaction(
        &mut transaction,
        organization_id,
        user_id,
        request,
        now,
        catalog_version,
    )
    .await?;
    transaction.commit().await?;
    audit(
        state,
        organization_id,
        &auth.name,
        "pricing.upsert",
        "model_price",
        response.id.to_string(),
        serde_json::json!({
            "providerId": response.provider_id,
            "modelId": response.model_id
        }),
    )
    .await;
    Ok(response)
}

async fn insert_org_price_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    user_id: Uuid,
    request: &PriceRequest,
    now: chrono::DateTime<Utc>,
    catalog_version: String,
) -> Result<PriceResponse, ApiError> {
    let provider_id = request.provider_id.trim().to_ascii_lowercase();
    let model_id = canonical_model_id(request.model_id.trim());
    sqlx::query(
        "UPDATE model_prices SET effective_until = $4, updated_at = $4
         WHERE organization_id = $1 AND provider_id = $2 AND model_id = $3
           AND effective_until IS NULL",
    )
    .bind(organization_id)
    .bind(&provider_id)
    .bind(&model_id)
    .bind(now)
    .execute(&mut **transaction)
    .await?;
    let row = sqlx::query_as::<_, (Uuid, chrono::DateTime<Utc>, chrono::DateTime<Utc>)>(
        "INSERT INTO model_prices(
           organization_id, provider_id, model_id, currency,
           input_per_million, output_per_million, cache_read_per_million,
           cache_write_per_million, reasoning_per_million,
           request_per_request, image_per_image, authority, catalog_version,
           effective_from, created_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
         RETURNING id, effective_from, updated_at",
    )
    .bind(organization_id)
    .bind(&provider_id)
    .bind(&model_id)
    .bind(request.currency.trim().to_ascii_uppercase())
    .bind(request.input_per_million)
    .bind(request.output_per_million)
    .bind(request.cache_read_per_million)
    .bind(request.cache_write_per_million)
    .bind(request.reasoning_per_million)
    .bind(request.request_per_request)
    .bind(request.image_per_image)
    .bind(&request.authority)
    .bind(&catalog_version)
    .bind(now)
    .bind(user_id)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(PriceResponse {
        id: row.0,
        scope: "organization".into(),
        provider_id,
        model_id,
        currency: request.currency.trim().to_ascii_uppercase(),
        price: ModelPrice {
            input_per_million: request.input_per_million,
            output_per_million: request.output_per_million,
            cache_read_per_million: request.cache_read_per_million,
            cache_write_per_million: request.cache_write_per_million,
            reasoning_per_million: request.reasoning_per_million,
            request_per_request: request.request_per_request,
            image_per_image: request.image_per_image,
        },
        authority: request.authority.clone(),
        catalog_version,
        effective_from: row.1,
        updated_at: row.2,
    })
}

async fn create_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PriceRequest>,
) -> Result<(StatusCode, Json<PriceResponse>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    Ok((
        StatusCode::CREATED,
        Json(insert_org_price(&state, &auth, &request).await?),
    ))
}

async fn update_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<PriceRequest>,
) -> Result<Json<PriceResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    validate_price_request(&request)?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::forbidden("user session required to edit pricing"))?;
    let organization_id = auth.organization_uuid()?;
    let now = Utc::now();
    let catalog_version = format!("org-{}", Uuid::new_v4().simple());
    let mut transaction = state.postgres.begin().await?;
    let owned = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM model_prices
         WHERE id = $1 AND organization_id = $2 AND effective_until IS NULL
         FOR UPDATE",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(&mut *transaction)
    .await?;
    if owned.is_none() {
        transaction.rollback().await.ok();
        return Err(ApiError::not_found("organization price not found"));
    }
    sqlx::query(
        "UPDATE model_prices SET effective_until = NOW(), updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND effective_until IS NULL",
    )
    .bind(id)
    .bind(organization_id)
    .execute(&mut *transaction)
    .await?;
    let response = insert_org_price_in_transaction(
        &mut transaction,
        organization_id,
        user_id,
        &request,
        now,
        catalog_version,
    )
    .await?;
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &auth.name,
        "pricing.upsert",
        "model_price",
        response.id.to_string(),
        serde_json::json!({
            "providerId": response.provider_id,
            "modelId": response.model_id,
            "replacedId": id
        }),
    )
    .await;
    Ok(Json(response))
}

async fn delete_price(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::forbidden("user session required to edit pricing"))?;
    let organization_id = auth.organization_uuid()?;
    let updated = sqlx::query(
        "UPDATE model_prices SET effective_until = NOW(), updated_at = NOW(), created_by = $3
         WHERE id = $1 AND organization_id = $2 AND effective_until IS NULL",
    )
    .bind(id)
    .bind(organization_id)
    .bind(user_id)
    .execute(&state.postgres)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("organization price not found"));
    }
    audit(
        &state,
        organization_id,
        &auth.name,
        "pricing.delete",
        "model_price",
        id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MyUsageResponse {
    overview: OverviewRow,
    providers: Vec<BreakdownRow>,
    models: Vec<BreakdownRow>,
    clients: Vec<BreakdownRow>,
    categories: Vec<BreakdownRow>,
    timeseries: Vec<TimeseriesRow>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MyUsageQuery {
    installation_id: Option<Uuid>,
}

fn personal_usage_suffix(filter_installation: bool) -> String {
    let installation_filter = if filter_installation {
        " AND installation_id = ?"
    } else {
        ""
    };
    format!(
        " WHERE organization_id = ? AND owner_user_id = ? AND ended_at_ms >= toUnixTimestamp(parseDateTimeBestEffort(?)) * 1000 AND ended_at_ms < (toUnixTimestamp(parseDateTimeBestEffort(?)) + 86400) * 1000{installation_filter}"
    )
}

async fn verify_owned_installation(
    state: &AppState,
    organization_id: &str,
    user_id: Uuid,
    installation_id: Uuid,
) -> Result<(), ApiError> {
    let owned = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
            SELECT 1 FROM installations
            WHERE id = $1 AND organization_id = $2::uuid AND owner_user_id = $3
        )",
    )
    .bind(installation_id)
    .bind(organization_id)
    .bind(user_id)
    .fetch_one(&state.postgres)
    .await?;
    if !owned {
        return Err(ApiError::not_found("owned installation not found"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MySessionsQuery {
    installation_id: Option<Uuid>,
    from: Option<String>,
    to: Option<String>,
    category: Option<String>,
    client: Option<String>,
    project: Option<String>,
    status: Option<String>,
    workflow: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
    sort: Option<String>,
}

async fn my_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MySessionsQuery>,
) -> Result<Json<Vec<SessionRow>>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    if let Some(installation_id) = query.installation_id {
        verify_owned_installation(&state, &auth.organization_id, user_id, installation_id).await?;
    }
    let from = query.from.clone().unwrap_or_else(|| {
        (Utc::now() - Duration::days(29))
            .format("%Y-%m-%d")
            .to_string()
    });
    let to = query
        .to
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let order = match query.sort.as_deref() {
        Some("cost") => "total_cost DESC",
        Some("tokens") => "total_tokens DESC",
        Some("category") => "category_id ASC, ended_at_ms DESC",
        _ => "ended_at_ms DESC",
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    // ClickHouse still scans every row it skips, so an unbounded offset is a
    // cheap way to make the server do expensive work.
    let offset = query.offset.unwrap_or(0).min(MAX_SESSION_PAGE_OFFSET);
    let mut sql = format!(
        "SELECT session_key, installation_id, client_id, project_alias, category_id, category_confidence, classification_status, total_tokens, total_cost, ended_at_ms FROM session_snapshots_dedup FINAL{}",
        personal_usage_suffix(query.installation_id.is_some())
    );
    for (value, column) in [
        (&query.category, "category_id"),
        (&query.client, "client_id"),
        (&query.project, "project_alias"),
        (&query.status, "classification_status"),
    ] {
        if value.is_some() {
            sql.push_str(&format!(" AND {column} = ?"));
        }
    }
    if query.workflow.is_some() {
        sql.push_str(" AND arrayExists(turn -> arrayExists(signal -> JSONExtractString(signal, 'signal') = ?, JSONExtractArrayRaw(turn, 'workflowSignals')), JSONExtractArrayRaw(snapshot_json, 'turns'))");
    }
    sql.push_str(&format!(" ORDER BY {order} LIMIT {limit} OFFSET {offset}"));
    let mut q = state
        .clickhouse
        .query(&sql)
        .bind(&auth.organization_id)
        .bind(user_id.to_string())
        .bind(&from)
        .bind(&to);
    if let Some(installation_id) = &query.installation_id {
        q = q.bind(installation_id.to_string());
    }
    for value in [
        &query.category,
        &query.client,
        &query.project,
        &query.status,
    ]
    .into_iter()
    .flatten()
    {
        q = q.bind(value);
    }
    if let Some(workflow) = &query.workflow {
        q = q.bind(workflow);
    }
    Ok(Json(q.fetch_all::<SessionRow>().await?))
}

async fn my_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<MyUsageQuery>,
) -> Result<Json<MyUsageResponse>, ApiError> {
    let auth = analytics_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let organization_id = auth.organization_id;
    let owner = user_id.to_string();
    let installation = query.installation_id.map(|id| id.to_string());
    if let Some(installation_id) = query.installation_id {
        verify_owned_installation(&state, &organization_id, user_id, installation_id).await?;
    }
    let from = (Utc::now() - Duration::days(29))
        .format("%Y-%m-%d")
        .to_string();
    let to = Utc::now().format("%Y-%m-%d").to_string();
    let suffix = personal_usage_suffix(installation.is_some());
    let bind = |query: clickhouse::query::Query| {
        let query = query
            .bind(&organization_id)
            .bind(&owner)
            .bind(&from)
            .bind(&to);
        if let Some(installation_id) = &installation {
            query.bind(installation_id)
        } else {
            query
        }
    };
    let overview_sql = format!(
        "SELECT toUInt64(sum(total_tokens)) total_tokens, sum(total_cost) total_cost, toUInt64(count()) sessions, toUInt64(1) active_users FROM session_snapshots_dedup FINAL{suffix}"
    );
    let overview = bind(state.clickhouse.query(&overview_sql))
        .fetch_one::<OverviewRow>()
        .await?;
    let timeseries_sql = format!(
        "SELECT formatDateTime(toDateTime(ended_at_ms/1000), '%Y-%m-%d') bucket, toUInt64(sum(total_tokens)) tokens, sum(total_cost) cost, toUInt64(count()) sessions FROM session_snapshots_dedup FINAL{suffix} GROUP BY bucket ORDER BY bucket"
    );
    let timeseries = bind(state.clickhouse.query(&timeseries_sql))
        .fetch_all::<TimeseriesRow>()
        .await?;
    let breakdown = |dimension: &str, array_join: &str, tokens: &str, cost: &str, extra: &str| {
        let sql = format!(
            "SELECT {dimension} dimension, toUInt64(sum({tokens})) tokens, sum({cost}) cost, toUInt64(uniqExact(session_key)) sessions FROM session_snapshots_dedup FINAL {array_join}{suffix}{extra} GROUP BY dimension ORDER BY cost DESC LIMIT 50"
        );
        bind(state.clickhouse.query(&sql))
    };
    let providers = breakdown(
        "JSONExtractString(usage_slice, 'providerId')",
        "ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice",
        "JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning')",
        "JSONExtractFloat(usage_slice, 'cost', 'amount')",
        "",
    )
    .fetch_all::<BreakdownRow>()
    .await?;
    let models = breakdown(
        "concat(JSONExtractString(usage_slice, 'providerId'), '/', JSONExtractString(usage_slice, 'modelId'))",
        "ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice",
        "JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning')",
        "JSONExtractFloat(usage_slice, 'cost', 'amount')",
        "",
    )
    .fetch_all::<BreakdownRow>()
    .await?;
    let clients = breakdown("client_id", "", "total_tokens", "total_cost", "")
        .fetch_all::<BreakdownRow>()
        .await?;
    let categories = breakdown(
        "category_id",
        "",
        "total_tokens",
        "total_cost",
        " AND classification_status = 'classified'",
    )
    .fetch_all::<BreakdownRow>()
    .await?;
    Ok(Json(MyUsageResponse {
        overview,
        providers,
        models,
        clients,
        categories,
        timeseries,
    }))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MyInstallationResponse {
    id: Uuid,
    name: String,
    platform: String,
    team_name: Option<String>,
    created_at: chrono::DateTime<Utc>,
    last_seen_at: Option<chrono::DateTime<Utc>>,
    last_client_version: Option<String>,
    revoked: bool,
}

async fn my_installations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<MyInstallationResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            String,
            Option<String>,
            Option<String>,
            chrono::DateTime<Utc>,
            Option<chrono::DateTime<Utc>>,
            Option<String>,
            bool,
        ),
    >(
        "SELECT i.id, i.name, i.platform, t.name, i.created_at, i.last_seen_at,
                i.last_client_version, i.revoked_at IS NOT NULL
         FROM installations i LEFT JOIN teams t ON t.id = i.team_id
         WHERE i.owner_user_id = $1 AND i.organization_id = $2::uuid
         ORDER BY i.created_at DESC",
    )
    .bind(user_id)
    .bind(&auth.organization_id)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| MyInstallationResponse {
                id: row.0,
                name: row.1,
                platform: row.2.unwrap_or_else(|| "other".into()),
                team_name: row.3,
                created_at: row.4,
                last_seen_at: row.5,
                last_client_version: row.6,
                revoked: row.7,
            })
            .collect(),
    ))
}

async fn revoke_my_installation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let updated = sqlx::query(
        "UPDATE installations SET revoked_at = NOW()
         WHERE id = $1 AND owner_user_id = $2 AND organization_id = $3::uuid
           AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(user_id)
    .bind(&auth.organization_id)
    .execute(&state.postgres)
    .await?;
    if updated.rows_affected() == 0 {
        return Err(ApiError::not_found("active owned installation not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentCodeRequest {
    installation_name: String,
    platform: String,
    team_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentCodeResponse {
    code: String,
    expires_at: chrono::DateTime<Utc>,
    installation_name: String,
    platform: String,
}

async fn create_enrollment_code(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<EnrollmentCodeRequest>,
) -> Result<(StatusCode, HeaderMap, Json<EnrollmentCodeResponse>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    state.rate_limiter.check(
        "enrollment-code",
        &auth.subject,
        state.rate_limits.enrollment_code,
    )?;
    let organization_id = auth.organization_uuid()?;
    let installation_name = validate_installation_name(&request.installation_name)?;
    validate_platform(&request.platform)?;
    if let Some(team_id) = request.team_id {
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM teams WHERE id = $1 AND organization_id = $2)",
        )
        .bind(team_id)
        .bind(organization_id)
        .fetch_one(&state.postgres)
        .await?;
        if !exists {
            return Err(ApiError::bad_request(
                "team does not exist in this organization",
            ));
        }
    }
    let code = format!("mec_{}", Uuid::new_v4().simple());
    let expires_at = Utc::now() + Duration::minutes(10);
    sqlx::query(
        "INSERT INTO enrollment_codes(
           organization_id, owner_user_id, team_id, token_hash,
           installation_name, platform, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(request.team_id)
    .bind(token_hash(&code))
    .bind(installation_name)
    .bind(&request.platform)
    .bind(expires_at)
    .execute(&state.postgres)
    .await?;
    Ok((
        StatusCode::CREATED,
        no_store_headers(),
        Json(EnrollmentCodeResponse {
            code,
            expires_at,
            installation_name: installation_name.into(),
            platform: request.platform,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> SecretVault {
        SecretVault {
            key: [7_u8; 32],
            created: false,
        }
    }

    #[test]
    fn credential_vault_uses_authenticated_context() {
        let vault = test_vault();
        let organization = Uuid::from_u128(1);
        let (ciphertext, nonce) = vault
            .encrypt(organization, "provider-secret", b"org:credential:1")
            .expect("encrypt");
        assert_ne!(ciphertext, b"provider-secret");
        assert_eq!(
            vault
                .decrypt(
                    organization,
                    KEY_DERIVATION_ORGANIZATION,
                    &ciphertext,
                    &nonce,
                    b"org:credential:1"
                )
                .expect("decrypt"),
            "provider-secret"
        );
        assert!(vault
            .decrypt(
                organization,
                KEY_DERIVATION_ORGANIZATION,
                &ciphertext,
                &nonce,
                b"other-org:credential:1"
            )
            .is_err());
    }

    #[test]
    fn one_organization_cannot_decrypt_another_organizations_credential() {
        let vault = test_vault();
        let (alpha, beta) = (Uuid::from_u128(1), Uuid::from_u128(2));
        let aad = credential_aad(alpha, "openrouter", 1);
        let (ciphertext, nonce) = vault
            .encrypt(alpha, "alpha-secret", aad.as_bytes())
            .expect("encrypt");

        // The co-tenant's derived key must not open it even with the right AAD.
        assert!(vault
            .decrypt(
                beta,
                KEY_DERIVATION_ORGANIZATION,
                &ciphertext,
                &nonce,
                aad.as_bytes()
            )
            .is_err());
        // Neither may the deployment master key, which is what the exported
        // recovery key used to be.
        assert!(vault
            .decrypt(
                alpha,
                KEY_DERIVATION_MASTER,
                &ciphertext,
                &nonce,
                aad.as_bytes()
            )
            .is_err());
    }

    #[test]
    fn organization_keys_are_distinct_and_are_not_the_master_key() {
        let vault = test_vault();
        let alpha = vault.organization_key(Uuid::from_u128(1));
        let beta = vault.organization_key(Uuid::from_u128(2));
        assert_ne!(alpha, beta);
        assert_ne!(alpha, vault.key);
        // Derivation is deterministic, or a restart would orphan every secret.
        assert_eq!(alpha, vault.organization_key(Uuid::from_u128(1)));
    }

    #[test]
    fn an_exported_recovery_key_is_scoped_to_its_organization() {
        let vault = test_vault();
        let alpha = vault.recovery_key(Uuid::from_u128(1));
        assert!(alpha.starts_with("mvrk_"));
        assert_ne!(alpha, vault.recovery_key(Uuid::from_u128(2)));
        // The master key must never leave the deployment.
        assert_ne!(alpha, format!("mvrk_{}", URL_SAFE_NO_PAD.encode(vault.key)));
    }

    #[test]
    fn credentials_sealed_before_derivation_stay_readable() {
        let vault = test_vault();
        let organization = Uuid::from_u128(9);
        let aad = credential_aad(organization, "openrouter", 3);
        // A pre-migration row: sealed under the master key directly.
        let (ciphertext, nonce) =
            SecretVault::seal(&vault.key, "legacy-secret", aad.as_bytes()).expect("seal");
        assert_eq!(
            vault
                .decrypt(
                    organization,
                    KEY_DERIVATION_MASTER,
                    &ciphertext,
                    &nonce,
                    aad.as_bytes()
                )
                .expect("legacy rows must survive the migration"),
            "legacy-secret"
        );
    }

    #[test]
    fn rate_limiter_rejects_once_the_window_budget_is_spent() {
        let limiter = RateLimiter::default();
        let limit = RateLimit::new(60, 2);
        assert!(limiter.check("ingest", "installation-a", limit).is_ok());
        assert!(limiter.check("ingest", "installation-a", limit).is_ok());
        let error = limiter
            .check("ingest", "installation-a", limit)
            .expect_err("third request must be rejected");
        assert_eq!(error.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn rate_limiter_keys_scopes_and_identities_separately() {
        let limiter = RateLimiter::default();
        let limit = RateLimit::new(60, 1);
        assert!(limiter.check("ingest", "installation-a", limit).is_ok());
        assert!(limiter.check("ingest", "installation-b", limit).is_ok());
        assert!(limiter.check("enroll", "installation-a", limit).is_ok());
        assert!(limiter.check("ingest", "installation-a", limit).is_err());
    }

    #[test]
    fn a_zero_budget_disables_the_limit() {
        let limiter = RateLimiter::default();
        let limit = RateLimit::new(60, 0);
        for _ in 0..1_000 {
            assert!(limiter.check("analytics", "user:1", limit).is_ok());
        }
    }

    #[test]
    fn forwarded_addresses_are_only_trusted_behind_a_declared_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, 10.0.0.1"),
        );
        let peer: SocketAddr = "10.0.0.1:5555".parse().expect("peer address");
        assert_eq!(client_address(&headers, peer, true), "203.0.113.7");
        assert_eq!(client_address(&headers, peer, false), "10.0.0.1");
        assert_eq!(client_address(&HeaderMap::new(), peer, true), "10.0.0.1");
    }
    use metrune_core::{
        CategoryAssignment, ClassificationMethod, Cost, ModelActivityStep, TokenBreakdown,
        TurnSnapshot, UsageSlice,
    };

    #[test]
    fn analytics_queries_are_always_organization_scoped() {
        let query = AnalyticsQuery {
            from: Some("2026-07-01".into()),
            to: Some("2026-07-22".into()),
            team: Some("platform".into()),
            project: None,
            category: None,
            client: None,
            status: None,
            workflow: None,
        };
        let (sql, params) =
            filtered_query("SELECT count() FROM session_snapshots", &query, "org-a");
        assert!(sql.contains("organization_id = ?"));
        assert!(sql.contains("team_key = ?"));
        assert_eq!(params.first().map(String::as_str), Some("org-a"));
    }

    #[test]
    fn analytics_queries_can_filter_semantic_status() {
        let query = AnalyticsQuery {
            from: None,
            to: None,
            team: None,
            project: None,
            category: None,
            client: None,
            status: Some("failed".into()),
            workflow: None,
        };
        let (sql, params) = filtered_query(
            "SELECT count() FROM session_snapshots_dedup",
            &query,
            "org-a",
        );
        assert!(sql.contains("classification_status = ?"));
        assert!(params.contains(&"failed".to_string()));
    }

    #[test]
    fn personal_usage_filter_keeps_owner_scope_and_uses_stable_installation_id() {
        let all_clients = personal_usage_suffix(false);
        assert!(all_clients.contains("organization_id = ?"));
        assert!(all_clients.contains("owner_user_id = ?"));
        assert!(!all_clients.contains("installation_id = ?"));

        let one_client = personal_usage_suffix(true);
        assert!(one_client.contains("owner_user_id = ?"));
        assert!(one_client.ends_with(" AND installation_id = ?"));
    }

    #[test]
    fn ingest_contract_rejects_raw_short_identifiers() {
        let snapshot = SessionSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            session_key: "raw-session".into(),
            revision: 1,
            user_key: "raw-user".into(),
            project_key: None,
            project_alias: None,
            team_key: None,
            client_id: "codex".into(),
            client_version: None,
            started_at: Utc::now(),
            ended_at: Utc::now(),
            usage_by_model: vec![UsageSlice {
                provider_id: "openai".into(),
                model_id: "gpt-5".into(),
                tokens: TokenBreakdown {
                    input: 1,
                    ..TokenBreakdown::default()
                },
                cost: Cost::default(),
            }],
            category: CategoryAssignment::default(),
            turns: vec![],
            classifier_usage: Default::default(),
            signal_capabilities: vec![],
            classified_token_coverage: 0.0,
            classification_method_counts: vec![],
            turn_detail_truncated: false,
            source_schema_version: None,
        };
        assert!(validate_snapshot(&snapshot).is_err());
    }

    #[test]
    fn v2_ingest_requires_turn_and_session_model_totals_to_reconcile() {
        let tokens = TokenBreakdown {
            input: 10,
            output: 2,
            ..TokenBreakdown::default()
        };
        let mut snapshot = SessionSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            session_key: "s".repeat(64),
            revision: 1,
            user_key: "u".repeat(64),
            project_key: None,
            project_alias: None,
            team_key: None,
            client_id: "codex".into(),
            client_version: None,
            started_at: Utc::now(),
            ended_at: Utc::now(),
            usage_by_model: vec![UsageSlice {
                provider_id: "openai".into(),
                model_id: "gpt-5".into(),
                tokens: tokens.clone(),
                cost: Cost::default(),
            }],
            category: CategoryAssignment::default(),
            turns: vec![TurnSnapshot {
                sequence: 1,
                category: CategoryAssignment::default(),
                classification_method: ClassificationMethod::None,
                classification_cached: false,
                model_activity: vec![ModelActivityStep {
                    sequence: 0,
                    provider_id: "openai".into(),
                    model_id: "gpt-5".into(),
                    tokens,
                    cost: Cost::default(),
                    call_count: 1,
                }],
                workflow_signals: vec![],
            }],
            classifier_usage: Default::default(),
            signal_capabilities: vec![],
            classified_token_coverage: 0.0,
            classification_method_counts: vec![],
            turn_detail_truncated: false,
            source_schema_version: None,
        };
        assert!(validate_snapshot(&snapshot).is_ok());
        let mut legacy = snapshot.clone();
        legacy.schema_version = LEGACY_SCHEMA_VERSION.into();
        legacy.turns.clear();
        assert!(validate_snapshot(&legacy).is_ok());
        snapshot.turns[0].model_activity[0].model_id = "another-model".into();
        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("model usage"));
    }

    #[test]
    fn ingest_contract_rejects_unbounded_or_non_finite_snapshot_values() {
        let mut snapshot = SessionSnapshot {
            schema_version: SCHEMA_VERSION.into(),
            session_key: "s".repeat(64),
            revision: 1,
            user_key: "u".repeat(64),
            project_key: None,
            project_alias: None,
            team_key: None,
            client_id: "codex".into(),
            client_version: None,
            started_at: Utc::now(),
            ended_at: Utc::now(),
            usage_by_model: vec![UsageSlice {
                provider_id: "openai".into(),
                model_id: "gpt-5".into(),
                tokens: TokenBreakdown {
                    input: 1,
                    ..TokenBreakdown::default()
                },
                cost: Cost::default(),
            }],
            category: CategoryAssignment::default(),
            turns: vec![],
            classifier_usage: Default::default(),
            signal_capabilities: vec![],
            classified_token_coverage: 0.0,
            classification_method_counts: vec![],
            turn_detail_truncated: false,
            source_schema_version: None,
        };
        snapshot.client_id = "x".repeat(MAX_SNAPSHOT_TEXT_BYTES + 1);
        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("client_id"));

        snapshot.client_id = "codex".into();
        snapshot.category.confidence = f32::NAN;
        assert!(validate_snapshot(&snapshot)
            .unwrap_err()
            .contains("confidence"));

        snapshot.category.confidence = 0.0;
        snapshot.usage_by_model[0].cost.amount = f64::INFINITY;
        assert!(validate_snapshot(&snapshot).unwrap_err().contains("cost"));
    }

    #[test]
    fn custom_price_validation_rejects_negative_or_unknown_authority() {
        let valid = PriceRequest {
            provider_id: "custom".into(),
            model_id: "coder-v1".into(),
            currency: "USD".into(),
            input_per_million: 1.0,
            output_per_million: 2.0,
            cache_read_per_million: 0.0,
            cache_write_per_million: 0.0,
            reasoning_per_million: 0.0,
            request_per_request: 0.0,
            image_per_image: 0.0,
            authority: "organization_override".into(),
        };
        assert!(validate_price_request(&valid).is_ok());
        let mut negative = valid.clone();
        negative.output_per_million = -0.01;
        assert!(validate_price_request(&negative).is_err());
        let mut unsupported = valid;
        unsupported.authority = "untrusted".into();
        assert!(validate_price_request(&unsupported).is_err());
    }

    #[test]
    fn classifier_presets_hide_protocol_and_endpoint_complexity() {
        let openrouter = resolve_provider_config(&ClassifierSettingsUpdateRequest {
            enabled: true,
            execution_mode: ClassifierExecutionMode::Managed,
            provider_id: "openrouter".into(),
            endpoint: "https://ignored.example/v1".into(),
            model: "inclusionai/ling-3.0-flash:free".into(),
            credential_id: "openrouter".into(),
            response_mode: None,
        })
        .expect("openrouter preset");
        assert_eq!(openrouter.protocol, "openai_chat");
        assert_eq!(
            openrouter.endpoint,
            "https://openrouter.ai/api/v1/chat/completions"
        );
        assert_eq!(openrouter.response_mode, ResponseMode::Auto);

        let custom = resolve_provider_config(&ClassifierSettingsUpdateRequest {
            enabled: true,
            execution_mode: ClassifierExecutionMode::Local,
            provider_id: "custom".into(),
            endpoint: "http://localhost:1234/v1/chat/completions".into(),
            model: "local-model".into(),
            credential_id: String::new(),
            response_mode: None,
        })
        .expect("custom localhost provider");
        assert_eq!(custom.response_mode, ResponseMode::PromptJson);
    }

    #[test]
    fn managed_classifier_material_never_exposes_provider_access() {
        let (endpoint, credential_id, credential, version) = provisioned_classifier_material(
            ClassifierExecutionMode::Managed,
            "https://provider.example/v1/chat/completions".into(),
            "provider-key".into(),
            Some("super-secret".into()),
            Some(7),
        );
        assert!(endpoint.is_empty());
        assert!(credential_id.is_empty());
        assert!(credential.is_none());
        assert!(version.is_none());

        let local = provisioned_classifier_material(
            ClassifierExecutionMode::Local,
            "http://localhost:11434/v1/chat/completions".into(),
            String::new(),
            None,
            None,
        );
        assert_eq!(local.0, "http://localhost:11434/v1/chat/completions");
    }

    #[test]
    fn managed_classification_text_is_bounded_and_non_empty() {
        assert!(validate_managed_classification_text(" useful context ").is_ok());
        assert!(validate_managed_classification_text(" \n ").is_err());
        assert!(
            validate_managed_classification_text(&"a".repeat(MAX_CLASSIFICATION_TEXT_BYTES))
                .is_ok()
        );
        let oversized =
            validate_managed_classification_text(&"a".repeat(MAX_CLASSIFICATION_TEXT_BYTES + 1))
                .expect_err("oversized managed text must be rejected");
        assert_eq!(oversized.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn workspace_roles_are_explicit_and_classifier_mode_defaults_private() {
        assert!(validate_member_role("viewer").is_ok());
        assert!(validate_member_role("analyst").is_ok());
        assert!(validate_member_role("admin").is_ok());
        assert!(validate_member_role("owner").is_err());
        assert_eq!(
            parse_classifier_execution_mode("managed"),
            ClassifierExecutionMode::Managed
        );
        assert_eq!(
            parse_classifier_execution_mode("unexpected"),
            ClassifierExecutionMode::Local
        );
    }

    #[test]
    fn production_configuration_rejects_insecure_defaults() {
        assert!(validate_production_configuration(
            "production",
            Some("http://metrune.example.com"),
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("strong-bootstrap")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            Some("https://metrune.example.com"),
            "postgres://metrune:metrune-dev@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("strong-bootstrap")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("admin")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some(DEVELOPMENT_BOOTSTRAP_EMAIL),
            Some("a-long-random-password")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
            Some("https://api.metrune.example.com"),
            Some("http://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("a-long-random-password")
        )
        .is_err());
    }

    #[test]
    fn production_configuration_accepts_explicit_secure_values() {
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "another-strong-password",
            Some("admin@example.com"),
            Some("a-long-random-bootstrap-password")
        )
        .is_ok());
        assert!(!valid_public_https_url("https://"));
        assert!(!valid_public_https_url("https://user:pass@metrune.example"));
        assert!(!valid_public_https_url("https://metrune.example/#fragment"));
        assert!(valid_public_https_url("https://metrune.example/api"));
        assert!(validate_production_configuration(
            "development",
            None,
            None,
            "postgres://metrune:metrune-dev@postgres/metrune",
            "metrune-dev",
            Some(DEVELOPMENT_BOOTSTRAP_EMAIL),
            Some("admin")
        )
        .is_ok());
    }

    #[test]
    fn installation_names_are_bounded_trimmed_and_printable() {
        assert_eq!(
            validate_installation_name("  flo-laptop  ").expect("trimmed name"),
            "flo-laptop"
        );
        assert!(validate_installation_name("   ").is_err());
        assert!(validate_installation_name(&"a".repeat(120)).is_ok());
        assert!(validate_installation_name(&"a".repeat(121)).is_err());
        // Enrollment is reachable by anyone holding a code, and the name is
        // rendered back to admins.
        assert!(validate_installation_name("laptop\u{7}\u{1b}[2J").is_err());
        assert!(validate_installation_name("line\nbreak").is_err());
    }

    #[test]
    fn only_known_platforms_are_accepted() {
        for platform in SUPPORTED_PLATFORMS {
            assert!(validate_platform(platform).is_ok());
        }
        assert!(validate_platform("solaris").is_err());
        assert!(validate_platform("").is_err());
        assert!(validate_platform("Linux").is_err());
    }

    #[test]
    fn cleartext_classifier_endpoints_are_confined_to_the_loopback_host() {
        assert!(endpoint_transport_is_allowed(
            "https://openrouter.ai/api/v1/chat/completions"
        ));
        assert!(endpoint_transport_is_allowed(
            "http://localhost:11434/v1/chat/completions"
        ));
        assert!(endpoint_transport_is_allowed("http://127.0.0.1:1234/v1"));
        assert!(endpoint_transport_is_allowed("http://[::1]:8080/v1"));
        assert!(endpoint_transport_is_allowed("http://LocalHost:11434/v1"));

        // A prefix test would accept all of these as "localhost".
        assert!(!endpoint_transport_is_allowed(
            "http://localhost.attacker.example/v1"
        ));
        assert!(!endpoint_transport_is_allowed(
            "http://127.0.0.1.attacker.example/v1"
        ));
        assert!(!endpoint_transport_is_allowed(
            "http://localhost@attacker.example/v1"
        ));
        assert!(!endpoint_transport_is_allowed(
            "http://localhost:11434@attacker.example/v1"
        ));

        assert!(!endpoint_transport_is_allowed("http://10.0.0.5/v1"));
        assert!(!endpoint_transport_is_allowed(
            "http://169.254.169.254/latest/meta-data/"
        ));
        assert!(!endpoint_transport_is_allowed("ftp://localhost/v1"));
        assert!(!endpoint_transport_is_allowed("file:///etc/passwd"));
        assert!(!endpoint_transport_is_allowed("https://"));
        assert!(!endpoint_transport_is_allowed("not-a-url"));
    }

    #[test]
    fn custom_classifier_providers_reject_cleartext_remote_endpoints() {
        let request = |endpoint: &str| ClassifierSettingsUpdateRequest {
            enabled: true,
            execution_mode: ClassifierExecutionMode::Managed,
            provider_id: "custom".into(),
            endpoint: endpoint.into(),
            model: "local-model".into(),
            credential_id: String::new(),
            response_mode: None,
        };
        assert!(resolve_provider_config(&request("http://localhost:1234/v1")).is_ok());
        assert!(resolve_provider_config(&request("http://localhost.evil.example/v1")).is_err());
        assert!(resolve_provider_config(&request("")).is_err());
    }

    #[test]
    fn session_pagination_offset_is_capped() {
        let clamp = |offset: Option<u32>| offset.unwrap_or(0).min(MAX_SESSION_PAGE_OFFSET);
        assert_eq!(clamp(None), 0);
        assert_eq!(clamp(Some(250)), 250);
        assert_eq!(clamp(Some(u32::MAX)), MAX_SESSION_PAGE_OFFSET);
    }

    #[test]
    fn login_limiter_throttles_failures_without_locking_out_valid_passwords() {
        let limiter = LoginAttemptLimiter::default();
        for _ in 0..MAX_LOGIN_FAILURES_PER_WINDOW {
            assert!(!limiter.is_limited("admin@example.com"));
            limiter.record_failure("admin@example.com");
        }
        assert!(limiter.is_limited("admin@example.com"));
        limiter.reset("admin@example.com");
        assert!(!limiter.is_limited("admin@example.com"));
    }
}
