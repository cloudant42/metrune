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
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use clickhouse::Row;
use metrune_core::{
    canonical_model_id,
    classifier::{OpenAiCompatibleClassifier, ResponseMode},
    pricing::{ModelPrice, PriceCatalog},
    BatchEnvelope, CostKind, IngestAck, SessionSnapshot, SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::Path as StdPath,
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
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
struct AppState {
    postgres: PgPool,
    clickhouse: clickhouse::Client,
    classifier: Option<ServerClassifierConfig>,
    vault: SecretVault,
    login_limiter: LoginAttemptLimiter,
    rate_limiter: RateLimiter,
    rate_limits: RateLimits,
    trust_proxy_headers: bool,
}

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;
const MAX_BATCH_SNAPSHOTS: usize = 1_000;
const DEFAULT_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(60);
const LONG_REQUEST_TIMEOUT: StdDuration = StdDuration::from_secs(300);
const LOGIN_WINDOW: StdDuration = StdDuration::from_secs(60);
const MAX_LOGIN_FAILURES_PER_WINDOW: u32 = 5;
/// Upper bound on tracked rate-limit windows so that a flood of unique keys
/// cannot grow the limiter without bound.
const MAX_RATE_LIMIT_KEYS: usize = 100_000;
const DEVELOPMENT_ORGANIZATION_ID: &str = "00000000-0000-0000-0000-000000000001";
const DEVELOPMENT_DASHBOARD_TOKEN_HASH: &str =
    "78e35941c163d606f0a3f1820de4eae3a43381b5603df86772bdd11168d2e434";
const DEVELOPMENT_ENROLLMENT_TOKEN_HASH: &str =
    "18daf9c40bec25b9eadfaad2a5b487d38c61716c60000ff4f61e981ba1462c26";
const DEVELOPMENT_BOOTSTRAP_EMAIL: &str = "admin@test.com";

#[derive(Clone, Default)]
struct LoginAttemptLimiter {
    attempts: Arc<Mutex<HashMap<String, LoginAttemptWindow>>>,
}

struct LoginAttemptWindow {
    started_at: Instant,
    failures: u32,
}

impl LoginAttemptLimiter {
    fn is_limited(&self, key: &str) -> bool {
        let mut attempts = self.attempts.lock().expect("login limiter mutex poisoned");
        let now = Instant::now();
        attempts.retain(|_, window| now.duration_since(window.started_at) < LOGIN_WINDOW);
        attempts
            .get(key)
            .is_some_and(|window| window.failures >= MAX_LOGIN_FAILURES_PER_WINDOW)
    }

    fn record_failure(&self, key: &str) {
        let mut attempts = self.attempts.lock().expect("login limiter mutex poisoned");
        let now = Instant::now();
        let window = attempts
            .entry(key.to_owned())
            .or_insert(LoginAttemptWindow {
                started_at: now,
                failures: 0,
            });
        if now.duration_since(window.started_at) >= LOGIN_WINDOW {
            window.started_at = now;
            window.failures = 0;
        }
        window.failures = window.failures.saturating_add(1);
    }

    fn reset(&self, key: &str) {
        self.attempts
            .lock()
            .expect("login limiter mutex poisoned")
            .remove(key);
    }
}

/// A fixed-window request budget for one scope.
#[derive(Clone, Copy)]
struct RateLimit {
    window: StdDuration,
    max_requests: u32,
}

impl RateLimit {
    const fn new(window_secs: u64, max_requests: u32) -> Self {
        Self {
            window: StdDuration::from_secs(window_secs),
            max_requests,
        }
    }

    /// Reads `METRUNE_RATE_LIMIT_<name>` as a per-window request budget.
    /// `0` disables the limit for the scope.
    fn with_env_override(self, name: &str) -> Self {
        match env::var(format!("METRUNE_RATE_LIMIT_{name}"))
            .ok()
            .and_then(|value| value.trim().parse::<u32>().ok())
        {
            Some(max_requests) => Self {
                max_requests,
                ..self
            },
            None => self,
        }
    }
}

/// Per-scope request budgets. Every limit is keyed by the authenticated
/// identity where one exists, and by client address otherwise.
#[derive(Clone, Copy)]
struct RateLimits {
    enroll: RateLimit,
    login: RateLimit,
    provision: RateLimit,
    ingest: RateLimit,
    analytics: RateLimit,
    enrollment_code: RateLimit,
}

impl RateLimits {
    fn from_env() -> Self {
        Self {
            enroll: RateLimit::new(60, 10).with_env_override("ENROLL_PER_MINUTE"),
            login: RateLimit::new(60, 30).with_env_override("LOGIN_PER_MINUTE"),
            provision: RateLimit::new(60, 20).with_env_override("PROVISION_PER_MINUTE"),
            ingest: RateLimit::new(60, 60).with_env_override("INGEST_PER_MINUTE"),
            analytics: RateLimit::new(60, 120).with_env_override("ANALYTICS_PER_MINUTE"),
            enrollment_code: RateLimit::new(3600, 20)
                .with_env_override("ENROLLMENT_CODES_PER_HOUR"),
        }
    }
}

struct RateWindow {
    expires_at: Instant,
    hits: u32,
}

#[derive(Clone, Default)]
struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, RateWindow>>>,
}

impl RateLimiter {
    /// Counts one request against `scope`/`key` and rejects it once the window
    /// budget is exhausted.
    fn check(&self, scope: &str, key: &str, limit: RateLimit) -> Result<(), ApiError> {
        if limit.max_requests == 0 {
            return Ok(());
        }
        let mut windows = self.windows.lock().expect("rate limiter mutex poisoned");
        let now = Instant::now();
        windows.retain(|_, window| window.expires_at > now);
        let entry = format!("{scope}:{key}");
        if windows.len() >= MAX_RATE_LIMIT_KEYS && !windows.contains_key(&entry) {
            tracing::warn!(scope, "rate limiter key table is full; shedding request");
            return Err(ApiError::too_many_requests("the server is shedding load"));
        }
        let window = windows.entry(entry).or_insert(RateWindow {
            expires_at: now + limit.window,
            hits: 0,
        });
        if window.hits >= limit.max_requests {
            return Err(ApiError::too_many_requests(format!(
                "rate limit exceeded for {scope}; retry later"
            )));
        }
        window.hits = window.hits.saturating_add(1);
        Ok(())
    }
}

/// Resolves the address a request should be rate-limited by.
///
/// `X-Forwarded-For` is only honoured when the deployment declares that it
/// runs behind a trusted reverse proxy, because clients can otherwise forge
/// the header and bypass every address-keyed limit.
fn client_address(headers: &HeaderMap, peer: SocketAddr, trust_proxy_headers: bool) -> String {
    if trust_proxy_headers {
        if let Some(forwarded) = headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return forwarded.to_owned();
        }
    }
    peer.ip().to_string()
}

#[derive(Clone)]
struct SecretVault {
    key: [u8; 32],
    created: bool,
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
            Ok(value) => (value, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut key = [0_u8; 32];
                OsRng.fill_bytes(&mut key);
                let encoded = URL_SAFE_NO_PAD.encode(key);
                let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
                file.write_all(encoded.as_bytes())?;
                file.sync_all()?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
                }
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

    fn encrypt(&self, plaintext: &str, aad: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce = [0_u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
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

    fn decrypt(&self, ciphertext: &[u8], nonce: &[u8], aad: &[u8]) -> anyhow::Result<String> {
        if nonce.len() != 12 {
            anyhow::bail!("invalid credential nonce");
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
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

    fn recovery_key(&self) -> String {
        format!("mvrk_{}", URL_SAFE_NO_PAD.encode(self.key))
    }
}

#[derive(Clone)]
struct ServerClassifierConfig {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
    validate_production_configuration(
        &environment,
        env::var("METRUNE_PUBLIC_API_URL").ok().as_deref(),
        &database_url,
        &clickhouse_password,
        bootstrap_email.as_deref(),
        bootstrap_password.as_deref(),
    )?;
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
    import_default_price_catalog(&state).await?;
    reprice_unknown_history(&state).await?;

    let long_running_routes = Router::new()
        .route("/v1/ingest/sessions", post(ingest_sessions))
        .route("/v1/analytics/overview", get(analytics_overview))
        .route("/v1/analytics/timeseries", get(analytics_timeseries))
        .route("/v1/analytics/breakdowns", get(analytics_breakdowns))
        .route(
            "/v1/analytics/category-model",
            get(analytics_category_model),
        )
        .route("/v1/analytics/sessions", get(analytics_sessions))
        .route("/v1/analytics/facets", get(analytics_facets))
        .route("/v1/me/usage", get(my_usage))
        .route("/v1/me/sessions", get(my_sessions))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            LONG_REQUEST_TIMEOUT,
        ));

    let app = Router::new()
        .route("/v1/healthz", get(health))
        .route("/v1/readyz", get(ready))
        .route("/v1/downloads/{artifact}", get(download_client))
        .route("/v1/auth/login", post(login))
        .route("/v1/auth/logout", post(logout))
        .route("/v1/auth/me", get(current_user))
        .route("/v1/enroll", post(enroll))
        .route(
            "/v1/installation/classifier/provision",
            post(provision_classifier),
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
        .with_state(state.clone());

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

async fn ensure_deduplicated_session_table(clickhouse: &clickhouse::Client) -> anyhow::Result<()> {
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

async fn download_client(Path(artifact): Path<String>) -> Result<Response, ApiError> {
    let (environment_key, default_path, filename) = match artifact.as_str() {
        "metrune-linux-x86_64" => (
            "METRUNE_LINUX_CLIENT_PATH",
            "/tmp/metrune-downloads/metrune-linux-x86_64",
            "metrune-linux-x86_64",
        ),
        "metrune-windows-x86_64.exe" => (
            "METRUNE_WINDOWS_CLIENT_PATH",
            "/tmp/metrune-downloads/metrune-windows-x86_64.exe",
            "metrune-windows-x86_64.exe",
        ),
        "metrune-macos-arm64" => (
            "METRUNE_MACOS_ARM64_CLIENT_PATH",
            "/tmp/metrune-downloads/metrune-macos-arm64",
            "metrune-macos-arm64",
        ),
        "metrune-macos-x86_64" => (
            "METRUNE_MACOS_X86_64_CLIENT_PATH",
            "/tmp/metrune-downloads/metrune-macos-x86_64",
            "metrune-macos-x86_64",
        ),
        _ => return Err(ApiError::not_found("Unknown client artifact")),
    };
    let path = env::var(environment_key).unwrap_or_else(|_| default_path.into());
    let binary = tokio::fs::read(path)
        .await
        .map_err(|_| ApiError::not_found(format!("{filename} client artifact is not available")))?;
    let content_disposition =
        HeaderValue::from_str(&format!("attachment; filename=\"{filename}\""))
            .map_err(|_| ApiError::bad_request("invalid client artifact filename"))?;
    Ok((
        [
            (
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (CONTENT_DISPOSITION, content_disposition),
            (CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        binary,
    )
        .into_response())
}

fn validate_production_configuration(
    environment: &str,
    public_api_url: Option<&str>,
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
    if !public_api_url.starts_with("https://") {
        anyhow::bail!("METRUNE_PUBLIC_API_URL must use HTTPS in production");
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
    let Some(email) = env::var("METRUNE_BOOTSTRAP_EMAIL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(());
    };
    let Some(password) = env::var("METRUNE_BOOTSTRAP_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let Some(organization_id) =
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM organizations ORDER BY created_at LIMIT 1")
            .fetch_optional(&state.postgres)
            .await?
    else {
        return Ok(());
    };
    let password_hash = Argon2::default()
        .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
        .map_err(|error| anyhow::anyhow!("hash bootstrap password: {error}"))?
        .to_string();
    sqlx::query(
        "INSERT INTO users(organization_id, email, display_name, password_hash, role)
         VALUES ($1,$2,'Metrune Admin',$3,'admin')
         ON CONFLICT (organization_id, email) DO NOTHING",
    )
    .bind(organization_id)
    .bind(email.trim().to_ascii_lowercase())
    .bind(password_hash)
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
struct CurrentUserResponse {
    id: Uuid,
    organization_id: Uuid,
    organization_name: String,
    email: String,
    display_name: Option<String>,
    role: String,
}

fn failed_login(state: &AppState, email: &str) -> ApiError {
    if state.login_limiter.is_limited(email) {
        return ApiError::too_many_requests("too many login attempts; try again later");
    }
    state.login_limiter.record_failure(email);
    ApiError::unauthorized("invalid email or password")
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    state
        .rate_limiter
        .check("login", &address, state.rate_limits.login)?;
    let email = request.email.trim().to_ascii_lowercase();
    let rows = sqlx::query_as::<
        _,
        (
            Uuid,
            Uuid,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        ),
    >(
        "SELECT u.id, u.organization_id, o.name, u.email, u.display_name, u.role, u.password_hash
         FROM users u JOIN organizations o ON o.id = u.organization_id
         WHERE LOWER(u.email) = $1 AND u.disabled_at IS NULL
         ORDER BY u.created_at LIMIT 2",
    )
    .bind(&email)
    .fetch_all(&state.postgres)
    .await?;
    if rows.len() != 1 {
        return Err(failed_login(&state, &email));
    }
    let row = &rows[0];
    let password_hash = row.6.clone().ok_or(ApiError::unauthorized(
        "local password login is unavailable",
    ))?;
    let password = request.password.clone();
    let password_valid = tokio::task::spawn_blocking(move || {
        PasswordHash::new(&password_hash).is_ok_and(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
    })
    .await?;
    if !password_valid {
        return Err(failed_login(&state, &email));
    }
    state.login_limiter.reset(&email);
    let session_token = format!("mts_{}", Uuid::new_v4().simple());
    let expires_at = Utc::now() + Duration::days(30);
    sqlx::query(
        "INSERT INTO web_sessions(user_id, token_hash, created_at, expires_at)
         VALUES ($1,$2,NOW(),$3)",
    )
    .bind(row.0)
    .bind(token_hash(&session_token))
    .bind(expires_at)
    .execute(&state.postgres)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(row.0)
        .execute(&state.postgres)
        .await?;
    Ok(Json(LoginResponse {
        session_token,
        expires_at,
        user: CurrentUserResponse {
            id: row.0,
            organization_id: row.1,
            organization_name: row.2.clone(),
            email: row.3.clone(),
            display_name: row.4.clone(),
            role: row.5.clone(),
        },
    }))
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let token = bearer(&headers)?;
    sqlx::query("UPDATE web_sessions SET revoked_at = NOW() WHERE token_hash = $1")
        .bind(token_hash(token))
        .execute(&state.postgres)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn current_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<CurrentUserResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, String, Option<String>, String)>(
        "SELECT u.id, u.organization_id, o.name, u.email, u.display_name, u.role
         FROM users u JOIN organizations o ON o.id = u.organization_id
         WHERE u.id = $1 AND u.disabled_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&state.postgres)
    .await?;
    Ok(Json(CurrentUserResponse {
        id: row.0,
        organization_id: row.1,
        organization_name: row.2,
        email: row.3,
        display_name: row.4,
        role: row.5,
    }))
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
struct EnrollResponse {
    installation_id: Uuid,
    installation_token: String,
    pseudonym_key: String,
    organization_id: Uuid,
    team_key: Option<String>,
}

#[derive(Serialize)]
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
    response_mode: ResponseMode,
}

async fn enroll(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, ApiError> {
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    state
        .rate_limiter
        .check("enroll", &address, state.rate_limits.enroll)?;
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
        .bind(&request.installation_name)
        .bind(token_hash(&installation_token))
        .bind(&team_name)
        .bind(team_id)
        .bind(owner_user_id)
        .bind(request.platform.as_deref().unwrap_or(&platform))
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE enrollment_codes SET redeemed_at = NOW() WHERE id = $1")
            .bind(code_id)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        return Ok(Json(EnrollResponse {
            installation_id,
            installation_token,
            pseudonym_key,
            organization_id,
            team_key: team_name,
        }));
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
    ).bind(installation_id).bind(row.0).bind(request.installation_name)
        .bind(token_hash(&installation_token)).bind(team_key.clone()).bind(row.2)
        .bind(request.platform.as_deref().unwrap_or("other"))
        .execute(&state.postgres).await?;
    Ok(Json(EnrollResponse {
        installation_id,
        installation_token,
        pseudonym_key,
        organization_id: row.0,
        team_key,
    }))
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
    )>(
        "SELECT classifier_configured, classifier_enabled, classifier_provider_id, classifier_endpoint,
                classifier_model, classifier_credential_id, classifier_config_version,
                classifier_protocol, classifier_response_mode
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
    let (provider_id, endpoint, model, credential_id, config_version, response_mode) = if configured
    {
        (
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
            config.provider_id.clone(),
            config.endpoint.clone(),
            config.model.clone(),
            config.credential_id.clone(),
            config.config_version.clone(),
            config.response_mode,
        )
    };
    let (credential, credential_version) =
        active_classifier_credential(&state, auth.organization_id, &credential_id).await?;
    let credential = credential.or_else(|| {
        fallback
            .filter(|config| config.credential_id == credential_id)
            .and_then(|config| config.api_key.clone())
    });
    sqlx::query(
        "UPDATE installations SET classifier_credential_id = $2,
             classifier_credential_version = $3 WHERE id = $1",
    )
    .bind(auth.installation_id)
    .bind(&credential_id)
    .bind(credential_version)
    .execute(&state.postgres)
    .await?;
    Ok((
        response_headers,
        Json(ClassifierProvisionResponse {
            enabled: true,
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
        return Ok(Json(IngestAck {
            batch_id: batch.batch_id,
            accepted: 0,
            duplicates: snapshot_count,
            rejected: 0,
            errors: vec![],
        }));
    }
    let mut ack = IngestAck {
        batch_id: batch.batch_id.clone(),
        accepted: 0,
        duplicates: 0,
        rejected: 0,
        errors: vec![],
    };
    if batch.schema_version != SCHEMA_VERSION {
        return Err(ApiError::bad_request(format!(
            "unsupported batch schema {}",
            batch.schema_version
        )));
    }
    let mut insert = state
        .clickhouse
        .insert::<SnapshotRow>("session_snapshots_dedup")?;
    for mut snapshot in batch.snapshots {
        match validate_snapshot(&snapshot) {
            Ok(()) => {
                apply_server_prices(&state, auth.organization_id, &mut snapshot).await?;
                insert.write(&SnapshotRow::new(&auth, snapshot)?).await?;
                ack.accepted += 1;
            }
            Err(error) => {
                ack.rejected += 1;
                ack.errors.push(error);
            }
        }
    }
    insert.end().await?;
    sqlx::query(
        "INSERT INTO ingest_batches(installation_id, batch_id, snapshot_count, completed_at) VALUES ($1,$2,$3,NOW()) ON CONFLICT DO NOTHING",
    )
    .bind(auth.installation_id)
    .bind(&batch.batch_id)
    .bind(snapshot_count as i32)
    .execute(&state.postgres)
    .await?;
    sqlx::query("UPDATE installations SET last_seen_at = NOW() WHERE id = $1")
        .bind(auth.installation_id)
        .execute(&state.postgres)
        .await?;
    Ok(Json(ack))
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
    if snapshot.schema_version != SCHEMA_VERSION {
        return Err("unsupported snapshot schema".into());
    }
    if snapshot.session_key.len() < 32 || snapshot.user_key.len() < 32 {
        return Err("identifiers are not pseudonymous".into());
    }
    if snapshot.ended_at < snapshot.started_at {
        return Err("session ended before it started".into());
    }
    if snapshot.usage_by_model.is_empty() {
        return Err("snapshot contains no usage".into());
    }
    Ok(())
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

#[derive(Debug, Deserialize)]
struct AnalyticsQuery {
    from: Option<String>,
    to: Option<String>,
    team: Option<String>,
    project: Option<String>,
    category: Option<String>,
    client: Option<String>,
    status: Option<String>,
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
    let base = "SELECT category_id category, concat(JSONExtractString(usage_slice, 'providerId'), '/', JSONExtractString(usage_slice, 'modelId')) model, toUInt64(sum(JSONExtractUInt(usage_slice, 'tokens', 'input') + JSONExtractUInt(usage_slice, 'tokens', 'output') + JSONExtractUInt(usage_slice, 'tokens', 'cacheRead') + JSONExtractUInt(usage_slice, 'tokens', 'cacheWrite') + JSONExtractUInt(usage_slice, 'tokens', 'reasoning'))) tokens, sum(JSONExtractFloat(usage_slice, 'cost', 'amount')) cost, toUInt64(uniqExact(session_key)) sessions FROM session_snapshots_dedup FINAL ARRAY JOIN JSONExtractArrayRaw(snapshot_json, 'usageByModel') AS usage_slice";
    let (mut sql, params) = filtered_query(base, &query, &auth.organization_id);
    sql.push_str(" AND classification_status = 'classified'");
    sql.push_str(" GROUP BY category, model ORDER BY category, tokens DESC LIMIT 500");
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<CategoryModelRow>().await?))
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
    };
    let base = format!("SELECT {dimension} dimension, toUInt64(sum({tokens})) tokens, sum({cost}) cost, toUInt64(uniqExact(session_key)) sessions FROM session_snapshots_dedup FINAL {array_join}");
    let (mut sql, params) = filtered_query(&base, &filters, &auth.organization_id);
    if query.dimension.as_deref().unwrap_or("category") == "category" {
        sql.push_str(" AND classification_status = 'classified'");
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
    if auth.user_id.is_some() {
        return Err(ApiError::forbidden(
            "organization session drilldown is not available to user sessions",
        ));
    }
    if auth.role == "viewer" {
        return Err(ApiError::forbidden(
            "session drilldown requires analyst or admin role",
        ));
    }
    let order = match query.sort.as_deref() {
        Some("cost") => "total_cost DESC",
        Some("tokens") => "total_tokens DESC",
        Some("category") => "category_id ASC, ended_at_ms DESC",
        _ => "ended_at_ms DESC",
    };
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0);
    let filters = AnalyticsQuery {
        from: query.from,
        to: query.to,
        team: query.team,
        project: query.project,
        category: query.category,
        client: query.client,
        status: query.status,
    };
    let base = "SELECT session_key, installation_id, client_id, project_alias, category_id, category_confidence, classification_status, total_tokens, total_cost, ended_at_ms FROM session_snapshots_dedup FINAL";
    let (mut sql, params) = filtered_query(base, &filters, &auth.organization_id);
    sql.push_str(&format!(" ORDER BY {order} LIMIT {limit} OFFSET {offset}"));
    let mut q = state.clickhouse.query(&sql);
    for param in params {
        q = q.bind(param);
    }
    Ok(Json(q.fetch_all::<SessionRow>().await?))
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
    (format!("{base} WHERE {}", clauses.join(" AND ")), params)
}

struct DashboardAuth {
    organization_id: String,
    role: String,
    name: String,
    user_id: Option<Uuid>,
    /// Stable rate-limiting identity: the user id for a web session, or the
    /// stored digest for a service dashboard token.
    subject: String,
}

impl DashboardAuth {
    fn require_admin(&self) -> Result<(), ApiError> {
        if self.role != "admin" {
            return Err(ApiError::forbidden("organization admin role required"));
        }
        Ok(())
    }

    fn organization_uuid(&self) -> Result<Uuid, ApiError> {
        self.organization_id
            .parse()
            .map_err(|_| ApiError::unauthorized("invalid dashboard token"))
    }
}

async fn dashboard_auth(state: &AppState, headers: &HeaderMap) -> Result<DashboardAuth, ApiError> {
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
        "SELECT u.organization_id, u.id, u.role, COALESCE(u.display_name, u.email)
         FROM web_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
           AND u.disabled_at IS NULL",
    )
    .bind(&digest)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::unauthorized("invalid or expired session"))?;
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

async fn audit(
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
        let result = sqlx::query(
            "DELETE FROM web_sessions WHERE expires_at < NOW() OR revoked_at < NOW() - INTERVAL '7 days'",
        )
        .execute(&pool)
        .await;
        if let Err(error) = result {
            tracing::warn!(%error, "expired session reaper failed");
        }
    }
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
    sqlx::query("UPDATE installations SET team_key = NULL WHERE team_id = $1")
        .bind(id)
        .execute(&state.postgres)
        .await?;
    let deleted = sqlx::query("DELETE FROM teams WHERE id = $1 AND organization_id = $2")
        .bind(id)
        .bind(organization_id)
        .execute(&state.postgres)
        .await?;
    if deleted.rows_affected() == 0 {
        return Err(ApiError::not_found("team not found"));
    }
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
            bool,
        ),
    >(
        "SELECT i.id, i.name, i.team_id, t.name, i.created_at, i.last_seen_at, i.revoked_at IS NOT NULL FROM installations i LEFT JOIN teams t ON t.id = i.team_id WHERE i.organization_id = $1 ORDER BY i.created_at DESC LIMIT 500",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, name, team_id, team_name, created_at, last_seen_at, revoked)| {
                    InstallationResponse {
                        id,
                        name,
                        team_id,
                        team_name,
                        created_at,
                        last_seen_at,
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
    let row = sqlx::query_as::<_, (String, i32, bool, bool)>(
        "SELECT name, retention_days, sso_enforced, local_login_enabled FROM organizations WHERE id = $1",
    )
    .bind(auth.organization_uuid()?)
    .fetch_one(&state.postgres)
    .await?;
    Ok(Json(SettingsResponse {
        organization_name: row.0,
        retention_days: row.1,
        sso_enforced: row.2,
        local_login_enabled: row.3,
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
    )>(
        "SELECT classifier_configured, classifier_enabled, classifier_provider_id, classifier_endpoint,
                classifier_model, classifier_credential_id, classifier_config_version,
                classifier_protocol, classifier_response_mode
         FROM organizations WHERE id = $1",
    )
    .bind(auth.organization_uuid()?)
    .fetch_one(&state.postgres)
    .await?;
    if !row.0 {
        if let Some(config) = &state.classifier {
            return Ok(Json(ClassifierSettingsResponse {
                enabled: true,
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
    if !(endpoint.starts_with("https://")
        || endpoint.starts_with("http://localhost")
        || endpoint.starts_with("http://127.0.0.1"))
    {
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
             classifier_protocol = $8, classifier_response_mode = $9
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
            "providerId": provider_id,
            "endpoint": endpoint,
            "model": model,
            "credentialId": credential_id,
        }),
    )
    .await;
    Ok(Json(ClassifierSettingsResponse {
        enabled: request.enabled,
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

async fn active_classifier_credential(
    state: &AppState,
    organization_id: Uuid,
    credential_id: &str,
) -> Result<(Option<String>, Option<i32>), ApiError> {
    if credential_id.is_empty() {
        return Ok((None, None));
    }
    let stored = sqlx::query_as::<_, (i32, Vec<u8>, Vec<u8>)>(
        "SELECT version, ciphertext, nonce FROM provider_credentials
         WHERE organization_id = $1 AND credential_id = $2
           AND revoked_at IS NULL AND grace_until IS NULL
         ORDER BY version DESC LIMIT 1",
    )
    .bind(organization_id)
    .bind(credential_id)
    .fetch_optional(&state.postgres)
    .await?;
    let Some((version, ciphertext, nonce)) = stored else {
        return Ok((None, None));
    };
    let aad = credential_aad(organization_id, credential_id, version);
    Ok((
        Some(state.vault.decrypt(&ciphertext, &nonce, aad.as_bytes())?),
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
    let (ciphertext, nonce) = state.vault.encrypt(&request.secret, aad.as_bytes())?;
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
            ciphertext, nonce, created_by, created_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
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
    password: String,
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
) -> Result<Json<RecoveryResponse>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let user_id = auth
        .user_id
        .ok_or(ApiError::unauthorized("user session required"))?;
    let row = sqlx::query_as::<_, (String, Uuid)>(
        "SELECT password_hash, organization_id FROM users
         WHERE id = $1 AND disabled_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(&state.postgres)
    .await?;
    let parsed = PasswordHash::new(&row.0)
        .map_err(|_| ApiError::unauthorized("password verification failed"))?;
    Argon2::default()
        .verify_password(request.password.as_bytes(), &parsed)
        .map_err(|_| ApiError::unauthorized("password verification failed"))?;
    let inserted = sqlx::query(
        "INSERT INTO vault_recovery_exports(organization_id, exported_by)
         VALUES ($1,$2) ON CONFLICT (organization_id) DO NOTHING",
    )
    .bind(row.1)
    .bind(user_id)
    .execute(&state.postgres)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::bad_request(
            "the recovery key has already been exported",
        ));
    }
    Ok(Json(RecoveryResponse {
        recovery_key: state.vault.recovery_key(),
    }))
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
    let provider_id = request.provider_id.trim().to_ascii_lowercase();
    let model_id = canonical_model_id(request.model_id.trim());
    let now = Utc::now();
    let catalog_version = format!("org-{}", Uuid::new_v4().simple());
    let mut transaction = state.postgres.begin().await?;
    sqlx::query(
        "UPDATE model_prices SET effective_until = $4, updated_at = $4
         WHERE organization_id = $1 AND provider_id = $2 AND model_id = $3
           AND effective_until IS NULL",
    )
    .bind(organization_id)
    .bind(&provider_id)
    .bind(&model_id)
    .bind(now)
    .execute(&mut *transaction)
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
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    audit(
        state,
        organization_id,
        &auth.name,
        "pricing.upsert",
        "model_price",
        row.0.to_string(),
        serde_json::json!({"providerId": provider_id, "modelId": model_id}),
    )
    .await;
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
    let organization_id = auth.organization_uuid()?;
    let owned = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM model_prices WHERE id = $1 AND organization_id = $2)",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_one(&state.postgres)
    .await?;
    if !owned {
        return Err(ApiError::not_found("organization price not found"));
    }
    sqlx::query(
        "UPDATE model_prices SET effective_until = NOW(), updated_at = NOW()
         WHERE id = $1 AND organization_id = $2 AND effective_until IS NULL",
    )
    .bind(id)
    .bind(organization_id)
    .execute(&state.postgres)
    .await?;
    Ok(Json(insert_org_price(&state, &auth, &request).await?))
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
    let offset = query.offset.unwrap_or(0);
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
            bool,
        ),
    >(
        "SELECT i.id, i.name, i.platform, t.name, i.created_at, i.last_seen_at,
                i.revoked_at IS NOT NULL
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
                revoked: row.6,
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
) -> Result<(StatusCode, Json<EnrollmentCodeResponse>), ApiError> {
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
    let installation_name = request.installation_name.trim();
    if installation_name.is_empty() || installation_name.chars().count() > 120 {
        return Err(ApiError::bad_request(
            "installationName must be between 1 and 120 characters",
        ));
    }
    if !matches!(
        request.platform.as_str(),
        "linux" | "wsl" | "windows" | "macos" | "other"
    ) {
        return Err(ApiError::bad_request("unsupported platform"));
    }
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
        Json(EnrollmentCodeResponse {
            code,
            expires_at,
            installation_name: installation_name.into(),
            platform: request.platform,
        }),
    ))
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(ApiError::unauthorized("missing bearer token"))
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }
    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }
    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }
    fn bad_gateway(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: message.into(),
        }
    }
    fn payload_too_large(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            message: message.into(),
        }
    }
    fn too_many_requests(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: message.into(),
        }
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(error: E) -> Self {
        tracing::error!(
            error = %format!("{:#}", error),
            error_type = std::any::type_name::<E>(),
            "request failed with an internal error"
        );
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal server error".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (
            self.status,
            Json(serde_json::json!({"error": self.message})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_vault_uses_authenticated_context() {
        let vault = SecretVault {
            key: [7_u8; 32],
            created: false,
        };
        let (ciphertext, nonce) = vault
            .encrypt("provider-secret", b"org:credential:1")
            .expect("encrypt");
        assert_ne!(ciphertext, b"provider-secret");
        assert_eq!(
            vault
                .decrypt(&ciphertext, &nonce, b"org:credential:1")
                .expect("decrypt"),
            "provider-secret"
        );
        assert!(vault
            .decrypt(&ciphertext, &nonce, b"other-org:credential:1")
            .is_err());
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
    use metrune_core::{CategoryAssignment, Cost, TokenBreakdown, UsageSlice};

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
            source_schema_version: None,
        };
        assert!(validate_snapshot(&snapshot).is_err());
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
    fn production_configuration_rejects_insecure_defaults() {
        assert!(validate_production_configuration(
            "production",
            Some("http://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("strong-bootstrap")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
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
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some("admin@example.com"),
            Some("admin")
        )
        .is_err());
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "strong",
            Some(DEVELOPMENT_BOOTSTRAP_EMAIL),
            Some("a-long-random-password")
        )
        .is_err());
    }

    #[test]
    fn production_configuration_accepts_explicit_secure_values() {
        assert!(validate_production_configuration(
            "production",
            Some("https://metrune.example.com"),
            "postgres://metrune:strong@example/postgres",
            "another-strong-password",
            Some("admin@example.com"),
            Some("a-long-random-bootstrap-password")
        )
        .is_ok());
        assert!(validate_production_configuration(
            "development",
            None,
            "postgres://metrune:metrune-dev@postgres/metrune",
            "metrune-dev",
            Some(DEVELOPMENT_BOOTSTRAP_EMAIL),
            Some("admin")
        )
        .is_ok());
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
