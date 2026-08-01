//! Deployment-wide OpenID Connect browser authentication.
//!
//! The native client remains a public OAuth client and uses Metrune's device
//! grant. OIDC authenticates the person in the browser; a successful callback
//! issues the same `mts_...` Metrune session used by password login and device
//! approval. Identity-provider tokens are never returned to or stored by the
//! native client.

use crate::{
    app::AppState,
    error::{token_hash, ApiError},
    limits::client_address,
    mailer,
};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{
        header::{CACHE_CONTROL, PRAGMA, SET_COOKIE},
        HeaderMap, HeaderValue,
    },
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::{Duration, Utc};
use openidconnect::{
    core::{
        CoreAuthenticationFlow, CoreClient, CoreClientAuthMethod, CoreIdToken, CoreProviderMetadata,
    },
    AuthType, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use std::{
    env, fs,
    net::SocketAddr,
    path::Path,
    sync::{Arc, RwLock},
    time::Duration as StdDuration,
};
use uuid::Uuid;

const AUTHORIZATION_LIFETIME_MINUTES: i64 = 10;
const DEFAULT_SESSION_TTL_HOURS: i64 = 12;
const MAX_SESSION_TTL_HOURS: i64 = 24 * 7;
const OIDC_HTTP_TIMEOUT_SECONDS: u64 = 10;

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum ProvisioningMode {
    PersonalOrganization,
    DefaultOrganization(String),
    None,
}

#[derive(Clone)]
struct OidcSettings {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
    public_api_url: String,
    public_web_url: String,
    provider_name: String,
    default_role: String,
    provisioning: ProvisioningMode,
    session_ttl_hours: i64,
}

#[derive(Clone)]
pub(crate) struct OidcRuntime {
    settings: Arc<OidcSettings>,
    provider_metadata: Arc<RwLock<CoreProviderMetadata>>,
    http_client: openidconnect::reqwest::Client,
    token_auth_method: TokenAuthMethod,
}

#[derive(Clone, Copy)]
enum TokenAuthMethod {
    ClientSecretBasic,
    ClientSecretPost,
}

#[derive(Default)]
struct OidcEnvironment {
    issuer_url: Option<String>,
    client_id: Option<String>,
    client_secret_file: Option<String>,
    client_secret: Option<String>,
    provider_name: Option<String>,
    default_role: Option<String>,
    provisioning: Option<String>,
    default_organization: Option<String>,
    session_ttl_hours: Option<String>,
}

impl OidcEnvironment {
    fn read() -> Self {
        Self {
            issuer_url: env::var("METRUNE_OIDC_ISSUER_URL").ok(),
            client_id: env::var("METRUNE_OIDC_CLIENT_ID").ok(),
            client_secret_file: env::var("METRUNE_OIDC_CLIENT_SECRET_FILE").ok(),
            client_secret: env::var("METRUNE_OIDC_CLIENT_SECRET").ok(),
            provider_name: env::var("METRUNE_OIDC_PROVIDER_NAME").ok(),
            default_role: env::var("METRUNE_OIDC_DEFAULT_ROLE").ok(),
            provisioning: env::var("METRUNE_OIDC_PROVISIONING").ok(),
            default_organization: env::var("METRUNE_OIDC_DEFAULT_ORGANIZATION").ok(),
            session_ttl_hours: env::var("METRUNE_OIDC_SESSION_TTL_HOURS").ok(),
        }
    }
}

impl OidcRuntime {
    pub(crate) async fn from_env(
        environment: &str,
        public_api_url: Option<&str>,
        public_web_url: &str,
    ) -> anyhow::Result<Option<Self>> {
        let Some(settings) = settings_from_values(
            OidcEnvironment::read(),
            environment,
            public_api_url,
            public_web_url,
        )?
        else {
            return Ok(None);
        };
        Ok(Some(
            Self::from_settings(settings, StdDuration::from_secs(OIDC_HTTP_TIMEOUT_SECONDS))
                .await?,
        ))
    }

    async fn from_settings(
        settings: OidcSettings,
        http_timeout: StdDuration,
    ) -> anyhow::Result<Self> {
        let http_client = openidconnect::reqwest::ClientBuilder::new()
            // Discovery, JWKS and token endpoints are security-sensitive
            // operator configuration. Following redirects would turn them
            // into an SSRF primitive.
            .redirect(openidconnect::reqwest::redirect::Policy::none())
            .timeout(http_timeout)
            .build()?;
        let provider_metadata =
            CoreProviderMetadata::discover_async(settings.issuer.clone(), &http_client)
                .await
                .map_err(|error| anyhow::anyhow!("discover OIDC provider: {error}"))?;
        validate_provider_metadata(&provider_metadata)?;
        let token_auth_method = select_token_auth_method(&provider_metadata)?;

        // Building the client now exercises the discovered authorization
        // endpoint contract before password login is disabled.
        let _ = CoreClient::from_provider_metadata(
            provider_metadata.clone(),
            settings.client_id.clone(),
            Some(settings.client_secret.clone()),
        )
        .set_redirect_uri(settings.redirect_url.clone())
        .set_auth_type(token_auth_method.oauth_type());

        Ok(Self {
            settings: Arc::new(settings),
            provider_metadata: Arc::new(RwLock::new(provider_metadata)),
            http_client,
            token_auth_method,
        })
    }

    #[cfg(test)]
    pub(crate) async fn for_tests(
        issuer_url: &str,
        public_api_url: &str,
        public_web_url: &str,
        provisioning: &str,
        default_organization: Option<&str>,
    ) -> anyhow::Result<Self> {
        let settings = settings_from_values(
            OidcEnvironment {
                issuer_url: Some(issuer_url.into()),
                client_id: Some("metrune-test".into()),
                client_secret: Some("test-client-secret".into()),
                provider_name: Some("Test identity provider".into()),
                default_role: Some("viewer".into()),
                provisioning: Some(provisioning.into()),
                default_organization: default_organization.map(str::to_owned),
                session_ttl_hours: Some("12".into()),
                client_secret_file: None,
            },
            "development",
            Some(public_api_url),
            public_web_url,
        )?
        .expect("test OIDC configuration is complete");
        Self::from_settings(settings, StdDuration::from_millis(500)).await
    }

    fn client(&self, provider_metadata: CoreProviderMetadata) -> OidcClient {
        CoreClient::from_provider_metadata(
            provider_metadata,
            self.settings.client_id.clone(),
            Some(self.settings.client_secret.clone()),
        )
        .set_redirect_uri(self.settings.redirect_url.clone())
        .set_auth_type(self.token_auth_method.oauth_type())
    }

    fn metadata(&self) -> CoreProviderMetadata {
        self.provider_metadata
            .read()
            .expect("OIDC metadata lock poisoned")
            .clone()
    }

    async fn refresh_metadata(&self) -> anyhow::Result<CoreProviderMetadata> {
        let metadata =
            CoreProviderMetadata::discover_async(self.settings.issuer.clone(), &self.http_client)
                .await
                .map_err(|error| anyhow::anyhow!("refresh OIDC provider metadata: {error}"))?;
        validate_provider_metadata(&metadata)?;
        ensure_token_auth_method(&metadata, self.token_auth_method)?;
        *self
            .provider_metadata
            .write()
            .expect("OIDC metadata lock poisoned") = metadata.clone();
        Ok(metadata)
    }

    fn is_secure(&self) -> bool {
        self.settings.public_api_url.starts_with("https://")
    }
}

impl TokenAuthMethod {
    fn oauth_type(self) -> AuthType {
        match self {
            Self::ClientSecretBasic => AuthType::BasicAuth,
            Self::ClientSecretPost => AuthType::RequestBody,
        }
    }
}

fn validate_provider_metadata(metadata: &CoreProviderMetadata) -> anyhow::Result<()> {
    if metadata.token_endpoint().is_none() {
        anyhow::bail!("OIDC discovery document does not advertise a token endpoint");
    }
    Ok(())
}

fn select_token_auth_method(metadata: &CoreProviderMetadata) -> anyhow::Result<TokenAuthMethod> {
    let Some(methods) = metadata.token_endpoint_auth_methods_supported() else {
        // OpenID Connect Discovery defines client_secret_basic as the default
        // when the field is omitted.
        return Ok(TokenAuthMethod::ClientSecretBasic);
    };
    if methods.contains(&CoreClientAuthMethod::ClientSecretBasic) {
        return Ok(TokenAuthMethod::ClientSecretBasic);
    }
    if methods.contains(&CoreClientAuthMethod::ClientSecretPost) {
        return Ok(TokenAuthMethod::ClientSecretPost);
    }
    anyhow::bail!(
        "OIDC provider does not support client_secret_basic or client_secret_post at its token endpoint"
    )
}

fn ensure_token_auth_method(
    metadata: &CoreProviderMetadata,
    selected: TokenAuthMethod,
) -> anyhow::Result<()> {
    let Some(methods) = metadata.token_endpoint_auth_methods_supported() else {
        if matches!(selected, TokenAuthMethod::ClientSecretBasic) {
            return Ok(());
        }
        anyhow::bail!("OIDC provider no longer advertises client_secret_post");
    };
    let expected = match selected {
        TokenAuthMethod::ClientSecretBasic => CoreClientAuthMethod::ClientSecretBasic,
        TokenAuthMethod::ClientSecretPost => CoreClientAuthMethod::ClientSecretPost,
    };
    if !methods.contains(&expected) {
        anyhow::bail!(
            "OIDC provider no longer supports the configured token client authentication method"
        );
    }
    Ok(())
}

fn nonempty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    })
}

fn settings_from_values(
    values: OidcEnvironment,
    environment: &str,
    public_api_url: Option<&str>,
    public_web_url: &str,
) -> anyhow::Result<Option<OidcSettings>> {
    let issuer_url = nonempty(values.issuer_url);
    let client_id = nonempty(values.client_id);
    let secret_file = nonempty(values.client_secret_file);
    let direct_secret = nonempty(values.client_secret);
    let any_configured = issuer_url.is_some()
        || client_id.is_some()
        || secret_file.is_some()
        || direct_secret.is_some();
    if !any_configured {
        return Ok(None);
    }
    if issuer_url.is_none()
        || client_id.is_none()
        || (secret_file.is_none() && direct_secret.is_none())
    {
        anyhow::bail!(
            "OIDC configuration is incomplete; issuer URL, client ID, and exactly one client secret source are required"
        );
    }
    if secret_file.is_some() && direct_secret.is_some() {
        anyhow::bail!(
            "configure only one of METRUNE_OIDC_CLIENT_SECRET_FILE and METRUNE_OIDC_CLIENT_SECRET"
        );
    }
    if environment == "production" && direct_secret.is_some() {
        anyhow::bail!(
            "METRUNE_OIDC_CLIENT_SECRET is development-only; use METRUNE_OIDC_CLIENT_SECRET_FILE in production"
        );
    }

    let issuer_text = issuer_url.expect("checked above");
    if environment == "production" && !issuer_text.starts_with("https://") {
        anyhow::bail!("METRUNE_OIDC_ISSUER_URL must use HTTPS in production");
    }
    let issuer = IssuerUrl::new(issuer_text)
        .map_err(|error| anyhow::anyhow!("invalid METRUNE_OIDC_ISSUER_URL: {error}"))?;
    let public_api_url = public_api_url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("METRUNE_PUBLIC_API_URL is required when OIDC is configured")
        })?
        .trim_end_matches('/')
        .to_owned();
    let public_web_url = public_web_url.trim().trim_end_matches('/').to_owned();
    if public_web_url.is_empty() {
        anyhow::bail!("METRUNE_PUBLIC_WEB_URL is required when OIDC is configured");
    }
    let public_api = reqwest::Url::parse(&public_api_url)
        .map_err(|error| anyhow::anyhow!("invalid METRUNE_PUBLIC_API_URL: {error}"))?;
    let public_web = reqwest::Url::parse(&public_web_url)
        .map_err(|error| anyhow::anyhow!("invalid METRUNE_PUBLIC_WEB_URL: {error}"))?;
    if public_api.host_str().is_none() || public_web.host_str().is_none() {
        anyhow::bail!("OIDC public API and web URLs must include a hostname");
    }
    if public_api.host_str() != public_web.host_str() {
        anyhow::bail!(
            "OIDC requires METRUNE_PUBLIC_API_URL and METRUNE_PUBLIC_WEB_URL to use the same hostname so the browser session cookie reaches the web application"
        );
    }

    let secret = match secret_file {
        Some(path) => read_secret_file(Path::new(&path), environment)?,
        None => direct_secret.expect("checked above"),
    };
    let default_role = nonempty(values.default_role).unwrap_or_else(|| "viewer".into());
    if !matches!(default_role.as_str(), "viewer" | "analyst" | "admin") {
        anyhow::bail!("METRUNE_OIDC_DEFAULT_ROLE must be viewer, analyst, or admin");
    }
    let provisioning = match nonempty(values.provisioning)
        .unwrap_or_else(|| "none".into())
        .as_str()
    {
        "personal-org" => ProvisioningMode::PersonalOrganization,
        "default-org" => {
            let organization = nonempty(values.default_organization).ok_or_else(|| {
                anyhow::anyhow!(
                    "METRUNE_OIDC_DEFAULT_ORGANIZATION is required for default-org provisioning"
                )
            })?;
            ProvisioningMode::DefaultOrganization(organization)
        }
        "none" => ProvisioningMode::None,
        _ => anyhow::bail!("METRUNE_OIDC_PROVISIONING must be personal-org, default-org, or none"),
    };
    let session_ttl_hours = match nonempty(values.session_ttl_hours) {
        Some(value) => value
            .parse::<i64>()
            .map_err(|_| anyhow::anyhow!("METRUNE_OIDC_SESSION_TTL_HOURS must be an integer"))?,
        None => DEFAULT_SESSION_TTL_HOURS,
    };
    if !(1..=MAX_SESSION_TTL_HOURS).contains(&session_ttl_hours) {
        anyhow::bail!(
            "METRUNE_OIDC_SESSION_TTL_HOURS must be between 1 and {MAX_SESSION_TTL_HOURS}"
        );
    }

    let provider_name = nonempty(values.provider_name).unwrap_or_else(|| "Single sign-on".into());
    if provider_name.chars().count() > 80 {
        anyhow::bail!("METRUNE_OIDC_PROVIDER_NAME must be at most 80 characters");
    }

    Ok(Some(OidcSettings {
        issuer,
        client_id: ClientId::new(client_id.expect("checked above")),
        client_secret: ClientSecret::new(secret),
        redirect_url: RedirectUrl::new(format!("{public_api_url}/v1/auth/sso/callback"))
            .map_err(|error| anyhow::anyhow!("invalid OIDC redirect URL: {error}"))?,
        public_api_url,
        public_web_url,
        provider_name,
        default_role,
        provisioning,
        session_ttl_hours,
    }))
}

fn read_secret_file(path: &Path, environment: &str) -> anyhow::Result<String> {
    let metadata = fs::metadata(path)
        .map_err(|error| anyhow::anyhow!("read OIDC client secret metadata: {error}"))?;
    if !metadata.is_file() {
        anyhow::bail!("METRUNE_OIDC_CLIENT_SECRET_FILE must reference a regular file");
    }
    #[cfg(unix)]
    if environment == "production" {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            anyhow::bail!("OIDC client secret file must not be readable by group or other users");
        }
    }
    let secret = fs::read_to_string(path)
        .map_err(|error| anyhow::anyhow!("read OIDC client secret file: {error}"))?;
    let secret = secret.trim();
    if secret.is_empty() {
        anyhow::bail!("OIDC client secret file is empty");
    }
    Ok(secret.to_owned())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthMethodsResponse {
    sso_enabled: bool,
    password_enabled: bool,
    provider_name: Option<String>,
}

pub(crate) async fn auth_methods(State(state): State<AppState>) -> Json<AuthMethodsResponse> {
    Json(AuthMethodsResponse {
        sso_enabled: state.oidc.is_some(),
        password_enabled: state.oidc.is_none(),
        provider_name: state
            .oidc
            .as_ref()
            .map(|oidc| oidc.settings.provider_name.clone()),
    })
}

#[derive(Deserialize, Default)]
pub(crate) struct StartQuery {
    next: Option<String>,
}

pub(crate) async fn start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query): Query<StartQuery>,
) -> Result<Response, ApiError> {
    let oidc = state
        .oidc
        .as_ref()
        .ok_or_else(|| ApiError::not_found("single sign-on is not configured"))?;
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    state
        .rate_limiter
        .check("sso-start", &address, state.rate_limits.login)?;
    let next = query.next.as_deref().and_then(safe_next_path);

    let client = oidc.client(oidc.metadata());
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorization_url, csrf_state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    sqlx::query(
        "INSERT INTO oidc_authorization_attempts(
           state_hash, pkce_verifier, nonce, next_path, expires_at
         ) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(token_hash(csrf_state.secret()))
    .bind(pkce_verifier.secret())
    .bind(nonce.secret())
    .bind(next)
    .bind(Utc::now() + Duration::minutes(AUTHORIZATION_LIFETIME_MINUTES))
    .execute(&state.postgres)
    .await?;

    Ok(no_store_redirect(authorization_url.as_str(), None))
}

#[derive(Deserialize, Default)]
pub(crate) struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub(crate) async fn callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = state.oidc.as_ref() else {
        return oidc_error_redirect(&state.public_web_url, "not_configured");
    };
    match callback_inner(&state, oidc, query).await {
        Ok(response) => response,
        Err(error) => {
            tracing::warn!(
                error = %format!("{:#}", error.source),
                public_code = error.public_code,
                "OIDC sign-in failed"
            );
            oidc_error_redirect(&oidc.settings.public_web_url, error.public_code)
        }
    }
}

struct FlowError {
    public_code: &'static str,
    source: anyhow::Error,
}

impl FlowError {
    fn new(public_code: &'static str, source: impl Into<anyhow::Error>) -> Self {
        Self {
            public_code,
            source: source.into(),
        }
    }
}

async fn callback_inner(
    state: &AppState,
    oidc: &OidcRuntime,
    query: CallbackQuery,
) -> Result<Response, FlowError> {
    let raw_state = query
        .state
        .filter(|state| !state.is_empty() && state.len() <= 1024)
        .ok_or_else(|| FlowError::new("invalid_state", anyhow::anyhow!("missing OIDC state")))?;
    let attempt = sqlx::query_as::<_, (String, String, Option<String>)>(
        "UPDATE oidc_authorization_attempts
         SET consumed_at = NOW()
         WHERE state_hash = $1 AND consumed_at IS NULL AND expires_at > NOW()
         RETURNING pkce_verifier, nonce, next_path",
    )
    .bind(token_hash(&raw_state))
    .fetch_optional(&state.postgres)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?
    .ok_or_else(|| {
        FlowError::new(
            "invalid_state",
            anyhow::anyhow!("OIDC state is missing, expired, or already consumed"),
        )
    })?;

    if let Some(provider_error) = query.error {
        return Err(FlowError::new(
            if provider_error == "access_denied" {
                "access_denied"
            } else {
                "provider_error"
            },
            anyhow::anyhow!("provider returned OAuth error {provider_error}"),
        ));
    }
    let code = query
        .code
        .filter(|code| !code.is_empty() && code.len() <= 8192)
        .ok_or_else(|| {
            FlowError::new(
                "invalid_response",
                anyhow::anyhow!("provider callback omitted authorization code"),
            )
        })?;

    let metadata = oidc.metadata();
    let client = oidc.client(metadata);
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|error| FlowError::new("provider_error", anyhow::anyhow!("{error}")))?
        .set_pkce_verifier(PkceCodeVerifier::new(attempt.0))
        .request_async(&oidc.http_client)
        .await
        .map_err(|error| {
            FlowError::new(
                "temporarily_unavailable",
                anyhow::anyhow!("OIDC code exchange failed: {error}"),
            )
        })?;
    let id_token = token_response.id_token().ok_or_else(|| {
        FlowError::new(
            "invalid_response",
            anyhow::anyhow!("provider token response omitted ID token"),
        )
    })?;
    let expected_nonce = Nonce::new(attempt.1);

    let identity = match extract_identity(&client, id_token, &expected_nonce) {
        Ok(identity) => identity,
        Err(first_error) => {
            // Retry verification once with freshly discovered keys. This
            // covers normal provider JWKS rotation without accepting a token
            // that failed any issuer, audience, expiry, signature or nonce
            // check.
            let refreshed = oidc
                .refresh_metadata()
                .await
                .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
            let refreshed_client = oidc.client(refreshed);
            extract_identity(&refreshed_client, id_token, &expected_nonce).map_err(|second_error| {
                FlowError::new(
                    "invalid_token",
                    anyhow::anyhow!(
                        "ID token validation failed before and after JWKS refresh: {first_error}; {second_error}"
                    ),
                )
            })?
        }
    };

    let issued = issue_oidc_session(state, oidc, identity)
        .await
        .map_err(|error| FlowError::new(error.public_code, error.source))?;
    let destination = attempt.2.unwrap_or_else(|| {
        if issued.active_organization_id.is_some() {
            "/".into()
        } else {
            "/organizations".into()
        }
    });
    let location = format!("{}{}", oidc.settings.public_web_url, destination);
    let expires = issued.expires_at.format("%a, %d %b %Y %H:%M:%S GMT");
    let mut cookie = format!(
        "metrune_session={}; Path=/; HttpOnly; SameSite=Lax; Expires={expires}",
        issued.session_token
    );
    if oidc.is_secure() {
        cookie.push_str("; Secure");
    }
    Ok(no_store_redirect(&location, Some(cookie)))
}

struct OidcIdentity {
    issuer: String,
    subject: String,
    email: String,
    display_name: Option<String>,
}

fn extract_identity(
    client: &OidcClient,
    id_token: &CoreIdToken,
    nonce: &Nonce,
) -> anyhow::Result<OidcIdentity> {
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, nonce)
        .map_err(|error| anyhow::anyhow!("verify ID token: {error}"))?;
    if claims.email_verified() != Some(true) {
        anyhow::bail!("ID token does not contain a verified email");
    }
    let email = claims
        .email()
        .map(|email| email.as_str().to_owned())
        .ok_or_else(|| anyhow::anyhow!("ID token does not contain an email"))?;
    let display_name = claims
        .name()
        .and_then(|names| names.get(None))
        .map(|name| name.as_str().trim())
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(200).collect());
    Ok(OidcIdentity {
        issuer: claims.issuer().as_str().to_owned(),
        subject: claims.subject().as_str().to_owned(),
        email,
        display_name,
    })
}

struct IssuedSession {
    session_token: String,
    expires_at: chrono::DateTime<Utc>,
    active_organization_id: Option<Uuid>,
}

async fn issue_oidc_session(
    state: &AppState,
    oidc: &OidcRuntime,
    identity: OidcIdentity,
) -> Result<IssuedSession, FlowError> {
    if identity.subject.is_empty() || identity.subject.chars().count() > 512 {
        return Err(FlowError::new(
            "invalid_token",
            anyhow::anyhow!("OIDC subject is empty or too long"),
        ));
    }
    let email = mailer::normalize_email(&identity.email).map_err(|_| {
        FlowError::new(
            "invalid_token",
            anyhow::anyhow!("OIDC email claim is invalid"),
        )
    })?;
    let mut transaction = state
        .postgres
        .begin()
        .await
        .map_err(|error| FlowError::new("temporarily_unavailable", error))?;

    let (user_id, audit_action, audit_organization) =
        resolve_user(&mut transaction, oidc, &identity, &email).await?;
    let organizations = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT m.organization_id, m.role
         FROM organization_memberships m
         JOIN organizations o ON o.id = m.organization_id
         WHERE m.user_id = $1 AND m.disabled_at IS NULL
         ORDER BY LOWER(o.name), o.id",
    )
    .bind(user_id)
    .fetch_all(&mut *transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    if organizations.is_empty() {
        return Err(FlowError::new(
            "account_unavailable",
            anyhow::anyhow!("OIDC user has no active organization membership"),
        ));
    }
    let active_organization_id = (organizations.len() == 1).then_some(organizations[0].0);
    let session_token = format!("mts_{}", Uuid::new_v4().simple());
    let expires_at = Utc::now() + Duration::hours(oidc.settings.session_ttl_hours);
    sqlx::query(
        "INSERT INTO web_sessions(
           user_id, token_hash, active_organization_id, created_at, expires_at,
           authentication_method
         ) VALUES ($1,$2,$3,NOW(),$4,'oidc')",
    )
    .bind(user_id)
    .bind(token_hash(&session_token))
    .bind(active_organization_id)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(&mut *transaction)
        .await
        .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    if let (Some(action), Some(organization_id)) = (audit_action, audit_organization) {
        sqlx::query(
            "INSERT INTO audit_events(
               organization_id, actor_user_id, actor_label, action,
               target_type, target_id, metadata
             ) VALUES ($1,$2,$3,$4,'user',$5,$6)",
        )
        .bind(organization_id)
        .bind(user_id)
        .bind(&email)
        .bind(action)
        .bind(user_id.to_string())
        .bind(serde_json::json!({"issuer": identity.issuer}))
        .execute(&mut *transaction)
        .await
        .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    }
    transaction
        .commit()
        .await
        .map_err(|error| FlowError::new("temporarily_unavailable", error))?;

    Ok(IssuedSession {
        session_token,
        expires_at,
        active_organization_id,
    })
}

async fn resolve_user(
    transaction: &mut Transaction<'_, Postgres>,
    oidc: &OidcRuntime,
    identity: &OidcIdentity,
    email: &str,
) -> Result<(Uuid, Option<&'static str>, Option<Uuid>), FlowError> {
    if let Some(user_id) = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users
         WHERE issuer = $1 AND subject = $2 AND disabled_at IS NULL
         FOR UPDATE",
    )
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?
    {
        if let Some(display_name) = identity.display_name.as_deref() {
            sqlx::query(
                "UPDATE users SET display_name = COALESCE(NULLIF($2, ''), display_name)
                 WHERE id = $1",
            )
            .bind(user_id)
            .bind(display_name)
            .execute(&mut **transaction)
            .await
            .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
        }
        return Ok((user_id, None, None));
    }

    let email_matches = sqlx::query_as::<_, (Uuid, Option<String>, Option<String>, Uuid)>(
        "SELECT id, issuer, subject, organization_id
         FROM users
         WHERE LOWER(email) = $1 AND disabled_at IS NULL
         ORDER BY created_at, id
         FOR UPDATE",
    )
    .bind(email)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    if email_matches.len() > 1 {
        return Err(FlowError::new(
            "account_conflict",
            anyhow::anyhow!("verified OIDC email matches more than one Metrune user"),
        ));
    }
    if let Some((user_id, issuer, subject, organization_id)) = email_matches.into_iter().next() {
        if issuer.is_some() || subject.is_some() {
            return Err(FlowError::new(
                "account_conflict",
                anyhow::anyhow!("Metrune user is already bound to another external identity"),
            ));
        }
        sqlx::query(
            "UPDATE users
             SET issuer = $2, subject = $3,
                 display_name = COALESCE(NULLIF($4, ''), display_name)
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(&identity.issuer)
        .bind(&identity.subject)
        .bind(identity.display_name.as_deref())
        .execute(&mut **transaction)
        .await
        .map_err(|error| FlowError::new("account_conflict", error))?;
        return Ok((user_id, Some("identity.oidc_bind"), Some(organization_id)));
    }

    match oidc.settings.provisioning {
        ProvisioningMode::None => Err(FlowError::new(
            "account_unavailable",
            anyhow::anyhow!("OIDC just-in-time provisioning is disabled"),
        )),
        ProvisioningMode::PersonalOrganization => {
            let organization_id = sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO organizations(name, sso_enforced, local_login_enabled)
                 VALUES ($1,TRUE,FALSE) RETURNING id",
            )
            .bind(personal_organization_name(email))
            .fetch_one(&mut **transaction)
            .await
            .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
            let user_id =
                insert_oidc_user(transaction, organization_id, identity, email, "admin").await?;
            insert_membership(transaction, organization_id, user_id, "admin").await?;
            Ok((
                user_id,
                Some("identity.oidc_provision"),
                Some(organization_id),
            ))
        }
        ProvisioningMode::DefaultOrganization(ref selector) => {
            let organization_id = resolve_default_organization(transaction, selector).await?;
            let user_id = insert_oidc_user(
                transaction,
                organization_id,
                identity,
                email,
                &oidc.settings.default_role,
            )
            .await?;
            insert_membership(
                transaction,
                organization_id,
                user_id,
                &oidc.settings.default_role,
            )
            .await?;
            Ok((
                user_id,
                Some("identity.oidc_provision"),
                Some(organization_id),
            ))
        }
    }
}

async fn resolve_default_organization(
    transaction: &mut Transaction<'_, Postgres>,
    selector: &str,
) -> Result<Uuid, FlowError> {
    if let Ok(id) = selector.parse::<Uuid>() {
        return sqlx::query_scalar::<_, Uuid>("SELECT id FROM organizations WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut **transaction)
            .await
            .map_err(|error| FlowError::new("temporarily_unavailable", error))?
            .ok_or_else(|| {
                FlowError::new(
                    "account_unavailable",
                    anyhow::anyhow!("configured default OIDC organization does not exist"),
                )
            });
    }
    let matches = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM organizations
         WHERE LOWER(name) = LOWER($1)
         ORDER BY created_at, id",
    )
    .bind(selector)
    .fetch_all(&mut **transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    if matches.len() != 1 {
        return Err(FlowError::new(
            "account_unavailable",
            anyhow::anyhow!("default OIDC organization name must match exactly one organization"),
        ));
    }
    Ok(matches[0])
}

async fn insert_oidc_user(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    identity: &OidcIdentity,
    email: &str,
    role: &str,
) -> Result<Uuid, FlowError> {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO users(
           organization_id, email, display_name, password_hash,
           role, issuer, subject
         ) VALUES ($1,$2,$3,NULL,$4,$5,$6)
         RETURNING id",
    )
    .bind(organization_id)
    .bind(email)
    .bind(identity.display_name.as_deref())
    .bind(role)
    .bind(&identity.issuer)
    .bind(&identity.subject)
    .fetch_one(&mut **transaction)
    .await
    .map_err(|error| FlowError::new("account_conflict", error))
}

async fn insert_membership(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    user_id: Uuid,
    role: &str,
) -> Result<(), FlowError> {
    sqlx::query(
        "INSERT INTO organization_memberships(organization_id, user_id, role)
         VALUES ($1,$2,$3)",
    )
    .bind(organization_id)
    .bind(user_id)
    .bind(role)
    .execute(&mut **transaction)
    .await
    .map_err(|error| FlowError::new("temporarily_unavailable", error))?;
    Ok(())
}

fn personal_organization_name(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("Personal").trim();
    let local = if local.is_empty() { "Personal" } else { local };
    format!("{local}'s Workspace").chars().take(120).collect()
}

fn safe_next_path(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_owned())
}

fn no_store_redirect(location: &str, cookie: Option<String>) -> Response {
    let mut response = Redirect::temporary(location).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(PRAGMA, HeaderValue::from_static("no-cache"));
    if let Some(cookie) = cookie {
        if let Ok(cookie) = HeaderValue::from_str(&cookie) {
            response.headers_mut().insert(SET_COOKIE, cookie);
        }
    }
    response
}

fn oidc_error_redirect(public_web_url: &str, code: &str) -> Response {
    no_store_redirect(
        &format!(
            "{}/login?sso_error={code}",
            public_web_url.trim_end_matches('/')
        ),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured_values() -> OidcEnvironment {
        OidcEnvironment {
            issuer_url: Some("http://127.0.0.1:9000".into()),
            client_id: Some("metrune-test".into()),
            client_secret: Some("secret".into()),
            provisioning: Some("none".into()),
            ..OidcEnvironment::default()
        }
    }

    #[test]
    fn an_empty_oidc_environment_keeps_password_login_enabled() {
        assert!(settings_from_values(
            OidcEnvironment::default(),
            "production",
            Some("https://metrune.example"),
            "https://metrune.example",
        )
        .expect("empty OIDC configuration")
        .is_none());
    }

    #[test]
    fn partial_oidc_configuration_fails_closed() {
        let error = settings_from_values(
            OidcEnvironment {
                issuer_url: Some("https://idp.example".into()),
                ..OidcEnvironment::default()
            },
            "production",
            Some("https://metrune.example"),
            "https://metrune.example",
        )
        .err()
        .expect("partial OIDC configuration must fail");
        assert!(error.to_string().contains("incomplete"));
    }

    #[test]
    fn production_requires_https_and_a_secret_file() {
        let error = settings_from_values(
            configured_values(),
            "production",
            Some("https://metrune.example"),
            "https://metrune.example",
        )
        .err()
        .expect("direct production secret must fail");
        assert!(error.to_string().contains("development-only"));
    }

    #[test]
    fn default_org_provisioning_accepts_an_operator_selected_name() {
        let mut values = configured_values();
        values.provisioning = Some("default-org".into());
        values.default_organization = Some("engineering".into());
        let settings = settings_from_values(
            values,
            "development",
            Some("http://localhost:8080"),
            "http://localhost:3001",
        )
        .expect("named default organization is resolved against the database")
        .expect("OIDC settings");
        assert_eq!(
            settings.provisioning,
            ProvisioningMode::DefaultOrganization("engineering".into())
        );
    }

    #[test]
    fn browser_and_api_urls_must_share_the_cookie_hostname() {
        let same_host = settings_from_values(
            configured_values(),
            "development",
            Some("http://localhost:8080"),
            "http://localhost:3001",
        )
        .expect("different development ports share a cookie hostname");
        assert!(same_host.is_some());

        let error = settings_from_values(
            configured_values(),
            "development",
            Some("http://api.example.test:8080"),
            "http://dashboard.example.test:3001",
        )
        .err()
        .expect("split hostnames must fail");
        assert!(error.to_string().contains("same hostname"));
    }

    #[test]
    fn provider_names_are_bounded_before_they_reach_the_login_page() {
        let mut values = configured_values();
        values.provider_name = Some("x".repeat(81));
        let error = settings_from_values(
            values,
            "development",
            Some("http://localhost:8080"),
            "http://localhost:3001",
        )
        .err()
        .expect("oversized provider name must fail");
        assert!(error.to_string().contains("at most 80"));
    }

    #[test]
    fn unsupported_token_client_authentication_fails_closed() {
        let metadata: CoreProviderMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://idp.example.test",
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["private_key_jwt"]
        }))
        .expect("provider metadata fixture");
        let error = select_token_auth_method(&metadata)
            .err()
            .expect("unsupported client authentication must fail");
        assert!(error.to_string().contains("client_secret_basic"));
    }

    #[cfg(unix)]
    #[test]
    fn production_secret_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "metrune-oidc-secret-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        fs::write(&path, "test-secret\n").expect("write OIDC test secret");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("make OIDC secret private");
        let values = || OidcEnvironment {
            issuer_url: Some("https://idp.example.test".into()),
            client_id: Some("metrune-test".into()),
            client_secret_file: Some(path.to_string_lossy().into_owned()),
            provisioning: Some("none".into()),
            ..OidcEnvironment::default()
        };
        assert!(settings_from_values(
            values(),
            "production",
            Some("https://metrune.example"),
            "https://metrune.example",
        )
        .expect("private secret file")
        .is_some());

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("make OIDC secret public");
        let error = settings_from_values(
            values(),
            "production",
            Some("https://metrune.example"),
            "https://metrune.example",
        )
        .err()
        .expect("public secret file must fail");
        assert!(error.to_string().contains("group or other"));
        fs::remove_file(path).expect("remove OIDC test secret");
    }

    #[test]
    fn next_paths_are_strictly_same_origin_relative_paths() {
        for accepted in [
            "/",
            "/device?user_code=ABCD-2345",
            "/organizations?next=%2Fdevice",
        ] {
            assert_eq!(safe_next_path(accepted).as_deref(), Some(accepted));
        }
        for rejected in [
            "",
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/line\nbreak",
        ] {
            assert_eq!(safe_next_path(rejected), None, "{rejected:?}");
        }
    }
}
