//! Browser OIDC, local-password fallback, device approval, and client upload.
//!
//! The provider is a real in-process HTTP server. It performs authorization
//! redirects, validates the PKCE verifier at its token endpoint, and signs ID
//! tokens with an RSA key exposed through discovery/JWKS. These tests therefore
//! exercise the same network and cryptographic path used with an enterprise
//! identity provider without requiring a vendor account.

use super::harness::{batch, snapshot, Harness, CLICKHOUSE_URL_VAR, DATABASE_URL_VAR};
use crate::{error::token_hash, oidc::OidcRuntime};

use axum::{
    body::Body,
    extract::{Form, Query, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, LOCATION, SET_COOKIE},
        HeaderMap, Request, StatusCode,
    },
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use chrono::{Duration, Utc};
use openidconnect::{
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
    AccessToken, Audience, EmptyAdditionalClaims, EndUserEmail, IssuerUrl, JsonWebKeyId, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
};
use uuid::Uuid;

const CLIENT_ID: &str = "metrune-test";
const CLIENT_SECRET: &str = "test-client-secret";
const PUBLIC_API: &str = "http://metrune.test";
const PUBLIC_WEB: &str = "http://metrune.test";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

fn test_rsa_private_key() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        let output = Command::new("openssl")
            .args(["genrsa", "-traditional", "2048"])
            .output()
            .expect("generate mock OIDC key with openssl");
        assert!(
            output.status.success(),
            "openssl failed to generate mock OIDC key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).expect("mock OIDC key is UTF-8 PEM")
    })
}

#[derive(Clone, Copy, Debug)]
enum ProviderMode {
    Valid,
    ClientSecretPost,
    UnverifiedEmail,
    WrongNonce,
    WrongAudience,
    Expired,
    MissingIdToken,
    Unavailable,
    Slow,
    AccessDenied,
}

struct PendingAuthorization {
    nonce: String,
    code_challenge: String,
}

struct ProviderState {
    issuer: String,
    email: String,
    subject: String,
    mode: ProviderMode,
    rotate_jwks: bool,
    signing_key: Arc<CoreRsaPrivateSigningKey>,
    pending: Mutex<HashMap<String, PendingAuthorization>>,
    token_requests: AtomicUsize,
    jwks_requests: AtomicUsize,
}

struct MockProvider {
    issuer: String,
    state: Arc<ProviderState>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockProvider {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl MockProvider {
    async fn start(email: &str, subject: &str, mode: ProviderMode, rotate_jwks: bool) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock OIDC provider");
        let issuer = format!(
            "http://{}",
            listener.local_addr().expect("mock provider address")
        );
        let signing_key = CoreRsaPrivateSigningKey::from_pem(
            test_rsa_private_key(),
            Some(JsonWebKeyId::new("metrune-test-key".into())),
        )
        .expect("parse mock provider signing key");
        let state = Arc::new(ProviderState {
            issuer: issuer.clone(),
            email: email.into(),
            subject: subject.into(),
            mode,
            rotate_jwks,
            signing_key: Arc::new(signing_key),
            pending: Mutex::new(HashMap::new()),
            token_requests: AtomicUsize::new(0),
            jwks_requests: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_document))
            .route("/authorize", get(authorize))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock OIDC provider");
        });
        Self {
            issuer,
            state,
            server,
        }
    }
}

async fn discovery_document(State(state): State<Arc<ProviderState>>) -> Json<Value> {
    let token_auth_method = if matches!(state.mode, ProviderMode::ClientSecretPost) {
        "client_secret_post"
    } else {
        "client_secret_basic"
    };
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": [token_auth_method],
        "claims_supported": ["sub", "email", "email_verified", "nonce"]
    }))
}

async fn jwks(State(state): State<Arc<ProviderState>>) -> Json<CoreJsonWebKeySet> {
    let request = state.jwks_requests.fetch_add(1, Ordering::SeqCst);
    if state.rotate_jwks && request == 0 {
        return Json(CoreJsonWebKeySet::new(Vec::new()));
    }
    Json(CoreJsonWebKeySet::new(vec![state
        .signing_key
        .as_verification_key()]))
}

#[derive(Deserialize)]
struct AuthorizationQuery {
    client_id: String,
    redirect_uri: String,
    response_type: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: String,
}

async fn authorize(
    State(state): State<Arc<ProviderState>>,
    Query(query): Query<AuthorizationQuery>,
) -> Response {
    if query.client_id != CLIENT_ID
        || query.response_type != "code"
        || query.code_challenge_method != "S256"
        || !query.scope.split(' ').any(|scope| scope == "openid")
        || !query.scope.split(' ').any(|scope| scope == "email")
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let mut callback = match reqwest::Url::parse(&query.redirect_uri) {
        Ok(callback) => callback,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if matches!(state.mode, ProviderMode::AccessDenied) {
        callback
            .query_pairs_mut()
            .append_pair("error", "access_denied")
            .append_pair("state", &query.state);
        return Redirect::temporary(callback.as_str()).into_response();
    }
    let code = format!("code-{}", Uuid::new_v4().simple());
    state.pending.lock().expect("provider pending lock").insert(
        code.clone(),
        PendingAuthorization {
            nonce: query.nonce,
            code_challenge: query.code_challenge,
        },
    );
    callback
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &query.state);
    Redirect::temporary(callback.as_str()).into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    code_verifier: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn token(
    State(state): State<Arc<ProviderState>>,
    headers: HeaderMap,
    Form(form): Form<TokenForm>,
) -> Response {
    state.token_requests.fetch_add(1, Ordering::SeqCst);
    let credentials_are_valid = if matches!(state.mode, ProviderMode::ClientSecretPost) {
        form.client_id.as_deref() == Some(CLIENT_ID)
            && form.client_secret.as_deref() == Some(CLIENT_SECRET)
            && headers.get(AUTHORIZATION).is_none()
    } else {
        headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Basic "))
            .and_then(|value| STANDARD.decode(value).ok())
            .is_some_and(|value| value == format!("{CLIENT_ID}:{CLIENT_SECRET}").as_bytes())
    };
    if !credentials_are_valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    if form.grant_type != "authorization_code"
        || !form.redirect_uri.ends_with("/v1/auth/sso/callback")
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_request"})),
        )
            .into_response();
    }
    if matches!(state.mode, ProviderMode::Unavailable) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "temporarily_unavailable"})),
        )
            .into_response();
    }
    if matches!(state.mode, ProviderMode::Slow) {
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
    }
    let Some(pending) = state
        .pending
        .lock()
        .expect("provider pending lock")
        .remove(&form.code)
    else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let actual_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(form.code_verifier.as_bytes()));
    if actual_challenge != pending.code_challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    }
    if matches!(state.mode, ProviderMode::MissingIdToken) {
        return Json(json!({
            "access_token": "mock-access-token",
            "token_type": "Bearer",
            "expires_in": 300
        }))
        .into_response();
    }

    let access_token = AccessToken::new("mock-access-token".into());
    let audience = if matches!(state.mode, ProviderMode::WrongAudience) {
        "another-client"
    } else {
        CLIENT_ID
    };
    let nonce = if matches!(state.mode, ProviderMode::WrongNonce) {
        "wrong-nonce".into()
    } else {
        pending.nonce
    };
    let expires_at = if matches!(state.mode, ProviderMode::Expired) {
        Utc::now() - Duration::minutes(1)
    } else {
        Utc::now() + Duration::minutes(5)
    };
    let claims = CoreIdTokenClaims::new(
        IssuerUrl::new(state.issuer.clone()).expect("provider issuer"),
        vec![Audience::new(audience.into())],
        expires_at,
        Utc::now() - Duration::seconds(1),
        StandardClaims::new(SubjectIdentifier::new(state.subject.clone()))
            .set_email(Some(EndUserEmail::new(state.email.clone())))
            .set_email_verified(Some(!matches!(state.mode, ProviderMode::UnverifiedEmail))),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(nonce)));
    let id_token = CoreIdToken::new(
        claims,
        state.signing_key.as_ref(),
        CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
        Some(&access_token),
        None,
    )
    .expect("sign mock ID token");
    Json(json!({
        "access_token": access_token.secret(),
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token.to_string()
    }))
    .into_response()
}

async fn configure(
    harness: &mut Harness,
    provider: &MockProvider,
    provisioning: &str,
    default_organization: Option<&str>,
) {
    harness.state.public_web_url = PUBLIC_WEB.into();
    harness.state.oidc = Some(
        OidcRuntime::for_tests(
            &provider.issuer,
            PUBLIC_API,
            PUBLIC_WEB,
            provisioning,
            default_organization,
        )
        .await
        .expect("configure OIDC runtime"),
    );
}

fn router_path(url: &reqwest::Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().into(),
    }
}

struct StartedFlow {
    callback_path: String,
    raw_state: String,
}

async fn begin_flow(harness: &Harness, next: Option<&str>) -> StartedFlow {
    let mut start =
        reqwest::Url::parse(&format!("{PUBLIC_API}/v1/auth/sso/start")).expect("SSO start URL");
    if let Some(next) = next {
        start.query_pairs_mut().append_pair("next", next);
    }
    let response = harness
        .raw_response(
            Request::builder()
                .uri(router_path(&start))
                .body(Body::empty())
                .expect("build SSO start request"),
        )
        .await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    let authorization_url = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| reqwest::Url::parse(value).ok())
        .expect("provider authorization redirect");
    let query: HashMap<_, _> = authorization_url.query_pairs().into_owned().collect();
    assert_eq!(query.get("client_id").map(String::as_str), Some(CLIENT_ID));
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    assert!(query
        .get("scope")
        .is_some_and(|scope| scope.split(' ').any(|value| value == "openid")));
    assert!(query
        .get("scope")
        .is_some_and(|scope| scope.split(' ').any(|value| value == "email")));
    let raw_state = query.get("state").expect("OIDC state").clone();

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("provider test client");
    let provider_response = client
        .get(authorization_url)
        .send()
        .await
        .expect("call provider authorization endpoint");
    assert_eq!(
        provider_response.status(),
        reqwest::StatusCode::TEMPORARY_REDIRECT
    );
    let callback = provider_response
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| reqwest::Url::parse(value).ok())
        .expect("provider callback redirect");
    StartedFlow {
        callback_path: router_path(&callback),
        raw_state,
    }
}

async fn finish_flow(harness: &Harness, flow: &StartedFlow) -> Response {
    harness
        .raw_response(
            Request::builder()
                .uri(&flow.callback_path)
                .body(Body::empty())
                .expect("build OIDC callback request"),
        )
        .await
}

fn redirect_location(response: &Response) -> &str {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
}

fn session_token(response: &Response) -> String {
    response
        .headers()
        .get(SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| cookie.split(';').next())
        .and_then(|cookie| cookie.strip_prefix("metrune_session="))
        .filter(|token| token.starts_with("mts_"))
        .expect("Metrune session cookie")
        .to_owned()
}

fn skipped(required: &[&str]) {
    eprintln!(
        "skipping: set {} to run this integration test",
        required.join(" and ")
    );
}

#[tokio::test]
async fn oidc_session_approves_device_enrollment_and_the_client_credential_uploads() {
    let Some(mut harness) = Harness::start_with_analytics().await else {
        skipped(&[DATABASE_URL_VAR, CLICKHOUSE_URL_VAR]);
        return;
    };
    let workspace = harness.workspace("oidc-device-upload").await;
    let provider = MockProvider::start(
        &workspace.admin.email,
        "enterprise-user-1",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;

    let (status, _) = harness
        .get("/v1/auth/me", Some(&workspace.admin.token))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a password-authenticated session survived SSO enforcement"
    );
    let service_token = harness
        .create_dashboard_token(workspace.organization_id, "admin")
        .await;
    let (status, settings) = harness.get("/v1/org/settings", Some(&service_token)).await;
    assert_eq!(status, StatusCode::OK, "{settings}");

    let (status, methods) = harness.get("/v1/auth/methods", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(methods["ssoEnabled"], true);
    assert_eq!(methods["passwordEnabled"], false);
    assert_eq!(methods["providerName"], "Test identity provider");
    let (status, body) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({
                "email": workspace.admin.email,
                "password": workspace.admin.password
            }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let next = "/device?user_code=ABCD-2345";
    let flow = begin_flow(&harness, Some(next)).await;
    let persisted: (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT state_hash, pkce_verifier, nonce, next_path
         FROM oidc_authorization_attempts WHERE state_hash = $1",
    )
    .bind(token_hash(&flow.raw_state))
    .fetch_one(&harness.postgres)
    .await
    .expect("persisted authorization attempt");
    assert_eq!(persisted.0, token_hash(&flow.raw_state));
    assert_ne!(persisted.0, flow.raw_state);
    assert!(!persisted.1.is_empty());
    assert!(!persisted.2.is_empty());
    assert_eq!(persisted.3.as_deref(), Some(next));

    let response = finish_flow(&harness, &flow).await;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(redirect_location(&response), format!("{PUBLIC_WEB}{next}"));
    let oidc_session = session_token(&response);
    let binding: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT issuer, subject FROM users WHERE id = $1")
            .bind(workspace.admin.user_id)
            .fetch_one(&harness.postgres)
            .await
            .expect("OIDC identity binding");
    assert_eq!(binding.0.as_deref(), Some(provider.issuer.as_str()));
    assert_eq!(binding.1.as_deref(), Some("enterprise-user-1"));
    let authentication_method: String =
        sqlx::query_scalar("SELECT authentication_method FROM web_sessions WHERE token_hash = $1")
            .bind(token_hash(&oidc_session))
            .fetch_one(&harness.postgres)
            .await
            .expect("OIDC session method");
    assert_eq!(authentication_method, "oidc");

    let (status, current_user) = harness.get("/v1/auth/me", Some(&oidc_session)).await;
    assert_eq!(status, StatusCode::OK, "{current_user}");
    assert_eq!(
        current_user["id"].as_str(),
        Some(workspace.admin.user_id.to_string().as_str())
    );

    let (status, authorization) = harness
        .send_form(
            "/v1/oauth/device/authorization",
            "client_id=metrune-cli&installation_name=sso-laptop&platform=linux",
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{authorization}");
    let user_code = authorization["user_code"]
        .as_str()
        .expect("device user code");
    let device_code = authorization["device_code"].as_str().expect("device code");
    let (status, approval) = harness
        .send(
            "POST",
            "/v1/oauth/device/approval",
            Some(&oidc_session),
            json!({"userCode": user_code, "decision": "approve"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{approval}");
    let (status, enrollment) = harness
        .send_form(
            "/v1/oauth/token",
            format!("grant_type={DEVICE_GRANT}&device_code={device_code}&client_id=metrune-cli"),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{enrollment}");
    let installation_token = enrollment["access_token"]
        .as_str()
        .expect("installation token");
    let installation_id = Uuid::parse_str(
        enrollment["installation_id"]
            .as_str()
            .expect("installation id"),
    )
    .expect("installation UUID");
    let owner: (Uuid, Option<Uuid>) =
        sqlx::query_as("SELECT organization_id, owner_user_id FROM installations WHERE id = $1")
            .bind(installation_id)
            .fetch_one(&harness.postgres)
            .await
            .expect("SSO-owned installation");
    assert_eq!(
        owner,
        (workspace.organization_id, Some(workspace.admin.user_id))
    );

    let (status, ack) = harness
        .send(
            "POST",
            "/v1/ingest/sessions",
            Some(installation_token),
            batch(
                &format!("oidc-upload-{}", Uuid::new_v4().simple()),
                vec![snapshot("oidc-client-session", "oidc-client-user")],
            ),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["accepted"].as_u64(), Some(1));

    harness.state.oidc = None;
    let (status, _) = harness.get("/v1/auth/me", Some(&oidc_session)).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an OIDC session survived a switch back to local authentication"
    );
    let (status, _) = harness
        .get("/v1/auth/me", Some(&workspace.admin.token))
        .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn oidc_state_and_authorization_code_are_single_use_under_concurrency() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };
    let workspace = harness.workspace("oidc-concurrency").await;
    let provider = MockProvider::start(
        &workspace.admin.email,
        "concurrent-user",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;
    let flow = begin_flow(&harness, None).await;
    let first = Request::builder()
        .uri(&flow.callback_path)
        .body(Body::empty())
        .expect("first callback");
    let second = Request::builder()
        .uri(&flow.callback_path)
        .body(Body::empty())
        .expect("second callback");
    let (first, second) = tokio::join!(harness.raw_response(first), harness.raw_response(second));
    let locations = [redirect_location(&first), redirect_location(&second)];
    assert_eq!(
        locations
            .iter()
            .filter(|location| **location == format!("{PUBLIC_WEB}/"))
            .count(),
        1,
        "{locations:?}"
    );
    assert_eq!(
        locations
            .iter()
            .filter(|location| location.contains("sso_error=invalid_state"))
            .count(),
        1,
        "{locations:?}"
    );
    assert_eq!(provider.state.token_requests.load(Ordering::SeqCst), 1);
    let sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM web_sessions
         WHERE user_id = $1 AND authentication_method = 'oidc'",
    )
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("OIDC session count");
    assert_eq!(sessions, 1);
}

#[tokio::test]
async fn invalid_provider_tokens_errors_and_timeouts_fail_closed() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };
    for (mode, expected_error) in [
        (ProviderMode::UnverifiedEmail, "invalid_token"),
        (ProviderMode::WrongNonce, "invalid_token"),
        (ProviderMode::WrongAudience, "invalid_token"),
        (ProviderMode::Expired, "invalid_token"),
        (ProviderMode::MissingIdToken, "invalid_response"),
        (ProviderMode::Unavailable, "temporarily_unavailable"),
        (ProviderMode::Slow, "temporarily_unavailable"),
        (ProviderMode::AccessDenied, "access_denied"),
    ] {
        let email = format!("failure-{}@example.test", Uuid::new_v4().simple());
        let provider = MockProvider::start(
            &email,
            &format!("subject-{}", Uuid::new_v4().simple()),
            mode,
            false,
        )
        .await;
        configure(&mut harness, &provider, "personal-org", None).await;
        let flow = begin_flow(&harness, None).await;
        let response = finish_flow(&harness, &flow).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(
            redirect_location(&response).ends_with(&format!("sso_error={expected_error}")),
            "{mode:?}: {}",
            redirect_location(&response)
        );
        assert!(
            response.headers().get(SET_COOKIE).is_none(),
            "a failed provider flow issued a browser session"
        );
        let user_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))")
                .bind(&email)
                .fetch_one(&harness.postgres)
                .await
                .expect("failed-flow identity lookup");
        assert!(!user_exists, "{mode:?} provisioned a user");
    }
}

#[tokio::test]
async fn expired_state_and_a_corrupted_pkce_verifier_never_issue_a_session() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };
    let workspace = harness.workspace("oidc-expiry-pkce").await;
    let provider = MockProvider::start(
        &workspace.admin.email,
        "expiry-pkce-user",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;

    let expired = begin_flow(&harness, None).await;
    sqlx::query(
        "UPDATE oidc_authorization_attempts SET expires_at = NOW() - INTERVAL '1 second'
         WHERE state_hash = $1",
    )
    .bind(token_hash(&expired.raw_state))
    .execute(&harness.postgres)
    .await
    .expect("expire OIDC state");
    let response = finish_flow(&harness, &expired).await;
    assert!(redirect_location(&response).ends_with("sso_error=invalid_state"));
    assert_eq!(provider.state.token_requests.load(Ordering::SeqCst), 0);

    let corrupt = begin_flow(&harness, None).await;
    sqlx::query(
        "UPDATE oidc_authorization_attempts SET pkce_verifier = $2
         WHERE state_hash = $1",
    )
    .bind(token_hash(&corrupt.raw_state))
    .bind("A".repeat(43))
    .execute(&harness.postgres)
    .await
    .expect("corrupt PKCE verifier");
    let response = finish_flow(&harness, &corrupt).await;
    assert!(redirect_location(&response).ends_with("sso_error=temporarily_unavailable"));
    assert_eq!(provider.state.token_requests.load(Ordering::SeqCst), 1);
    let sessions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM web_sessions
         WHERE user_id = $1 AND authentication_method = 'oidc'",
    )
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("OIDC session count");
    assert_eq!(sessions, 0);
}

#[tokio::test]
async fn discovery_refresh_accepts_a_legitimate_signing_key_rotation() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };
    let workspace = harness.workspace("oidc-key-rotation").await;
    let provider = MockProvider::start(
        &workspace.admin.email,
        "rotated-key-user",
        ProviderMode::ClientSecretPost,
        true,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;
    let flow = begin_flow(&harness, None).await;
    let response = finish_flow(&harness, &flow).await;
    assert_eq!(redirect_location(&response), format!("{PUBLIC_WEB}/"));
    assert!(session_token(&response).starts_with("mts_"));
    assert!(
        provider.state.jwks_requests.load(Ordering::SeqCst) >= 2,
        "the verifier did not refresh discovery/JWKS"
    );
}

#[tokio::test]
async fn provisioning_modes_and_external_identity_conflicts_are_enforced() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };

    let no_access_email = format!("no-access-{}@example.test", Uuid::new_v4().simple());
    let provider = MockProvider::start(
        &no_access_email,
        "no-access-user",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;
    let flow = begin_flow(&harness, None).await;
    let response = finish_flow(&harness, &flow).await;
    assert!(redirect_location(&response).ends_with("sso_error=account_unavailable"));
    let no_user: bool =
        sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = LOWER($1))")
            .bind(&no_access_email)
            .fetch_one(&harness.postgres)
            .await
            .expect("no-provisioning user absence");
    assert!(no_user);

    let personal_email = format!("personal-{}@example.test", Uuid::new_v4().simple());
    let personal =
        MockProvider::start(&personal_email, "personal-user", ProviderMode::Valid, false).await;
    configure(&mut harness, &personal, "personal-org", None).await;
    let response = finish_flow(&harness, &begin_flow(&harness, None).await).await;
    assert_eq!(redirect_location(&response), format!("{PUBLIC_WEB}/"));
    let personal_user: (Uuid, String, Option<String>, bool, bool) = sqlx::query_as(
        "SELECT u.id, m.role, u.password_hash, o.sso_enforced, o.local_login_enabled
         FROM users u
         JOIN organization_memberships m ON m.user_id = u.id
         JOIN organizations o ON o.id = m.organization_id
         WHERE LOWER(u.email) = LOWER($1)",
    )
    .bind(&personal_email)
    .fetch_one(&harness.postgres)
    .await
    .expect("personal organization user");
    assert_eq!(personal_user.1, "admin");
    assert_eq!(personal_user.2, None);
    assert!(personal_user.3);
    assert!(!personal_user.4);

    let default_org = harness.create_organization("oidc-default").await;
    let default_email = format!("default-{}@example.test", Uuid::new_v4().simple());
    let default =
        MockProvider::start(&default_email, "default-user", ProviderMode::Valid, false).await;
    configure(
        &mut harness,
        &default,
        "default-org",
        Some(&default_org.to_string()),
    )
    .await;
    let response = finish_flow(&harness, &begin_flow(&harness, None).await).await;
    assert_eq!(redirect_location(&response), format!("{PUBLIC_WEB}/"));
    let membership: (Uuid, String, Option<String>) = sqlx::query_as(
        "SELECT m.organization_id, m.role, u.password_hash
         FROM users u JOIN organization_memberships m ON m.user_id = u.id
         WHERE LOWER(u.email) = LOWER($1)",
    )
    .bind(&default_email)
    .fetch_one(&harness.postgres)
    .await
    .expect("default organization membership");
    assert_eq!(membership, (default_org, "viewer".into(), None));

    let conflict = harness.workspace("oidc-conflict").await;
    sqlx::query("UPDATE users SET issuer = $2, subject = $3 WHERE id = $1")
        .bind(conflict.admin.user_id)
        .bind(format!(
            "https://other-{}.idp.test",
            Uuid::new_v4().simple()
        ))
        .bind(format!("other-{}", Uuid::new_v4().simple()))
        .execute(&harness.postgres)
        .await
        .expect("bind conflicting identity");
    let conflict_provider = MockProvider::start(
        &conflict.admin.email,
        "new-subject",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &conflict_provider, "personal-org", None).await;
    let response = finish_flow(&harness, &begin_flow(&harness, None).await).await;
    assert!(redirect_location(&response).ends_with("sso_error=account_conflict"));
}

#[tokio::test]
async fn sso_invitations_password_recovery_and_reset_obey_the_fallback_policy() {
    let Some(mut harness) = Harness::start().await else {
        skipped(&[DATABASE_URL_VAR]);
        return;
    };
    let workspace = harness.workspace("oidc-password-policy").await;
    let invited_email = format!("sso-invite-{}@example.test", Uuid::new_v4().simple());
    let provider = MockProvider::start(
        &invited_email,
        "invited-sso-user",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &provider, "none", None).await;

    let mut invitation_entropy = Vec::with_capacity(32);
    invitation_entropy.extend_from_slice(Uuid::new_v4().as_bytes());
    invitation_entropy.extend_from_slice(Uuid::new_v4().as_bytes());
    let invitation_token = format!("mti_{}", URL_SAFE_NO_PAD.encode(invitation_entropy));
    let invitation_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO workspace_invitations(
           organization_id, email, role, token_hash, invited_by, expires_at, sent_at
         ) VALUES ($1,$2,'viewer',$3,$4,NOW() + INTERVAL '1 hour',NOW())
         RETURNING id",
    )
    .bind(workspace.organization_id)
    .bind(&invited_email)
    .bind(token_hash(&invitation_token))
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("insert SSO invitation");

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/invitations/accept",
            None,
            json!({
                "token": invitation_token,
                "displayName": "Invited SSO User",
                "password": "passwords-are-not-used"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let accepted_at: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT accepted_at FROM workspace_invitations WHERE id = $1")
            .bind(invitation_id)
            .fetch_one(&harness.postgres)
            .await
            .expect("unconsumed SSO invitation");
    assert!(accepted_at.is_none());

    let (status, body) = harness
        .send(
            "POST",
            "/v1/auth/invitations/accept",
            None,
            json!({
                "token": invitation_token,
                "displayName": "Invited SSO User"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    let invited: (Uuid, Option<String>, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT id, password_hash, issuer, subject FROM users WHERE LOWER(email) = LOWER($1)",
    )
    .bind(&invited_email)
    .fetch_one(&harness.postgres)
    .await
    .expect("SSO invitation user");
    assert_eq!(invited.1, None);
    assert_eq!(invited.2, None);
    assert_eq!(invited.3, None);

    let response = finish_flow(&harness, &begin_flow(&harness, None).await).await;
    assert_eq!(redirect_location(&response), format!("{PUBLIC_WEB}/"));
    let invited_session = session_token(&response);
    let linked: (String, String) =
        sqlx::query_as("SELECT issuer, subject FROM users WHERE id = $1")
            .bind(invited.0)
            .fetch_one(&harness.postgres)
            .await
            .expect("linked invited SSO user");
    assert_eq!(linked, (provider.issuer.clone(), "invited-sso-user".into()));
    let (status, me) = harness.get("/v1/auth/me", Some(&invited_session)).await;
    assert_eq!(status, StatusCode::OK, "{me}");

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/password-reset/request",
            None,
            json!({"email": invited_email}),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/password-reset/complete",
            None,
            json!({
                "token": format!("mtr_{}", "A".repeat(43)),
                "newPassword": "a completely ignored password"
            }),
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let admin_provider = MockProvider::start(
        &workspace.admin.email,
        "recovery-admin",
        ProviderMode::Valid,
        false,
    )
    .await;
    configure(&mut harness, &admin_provider, "none", None).await;
    let response = finish_flow(&harness, &begin_flow(&harness, None).await).await;
    let admin_session = session_token(&response);
    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/vault/recovery",
            Some(&admin_session),
            json!({"password": workspace.admin.password}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, recovery) = harness
        .send(
            "POST",
            "/v1/org/vault/recovery",
            Some(&admin_session),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{recovery}");
    assert!(recovery["recoveryKey"]
        .as_str()
        .is_some_and(|key| key.starts_with("mvrk_")));
    sqlx::query(
        "UPDATE web_sessions SET created_at = NOW() - INTERVAL '11 minutes'
         WHERE token_hash = $1",
    )
    .bind(token_hash(&admin_session))
    .execute(&harness.postgres)
    .await
    .expect("age OIDC session");
    let (status, _) = harness
        .send(
            "POST",
            "/v1/org/vault/recovery",
            Some(&admin_session),
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
