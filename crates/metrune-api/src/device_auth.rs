//! RFC 8628-shaped browser approval for the native Metrune client.
//!
//! Metrune is the authorization server for this flow. The CLI is a public
//! client and therefore has no embedded client secret. A signed-in browser
//! session approves a short-lived device request; the token endpoint then
//! returns the same revocable installation credential used by uploads.

use crate::{
    app::{
        audit, user_session_auth, validate_installation_name, validate_platform, AppState,
        EnrollResponse,
    },
    error::{token_hash, ApiError},
    limits::client_address,
};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use axum::{
    extract::{ConnectInfo, Form, State},
    http::{
        header::{CACHE_CONTROL, PRAGMA},
        HeaderMap, HeaderValue, StatusCode,
    },
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Postgres, Transaction};
use std::net::SocketAddr;
use uuid::Uuid;

const DEVICE_CLIENT_ID: &str = "metrune-cli";
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
const DEVICE_CODE_LIFETIME_MINUTES: i64 = 10;
const INITIAL_POLL_INTERVAL_SECONDS: i32 = 5;
const MAX_POLL_INTERVAL_SECONDS: i32 = 60;
const USER_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

type OAuthFailure = (StatusCode, HeaderMap, Json<OAuthErrorResponse>);
type OAuthResult<T> = Result<(HeaderMap, Json<T>), OAuthFailure>;

#[derive(Deserialize)]
pub(crate) struct DeviceAuthorizationRequest {
    client_id: String,
    installation_name: String,
    platform: String,
}

#[derive(Serialize)]
pub(crate) struct DeviceAuthorizationResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    verification_uri_complete: String,
    expires_in: i64,
    interval: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceVerificationRequest {
    user_code: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceVerificationResponse {
    user_code: String,
    installation_name: String,
    platform: String,
    expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DeviceDecision {
    Approve,
    Deny,
}

impl DeviceDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approved",
            Self::Deny => "denied",
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceApprovalRequest {
    user_code: String,
    decision: DeviceDecision,
    #[serde(default)]
    team_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceApprovalResponse {
    status: &'static str,
    user_code: String,
    installation_name: String,
    platform: String,
}

#[derive(Deserialize)]
pub(crate) struct DeviceTokenRequest {
    grant_type: String,
    device_code: String,
    client_id: String,
}

#[derive(Serialize)]
pub(crate) struct DeviceTokenResponse {
    access_token: String,
    token_type: &'static str,
    installation_id: Uuid,
    pseudonym_key: String,
    organization_id: Uuid,
    team_key: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct OAuthErrorResponse {
    error: &'static str,
    error_description: &'static str,
}

#[derive(FromRow)]
struct DeviceAuthorizationRow {
    id: Uuid,
    installation_name: String,
    platform: String,
    organization_id: Option<Uuid>,
    owner_user_id: Option<Uuid>,
    team_id: Option<Uuid>,
    status: String,
    poll_interval_seconds: i32,
    last_polled_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers
}

fn oauth_failure(
    status: StatusCode,
    error: &'static str,
    description: &'static str,
) -> OAuthFailure {
    (
        status,
        no_store_headers(),
        Json(OAuthErrorResponse {
            error,
            error_description: description,
        }),
    )
}

fn oauth_server_error(error: impl std::fmt::Display) -> OAuthFailure {
    tracing::error!(%error, "device authorization request failed");
    oauth_failure(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        "the authorization server could not complete the request",
    )
}

fn generate_device_code() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("mdc_{}", URL_SAFE_NO_PAD.encode(bytes))
}

fn generate_user_code() -> String {
    let mut bytes = [0_u8; 5];
    OsRng.fill_bytes(&mut bytes);
    let mut bits = 0_u64;
    for byte in bytes {
        bits = (bits << 8) | u64::from(byte);
    }
    let mut code = [b'0'; 8];
    for index in (0..8).rev() {
        code[index] = USER_CODE_ALPHABET[(bits & 31) as usize];
        bits >>= 5;
    }
    format!(
        "{}-{}",
        std::str::from_utf8(&code[..4]).expect("user code alphabet is ASCII"),
        std::str::from_utf8(&code[4..]).expect("user code alphabet is ASCII")
    )
}

fn normalize_user_code(value: &str) -> Option<String> {
    let normalized: String = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace() && *character != '-')
        .map(|character| match character.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect();
    if normalized.len() != 8
        || !normalized
            .bytes()
            .all(|character| USER_CODE_ALPHABET.contains(&character))
    {
        return None;
    }
    Some(normalized)
}

fn display_user_code(normalized: &str) -> String {
    format!("{}-{}", &normalized[..4], &normalized[4..])
}

fn verification_urls(public_web_url: &str, user_code: &str) -> (String, String) {
    let verification_uri = format!("{}/device", public_web_url.trim_end_matches('/'));
    let complete = format!("{verification_uri}?user_code={user_code}");
    (verification_uri, complete)
}

pub(crate) async fn authorize_device(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(request): Form<DeviceAuthorizationRequest>,
) -> OAuthResult<DeviceAuthorizationResponse> {
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    if state
        .rate_limiter
        .check(
            "device-authorization",
            &address,
            state.rate_limits.device_authorization,
        )
        .is_err()
    {
        return Err(oauth_failure(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "too many device authorization requests; retry later",
        ));
    }
    if request.client_id != DEVICE_CLIENT_ID {
        return Err(oauth_failure(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "unknown public client",
        ));
    }
    let installation_name = validate_installation_name(&request.installation_name)
        .map_err(|_| {
            oauth_failure(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "installation_name must be printable and between 1 and 120 characters",
            )
        })?
        .to_owned();
    let platform = validate_platform(&request.platform)
        .map_err(|_| {
            oauth_failure(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "unsupported platform",
            )
        })?
        .to_owned();

    let device_code = generate_device_code();
    let user_code = generate_user_code();
    let normalized_user_code =
        normalize_user_code(&user_code).expect("generated user code is valid");
    let expires_at = Utc::now() + Duration::minutes(DEVICE_CODE_LIFETIME_MINUTES);
    sqlx::query(
        "INSERT INTO device_enrollment_authorizations(
           device_code_hash, user_code_hash, client_id, installation_name,
           platform, poll_interval_seconds, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(token_hash(&device_code))
    .bind(token_hash(&normalized_user_code))
    .bind(DEVICE_CLIENT_ID)
    .bind(installation_name)
    .bind(platform)
    .bind(INITIAL_POLL_INTERVAL_SECONDS)
    .bind(expires_at)
    .execute(&state.postgres)
    .await
    .map_err(oauth_server_error)?;

    let (verification_uri, verification_uri_complete) =
        verification_urls(&state.public_web_url, &user_code);
    Ok((
        no_store_headers(),
        Json(DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete,
            expires_in: DEVICE_CODE_LIFETIME_MINUTES * 60,
            interval: INITIAL_POLL_INTERVAL_SECONDS,
        }),
    ))
}

async fn active_organization(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(Uuid, Uuid), ApiError> {
    let session = user_session_auth(state, headers).await?;
    let organization_id = session.active_organization_id.ok_or(ApiError::bad_request(
        "select a workspace before approving a device",
    ))?;
    let active: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM organization_memberships
           WHERE organization_id = $1 AND user_id = $2 AND disabled_at IS NULL
         )",
    )
    .bind(organization_id)
    .bind(session.user_id)
    .fetch_one(&state.postgres)
    .await?;
    if !active {
        return Err(ApiError::forbidden(
            "you are not an active member of this workspace",
        ));
    }
    Ok((organization_id, session.user_id))
}

fn normalized_code_or_error(user_code: &str) -> Result<String, ApiError> {
    normalize_user_code(user_code).ok_or(ApiError::bad_request(
        "the device code is invalid or expired",
    ))
}

pub(crate) async fn inspect_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceVerificationRequest>,
) -> Result<(HeaderMap, Json<DeviceVerificationResponse>), ApiError> {
    let (organization_id, user_id) = active_organization(&state, &headers).await?;
    state.rate_limiter.check(
        "device-verification",
        &format!("user:{user_id}"),
        state.rate_limits.device_verification,
    )?;
    let normalized = normalized_code_or_error(&request.user_code)?;
    let row = sqlx::query_as::<_, (String, String, DateTime<Utc>)>(
        "SELECT installation_name, platform, expires_at
         FROM device_enrollment_authorizations
         WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > NOW()",
    )
    .bind(token_hash(&normalized))
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::bad_request(
        "the device code is invalid or expired",
    ))?;
    // `organization_id` is deliberately resolved even though inspection does
    // not bind the request yet: a user with no active workspace may not review
    // or approve a device.
    let _ = organization_id;
    Ok((
        no_store_headers(),
        Json(DeviceVerificationResponse {
            user_code: display_user_code(&normalized),
            installation_name: row.0,
            platform: row.1,
            expires_at: row.2,
        }),
    ))
}

async fn validate_team(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: Uuid,
    team_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(team_id) = team_id else {
        return Ok(());
    };
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM teams WHERE id = $1 AND organization_id = $2
         )",
    )
    .bind(team_id)
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !valid {
        return Err(ApiError::bad_request(
            "teamId does not belong to the active workspace",
        ));
    }
    Ok(())
}

pub(crate) async fn approve_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceApprovalRequest>,
) -> Result<(HeaderMap, Json<DeviceApprovalResponse>), ApiError> {
    let (organization_id, user_id) = active_organization(&state, &headers).await?;
    state.rate_limiter.check(
        "device-verification",
        &format!("user:{user_id}"),
        state.rate_limits.device_verification,
    )?;
    let normalized = normalized_code_or_error(&request.user_code)?;
    let mut transaction = state.postgres.begin().await?;
    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, installation_name, platform
         FROM device_enrollment_authorizations
         WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > NOW()
         FOR UPDATE",
    )
    .bind(token_hash(&normalized))
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::bad_request(
        "the device code is invalid or expired",
    ))?;

    match request.decision {
        DeviceDecision::Approve => {
            validate_team(&mut transaction, organization_id, request.team_id).await?;
            sqlx::query(
                "UPDATE device_enrollment_authorizations
                 SET status = 'approved', organization_id = $2,
                     owner_user_id = $3, team_id = $4, approved_at = NOW()
                 WHERE id = $1",
            )
            .bind(row.0)
            .bind(organization_id)
            .bind(user_id)
            .bind(request.team_id)
            .execute(&mut *transaction)
            .await?;
        }
        DeviceDecision::Deny => {
            sqlx::query(
                "UPDATE device_enrollment_authorizations
                 SET status = 'denied', organization_id = $2,
                     owner_user_id = $3, team_id = NULL, denied_at = NOW()
                 WHERE id = $1",
            )
            .bind(row.0)
            .bind(organization_id)
            .bind(user_id)
            .execute(&mut *transaction)
            .await?;
        }
    }
    transaction.commit().await?;
    audit(
        &state,
        organization_id,
        &format!("user:{user_id}"),
        &format!("device_enrollment.{}", request.decision.as_str()),
        "device_enrollment",
        row.0.to_string(),
        serde_json::json!({
            "installationName": row.1,
            "platform": row.2,
            "teamId": request.team_id,
        }),
    )
    .await;
    Ok((
        no_store_headers(),
        Json(DeviceApprovalResponse {
            status: request.decision.as_str(),
            user_code: display_user_code(&normalized),
            installation_name: row.1,
            platform: row.2,
        }),
    ))
}

async fn lock_device_authorization(
    transaction: &mut Transaction<'_, Postgres>,
    request: &DeviceTokenRequest,
) -> Result<Option<DeviceAuthorizationRow>, sqlx::Error> {
    sqlx::query_as::<_, DeviceAuthorizationRow>(
        "SELECT id, installation_name, platform, organization_id,
                owner_user_id, team_id, status, poll_interval_seconds,
                last_polled_at, expires_at
         FROM device_enrollment_authorizations
         WHERE device_code_hash = $1 AND client_id = $2
         FOR UPDATE",
    )
    .bind(token_hash(&request.device_code))
    .bind(&request.client_id)
    .fetch_optional(&mut **transaction)
    .await
}

async fn pending_response(
    mut transaction: Transaction<'_, Postgres>,
    row: &DeviceAuthorizationRow,
) -> OAuthFailure {
    let now = Utc::now();
    let polled_too_soon = row
        .last_polled_at
        .is_some_and(|last| now < last + Duration::seconds(i64::from(row.poll_interval_seconds)));
    if polled_too_soon {
        let next_interval = (row.poll_interval_seconds + 5).min(MAX_POLL_INTERVAL_SECONDS);
        if let Err(error) = sqlx::query(
            "UPDATE device_enrollment_authorizations
             SET poll_interval_seconds = $2, last_polled_at = $3
             WHERE id = $1",
        )
        .bind(row.id)
        .bind(next_interval)
        .bind(now)
        .execute(&mut *transaction)
        .await
        {
            return oauth_server_error(error);
        }
        if let Err(error) = transaction.commit().await {
            return oauth_server_error(error);
        }
        return oauth_failure(
            StatusCode::BAD_REQUEST,
            "slow_down",
            "polling is faster than the permitted interval",
        );
    }
    if let Err(error) = sqlx::query(
        "UPDATE device_enrollment_authorizations
         SET last_polled_at = $2
         WHERE id = $1",
    )
    .bind(row.id)
    .bind(now)
    .execute(&mut *transaction)
    .await
    {
        return oauth_server_error(error);
    }
    if let Err(error) = transaction.commit().await {
        return oauth_server_error(error);
    }
    oauth_failure(
        StatusCode::BAD_REQUEST,
        "authorization_pending",
        "the user has not yet approved this device",
    )
}

pub(crate) async fn exchange_device_code(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(request): Form<DeviceTokenRequest>,
) -> OAuthResult<DeviceTokenResponse> {
    let address = client_address(&headers, peer, state.trust_proxy_headers);
    if state
        .rate_limiter
        .check("device-token", &address, state.rate_limits.device_token)
        .is_err()
    {
        return Err(oauth_failure(
            StatusCode::TOO_MANY_REQUESTS,
            "temporarily_unavailable",
            "too many token requests; retry later",
        ));
    }
    if request.grant_type != DEVICE_GRANT_TYPE {
        return Err(oauth_failure(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "grant_type must be the device authorization grant",
        ));
    }
    if request.client_id != DEVICE_CLIENT_ID {
        return Err(oauth_failure(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "unknown public client",
        ));
    }

    let mut transaction = state.postgres.begin().await.map_err(oauth_server_error)?;
    let Some(row) = lock_device_authorization(&mut transaction, &request)
        .await
        .map_err(oauth_server_error)?
    else {
        return Err(oauth_failure(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the device code is invalid or already consumed",
        ));
    };
    if row.expires_at <= Utc::now() {
        return Err(oauth_failure(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device code has expired",
        ));
    }
    match row.status.as_str() {
        "pending" => return Err(pending_response(transaction, &row).await),
        "denied" => {
            return Err(oauth_failure(
                StatusCode::BAD_REQUEST,
                "access_denied",
                "the user denied this device",
            ));
        }
        "consumed" => {
            return Err(oauth_failure(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "the device code is invalid or already consumed",
            ));
        }
        "approved" => {}
        _ => return Err(oauth_server_error("invalid device authorization state")),
    }

    let organization_id = row
        .organization_id
        .ok_or_else(|| oauth_server_error("approved device has no organization"))?;
    let owner_user_id = row
        .owner_user_id
        .ok_or_else(|| oauth_server_error("approved device has no owner"))?;
    let team_key = match row.team_id {
        Some(team_id) => sqlx::query_scalar::<_, String>(
            "SELECT name FROM teams WHERE id = $1 AND organization_id = $2",
        )
        .bind(team_id)
        .bind(organization_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(oauth_server_error)?,
        None => None,
    };
    let installation_id = Uuid::new_v4();
    let installation_token = format!("mti_{}", Uuid::new_v4().simple());
    let pseudonym_key = format!("mpk_{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO installations(
           id, organization_id, name, token_hash, team_key, team_id,
           owner_user_id, platform, created_at
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())",
    )
    .bind(installation_id)
    .bind(organization_id)
    .bind(&row.installation_name)
    .bind(token_hash(&installation_token))
    .bind(&team_key)
    .bind(row.team_id)
    .bind(owner_user_id)
    .bind(&row.platform)
    .execute(&mut *transaction)
    .await
    .map_err(oauth_server_error)?;
    sqlx::query(
        "UPDATE device_enrollment_authorizations
         SET status = 'consumed', consumed_at = NOW()
         WHERE id = $1 AND status = 'approved'",
    )
    .bind(row.id)
    .execute(&mut *transaction)
    .await
    .map_err(oauth_server_error)?;
    transaction.commit().await.map_err(oauth_server_error)?;

    let enrollment = EnrollResponse {
        installation_id,
        installation_token,
        pseudonym_key,
        organization_id,
        team_key,
    };
    Ok((
        no_store_headers(),
        Json(DeviceTokenResponse {
            access_token: enrollment.installation_token,
            token_type: "Bearer",
            installation_id: enrollment.installation_id,
            pseudonym_key: enrollment.pseudonym_key,
            organization_id: enrollment.organization_id,
            team_key: enrollment.team_key,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_round_trip_and_accept_human_equivalents() {
        for _ in 0..128 {
            let code = generate_user_code();
            let normalized = normalize_user_code(&code).expect("generated code");
            assert_eq!(normalized.len(), 8);
            assert_eq!(display_user_code(&normalized), code);
        }
        assert_eq!(
            normalize_user_code("o1il-2345").as_deref(),
            Some("01112345")
        );
        assert!(normalize_user_code("short").is_none());
        assert!(normalize_user_code("ABCD-!234").is_none());
    }

    #[test]
    fn verification_urls_are_scoped_to_the_browser_origin() {
        assert_eq!(
            verification_urls("https://metrune.example/", "ABCD-2345"),
            (
                "https://metrune.example/device".into(),
                "https://metrune.example/device?user_code=ABCD-2345".into()
            )
        );
    }

    #[test]
    fn device_codes_have_a_distinct_prefix_and_256_random_bits() {
        let code = generate_device_code();
        let encoded = code.strip_prefix("mdc_").expect("device-code prefix");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .expect("base64url code")
                .len(),
            32
        );
    }
}
