use crate::{
    app::{audit, dashboard_auth, user_session_auth, AppState},
    error::{token_hash, ApiError},
    limits::client_address,
};
use argon2::{
    password_hash::{rand_core::RngCore, PasswordHasher, SaltString},
    Argon2,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{header::CACHE_CONTROL, HeaderMap, HeaderValue, StatusCode},
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use uuid::Uuid;

const INVITATION_TTL_HOURS: i64 = 24;
const PASSWORD_RESET_TTL_MINUTES: i64 = 30;
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_CHARS: usize = 128;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InvitationResponse {
    id: Uuid,
    email: String,
    role: String,
    status: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

/// A freshly created invitation, plus how it reached its recipient.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedInvitation {
    #[serde(flatten)]
    invitation: InvitationResponse,
    #[serde(flatten)]
    delivery: InvitationDelivery,
}

/// How an invitation reached its recipient. `email` when the server mailed it,
/// `manual` when there is no mail transport and the administrator has to
/// deliver `accept_url` themselves. The URL carries the single-use token, so it
/// is never returned once the server has mailed it instead.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InvitationDelivery {
    delivery: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    accept_url: Option<String>,
}

/// How an administrator-issued password reset reached the member. `manual`
/// carries the single-use link for the administrator to deliver.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PasswordResetDelivery {
    delivery: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset_url: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct CreateInvitationRequest {
    email: String,
    role: String,
}

pub(crate) async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<InvitationResponse>>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let rows = sqlx::query_as::<_, (Uuid, String, String, String, DateTime<Utc>, DateTime<Utc>)>(
        "SELECT id, email, role,
           CASE
             WHEN accepted_at IS NOT NULL THEN 'accepted'
             WHEN revoked_at IS NOT NULL THEN 'revoked'
             WHEN expires_at <= NOW() THEN 'expired'
             WHEN delivery_error_at IS NOT NULL THEN 'delivery_failed'
             WHEN sent_at IS NOT NULL THEN 'pending'
             ELSE 'manual'
           END,
           created_at, expires_at
         FROM workspace_invitations
         WHERE organization_id = $1
         ORDER BY created_at DESC",
    )
    .bind(auth.organization_uuid()?)
    .fetch_all(&state.postgres)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|row| InvitationResponse {
                id: row.0,
                email: row.1,
                role: row.2,
                status: row.3,
                created_at: row.4,
                expires_at: row.5,
            })
            .collect(),
    ))
}

pub(crate) async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateInvitationRequest>,
) -> Result<(StatusCode, Json<CreatedInvitation>), ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    state
        .rate_limiter
        .check("invitation", &auth.subject, state.rate_limits.invitation)?;
    let invited_by = auth.user_id.ok_or(ApiError::forbidden(
        "workspace invitations require an authenticated administrator",
    ))?;
    let role = crate::app::validate_member_role(request.role.trim())?.to_owned();
    let email = crate::mailer::normalize_email(&request.email)
        .map_err(|_| ApiError::bad_request("a valid email address is required"))?;
    // A deployment without SMTP is a supported configuration: the invitation is
    // still created, and the accept link is handed back for the administrator
    // to deliver. Failing here instead would leave such a workspace with no way
    // to add anyone.
    let mailer = state.mailer.clone();
    let organization_id = auth.organization_uuid()?;
    let organization_name =
        sqlx::query_scalar::<_, String>("SELECT name FROM organizations WHERE id = $1")
            .bind(organization_id)
            .fetch_one(&state.postgres)
            .await?;
    let is_member = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
           SELECT 1
           FROM organization_memberships m
           JOIN users u ON u.id = m.user_id
           WHERE m.organization_id = $1 AND LOWER(u.email) = $2
             AND m.disabled_at IS NULL AND u.disabled_at IS NULL
         )",
    )
    .bind(organization_id)
    .bind(&email)
    .fetch_one(&state.postgres)
    .await?;
    if is_member {
        return Err(ApiError::conflict(
            "that email already belongs to this workspace",
        ));
    }
    let has_pending = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(
           SELECT 1 FROM workspace_invitations
           WHERE organization_id = $1 AND LOWER(email) = $2
             AND accepted_at IS NULL AND revoked_at IS NULL
         )",
    )
    .bind(organization_id)
    .bind(&email)
    .fetch_one(&state.postgres)
    .await?;
    if has_pending {
        return Err(ApiError::conflict(
            "a pending invitation already exists; resend or revoke it",
        ));
    }
    let (token, digest) = generate_token("mti_");
    let expires_at = Utc::now() + invitation_ttl();
    let row = sqlx::query_as::<_, (Uuid, DateTime<Utc>)>(
        "INSERT INTO workspace_invitations(
           organization_id, email, role, token_hash, invited_by, expires_at
         ) VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id, created_at",
    )
    .bind(organization_id)
    .bind(&email)
    .bind(&role)
    .bind(digest)
    .bind(invited_by)
    .bind(expires_at)
    .fetch_one(&state.postgres)
    .await?;
    let accept_url = match &mailer {
        Some(mailer) => {
            if let Err(error) = mailer
                .send_invitation(&email, &organization_name, &role, &token)
                .await
            {
                tracing::warn!(
                    invitation_id = %row.0,
                    error = %error,
                    "invitation delivery failed"
                );
                mark_invitation_delivery(&state, row.0, false).await?;
                return Err(ApiError::bad_gateway(
                    "the invitation was created but email delivery failed; retry it from the invitations list",
                ));
            }
            mark_invitation_delivery(&state, row.0, true).await?;
            None
        }
        // Deliberately not marked as a delivery error: nothing failed, the
        // server simply has no mail transport and the link goes back instead.
        None => Some(invitation_accept_url(&state, &token)),
    };
    audit(
        &state,
        organization_id,
        &auth.name,
        "invitation.create",
        "workspace_invitation",
        row.0.to_string(),
        serde_json::json!({"email": email, "role": role}),
    )
    .await;
    Ok((
        StatusCode::CREATED,
        Json(CreatedInvitation {
            invitation: InvitationResponse {
                id: row.0,
                email,
                role,
                status: "pending".into(),
                created_at: row.1,
                expires_at,
            },
            delivery: InvitationDelivery {
                delivery: if accept_url.is_some() {
                    "manual"
                } else {
                    "email"
                },
                accept_url,
            },
        }),
    ))
}

/// The link an invited person opens. The token lives in the fragment so it is
/// never sent to the server in a request line, matching what the mailer sends.
fn invitation_accept_url(state: &AppState, token: &str) -> String {
    format!(
        "{}/accept-invite#{}",
        state.public_web_url.trim_end_matches('/'),
        token
    )
}

pub(crate) async fn resend_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<InvitationDelivery>, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    state
        .rate_limiter
        .check("invitation", &auth.subject, state.rate_limits.invitation)?;
    // Resending always rotates the token, so a workspace without SMTP can use
    // this to re-issue a link the administrator lost.
    let mailer = state.mailer.clone();
    let organization_id = auth.organization_uuid()?;
    let row = sqlx::query_as::<_, (String, String, String)>(
        "SELECT i.email, i.role, o.name
         FROM workspace_invitations i
         JOIN organizations o ON o.id = i.organization_id
         WHERE i.id = $1 AND i.organization_id = $2
           AND i.accepted_at IS NULL AND i.revoked_at IS NULL",
    )
    .bind(id)
    .bind(organization_id)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::not_found("pending invitation not found"))?;
    let (token, digest) = generate_token("mti_");
    sqlx::query(
        "UPDATE workspace_invitations
         SET token_hash = $2, expires_at = $3, sent_at = NULL,
             delivery_error_at = NULL
         WHERE id = $1",
    )
    .bind(id)
    .bind(digest)
    .bind(Utc::now() + invitation_ttl())
    .execute(&state.postgres)
    .await?;
    let accept_url = match &mailer {
        Some(mailer) => {
            if let Err(error) = mailer.send_invitation(&row.0, &row.2, &row.1, &token).await {
                tracing::warn!(invitation_id = %id, error = %error, "invitation delivery failed");
                mark_invitation_delivery(&state, id, false).await?;
                return Err(ApiError::bad_gateway(
                    "email delivery failed; the invitation remains available to retry",
                ));
            }
            mark_invitation_delivery(&state, id, true).await?;
            None
        }
        None => Some(invitation_accept_url(&state, &token)),
    };
    audit(
        &state,
        organization_id,
        &auth.name,
        "invitation.resend",
        "workspace_invitation",
        id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(Json(InvitationDelivery {
        delivery: if accept_url.is_some() {
            "manual"
        } else {
            "email"
        },
        accept_url,
    }))
}

pub(crate) async fn revoke_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    let organization_id = auth.organization_uuid()?;
    let result = sqlx::query(
        "UPDATE workspace_invitations
         SET revoked_at = NOW()
         WHERE id = $1 AND organization_id = $2
           AND accepted_at IS NULL AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(organization_id)
    .execute(&state.postgres)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("pending invitation not found"));
    }
    audit(
        &state,
        organization_id,
        &auth.name,
        "invitation.revoke",
        "workspace_invitation",
        id.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct InvitationTokenRequest {
    token: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InvitationInspectionResponse {
    organization_name: String,
    masked_email: String,
    role: String,
    existing_account: bool,
    expires_at: DateTime<Utc>,
}

pub(crate) async fn inspect_invitation(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<InvitationTokenRequest>,
) -> Result<Json<InvitationInspectionResponse>, ApiError> {
    limit_public_identity_request(&state, &headers, peer, "invitation")?;
    let digest = invitation_digest(&request.token)?;
    let row = sqlx::query_as::<_, (String, String, String, DateTime<Utc>)>(
        "SELECT o.name, i.email, i.role, i.expires_at
         FROM workspace_invitations i
         JOIN organizations o ON o.id = i.organization_id
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL
           AND i.revoked_at IS NULL AND i.expires_at > NOW()",
    )
    .bind(digest)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::bad_request(
        "invitation is invalid, expired, or already used",
    ))?;
    let existing_account = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM users WHERE LOWER(email) = $1 AND disabled_at IS NULL)",
    )
    .bind(row.1.to_ascii_lowercase())
    .fetch_one(&state.postgres)
    .await?;
    Ok(Json(InvitationInspectionResponse {
        organization_name: row.0,
        masked_email: mask_email(&row.1),
        role: row.2,
        existing_account,
        expires_at: row.3,
    }))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AcceptInvitationRequest {
    token: String,
    display_name: Option<String>,
    password: Option<String>,
}

pub(crate) async fn accept_invitation(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<AcceptInvitationRequest>,
) -> Result<StatusCode, ApiError> {
    limit_public_identity_request(&state, &headers, peer, "invitation")?;
    let digest = invitation_digest(&request.token)?;
    let password_hash = match (state.oidc.is_some(), request.password) {
        (true, Some(_)) => {
            return Err(ApiError::bad_request(
                "passwords are unavailable while single sign-on is configured",
            ));
        }
        (true, None) => None,
        (false, Some(password)) => Some(hash_password(password).await?),
        (false, None) => None,
    };
    let mut transaction = state.postgres.begin().await?;
    let invitation = sqlx::query_as::<_, (Uuid, Uuid, String, String, String)>(
        "SELECT i.id, i.organization_id, i.email, i.role, o.name
         FROM workspace_invitations i
         JOIN organizations o ON o.id = i.organization_id
         WHERE i.token_hash = $1 AND i.accepted_at IS NULL
           AND i.revoked_at IS NULL AND i.expires_at > NOW()
         FOR UPDATE OF i",
    )
    .bind(digest)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::bad_request(
        "invitation is invalid, expired, or already used",
    ))?;
    let users = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, email FROM users
         WHERE LOWER(email) = $1 AND disabled_at IS NULL
         ORDER BY created_at LIMIT 2",
    )
    .bind(invitation.2.to_ascii_lowercase())
    .fetch_all(&mut *transaction)
    .await?;
    let user_id = match users.as_slice() {
        [] => {
            let display_name = request
                .display_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty());
            if display_name.is_some_and(|value| value.chars().count() > 120) {
                return Err(ApiError::bad_request(
                    "display name must be between 1 and 120 characters",
                ));
            }
            if state.oidc.is_none() && display_name.is_none() {
                return Err(ApiError::bad_request(
                    "display name must be between 1 and 120 characters",
                ));
            }
            if state.oidc.is_none() && password_hash.is_none() {
                return Err(ApiError::bad_request(
                    "a password is required for a new account",
                ));
            }
            sqlx::query_scalar::<_, Uuid>(
                "INSERT INTO users(
                   organization_id, email, display_name, password_hash, role
                 ) VALUES ($1,$2,$3,$4,$5)
                 RETURNING id",
            )
            .bind(invitation.1)
            .bind(&invitation.2)
            .bind(display_name)
            .bind(password_hash)
            .bind(&invitation.3)
            .fetch_one(&mut *transaction)
            .await?
        }
        [user] => {
            let session = user_session_auth(&state, &headers).await.map_err(|_| {
                ApiError::unauthorized(
                    "sign in with the invited account before accepting this invitation",
                )
            })?;
            if session.user_id != user.0 {
                return Err(ApiError::forbidden(
                    "the signed-in account does not match the invited email",
                ));
            }
            user.0
        }
        _ => {
            return Err(ApiError::conflict(
                "multiple legacy accounts use that email; an administrator must consolidate them",
            ));
        }
    };
    sqlx::query(
        "INSERT INTO organization_memberships(
           organization_id, user_id, role, disabled_at, updated_at
         ) VALUES ($1,$2,$3,NULL,NOW())
         ON CONFLICT (organization_id, user_id)
         DO UPDATE SET role = EXCLUDED.role, disabled_at = NULL, updated_at = NOW()",
    )
    .bind(invitation.1)
    .bind(user_id)
    .bind(&invitation.3)
    .execute(&mut *transaction)
    .await?;
    sqlx::query("UPDATE workspace_invitations SET accepted_at = NOW() WHERE id = $1")
        .bind(invitation.0)
        .execute(&mut *transaction)
        .await?;
    transaction.commit().await?;
    audit(
        &state,
        invitation.1,
        &invitation.2,
        "invitation.accept",
        "workspace_invitation",
        invitation.0.to_string(),
        serde_json::json!({"userId": user_id, "role": invitation.3}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub(crate) struct PasswordResetRequest {
    email: String,
}

/// Issue a password reset for a member on an administrator's behalf.
///
/// The public endpoint answers `202` for every address so it cannot be used to
/// enumerate accounts, which also means it can never hand back a link. A
/// deployment without SMTP therefore has no recovery path at all, so an
/// administrator can mint one here and deliver it out of band, exactly as with
/// an invitation.
pub(crate) async fn reset_member_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Json<PasswordResetDelivery>, ApiError> {
    if state.oidc.is_some() {
        return Err(ApiError::not_found(
            "password reset is unavailable while single sign-on is configured",
        ));
    }
    let auth = dashboard_auth(&state, &headers).await?;
    auth.require_admin()?;
    auth.user_id.ok_or(ApiError::forbidden(
        "resetting a member password requires an authenticated administrator",
    ))?;
    let organization_id = auth.organization_uuid()?;
    state.rate_limiter.check(
        "password_reset",
        &auth.subject,
        state.rate_limits.password_reset,
    )?;

    // Scoped to the caller's own organization so an admin cannot reset an
    // account that merely shares this server.
    let member = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT u.id, u.email
         FROM users u
         JOIN organization_memberships m ON m.user_id = u.id
         WHERE u.id = $1 AND m.organization_id = $2
           AND u.disabled_at IS NULL AND m.disabled_at IS NULL",
    )
    .bind(user_id)
    .bind(organization_id)
    .fetch_optional(&state.postgres)
    .await?
    .ok_or(ApiError::not_found("member not found"))?;

    let (token, digest) = generate_token("mtr_");
    let mut transaction = state.postgres.begin().await?;
    sqlx::query(
        "UPDATE password_reset_tokens
         SET revoked_at = NOW()
         WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(member.0)
    .execute(&mut *transaction)
    .await?;
    let reset_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at)
         VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(member.0)
    .bind(digest)
    .bind(Utc::now() + password_reset_ttl())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;

    let reset_url = match state.mailer.clone() {
        Some(mailer) => {
            if let Err(error) = mailer.send_password_reset(&member.1, &token).await {
                tracing::warn!(reset_id = %reset_id, error = %error, "password reset delivery failed");
                sqlx::query(
                    "UPDATE password_reset_tokens SET delivery_error_at = NOW() WHERE id = $1",
                )
                .bind(reset_id)
                .execute(&state.postgres)
                .await?;
                return Err(ApiError::bad_gateway(
                    "the reset was created but email delivery failed; try again",
                ));
            }
            sqlx::query(
                "UPDATE password_reset_tokens
                 SET sent_at = NOW(), delivery_error_at = NULL WHERE id = $1",
            )
            .bind(reset_id)
            .execute(&state.postgres)
            .await?;
            None
        }
        None => Some(format!(
            "{}/reset-password#{}",
            state.public_web_url.trim_end_matches('/'),
            token
        )),
    };

    audit(
        &state,
        organization_id,
        &auth.name,
        "member.password_reset",
        "user",
        member.0.to_string(),
        serde_json::json!({}),
    )
    .await;
    Ok(Json(PasswordResetDelivery {
        delivery: if reset_url.is_some() {
            "manual"
        } else {
            "email"
        },
        reset_url,
    }))
}

pub(crate) async fn request_password_reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<PasswordResetRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    if state.oidc.is_some() {
        return Err(ApiError::not_found(
            "password reset is unavailable while single sign-on is configured",
        ));
    }
    limit_public_identity_request(&state, &headers, peer, "password_reset")?;
    let Ok(email) = crate::mailer::normalize_email(&request.email) else {
        return Ok((no_store_headers(), StatusCode::ACCEPTED));
    };
    let Some(mailer) = state.mailer.clone() else {
        return Ok((no_store_headers(), StatusCode::ACCEPTED));
    };
    let users = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, email FROM users
         WHERE LOWER(email) = $1 AND disabled_at IS NULL
         ORDER BY created_at LIMIT 2",
    )
    .bind(&email)
    .fetch_all(&state.postgres)
    .await?;
    let [user] = users.as_slice() else {
        return Ok((no_store_headers(), StatusCode::ACCEPTED));
    };
    let (token, digest) = generate_token("mtr_");
    let mut transaction = state.postgres.begin().await?;
    sqlx::query(
        "UPDATE password_reset_tokens
         SET revoked_at = NOW()
         WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(user.0)
    .execute(&mut *transaction)
    .await?;
    let reset_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at)
         VALUES ($1,$2,$3) RETURNING id",
    )
    .bind(user.0)
    .bind(digest)
    .bind(Utc::now() + password_reset_ttl())
    .fetch_one(&mut *transaction)
    .await?;
    transaction.commit().await?;
    match mailer.send_password_reset(&user.1, &token).await {
        Ok(()) => {
            sqlx::query(
                "UPDATE password_reset_tokens
                 SET sent_at = NOW(), delivery_error_at = NULL WHERE id = $1",
            )
            .bind(reset_id)
            .execute(&state.postgres)
            .await?;
        }
        Err(error) => {
            tracing::warn!(
                reset_id = %reset_id,
                error = %error,
                "password reset delivery failed"
            );
            sqlx::query(
                "UPDATE password_reset_tokens
                 SET delivery_error_at = NOW() WHERE id = $1",
            )
            .bind(reset_id)
            .execute(&state.postgres)
            .await?;
        }
    }
    Ok((no_store_headers(), StatusCode::ACCEPTED))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompletePasswordResetRequest {
    token: String,
    new_password: String,
}

pub(crate) async fn complete_password_reset(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<CompletePasswordResetRequest>,
) -> Result<(HeaderMap, StatusCode), ApiError> {
    if state.oidc.is_some() {
        return Err(ApiError::not_found(
            "password reset is unavailable while single sign-on is configured",
        ));
    }
    limit_public_identity_request(&state, &headers, peer, "password_reset")?;
    let digest = reset_digest(&request.token)?;
    let password_hash = hash_password(request.new_password).await?;
    let mut transaction = state.postgres.begin().await?;
    let token_row = sqlx::query_as::<_, (Uuid, Uuid)>(
        "SELECT id, user_id FROM password_reset_tokens
         WHERE token_hash = $1 AND consumed_at IS NULL
           AND revoked_at IS NULL AND expires_at > NOW()
         FOR UPDATE",
    )
    .bind(digest)
    .fetch_optional(&mut *transaction)
    .await?
    .ok_or(ApiError::bad_request(
        "password reset link is invalid, expired, or already used",
    ))?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1 AND disabled_at IS NULL")
        .bind(token_row.1)
        .bind(password_hash)
        .execute(&mut *transaction)
        .await?;
    sqlx::query(
        "UPDATE password_reset_tokens
         SET consumed_at = CASE WHEN id = $2 THEN NOW() ELSE consumed_at END,
             revoked_at = CASE WHEN id <> $2 THEN NOW() ELSE revoked_at END
         WHERE user_id = $1 AND consumed_at IS NULL AND revoked_at IS NULL",
    )
    .bind(token_row.1)
    .bind(token_row.0)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "UPDATE web_sessions SET revoked_at = NOW()
         WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(token_row.1)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok((no_store_headers(), StatusCode::NO_CONTENT))
}

fn no_store_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

async fn mark_invitation_delivery(
    state: &AppState,
    invitation_id: Uuid,
    delivered: bool,
) -> Result<(), ApiError> {
    let query = if delivered {
        "UPDATE workspace_invitations
         SET sent_at = NOW(), delivery_error_at = NULL WHERE id = $1"
    } else {
        "UPDATE workspace_invitations
         SET delivery_error_at = NOW() WHERE id = $1"
    };
    sqlx::query(query)
        .bind(invitation_id)
        .execute(&state.postgres)
        .await?;
    Ok(())
}

fn limit_public_identity_request(
    state: &AppState,
    headers: &HeaderMap,
    peer: SocketAddr,
    scope: &str,
) -> Result<(), ApiError> {
    let address = client_address(headers, peer, state.trust_proxy_headers);
    let limit = match scope {
        "invitation" => state.rate_limits.invitation,
        _ => state.rate_limits.password_reset,
    };
    state.rate_limiter.check(scope, &address, limit)
}

fn generate_token(prefix: &str) -> (String, String) {
    let mut bytes = [0_u8; 32];
    argon2::password_hash::rand_core::OsRng.fill_bytes(&mut bytes);
    let token = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes));
    let digest = token_hash(&token);
    (token, digest)
}

fn invitation_digest(token: &str) -> Result<String, ApiError> {
    if !valid_token(token, "mti_") {
        return Err(ApiError::bad_request(
            "invitation is invalid, expired, or already used",
        ));
    }
    Ok(token_hash(token))
}

fn reset_digest(token: &str) -> Result<String, ApiError> {
    if !valid_token(token, "mtr_") {
        return Err(ApiError::bad_request(
            "password reset link is invalid, expired, or already used",
        ));
    }
    Ok(token_hash(token))
}

fn valid_token(token: &str, prefix: &str) -> bool {
    token.starts_with(prefix)
        && token.len() == prefix.len() + 43
        && token[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn invitation_ttl() -> Duration {
    Duration::hours(
        std::env::var("METRUNE_INVITATION_TTL_HOURS")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &i64| (1..=168).contains(value))
            .unwrap_or(INVITATION_TTL_HOURS),
    )
}

fn password_reset_ttl() -> Duration {
    Duration::minutes(
        std::env::var("METRUNE_PASSWORD_RESET_TTL_MINUTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .filter(|value: &i64| (5..=120).contains(value))
            .unwrap_or(PASSWORD_RESET_TTL_MINUTES),
    )
}

async fn hash_password(password: String) -> Result<String, ApiError> {
    validate_password(&password)?;
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(
                password.as_bytes(),
                &SaltString::generate(&mut argon2::password_hash::rand_core::OsRng),
            )
            .map(|hash| hash.to_string())
            .map_err(|_| ApiError::bad_request("password could not be secured"))
    })
    .await?
}

fn validate_password(password: &str) -> Result<(), ApiError> {
    let count = password.chars().count();
    if !(MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&count) {
        return Err(ApiError::bad_request(format!(
            "password must be between {MIN_PASSWORD_CHARS} and {MAX_PASSWORD_CHARS} characters"
        )));
    }
    Ok(())
}

fn mask_email(email: &str) -> String {
    let Some((local, domain)) = email.split_once('@') else {
        return "***".into();
    };
    let first = local.chars().next().unwrap_or('*');
    format!("{first}***@{domain}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_are_prefixed_high_entropy_and_hashable() {
        let (invitation, digest) = generate_token("mti_");
        assert!(valid_token(&invitation, "mti_"));
        assert_eq!(digest, token_hash(&invitation));
        assert_ne!(invitation, generate_token("mti_").0);

        let (reset, _) = generate_token("mtr_");
        assert!(valid_token(&reset, "mtr_"));
        assert!(!valid_token(&reset, "mti_"));
    }

    #[test]
    fn password_policy_is_explicit_and_bounded() {
        assert!(validate_password("correct horse").is_ok());
        assert!(validate_password("short").is_err());
        assert!(validate_password(&"x".repeat(MAX_PASSWORD_CHARS + 1)).is_err());
    }

    #[test]
    fn invitation_inspection_masks_the_recipient() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_email("invalid"), "***");
    }
}
