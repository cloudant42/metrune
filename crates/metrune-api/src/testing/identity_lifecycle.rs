//! Invitation and password-reset token lifecycles against live PostgreSQL.

use super::harness::{harness, Harness, Workspace};
use crate::error::token_hash;
use axum::http::StatusCode;
use chrono::{Duration, Utc};
use serde_json::json;
use uuid::Uuid;

fn token(prefix: &str, marker: char) -> String {
    let entropy = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    format!("{prefix}{marker}{}", &entropy[..42])
}

async fn invitation(
    harness: &Harness,
    workspace: &Workspace,
    email: &str,
    role: &str,
    raw_token: &str,
    expires_in: Duration,
) -> Uuid {
    sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO workspace_invitations(
           organization_id, email, role, token_hash, invited_by, expires_at, sent_at
         ) VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING id",
    )
    .bind(workspace.organization_id)
    .bind(email)
    .bind(role)
    .bind(token_hash(raw_token))
    .bind(workspace.admin.user_id)
    .bind(Utc::now() + expires_in)
    .fetch_one(&harness.postgres)
    .await
    .expect("insert invitation")
}

#[tokio::test]
async fn a_new_account_invitation_is_masked_single_use_and_concurrency_safe() {
    let harness = harness!();
    let workspace = harness.workspace("invite-new").await;
    let raw_token = token("mti_", 'A');
    let email = format!("new-{}@example.test", Uuid::new_v4().simple());
    invitation(
        &harness,
        &workspace,
        &email,
        "analyst",
        &raw_token,
        Duration::hours(1),
    )
    .await;

    let (status, inspection) = harness
        .send(
            "POST",
            "/v1/auth/invitations/inspect",
            None,
            json!({"token": raw_token}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(inspection["existingAccount"].as_bool(), Some(false));
    assert_eq!(inspection["role"].as_str(), Some("analyst"));
    assert_eq!(
        inspection["maskedEmail"].as_str(),
        Some(format!("n***@{}", email.split_once('@').unwrap().1).as_str())
    );
    assert!(
        inspection.to_string().find(&email).is_none(),
        "inspection exposed the full invited email"
    );

    let request = json!({
        "token": raw_token,
        "displayName": "New Teammate",
        "password": "a secure password",
    });
    let (first, second) = tokio::join!(
        harness.send("POST", "/v1/auth/invitations/accept", None, request.clone()),
        harness.send("POST", "/v1/auth/invitations/accept", None, request)
    );
    let mut statuses = [first.0, second.0];
    statuses.sort();
    assert_eq!(
        statuses,
        [StatusCode::NO_CONTENT, StatusCode::BAD_REQUEST],
        "the single-use invitation was accepted more than once"
    );

    let membership_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*)
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
         WHERE m.organization_id = $1 AND LOWER(u.email) = LOWER($2)
           AND m.role = 'analyst' AND m.disabled_at IS NULL",
    )
    .bind(workspace.organization_id)
    .bind(&email)
    .fetch_one(&harness.postgres)
    .await
    .expect("count accepted membership");
    assert_eq!(membership_count, 1);

    let (status, login) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": email, "password": "a secure password"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(login["sessionToken"]
        .as_str()
        .is_some_and(|value| value.starts_with("mts_")));
}

#[tokio::test]
async fn an_existing_account_must_sign_in_as_the_invited_identity() {
    let harness = harness!();
    let target = harness.workspace("invite-target").await;
    let source = harness.workspace("invite-source").await;
    let raw_token = token("mti_", 'B');
    invitation(
        &harness,
        &target,
        &source.viewer.email,
        "viewer",
        &raw_token,
        Duration::hours(1),
    )
    .await;

    let payload = json!({"token": raw_token});
    let (status, _) = harness
        .send("POST", "/v1/auth/invitations/accept", None, payload.clone())
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/invitations/accept",
            Some(&target.admin.token),
            payload.clone(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/invitations/accept",
            Some(&source.viewer.token),
            payload,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let role = sqlx::query_scalar::<_, String>(
        "SELECT role FROM organization_memberships
         WHERE organization_id = $1 AND user_id = $2 AND disabled_at IS NULL",
    )
    .bind(target.organization_id)
    .bind(source.viewer.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("accepted existing-account membership");
    assert_eq!(role, "viewer");
}

#[tokio::test]
async fn invalid_expired_and_revoked_invitations_share_the_same_public_failure() {
    let harness = harness!();
    let workspace = harness.workspace("invite-invalid").await;
    let expired = token("mti_", 'C');
    invitation(
        &harness,
        &workspace,
        "expired@example.test",
        "viewer",
        &expired,
        Duration::minutes(-1),
    )
    .await;
    let revoked = token("mti_", 'D');
    let revoked_id = invitation(
        &harness,
        &workspace,
        "revoked@example.test",
        "viewer",
        &revoked,
        Duration::hours(1),
    )
    .await;
    sqlx::query("UPDATE workspace_invitations SET revoked_at = NOW() WHERE id = $1")
        .bind(revoked_id)
        .execute(&harness.postgres)
        .await
        .expect("revoke invitation");

    let mut failures = Vec::new();
    for raw_token in [expired, revoked, token("mti_", 'E'), "not-a-token".into()] {
        let (status, body) = harness
            .send(
                "POST",
                "/v1/auth/invitations/inspect",
                None,
                json!({"token": raw_token}),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        failures.push(body);
    }
    assert!(
        failures.windows(2).all(|pair| pair[0] == pair[1]),
        "public invitation errors disclosed token state"
    );
}

#[tokio::test]
async fn password_reset_is_single_use_changes_the_password_and_revokes_sessions() {
    let harness = harness!();
    let workspace = harness.workspace("password-reset").await;
    let raw_token = token("mtr_", 'R');
    sqlx::query(
        "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at, sent_at)
         VALUES ($1,$2,$3,NOW())",
    )
    .bind(workspace.admin.user_id)
    .bind(token_hash(&raw_token))
    .bind(Utc::now() + Duration::minutes(30))
    .execute(&harness.postgres)
    .await
    .expect("insert password reset");

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/password-reset/complete",
            None,
            json!({"token": raw_token, "newPassword": "the new secure password"}),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = harness
        .get("/v1/auth/me", Some(&workspace.admin.token))
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "password reset left an existing session active"
    );
    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": workspace.admin.email, "password": workspace.admin.password}),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/login",
            None,
            json!({"email": workspace.admin.email, "password": "the new secure password"}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = harness
        .send(
            "POST",
            "/v1/auth/password-reset/complete",
            None,
            json!({"token": raw_token, "newPassword": "another secure password"}),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn password_reset_requests_are_generic_when_smtp_is_unavailable() {
    let harness = harness!();
    let workspace = harness.workspace("password-request").await;
    let before = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1",
    )
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("count resets before request");
    for email in [
        workspace.admin.email.as_str(),
        "not-an-email",
        "unknown@example.test",
    ] {
        let (status, body) = harness
            .send(
                "POST",
                "/v1/auth/password-reset/request",
                None,
                json!({"email": email}),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert!(body.is_null());
    }
    let after = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE user_id = $1",
    )
    .bind(workspace.admin.user_id)
    .fetch_one(&harness.postgres)
    .await
    .expect("count resets after request");
    assert_eq!(
        before, after,
        "a reset token was created even though it could not be delivered"
    );
}

#[tokio::test]
async fn the_identity_reaper_deletes_only_records_past_their_retention_window() {
    let harness = harness!();
    let workspace = harness.workspace("identity-reaper").await;

    let expired_session = harness
        .issue_session(workspace.admin.user_id, Some(workspace.organization_id))
        .await;
    sqlx::query(
        "UPDATE web_sessions SET expires_at = NOW() - INTERVAL '1 second' WHERE token_hash = $1",
    )
    .bind(token_hash(&expired_session))
    .execute(&harness.postgres)
    .await
    .expect("expire session");
    let recently_revoked_session = harness
        .issue_session(workspace.admin.user_id, Some(workspace.organization_id))
        .await;
    sqlx::query(
        "UPDATE web_sessions SET revoked_at = NOW() - INTERVAL '1 day' WHERE token_hash = $1",
    )
    .bind(token_hash(&recently_revoked_session))
    .execute(&harness.postgres)
    .await
    .expect("recently revoke session");

    let old_invitation = token("mti_", 'O');
    invitation(
        &harness,
        &workspace,
        &format!("old-{}@example.test", Uuid::new_v4().simple()),
        "viewer",
        &old_invitation,
        Duration::days(-8),
    )
    .await;
    let recent_invitation = token("mti_", 'N');
    invitation(
        &harness,
        &workspace,
        &format!("recent-{}@example.test", Uuid::new_v4().simple()),
        "viewer",
        &recent_invitation,
        Duration::days(-1),
    )
    .await;

    let old_reset = token("mtr_", 'O');
    let recent_reset = token("mtr_", 'N');
    for (raw_token, age) in [(&old_reset, -8_i64), (&recent_reset, -1_i64)] {
        sqlx::query(
            "INSERT INTO password_reset_tokens(user_id, token_hash, expires_at)
             VALUES ($1,$2,NOW() + ($3 * INTERVAL '1 day'))",
        )
        .bind(workspace.admin.user_id)
        .bind(token_hash(raw_token))
        .bind(age)
        .execute(&harness.postgres)
        .await
        .expect("insert reset record");
    }
    let old_device = token("mdc_", 'O');
    let recent_device = token("mdc_", 'N');
    for (raw_token, age) in [(&old_device, -8_i64), (&recent_device, -1_i64)] {
        sqlx::query(
            "INSERT INTO device_enrollment_authorizations(
               device_code_hash, user_code_hash, client_id, installation_name,
               platform, expires_at
             ) VALUES ($1,$2,'metrune-cli','reaper-device','linux',
                       NOW() + ($3 * INTERVAL '1 day'))",
        )
        .bind(token_hash(raw_token))
        .bind(token_hash(&format!("user-{raw_token}")))
        .bind(age)
        .execute(&harness.postgres)
        .await
        .expect("insert device authorization");
    }

    crate::app::reap_expired_identity_records(&harness.postgres)
        .await
        .expect("run one reaper pass");

    async fn exists(harness: &Harness, table: &str, hash: String) -> bool {
        let query = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE token_hash = $1)");
        sqlx::query_scalar::<_, bool>(&query)
            .bind(hash)
            .fetch_one(&harness.postgres)
            .await
            .expect("check reaper result")
    }

    assert!(!exists(&harness, "web_sessions", token_hash(&expired_session)).await);
    assert!(
        exists(
            &harness,
            "web_sessions",
            token_hash(&recently_revoked_session)
        )
        .await
    );
    assert!(
        !exists(
            &harness,
            "workspace_invitations",
            token_hash(&old_invitation)
        )
        .await
    );
    assert!(
        exists(
            &harness,
            "workspace_invitations",
            token_hash(&recent_invitation)
        )
        .await
    );
    assert!(!exists(&harness, "password_reset_tokens", token_hash(&old_reset)).await);
    assert!(exists(&harness, "password_reset_tokens", token_hash(&recent_reset)).await);
    let old_device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM device_enrollment_authorizations
           WHERE device_code_hash = $1
         )",
    )
    .bind(token_hash(&old_device))
    .fetch_one(&harness.postgres)
    .await
    .expect("check old device authorization");
    let recent_device_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM device_enrollment_authorizations
           WHERE device_code_hash = $1
         )",
    )
    .bind(token_hash(&recent_device))
    .fetch_one(&harness.postgres)
    .await
    .expect("check recent device authorization");
    assert!(!old_device_exists);
    assert!(recent_device_exists);
}
